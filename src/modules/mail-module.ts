import type { EventBus } from '../core/events';
import type { ExternalRequest, ExternalResponse, ExternalServiceHandler } from '../core/fabric/types';
import type { Module, SimulationContext, Capability } from '../core/modules';
import type {
    MailAttachmentSpec,
    MailMessageSpec,
    MailSystemSpec,
    MailTemplateSpec,
} from '../core/world/types';

const MODULE_ID = 'mail-system';
const MODULE_VERSION = '1.0.0';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

interface MailAccountRuntime {
    readonly displayName: string;
    readonly machine: string;
    readonly role?: string;
    readonly password?: string;
    readonly forwardTo?: readonly string[];
    readonly accessibleMailboxes?: readonly string[];
}

interface RuntimeMessage extends MailMessageSpec {
    readonly folder: MailFolder;
    readonly createdAt: number;
}

type MailFolder = 'inbox' | 'sent' | 'drafts' | 'trash';

interface CampaignMessage {
    readonly id: string;
    readonly account: string;
    readonly clicked: boolean;
}

interface CampaignState {
    readonly id: string;
    readonly templateId: string;
    readonly createdAt: number;
    readonly targets: readonly string[];
    readonly messages: readonly CampaignMessage[];
}

interface MailSystemRuntime {
    readonly domain: string;
    readonly accounts: Readonly<Record<string, MailAccountRuntime>>;
    readonly templates: Readonly<Record<string, MailTemplateSpec>>;
    readonly mailboxes: Map<string, Map<MailFolder, RuntimeMessage[]>>;
    readonly campaigns: Map<string, CampaignState>;
    nextMessageId: number;
    nextCampaignId: number;
}

interface SendPayload {
    readonly from?: string;
    readonly to?: string | readonly string[];
    readonly subject?: string;
    readonly body?: string;
    readonly html?: boolean;
    readonly attachments?: readonly MailAttachmentSpec[];
    readonly headers?: Readonly<Record<string, string>>;
    readonly malicious?: boolean;
    readonly maliciousAction?: string;
    readonly senderPassword?: string;
    readonly templateId?: string;
    readonly variables?: Readonly<Record<string, string>>;
}

interface CampaignPayload {
    readonly templateId?: string;
    readonly targets?: readonly string[];
    readonly variables?: Readonly<Record<string, string>>;
    readonly clickAccounts?: readonly string[];
}

const noopEventBus: EventBus = {
    emit() {},
    on() { return () => undefined; },
    onPrefix() { return () => undefined; },
    getLog() { return []; },
    clearLog() {},
    once() { return () => undefined; },
    waitFor() { return Promise.reject(new Error('noop event bus')); },
    removeAllListeners() {},
};

function jsonResponse(status: number, data: unknown): ExternalResponse {
    const headers = new Map<string, string>();
    headers.set('content-type', 'application/json');
    headers.set('server', 'VARIANT-Mail/1.0');
    return { status, headers, body: encoder.encode(JSON.stringify(data, null, 2)) };
}

function textResponse(status: number, text: string, contentType = 'text/plain'): ExternalResponse {
    const headers = new Map<string, string>();
    headers.set('content-type', contentType);
    headers.set('server', 'VARIANT-Mail/1.0');
    return { status, headers, body: encoder.encode(text) };
}

function parseRequestJson(request: ExternalRequest): Record<string, unknown> {
    if (request.body === null || request.body.length === 0) return {};
    try {
        const raw = decoder.decode(request.body);
        const parsed = JSON.parse(raw);
        return typeof parsed === 'object' && parsed !== null ? parsed as Record<string, unknown> : {};
    } catch {
        return {};
    }
}

function stripQuery(path: string): string {
    const idx = path.indexOf('?');
    return idx >= 0 ? path.slice(0, idx) : path;
}

function parseQuery(path: string): URLSearchParams {
    const idx = path.indexOf('?');
    return new URLSearchParams(idx >= 0 ? path.slice(idx + 1) : '');
}

function splitPath(path: string): readonly string[] {
    const normalized = stripQuery(path).replace(/^\/+/, '').replace(/\/+$/, '');
    if (normalized === '') return [];
    return normalized.split('/');
}

function parseBasicAuth(headers: ReadonlyMap<string, string>): { user: string; pass: string } | null {
    let auth: string | undefined;
    for (const [name, value] of headers) {
        if (name.toLowerCase() === 'authorization') {
            auth = value;
            break;
        }
    }
    if (auth === undefined) return null;
    const [scheme, token] = auth.split(' ', 2) as [string, string | undefined];
    if (!scheme || scheme.toLowerCase() !== 'basic' || token === undefined || token.trim() === '') return null;
    try {
        const decoded = atob(token);
        const sep = decoded.indexOf(':');
        if (sep < 0) return null;
        return {
            user: decoded.slice(0, sep),
            pass: decoded.slice(sep + 1),
        };
    } catch {
        return null;
    }
}

function resolveAuthAccount(
    request: ExternalRequest,
    runtime: MailSystemRuntime,
): { account: string; mailboxAccess: ReadonlySet<string> } | null {
    const auth = parseBasicAuth(request.headers);
    if (auth === null) return null;
    const account = runtime.accounts[auth.user];
    if (account === undefined || account.password === undefined) return null;
    if (auth.pass !== account.password) return null;

    const mailboxAccess = new Set<string>();
    mailboxAccess.add(auth.user);
    if (account.accessibleMailboxes !== undefined) {
        for (const mailbox of account.accessibleMailboxes) {
            mailboxAccess.add(mailbox);
        }
    }
    return { account: auth.user, mailboxAccess };
}

function accountExists(runtime: MailSystemRuntime, account: string): boolean {
    return runtime.accounts[account] !== undefined;
}

function ensureMailbox(runtime: MailSystemRuntime, account: string): Map<MailFolder, RuntimeMessage[]> {
    const existing = runtime.mailboxes.get(account);
    if (existing !== undefined) return existing;

    const folders = new Map<MailFolder, RuntimeMessage[]>();
    folders.set('inbox', []);
    folders.set('sent', []);
    folders.set('drafts', []);
    folders.set('trash', []);
    runtime.mailboxes.set(account, folders);
    return folders;
}

function folderMessages(runtime: MailSystemRuntime, account: string, folder: MailFolder): RuntimeMessage[] {
    const mailbox = ensureMailbox(runtime, account);
    const messages = mailbox.get(folder);
    if (messages === undefined) {
        const empty: RuntimeMessage[] = [];
        mailbox.set(folder, empty);
        return empty;
    }
    return messages;
}

function nextMessageId(runtime: MailSystemRuntime): string {
    const id = `msg-${runtime.nextMessageId}`;
    runtime.nextMessageId += 1;
    return id;
}

function applyTemplate(template: MailTemplateSpec, variables: Readonly<Record<string, string>>): MailTemplateSpec {
    const replace = (input: string): string => input.replace(/\{([a-zA-Z0-9_]+)\}/g, (_m, key: string) => variables[key] ?? `{${key}}`);

    const result: MailTemplateSpec = {
        ...template,
        from: replace(template.from),
        subject: replace(template.subject),
        body: replace(template.body),
    };
    if (template.attachments !== undefined) {
        (result as { attachments: typeof template.attachments }).attachments = template.attachments.map(att => ({
            ...att,
            filename: replace(att.filename),
            content: replace(att.content),
        }));
    }
    if (template.headers !== undefined) {
        (result as { headers: Record<string, string> }).headers = Object.fromEntries(
            Object.entries(template.headers).map(([k, v]) => [k, replace(v)])
        );
    }
    return result;
}

function enrichHeaders(
    message: MailMessageSpec,
    runtime: MailSystemRuntime,
    sourceHost: string,
): Readonly<Record<string, string>> {
    const account = runtime.accounts[message.to];
    const internalHost = account?.machine ?? 'mail-gateway.internal';
    const leakedIp = `10.42.${(message.id.length * 11) % 255}.${(message.subject.length * 7) % 255}`;
    return {
        'Message-ID': `<${message.id}@${runtime.domain}>`,
        'Received': `from ${sourceHost} (${leakedIp}) by ${internalHost}.${runtime.domain}; ${new Date().toUTCString()}`,
        'X-Originating-IP': leakedIp,
        ...(message.headers ?? {}),
    };
}

function recordCredentialSignals(
    eventBus: EventBus,
    runtime: MailSystemRuntime,
    account: string,
    message: RuntimeMessage,
    locationSuffix: string,
): void {
    const patterns: Array<{ pattern: RegExp; idPrefix: string }> = [
        { pattern: /password\s*[:=]\s*([^\s\n]+)/i, idPrefix: 'mail-password' },
        { pattern: /api[_-]?key\s*[:=]\s*([^\s\n]+)/i, idPrefix: 'mail-api-key' },
        { pattern: /reset[^\n]{0,40}token\s*[:=]\s*([A-Za-z0-9._-]+)/i, idPrefix: 'mail-reset-token' },
        { pattern: /token\s*[:=]\s*([A-Za-z0-9._-]{8,})/i, idPrefix: 'mail-token' },
    ];

    const scan = (content: string, label: string): void => {
        for (const item of patterns) {
            const match = content.match(item.pattern);
            if (match === null) continue;
            eventBus.emit({
                type: 'auth:credential-found',
                credentialId: `${item.idPrefix}:${message.id}`,
                machine: runtime.accounts[account]?.machine ?? account,
                location: `${locationSuffix}:${label}`,
                timestamp: Date.now(),
            });
        }
    };

    scan(message.body, 'body');
    if (message.attachments !== undefined) {
        for (const attachment of message.attachments) {
            scan(attachment.content, `attachment:${attachment.filename}`);
        }
    }
}

function emitForwardingLeak(eventBus: EventBus, from: string, to: string, message: RuntimeMessage): void {
    eventBus.emit({
        type: 'custom:mail-forwarding-leak',
        data: {
            from,
            to,
            messageId: message.id,
            subject: message.subject,
        },
        timestamp: Date.now(),
    });
}

function deliverMessage(
    runtime: MailSystemRuntime,
    eventBus: EventBus,
    message: MailMessageSpec,
    sourceHost: string,
): RuntimeMessage[] {
    const base: RuntimeMessage = {
        ...message,
        folder: 'inbox',
        createdAt: Date.now(),
        headers: enrichHeaders(message, runtime, sourceHost),
    };

    const delivered: RuntimeMessage[] = [];
    if (!accountExists(runtime, base.to)) return delivered;

    folderMessages(runtime, base.to, 'inbox').unshift(base);
    delivered.push(base);

    const forwardTargets = runtime.accounts[base.to]?.forwardTo ?? [];
    for (const target of forwardTargets) {
        if (!accountExists(runtime, target)) continue;
        const forwarded: RuntimeMessage = {
            ...base,
            id: nextMessageId(runtime),
            to: target,
            headers: {
                ...(base.headers ?? {}),
                'X-Forwarded-For': base.to,
            },
        };
        folderMessages(runtime, target, 'inbox').unshift(forwarded);
        delivered.push(forwarded);
        emitForwardingLeak(eventBus, base.to, target, forwarded);
    }

    return delivered;
}

function normalizeRecipients(input: string | readonly string[]): readonly string[] {
    if (Array.isArray(input)) return input.map((v: string) => v.trim()).filter((v: string) => v.length > 0);
    return (input as string)
        .split(',')
        .map((v: string) => v.trim())
        .filter((v: string) => v.length > 0);
}

function composeMessageFromPayload(
    runtime: MailSystemRuntime,
    payload: SendPayload,
): { message: MailMessageSpec; sender: string; recipients: readonly string[] } | null {
    let from = payload.from;
    let subject = payload.subject;
    let body = payload.body;
    let html = payload.html;
    let attachments = payload.attachments;
    let headers = payload.headers;
    let malicious = payload.malicious;
    let maliciousAction = payload.maliciousAction;

    if (payload.templateId !== undefined) {
        const template = runtime.templates[payload.templateId];
        if (template === undefined) return null;
        const variables = payload.variables ?? {};
        const rendered = applyTemplate(template, variables);
        from = from ?? rendered.from;
        subject = subject ?? rendered.subject;
        body = body ?? rendered.body;
        html = html ?? rendered.html;
        attachments = attachments ?? rendered.attachments;
        headers = headers ?? rendered.headers;
        malicious = malicious ?? rendered.malicious;
        maliciousAction = maliciousAction ?? rendered.maliciousAction;
    }

    if (from === undefined || subject === undefined || body === undefined || payload.to === undefined) {
        return null;
    }

    const recipients = normalizeRecipients(payload.to);
    if (recipients.length === 0) return null;

    const message: MailMessageSpec = {
        id: nextMessageId(runtime),
        from,
        to: recipients[0] ?? '',
        subject,
        body,
        ...(html !== undefined ? { html } : {}),
        ...(attachments !== undefined ? { attachments } : {}),
        ...(headers !== undefined ? { headers } : {}),
        ...(malicious !== undefined ? { malicious } : {}),
        ...(maliciousAction !== undefined ? { maliciousAction } : {}),
    };

    return { message, sender: from, recipients };
}

function redactMessageForList(message: RuntimeMessage): Record<string, unknown> {
    return {
        id: message.id,
        from: message.from,
        to: message.to,
        subject: message.subject,
        html: message.html === true,
        malicious: message.malicious === true,
        hasAttachments: (message.attachments?.length ?? 0) > 0,
        createdAt: message.createdAt,
    };
}

function createRuntime(spec: MailSystemSpec): MailSystemRuntime {
    const rawAccounts = spec.accounts as unknown as Readonly<Record<string, MailAccountRuntime>>;
    const templates = spec.templates ?? {};
    const runtime: MailSystemRuntime = {
        domain: resolveMailDomain(spec, rawAccounts),
        accounts: rawAccounts,
        templates,
        mailboxes: new Map<string, Map<MailFolder, RuntimeMessage[]>>(),
        campaigns: new Map<string, CampaignState>(),
        nextMessageId: 1,
        nextCampaignId: 1,
    };

    for (const account of Object.keys(rawAccounts)) {
        ensureMailbox(runtime, account);
    }

    for (const preloaded of spec.inbox ?? []) {
        const message: MailMessageSpec = {
            ...preloaded,
            id: preloaded.id || nextMessageId(runtime),
        };
        if (preloaded.id !== undefined) {
            const numeric = Number(preloaded.id.replace(/^msg-/, ''));
            if (Number.isFinite(numeric) && numeric >= runtime.nextMessageId) {
                runtime.nextMessageId = numeric + 1;
            }
        }
        deliverMessage(runtime, noopEventBus, message, 'seed-loader');
    }

    return runtime;
}

function resolveMailDomain(
    spec: MailSystemSpec,
    accounts: Readonly<Record<string, MailAccountRuntime>>,
): string {
    const withDomain = spec as MailSystemSpec & { readonly domain?: string };
    if (typeof withDomain.domain === 'string' && withDomain.domain.trim() !== '') {
        return withDomain.domain.trim();
    }

    for (const email of Object.keys(accounts)) {
        const at = email.indexOf('@');
        if (at > 0 && at < email.length - 1) {
            return email.slice(at + 1);
        }
    }
    return 'variant.local';
}

function handleInbox(
    runtime: MailSystemRuntime,
    eventBus: EventBus,
    request: ExternalRequest,
    account: string,
): ExternalResponse {
    const auth = resolveAuthAccount(request, runtime);
    if (auth === null || !auth.mailboxAccess.has(account)) {
        return jsonResponse(401, { error: 'authentication required' });
    }
    if (!accountExists(runtime, account)) return jsonResponse(404, { error: 'account not found' });

    const inbox = folderMessages(runtime, account, 'inbox');
    eventBus.emit({
        type: 'custom:mail-inbox-access',
        data: { actor: auth.account, account, count: inbox.length },
        timestamp: Date.now(),
    });

    return jsonResponse(200, {
        account,
        messages: inbox.map(redactMessageForList),
    });
}

function handleGetMessage(
    runtime: MailSystemRuntime,
    eventBus: EventBus,
    request: ExternalRequest,
    account: string,
    id: string,
): ExternalResponse {
    const auth = resolveAuthAccount(request, runtime);
    if (auth === null || !auth.mailboxAccess.has(account)) {
        return jsonResponse(401, { error: 'authentication required' });
    }

    const msg = folderMessages(runtime, account, 'inbox').find(m => m.id === id)
        ?? folderMessages(runtime, account, 'sent').find(m => m.id === id)
        ?? folderMessages(runtime, account, 'drafts').find(m => m.id === id)
        ?? folderMessages(runtime, account, 'trash').find(m => m.id === id);
    if (msg === undefined) return jsonResponse(404, { error: 'message not found' });

    recordCredentialSignals(eventBus, runtime, account, msg, `mail:${account}:${id}`);

    return jsonResponse(200, {
        ...msg,
        attachments: msg.attachments ?? [],
    });
}

function handleAttachmentDownload(
    runtime: MailSystemRuntime,
    eventBus: EventBus,
    request: ExternalRequest,
    account: string,
    messageId: string,
    filename: string,
): ExternalResponse {
    const auth = resolveAuthAccount(request, runtime);
    if (auth === null || !auth.mailboxAccess.has(account)) {
        return jsonResponse(401, { error: 'authentication required' });
    }

    const message = folderMessages(runtime, account, 'inbox').find(item => item.id === messageId)
        ?? folderMessages(runtime, account, 'sent').find(item => item.id === messageId);
    if (message === undefined) return jsonResponse(404, { error: 'message not found' });
    const attachment = message.attachments?.find(item => item.filename === filename);
    if (attachment === undefined) return jsonResponse(404, { error: 'attachment not found' });

    if (attachment.malicious === true) {
        eventBus.emit({
            type: 'defense:alert',
            machine: runtime.accounts[account]?.machine ?? account,
            ruleId: 'mail-malicious-attachment-download',
            severity: 'high',
            detail: `Malicious attachment downloaded: ${filename}`,
            timestamp: Date.now(),
        });
    }

    const tempMessage: RuntimeMessage = {
        ...message,
        attachments: [attachment],
        folder: 'inbox',
        createdAt: Date.now(),
    };
    recordCredentialSignals(eventBus, runtime, account, tempMessage, `mail:${account}:${messageId}:attachment`);

    return textResponse(200, attachment.content, attachment.mimeType);
}

function authenticateSender(runtime: MailSystemRuntime, from: string, senderPassword?: string): boolean {
    const account = runtime.accounts[from];
    if (account === undefined) return false;
    if (account.password === undefined) return true;
    return senderPassword === account.password;
}

function deliverFromPayload(
    runtime: MailSystemRuntime,
    eventBus: EventBus,
    payload: SendPayload,
    sourceHost: string,
): ExternalResponse {
    const composed = composeMessageFromPayload(runtime, payload);
    if (composed === null) {
        return jsonResponse(400, { error: 'invalid payload' });
    }

    if (!authenticateSender(runtime, composed.sender, payload.senderPassword)) {
        return jsonResponse(401, { error: 'invalid sender credentials' });
    }

    const deliveredTo: string[] = [];
    for (const recipient of composed.recipients) {
        const targetMessage: MailMessageSpec = {
            ...composed.message,
            id: nextMessageId(runtime),
            to: recipient,
        };
        if (!accountExists(runtime, recipient)) continue;
        const delivered = deliverMessage(runtime, eventBus, targetMessage, sourceHost);
        for (const item of delivered) {
            deliveredTo.push(item.to);
        }
    }

    const sentMessage: RuntimeMessage = {
        ...composed.message,
        id: nextMessageId(runtime),
        to: composed.recipients.join(','),
        folder: 'sent',
        createdAt: Date.now(),
        headers: enrichHeaders(composed.message, runtime, sourceHost),
    };
    folderMessages(runtime, composed.sender, 'sent').unshift(sentMessage);

    eventBus.emit({
        type: 'custom:mail-send',
        data: {
            from: composed.sender,
            recipients: composed.recipients,
            deliveredTo,
        },
        timestamp: Date.now(),
    });

    return jsonResponse(200, {
        status: 'sent',
        from: composed.sender,
        recipients: composed.recipients,
        deliveredTo,
    });
}

function handleSearch(runtime: MailSystemRuntime, request: ExternalRequest): ExternalResponse {
    const auth = resolveAuthAccount(request, runtime);
    if (auth === null) return jsonResponse(401, { error: 'authentication required' });

    const query = parseQuery(request.path).get('q')?.toLowerCase().trim() ?? '';
    if (query === '') return jsonResponse(400, { error: 'missing query' });

    const results: Array<Record<string, unknown>> = [];
    for (const account of auth.mailboxAccess) {
        for (const folder of ['inbox', 'sent', 'drafts', 'trash'] as const) {
            const messages = folderMessages(runtime, account, folder);
            for (const message of messages) {
                const haystack = [
                    message.subject,
                    message.body,
                    message.from,
                    message.to,
                    ...(message.attachments?.map(att => `${att.filename} ${att.content}`) ?? []),
                ].join('\n').toLowerCase();
                if (haystack.includes(query)) {
                    results.push({ account, folder, id: message.id, subject: message.subject, from: message.from });
                }
            }
        }
    }

    return jsonResponse(200, { query, count: results.length, results });
}

function handleCampaign(
    runtime: MailSystemRuntime,
    eventBus: EventBus,
    request: ExternalRequest,
): ExternalResponse {
    const auth = resolveAuthAccount(request, runtime);
    if (auth === null) return jsonResponse(401, { error: 'authentication required' });

    const payload = parseRequestJson(request) as CampaignPayload;
    if (payload.templateId === undefined || payload.targets === undefined || payload.targets.length === 0) {
        return jsonResponse(400, { error: 'templateId and targets are required' });
    }

    const template = runtime.templates[payload.templateId];
    if (template === undefined) return jsonResponse(404, { error: 'template not found' });

    const variables = payload.variables ?? {};
    const rendered = applyTemplate(template, variables);

    const campaignId = `campaign-${runtime.nextCampaignId}`;
    runtime.nextCampaignId += 1;

    const clickedSet = new Set(payload.clickAccounts ?? []);
    const campaignMessages: CampaignMessage[] = [];

    for (const target of payload.targets) {
        if (!accountExists(runtime, target)) continue;

        const msg: MailMessageSpec = {
            id: nextMessageId(runtime),
            from: rendered.from,
            to: target,
            subject: rendered.subject,
            body: rendered.body,
            ...(rendered.html !== undefined ? { html: rendered.html } : {}),
            ...(rendered.attachments !== undefined ? { attachments: rendered.attachments } : {}),
            ...(rendered.malicious !== undefined ? { malicious: rendered.malicious } : {}),
            ...(rendered.maliciousAction !== undefined ? { maliciousAction: rendered.maliciousAction } : {}),
            ...(rendered.headers !== undefined ? { headers: rendered.headers } : {}),
        };
        deliverMessage(runtime, eventBus, msg, `campaign.${runtime.domain}`);

        const clicked = clickedSet.has(target) || (msg.body.includes('{link}') ? false : /https?:\/\//i.test(msg.body));
        campaignMessages.push({ id: msg.id, account: target, clicked });

        if (clicked) {
            eventBus.emit({
                type: 'custom:mail-campaign-clicked',
                data: {
                    campaignId,
                    account: target,
                    messageId: msg.id,
                },
                timestamp: Date.now(),
            });
        }
    }

    const campaign: CampaignState = {
        id: campaignId,
        templateId: payload.templateId,
        createdAt: Date.now(),
        targets: payload.targets,
        messages: campaignMessages,
    };
    runtime.campaigns.set(campaignId, campaign);

    eventBus.emit({
        type: 'custom:mail-campaign-created',
        data: {
            campaignId,
            templateId: payload.templateId,
            targetCount: campaignMessages.length,
        },
        timestamp: Date.now(),
    });

    return jsonResponse(200, {
        campaignId,
        sent: campaignMessages.length,
        clicked: campaignMessages.filter(item => item.clicked).map(item => item.account),
    });
}

function handleImapList(
    runtime: MailSystemRuntime,
    request: ExternalRequest,
    account: string,
): ExternalResponse {
    const auth = resolveAuthAccount(request, runtime);
    if (auth === null || auth.account !== account) {
        return jsonResponse(401, { error: 'authentication required' });
    }
    if (!accountExists(runtime, account)) return jsonResponse(404, { error: 'account not found' });

    return jsonResponse(200, {
        account,
        folders: ['inbox', 'sent', 'drafts', 'trash'],
    });
}

function handleImapFetch(
    runtime: MailSystemRuntime,
    request: ExternalRequest,
    account: string,
    folder: string,
): ExternalResponse {
    const auth = resolveAuthAccount(request, runtime);
    if (auth === null || auth.account !== account) {
        return jsonResponse(401, { error: 'authentication required' });
    }
    if (!accountExists(runtime, account)) return jsonResponse(404, { error: 'account not found' });
    if (folder !== 'inbox' && folder !== 'sent' && folder !== 'drafts' && folder !== 'trash') {
        return jsonResponse(404, { error: 'folder not found' });
    }

    const messages = folderMessages(runtime, account, folder);
    return jsonResponse(200, {
        account,
        folder,
        messages,
    });
}

function routeRequest(
    runtime: MailSystemRuntime,
    eventBus: EventBus,
    request: ExternalRequest,
): ExternalResponse {
    const segments = splitPath(request.path);
    const method = request.method.toUpperCase();

    if (method === 'GET' && segments[0] === 'api' && segments[1] === 'inbox' && segments[2] !== undefined && segments.length === 3) {
        return handleInbox(runtime, eventBus, request, segments[2]);
    }

    if (method === 'GET' && segments[0] === 'api' && segments[1] === 'message' && segments[2] !== undefined && segments[3] !== undefined && segments.length === 4) {
        return handleGetMessage(runtime, eventBus, request, segments[2], segments[3]);
    }

    if (
        method === 'GET'
        && segments[0] === 'api'
        && segments[1] === 'attachments'
        && segments[2] !== undefined
        && segments[3] !== undefined
        && segments[4] !== undefined
        && segments.length === 5
    ) {
        return handleAttachmentDownload(runtime, eventBus, request, segments[2], segments[3], decodeURIComponent(segments[4]));
    }

    if (method === 'POST' && segments[0] === 'api' && segments[1] === 'send' && segments.length === 2) {
        return deliverFromPayload(runtime, eventBus, parseRequestJson(request) as SendPayload, 'webmail-client');
    }

    if (method === 'GET' && segments[0] === 'api' && segments[1] === 'search' && segments.length === 2) {
        return handleSearch(runtime, request);
    }

    if (method === 'POST' && segments[0] === 'api' && segments[1] === 'campaign' && segments.length === 2) {
        return handleCampaign(runtime, eventBus, request);
    }

    if (method === 'POST' && segments[0] === 'smtp' && segments[1] === 'send' && segments.length === 2) {
        return deliverFromPayload(runtime, eventBus, parseRequestJson(request) as SendPayload, 'smtp-gateway');
    }

    if (method === 'GET' && segments[0] === 'imap' && segments[1] === 'list' && segments[2] !== undefined && segments.length === 3) {
        return handleImapList(runtime, request, segments[2]);
    }

    if (method === 'GET' && segments[0] === 'imap' && segments[1] === 'fetch' && segments[2] !== undefined && segments[3] !== undefined && segments.length === 4) {
        return handleImapFetch(runtime, request, segments[2], segments[3]);
    }

    return jsonResponse(404, { error: 'not found' });
}

export function createMailModule(spec: MailSystemSpec, eventBus: EventBus): Module {
    const injectedSpec = spec;
    const injectedEventBus = eventBus;

    return {
        id: MODULE_ID,
        type: 'engine',
        version: MODULE_VERSION,
        description: 'Simulates webmail, SMTP, and IMAP interfaces with phishing and telemetry attack surfaces',

        provides: [
            { name: 'mail' },
            { name: 'smtp' },
            { name: 'imap' },
        ] as readonly Capability[],
        requires: [{ name: 'variant-internet' }] as readonly Capability[],

        init(context: SimulationContext): void {
            const runtimeSpec = injectedSpec ?? context.world.mail;
            if (runtimeSpec === undefined) return;

            const runtime = createRuntime(runtimeSpec);
            const activeEvents = injectedEventBus ?? context.events;
            const mailDomain = `mail.${runtime.domain}`;

            const handler: ExternalServiceHandler = {
                domain: mailDomain,
                description: `VARIANT Mail service at ${mailDomain}`,
                handleRequest(request: ExternalRequest): ExternalResponse {
                    return routeRequest(runtime, activeEvents, request);
                },
            };

            context.fabric.addDNSRecord({
                domain: mailDomain,
                ip: '172.16.1.30',
                type: 'A',
                ttl: 3600,
            });
            context.fabric.registerExternal(handler);

            context.events.emit({
                type: 'sim:alert',
                source: MODULE_ID,
                message: `Mail module activated on ${mailDomain}: ${Object.keys(runtime.accounts).length} accounts`,
                timestamp: Date.now(),
            });
        },

        destroy(): void {
            // External handlers are owned by the fabric
        },
    };
}
