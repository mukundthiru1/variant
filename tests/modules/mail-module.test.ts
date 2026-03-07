import { beforeEach, describe, expect, it } from 'vitest';
import { createMailModule } from '../../src/modules/mail-module';
import type { EventBus } from '../../src/core/events';
import type { ExternalRequest, ExternalServiceHandler } from '../../src/core/fabric/types';
import type { MailSystemSpec } from '../../src/core/world/types';

const decoder = new TextDecoder();
const encoder = new TextEncoder();

function makeBasicAuth(user: string, pass: string): string {
    return `Basic ${globalThis.btoa(`${user}:${pass}`)}`;
}

function makeRequest(
    method: string,
    path: string,
    headers?: Record<string, string>,
    body?: unknown,
): ExternalRequest {
    const headerMap = new Map<string, string>();
    if (headers !== undefined) {
        for (const [k, v] of Object.entries(headers)) {
            headerMap.set(k, v);
        }
    }

    return {
        method,
        path,
        headers: headerMap,
        body: body !== undefined ? encoder.encode(typeof body === 'string' ? body : JSON.stringify(body)) : null,
    };
}

function responseStatus(handler: ExternalServiceHandler, request: ExternalRequest): number {
    return handler.handleRequest(request).status;
}

function responseText(handler: ExternalServiceHandler, request: ExternalRequest): string {
    return decoder.decode(handler.handleRequest(request).body);
}

function responseJson(handler: ExternalServiceHandler, request: ExternalRequest): any {
    return JSON.parse(responseText(handler, request));
}

function createMockContext(spec: MailSystemSpec) {
    const registeredHandlers: ExternalServiceHandler[] = [];
    const registeredDNS: Array<{ domain: string; ip: string; type: string; ttl: number }> = [];
    const emittedEvents: any[] = [];

    const eventBus: EventBus = {
        emit(event) {
            emittedEvents.push(event);
        },
        on() {
            return () => undefined;
        },
        onPrefix() {
            return () => undefined;
        },
        getLog() {
            return [];
        },
        clearLog() {},
        once() {
            return () => undefined;
        },
        waitFor() {
            return Promise.reject(new Error('not implemented in tests'));
        },
        removeAllListeners() {},
    };

    const context = {
        world: { mail: spec } as any,
        fabric: {
            addDNSRecord(record: { domain: string; ip: string; type: string; ttl: number }) {
                registeredDNS.push(record);
            },
            registerExternal(handler: ExternalServiceHandler) {
                registeredHandlers.push(handler);
            },
        } as any,
        events: eventBus,
        vms: new Map(),
        tick: 0,
        services: {} as any,
    };

    return { context, eventBus, registeredHandlers, registeredDNS, emittedEvents };
}

function findHandler(handlers: ExternalServiceHandler[], domain: string): ExternalServiceHandler {
    return handlers.find(handler => handler.domain === domain) as ExternalServiceHandler;
}

function makeSpec(): MailSystemSpec {
    return {
        accounts: {
            'alice@corp.local': {
                displayName: 'Alice',
                machine: 'ws-alice',
                password: 'alicepass',
                accessibleMailboxes: ['security@corp.local'],
            } as any,
            'bob@corp.local': {
                displayName: 'Bob',
                machine: 'ws-bob',
                password: 'bobpass',
                forwardTo: ['archive@corp.local'],
            } as any,
            'archive@corp.local': {
                displayName: 'Archive',
                machine: 'mail-archive',
                password: 'archivepass',
            } as any,
            'security@corp.local': {
                displayName: 'Security',
                machine: 'soc-01',
                password: 'socpass',
            } as any,
            'ceo@corp.local': {
                displayName: 'CEO',
                machine: 'exec-01',
                password: 'ceopass',
            } as any,
        },
        inbox: [
            {
                id: 'msg-100',
                from: 'hr@corp.local',
                to: 'alice@corp.local',
                subject: 'Welcome packet',
                body: 'Please review onboarding docs. reset token: RST-12345',
                attachments: [
                    {
                        filename: 'welcome.txt',
                        content: 'VPN setup guide',
                        mimeType: 'text/plain',
                    },
                ],
            },
            {
                id: 'msg-101',
                from: 'it-admin@corp.local',
                to: 'bob@corp.local',
                subject: 'Quarterly report',
                body: 'Attached report and creds',
                attachments: [
                    {
                        filename: 'creds.txt',
                        content: 'password=BobS3cret',
                        mimeType: 'text/plain',
                    },
                    {
                        filename: 'invoice.exe',
                        content: 'MZ...malicious',
                        mimeType: 'application/octet-stream',
                        malicious: true,
                    },
                ],
            },
            {
                id: 'msg-102',
                from: 'alerts@corp.local',
                to: 'security@corp.local',
                subject: 'Threat intel',
                body: 'Suspicious login from 10.0.5.9',
            },
        ],
        templates: {
            phishing_reset: {
                from: 'it-support@corp.local',
                subject: 'Action required for {name}',
                body: 'Hello {name}, visit {link} to keep {company} access.',
                html: false,
                malicious: true,
            },
            invoice: {
                from: 'billing@corp.local',
                subject: 'Invoice for {company}',
                body: 'See attachment for {company}',
                attachments: [
                    {
                        filename: '{company}-invoice.txt',
                        content: 'api_key=KEY-{name}',
                        mimeType: 'text/plain',
                    },
                ],
            },
        },
    };
}

describe('createMailModule', () => {
    let spec: MailSystemSpec;
    let handler: ExternalServiceHandler;
    let emittedEvents: any[];

    beforeEach(() => {
        spec = makeSpec();
        const { context, eventBus, registeredHandlers, emittedEvents: events } = createMockContext(spec);
        emittedEvents = events;

        const module = createMailModule(spec, eventBus);
        expect(module.id).toBe('mail-system');
        expect(module.version).toBe('1.0.0');
        expect(module.provides).toEqual([{ name: 'mail' }, { name: 'smtp' }, { name: 'imap' }]);

        module.init(context);
        handler = findHandler(registeredHandlers, 'mail.corp.local');
    });

    it('registers DNS and emits activation event', () => {
        const { context, eventBus, registeredDNS, emittedEvents: events } = createMockContext(spec);
        createMailModule(spec, eventBus).init(context);

        expect(registeredDNS).toHaveLength(1);
        expect(registeredDNS[0]).toMatchObject({
            domain: 'mail.corp.local',
            type: 'A',
            ttl: 3600,
        });
        expect(events.some(event => event.type === 'sim:alert')).toBe(true);
    });

    it('requires auth for inbox access', () => {
        const req = makeRequest('GET', '/api/inbox/alice@corp.local');
        expect(responseStatus(handler, req)).toBe(401);
    });

    it('lists inbox with valid auth', () => {
        const req = makeRequest('GET', '/api/inbox/alice@corp.local', {
            Authorization: makeBasicAuth('alice@corp.local', 'alicepass'),
        });
        const res = responseJson(handler, req);
        expect(res.account).toBe('alice@corp.local');
        expect(res.messages.length).toBeGreaterThan(0);
        expect(res.messages[0].subject).toBe('Welcome packet');
    });

    it('reads a message with body and attachments', () => {
        const req = makeRequest('GET', '/api/message/alice@corp.local/msg-100', {
            Authorization: makeBasicAuth('alice@corp.local', 'alicepass'),
        });
        const res = responseJson(handler, req);

        expect(res.subject).toBe('Welcome packet');
        expect(res.body).toContain('reset token');
        expect(res.attachments[0].filename).toBe('welcome.txt');
        expect(res.headers.Received).toContain('ws-alice.corp.local');
    });

    it('downloads attachment content', () => {
        const req = makeRequest('GET', '/api/attachments/alice@corp.local/msg-100/welcome.txt', {
            Authorization: makeBasicAuth('alice@corp.local', 'alicepass'),
        });
        const text = responseText(handler, req);
        expect(text).toContain('VPN setup');
    });

    it('sends message via webmail API and delivers to recipient', () => {
        const sendReq = makeRequest(
            'POST',
            '/api/send',
            {},
            {
                from: 'alice@corp.local',
                senderPassword: 'alicepass',
                to: 'ceo@corp.local',
                subject: 'Q3 plan',
                body: 'Draft attached',
            },
        );
        const sendRes = responseJson(handler, sendReq);
        expect(sendRes.status).toBe('sent');
        expect(sendRes.deliveredTo).toContain('ceo@corp.local');

        const inboxReq = makeRequest('GET', '/api/inbox/ceo@corp.local', {
            Authorization: makeBasicAuth('ceo@corp.local', 'ceopass'),
        });
        const inboxRes = responseJson(handler, inboxReq);
        expect(inboxRes.messages.some((msg: any) => msg.subject === 'Q3 plan')).toBe(true);
    });

    it('searches accessible mailboxes', () => {
        const req = makeRequest('GET', '/api/search?q=threat', {
            Authorization: makeBasicAuth('alice@corp.local', 'alicepass'),
        });
        const res = responseJson(handler, req);
        expect(res.count).toBeGreaterThan(0);
        expect(res.results.some((item: any) => item.account === 'security@corp.local')).toBe(true);
    });

    it('emits credential-found event when reading token-bearing message', () => {
        const req = makeRequest('GET', '/api/message/alice@corp.local/msg-100', {
            Authorization: makeBasicAuth('alice@corp.local', 'alicepass'),
        });
        responseStatus(handler, req);

        expect(emittedEvents.some(event => event.type === 'auth:credential-found')).toBe(true);
    });

    it('emits credential-found when downloading attachment with credential', () => {
        const req = makeRequest('GET', '/api/attachments/bob@corp.local/msg-101/creds.txt', {
            Authorization: makeBasicAuth('bob@corp.local', 'bobpass'),
        });
        responseStatus(handler, req);

        expect(emittedEvents.some(event => event.type === 'auth:credential-found')).toBe(true);
    });

    it('emits defense alert for malicious attachment download', () => {
        const req = makeRequest('GET', '/api/attachments/bob@corp.local/msg-101/invoice.exe', {
            Authorization: makeBasicAuth('bob@corp.local', 'bobpass'),
        });
        responseStatus(handler, req);

        expect(emittedEvents.some(event => event.type === 'defense:alert')).toBe(true);
    });

    it('smtp send accepts valid sender credentials', () => {
        const smtpReq = makeRequest(
            'POST',
            '/smtp/send',
            {},
            {
                from: 'bob@corp.local',
                senderPassword: 'bobpass',
                to: 'alice@corp.local',
                subject: 'SMTP hello',
                body: 'body via smtp',
            },
        );

        const response = responseJson(handler, smtpReq);
        expect(response.status).toBe('sent');
        expect(response.recipients).toContain('alice@corp.local');
    });

    it('smtp send rejects invalid sender credentials', () => {
        const smtpReq = makeRequest(
            'POST',
            '/smtp/send',
            {},
            {
                from: 'bob@corp.local',
                senderPassword: 'wrong-pass',
                to: 'alice@corp.local',
                subject: 'Denied',
                body: 'no',
            },
        );

        expect(responseStatus(handler, smtpReq)).toBe(401);
    });

    it('supports template variable substitution for smtp sends', () => {
        const smtpReq = makeRequest(
            'POST',
            '/smtp/send',
            {},
            {
                from: 'alice@corp.local',
                senderPassword: 'alicepass',
                to: 'bob@corp.local',
                templateId: 'invoice',
                variables: {
                    company: 'ACME',
                    name: 'Bob',
                },
            },
        );

        const sendRes = responseJson(handler, smtpReq);
        expect(sendRes.status).toBe('sent');

        const inbox = responseJson(handler, makeRequest('GET', '/api/inbox/bob@corp.local', {
            Authorization: makeBasicAuth('bob@corp.local', 'bobpass'),
        }));

        const message = inbox.messages.find((item: any) => item.subject === 'Invoice for ACME');
        expect(message).toBeTruthy();
    });

    it('supports IMAP folder listing and fetch with auth', () => {
        const listReq = makeRequest('GET', '/imap/list/alice@corp.local', {
            Authorization: makeBasicAuth('alice@corp.local', 'alicepass'),
        });
        const listRes = responseJson(handler, listReq);
        expect(listRes.folders).toContain('inbox');
        expect(listRes.folders).toContain('sent');

        const fetchReq = makeRequest('GET', '/imap/fetch/alice@corp.local/inbox', {
            Authorization: makeBasicAuth('alice@corp.local', 'alicepass'),
        });
        const fetchRes = responseJson(handler, fetchReq);
        expect(fetchRes.folder).toBe('inbox');
        expect(fetchRes.messages.length).toBeGreaterThan(0);
    });

    it('rejects IMAP access for wrong account credentials', () => {
        const req = makeRequest('GET', '/imap/list/alice@corp.local', {
            Authorization: makeBasicAuth('bob@corp.local', 'bobpass'),
        });
        expect(responseStatus(handler, req)).toBe(401);
    });

    it('creates phishing campaign and tracks simulated clicks', () => {
        const campaignReq = makeRequest(
            'POST',
            '/api/campaign',
            {
                Authorization: makeBasicAuth('alice@corp.local', 'alicepass'),
            },
            {
                templateId: 'phishing_reset',
                targets: ['bob@corp.local', 'ceo@corp.local'],
                variables: {
                    name: 'Teammate',
                    company: 'Corp',
                    link: 'https://evil.test/reset',
                },
                clickAccounts: ['ceo@corp.local'],
            },
        );
        const res = responseJson(handler, campaignReq);

        expect(res.campaignId).toContain('campaign-');
        expect(res.sent).toBe(2);
        expect(res.clicked).toContain('ceo@corp.local');

        expect(emittedEvents.some(event => event.type === 'custom:mail-campaign-created')).toBe(true);
        expect(emittedEvents.some(event => event.type === 'custom:mail-campaign-clicked')).toBe(true);
    });

    it('applies auto-forwarding rules and emits leak telemetry', () => {
        const req = makeRequest(
            'POST',
            '/api/send',
            {},
            {
                from: 'alice@corp.local',
                senderPassword: 'alicepass',
                to: 'bob@corp.local',
                subject: 'Forward check',
                body: 'message',
            },
        );

        const sendRes = responseJson(handler, req);
        expect(sendRes.deliveredTo).toContain('archive@corp.local');
        expect(emittedEvents.some(event => event.type === 'custom:mail-forwarding-leak')).toBe(true);
    });
});
