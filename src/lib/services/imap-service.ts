/**
 * VARIANT — IMAP Service Handler
 *
 * Simulated IMAP email retrieval service for email forensics
 * and credential harvesting scenarios. Supports mailbox
 * operations and realistic IMAP protocol responses.
 *
 * What it does:
 *   - LOGIN command with credential validation
 *   - LIST mailboxes
 *   - SELECT/EXAMINE mailbox
 *   - FETCH message content
 *   - SEARCH by criteria
 *   - Realistic IMAP response format with tags
 *   - Emits events for objective detection
 *
 * EXTENSIBILITY: Configurable via ServiceConfig.config:
 *   - mailboxes: Pre-defined mailboxes and messages
 *   - allowPlaintext: Allow LOGIN (default: true)
 *   - domain: Mail domain (default: variant.local)
 */

import type {
    ServiceHandler,
    ServiceRequest,
    ServiceResponse,
    ServiceContext,
} from './types';
import type { ServiceConfig } from '../../core/world/types';

// ── IMAP Config ────────────────────────────────────────────────

interface IMAPConfig {
    readonly domain: string;
    readonly allowPlaintext: boolean;
    readonly port: number;
    readonly logFile: string;
    readonly defaultMailboxes: Record<string, IMailbox>;
}

interface IMailbox {
    readonly name: string;
    readonly flags: readonly string[];
    readonly messages: IMAPMessage[];
    readonly uidValidity: number;
}

interface IMAPMessage {
    readonly uid: number;
    readonly seq: number;
    readonly flags: string[];
    readonly size: number;
    readonly headers: Record<string, string>;
    readonly body: string;
    readonly internalDate: Date;
}

interface IMAPSession {
    authenticated: boolean;
    username: string;
    selectedMailbox: string | null;
    messageCounter: number;
}

function resolveIMAPConfig(config: ServiceConfig): IMAPConfig {
    const c = config.config ?? {};
    return {
        domain: (c['domain'] as string) ?? 'variant.local',
        allowPlaintext: (c['allowPlaintext'] as boolean) ?? true,
        port: config.ports[0] ?? 143,
        logFile: (c['logFile'] as string) ?? '/var/log/dovecot.log',
        defaultMailboxes: (c['mailboxes'] as Record<string, IMailbox>) ?? getDefaultMailboxes(),
    };
}

function getDefaultMailboxes(): Record<string, IMailbox> {
    return {
        'INBOX': {
            name: 'INBOX',
            flags: ['\\HasNoChildren'],
            uidValidity: 1704067200,
            messages: [
                {
                    uid: 1,
                    seq: 1,
                    flags: ['\\Seen'],
                    size: 1024,
                    headers: {
                        'From': 'admin@variant.local',
                        'To': 'user@variant.local',
                        'Subject': 'Welcome to Variant Mail',
                        'Date': 'Mon, 01 Jan 2024 09:00:00 +0000',
                        'Message-Id': '<welcome-001@variant.local>',
                    },
                    body: 'Welcome to your new email account!\r\n\r\nThis is your inbox.\r\n\r\nBest regards,\r\nVariant IT Team',
                    internalDate: new Date('2024-01-01T09:00:00Z'),
                },
                {
                    uid: 2,
                    seq: 2,
                    flags: [],
                    size: 2048,
                    headers: {
                        'From': 'security@variant.local',
                        'To': 'user@variant.local',
                        'Subject': 'Security Alert: Password Expiry',
                        'Date': 'Mon, 15 Jan 2024 14:30:00 +0000',
                        'Message-Id': '<security-002@variant.local>',
                    },
                    body: 'Your password will expire in 7 days.\r\n\r\nPlease change your password at your earliest convenience.\r\n\r\nSecurity Team',
                    internalDate: new Date('2024-01-15T14:30:00Z'),
                },
                {
                    uid: 3,
                    seq: 3,
                    flags: ['\\Flagged'],
                    size: 512,
                    headers: {
                        'From': 'boss@variant.local',
                        'To': 'user@variant.local',
                        'Subject': 'URGENT: Q4 Report Due',
                        'Date': 'Tue, 16 Jan 2024 08:15:00 +0000',
                        'Message-Id': '<urgent-003@variant.local>',
                    },
                    body: 'Please submit the Q4 report by EOD.\r\n\r\nThanks!',
                    internalDate: new Date('2024-01-16T08:15:00Z'),
                },
            ],
        },
        'Sent': {
            name: 'Sent',
            flags: ['\\HasNoChildren', '\\Sent'],
            uidValidity: 1704067201,
            messages: [
                {
                    uid: 1,
                    seq: 1,
                    flags: ['\\Seen'],
                    size: 768,
                    headers: {
                        'From': 'user@variant.local',
                        'To': 'client@example.com',
                        'Subject': 'Re: Project Update',
                        'Date': 'Wed, 10 Jan 2024 11:00:00 +0000',
                        'Message-Id': '<sent-001@variant.local>',
                    },
                    body: 'Hi,\r\n\r\nThe project is on track for delivery next week.\r\n\r\nRegards,\r\nUser',
                    internalDate: new Date('2024-01-10T11:00:00Z'),
                },
            ],
        },
        'Drafts': {
            name: 'Drafts',
            flags: ['\\HasNoChildren', '\\Drafts'],
            uidValidity: 1704067202,
            messages: [],
        },
        'Trash': {
            name: 'Trash',
            flags: ['\\HasNoChildren', '\\Trash'],
            uidValidity: 1704067203,
            messages: [],
        },
        'Spam': {
            name: 'Spam',
            flags: ['\\HasNoChildren', '\\Junk'],
            uidValidity: 1704067204,
            messages: [
                {
                    uid: 1,
                    seq: 1,
                    flags: [],
                    size: 1536,
                    headers: {
                        'From': 'winner@lottery-scam.example',
                        'To': 'user@variant.local',
                        'Subject': 'Congratulations! You won!',
                        'Date': 'Fri, 12 Jan 2024 03:00:00 +0000',
                        'Message-Id': '<spam-001@lottery-scam.example>',
                        'X-Spam-Flag': 'YES',
                    },
                    body: 'CONGRATULATIONS!\r\n\r\nYou have won $1,000,000! Click here to claim your prize!\r\n\r\n[This message was marked as spam]',
                    internalDate: new Date('2024-01-12T03:00:00Z'),
                },
            ],
        },
    };
}

// ── IMAP Service Handler ───────────────────────────────────────

export function createIMAPService(config: ServiceConfig): ServiceHandler {
    const imapConfig = resolveIMAPConfig(config);
    const sessions = new Map<string, IMAPSession>();
    const userMailboxes = new Map<string, Record<string, IMailbox>>();

    function getSession(sourceIP: string): IMAPSession {
        let session = sessions.get(sourceIP);
        if (session === undefined) {
            session = {
                authenticated: false,
                username: '',
                selectedMailbox: null,
                messageCounter: 0,
            };
            sessions.set(sourceIP, session);
        }
        return session;
    }

    function getUserMailboxes(username: string): Record<string, IMailbox> {
        if (!userMailboxes.has(username)) {
            // Deep clone default mailboxes for this user
            userMailboxes.set(username, JSON.parse(JSON.stringify(imapConfig.defaultMailboxes)));
        }
        return userMailboxes.get(username)!;
    }

    function writeIMAPLog(ctx: ServiceContext, message: string): void {
        const timestamp = new Date().toISOString();
        const line = `${timestamp} imap(${1000 + Math.floor(Math.random() * 9000)}): ${message}`;
        try {
            const existing = ctx.vfs.readFile(imapConfig.logFile);
            ctx.vfs.writeFile(imapConfig.logFile, existing + '\n' + line);
        } catch {
            ctx.vfs.writeFile(imapConfig.logFile, line);
        }
    }

    function imapResponse(tag: string, status: string, message: string, data = '', close = false): ServiceResponse {
        const response = data !== '' ? `${data}\r\n${tag} ${status} ${message}\r\n` : `${tag} ${status} ${message}\r\n`;
        return {
            payload: new TextEncoder().encode(response),
            close,
        };
    }

    function untaggedResponse(type: string, data: string): string {
        return `* ${type} ${data}`;
    }

    return {
        name: 'imap',
        port: imapConfig.port,
        protocol: 'tcp',

        start(ctx: ServiceContext): void {
            ctx.emit({
                type: 'service:custom',
                service: 'imap',
                action: 'started',
                details: {
                    port: imapConfig.port,
                    domain: imapConfig.domain,
                },
            });
        },

        handle(request: ServiceRequest, ctx: ServiceContext): ServiceResponse | null {
            const text = request.payloadText.trim();

            // Initial connection greeting
            if (text === '') {
                return {
                    payload: new TextEncoder().encode(`* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN] Dovecot ready.\r\n`),
                    close: false,
                };
            }

            // Parse tagged command: <tag> <command> [args]
            const parts = text.split(' ');
            if (parts.length < 2) {
                return imapResponse('*', 'BAD', 'Invalid command');
            }

            const tag = parts[0]!;
            const cmd = parts[1]!.toUpperCase();
            const args = parts.slice(2).join(' ');

            const session = getSession(request.sourceIP);

            switch (cmd) {
                case 'CAPABILITY': {
                    return imapResponse(tag, 'OK', 'CAPABILITY completed',
                        `* CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN`);
                }

                case 'NOOP': {
                    return imapResponse(tag, 'OK', 'NOOP completed');
                }

                case 'LOGOUT': {
                    sessions.delete(request.sourceIP);
                    return imapResponse(tag, 'OK', 'Logout completed', '* BYE Logging out\r\n', true);
                }

                case 'LOGIN': {
                    if (!imapConfig.allowPlaintext) {
                        return imapResponse(tag, 'NO', 'Plaintext authentication not allowed');
                    }

                    // Parse: LOGIN <username> <password>
                    const loginMatch = args.match(/"([^"]+)"\s+"([^"]+)"/);
                    const bareMatch = args.match(/^(\S+)\s+(\S+)$/);

                    let username = '';
                    let password = '';

                    if (loginMatch !== null) {
                        username = loginMatch[1] ?? '';
                        password = loginMatch[2] ?? '';
                    } else if (bareMatch !== null) {
                        username = bareMatch[1] ?? '';
                        password = bareMatch[2] ?? '';
                    }

                    // Validate credentials against VFS /etc/shadow
                    const valid = validateCredentials(ctx, username, password);

                    if (valid) {
                        session.authenticated = true;
                        session.username = username;
                        writeIMAPLog(ctx, `Login: user=${username}, method=PLAIN, rip=${request.sourceIP}, lip=${ctx.ip}, mpid=0, secured`);
                        ctx.emit({
                            type: 'service:custom',
                            service: 'imap',
                            action: 'login',
                            details: { username, sourceIP: request.sourceIP, success: true },
                        });
                        return imapResponse(tag, 'OK', '[CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY PREVIEW STATUS=SIZE SAVEDATE COMPRESS=DEFLATE] Logged in');
                    }

                    writeIMAPLog(ctx, `Disconnected: rip=${request.sourceIP}, lip=${ctx.ip}, no auth attempts`);
                    ctx.emit({
                        type: 'service:custom',
                        service: 'imap',
                        action: 'login',
                        details: { username, sourceIP: request.sourceIP, success: false },
                    });
                    return imapResponse(tag, 'NO', '[AUTHENTICATIONFAILED] Authentication failed');
                }

                case 'LIST': {
                    if (!session.authenticated) {
                        return imapResponse(tag, 'NO', 'Not authenticated');
                    }

                    const mailboxes = getUserMailboxes(session.username);
                    let output = '';

                    for (const [name, mbox] of Object.entries(mailboxes)) {
                        const flags = mbox.flags.join(' ');
                        output += untaggedResponse('LIST', `(${flags}) "/" "${name}"`) + '\r\n';
                    }

                    return imapResponse(tag, 'OK', 'LIST completed', output);
                }

                case 'SELECT':
                case 'EXAMINE': {
                    if (!session.authenticated) {
                        return imapResponse(tag, 'NO', 'Not authenticated');
                    }

                    const readonly = cmd === 'EXAMINE';
                    const mailboxName = args.replace(/"/g, '').trim();
                    const mailboxes = getUserMailboxes(session.username);
                    const mailbox = mailboxes[mailboxName];

                    if (mailbox === undefined) {
                        return imapResponse(tag, 'NO', `Mailbox doesn't exist: ${mailboxName}`);
                    }

                    session.selectedMailbox = mailboxName;
                    const messageCount = mailbox.messages.length;
                    const recentCount = mailbox.messages.filter(m => !m.flags.includes('\\Seen')).length;
                    const firstUnseen = mailbox.messages.find(m => !m.flags.includes('\\Seen'));

                    let output = '';
                    output += untaggedResponse('FLAGS', '(\\Answered \\Flagged \\Deleted \\Seen \\Draft)') + '\r\n';
                    output += untaggedResponse('OK', `[PERMANENTFLAGS (${readonly ? '' : '\\Deleted \\Seen \\Draft '}\\*)] Flags permitted`) + '\r\n';
                    output += untaggedResponse(String(messageCount), 'EXISTS') + '\r\n';
                    output += untaggedResponse(String(recentCount), 'RECENT') + '\r\n';
                    output += untaggedResponse('OK', `[UIDVALIDITY ${mailbox.uidValidity}] UIDs valid`) + '\r\n';
                    output += untaggedResponse('OK', '[UIDNEXT ' + (mailbox.messages.length + 1) + '] Predicted next UID') + '\r\n';
                    if (firstUnseen !== undefined) {
                        output += untaggedResponse('OK', `[UNSEEN ${firstUnseen.seq}] First unseen`) + '\r\n';
                    }

                    const cmdStr = readonly ? '[READ-ONLY]' : '[READ-WRITE]';
                    return imapResponse(tag, 'OK', `${cmdStr} ${cmd.toLowerCase()} completed`, output);
                }

                case 'FETCH': {
                    if (!session.authenticated) {
                        return imapResponse(tag, 'NO', 'Not authenticated');
                    }

                    if (session.selectedMailbox === null) {
                        return imapResponse(tag, 'NO', 'No mailbox selected');
                    }

                    const mailboxes = getUserMailboxes(session.username);
                    const mailbox = mailboxes[session.selectedMailbox];
                    if (mailbox === undefined) {
                        return imapResponse(tag, 'NO', 'Mailbox not found');
                    }

                    // Parse: FETCH <sequence> <items>
                    const fetchMatch = args.match(/(\S+)\s+(.+)/);
                    if (fetchMatch === null) {
                        return imapResponse(tag, 'BAD', 'Invalid FETCH syntax');
                    }

                    const seq = fetchMatch[1] ?? '';
                    const items = fetchMatch[2] ?? '';

                    let messages: IMAPMessage[];
                    if (seq === '1:*' || seq === 'ALL') {
                        messages = mailbox.messages;
                    } else if (seq.includes(':')) {
                        const [start, end] = seq.split(':');
                        const startNum = parseInt(start ?? '1', 10);
                        const endNum = end === '*' ? mailbox.messages.length : parseInt(end ?? '1', 10);
                        messages = mailbox.messages.filter(m => m.seq >= startNum && m.seq <= endNum);
                    } else {
                        const seqNum = parseInt(seq, 10);
                        messages = mailbox.messages.filter(m => m.seq === seqNum);
                    }

                    let output = '';
                    for (const msg of messages) {
                        const fetchData = formatFetchResponse(msg, items);
                        output += untaggedResponse(`${msg.seq} FETCH`, fetchData) + '\r\n';

                        // Mark as seen if fetching body
                        if (items.toUpperCase().includes('BODY') || items.toUpperCase().includes('TEXT')) {
                            if (!msg.flags.includes('\\Seen')) {
                                msg.flags.push('\\Seen');
                            }
                            ctx.emit({
                                type: 'service:custom',
                                service: 'imap',
                                action: 'message-read',
                                details: {
                                    username: session.username,
                                    mailbox: session.selectedMailbox,
                                    uid: msg.uid,
                                    subject: msg.headers['Subject'] ?? '(no subject)',
                                },
                            });
                        }
                    }

                    return imapResponse(tag, 'OK', 'FETCH completed', output);
                }

                case 'SEARCH': {
                    if (!session.authenticated) {
                        return imapResponse(tag, 'NO', 'Not authenticated');
                    }

                    if (session.selectedMailbox === null) {
                        return imapResponse(tag, 'NO', 'No mailbox selected');
                    }

                    const mailboxes = getUserMailboxes(session.username);
                    const mailbox = mailboxes[session.selectedMailbox];
                    if (mailbox === undefined) {
                        return imapResponse(tag, 'NO', 'Mailbox not found');
                    }

                    const criteria = args.toUpperCase();
                    let results: number[] = [];

                    if (criteria === 'ALL') {
                        results = mailbox.messages.map(m => m.seq);
                    } else if (criteria === 'UNSEEN') {
                        results = mailbox.messages.filter(m => !m.flags.includes('\\Seen')).map(m => m.seq);
                    } else if (criteria === 'SEEN') {
                        results = mailbox.messages.filter(m => m.flags.includes('\\Seen')).map(m => m.seq);
                    } else if (criteria === 'FLAGGED') {
                        results = mailbox.messages.filter(m => m.flags.includes('\\Flagged')).map(m => m.seq);
                    } else if (criteria === 'DELETED') {
                        results = mailbox.messages.filter(m => m.flags.includes('\\Deleted')).map(m => m.seq);
                    } else if (criteria.startsWith('FROM ')) {
                        const from = args.slice(5).replace(/"/g, '').toLowerCase();
                        results = mailbox.messages.filter(m =>
                            (m.headers['From'] ?? '').toLowerCase().includes(from)
                        ).map(m => m.seq);
                    } else if (criteria.startsWith('TO ')) {
                        const to = args.slice(3).replace(/"/g, '').toLowerCase();
                        results = mailbox.messages.filter(m =>
                            (m.headers['To'] ?? '').toLowerCase().includes(to)
                        ).map(m => m.seq);
                    } else if (criteria.startsWith('SUBJECT ')) {
                        const subject = args.slice(8).replace(/"/g, '').toLowerCase();
                        results = mailbox.messages.filter(m =>
                            (m.headers['Subject'] ?? '').toLowerCase().includes(subject)
                        ).map(m => m.seq);
                    } else if (criteria.startsWith('UID ')) {
                        const uidStr = args.slice(4).trim();
                        if (uidStr.includes(':')) {
                            const [start, end] = uidStr.split(':');
                            const startUid = parseInt(start ?? '1', 10);
                            const endUid = end === '*' ? Infinity : parseInt(end ?? '1', 10);
                            results = mailbox.messages.filter(m => m.uid >= startUid && m.uid <= endUid).map(m => m.seq);
                        } else {
                            const uid = parseInt(uidStr, 10);
                            results = mailbox.messages.filter(m => m.uid === uid).map(m => m.seq);
                        }
                    } else {
                        return imapResponse(tag, 'NO', 'SEARCH criterion not implemented');
                    }

                    const output = untaggedResponse('SEARCH', results.join(' '));
                    return imapResponse(tag, 'OK', 'SEARCH completed', output);
                }

                case 'STATUS': {
                    if (!session.authenticated) {
                        return imapResponse(tag, 'NO', 'Not authenticated');
                    }

                    const statusMatch = args.match(/"([^"]+)"\s+\(([^)]+)\)/);
                    if (statusMatch === null) {
                        return imapResponse(tag, 'BAD', 'Invalid STATUS syntax');
                    }

                    const mboxName = statusMatch[1] ?? '';
                    const items = statusMatch[2] ?? '';

                    const mailboxes = getUserMailboxes(session.username);
                    const mailbox = mailboxes[mboxName];
                    if (mailbox === undefined) {
                        return imapResponse(tag, 'NO', `Mailbox doesn't exist: ${mboxName}`);
                    }

                    const statusItems: string[] = [];
                    if (items.toUpperCase().includes('MESSAGES')) {
                        statusItems.push(`MESSAGES ${mailbox.messages.length}`);
                    }
                    if (items.toUpperCase().includes('UNSEEN')) {
                        const unseen = mailbox.messages.filter(m => !m.flags.includes('\\Seen')).length;
                        statusItems.push(`UNSEEN ${unseen}`);
                    }
                    if (items.toUpperCase().includes('UIDVALIDITY')) {
                        statusItems.push(`UIDVALIDITY ${mailbox.uidValidity}`);
                    }

                    const output = untaggedResponse('STATUS', `"${mboxName}" (${statusItems.join(' ')})`);
                    return imapResponse(tag, 'OK', 'STATUS completed', output);
                }

                case 'ID': {
                    const output = untaggedResponse('ID', '("name" "Dovecot" "vendor" "Variant Mail")');
                    return imapResponse(tag, 'OK', 'ID completed', output);
                }

                case 'NAMESPACE': {
                    const output = untaggedResponse('NAMESPACE', '(("" "/")) NIL NIL');
                    return imapResponse(tag, 'OK', 'NAMESPACE completed', output);
                }

                default:
                    return imapResponse(tag, 'BAD', `Unknown command: ${cmd}`);
            }
        },

        stop(): void {
            sessions.clear();
            userMailboxes.clear();
        },
    };
}

function formatFetchResponse(msg: IMAPMessage, items: string): string {
    const upperItems = items.toUpperCase();
    const fetchParts: string[] = [];

    if (upperItems.includes('FLAGS')) {
        fetchParts.push(`FLAGS (${msg.flags.join(' ')})`);
    }

    if (upperItems.includes('INTERNALDATE')) {
        fetchParts.push(`INTERNALDATE "${msg.internalDate.toUTCString()}"`);
    }

    if (upperItems.includes('RFC822.SIZE')) {
        fetchParts.push(`RFC822.SIZE ${msg.size}`);
    }

    if (upperItems.includes('UID')) {
        fetchParts.push(`UID ${msg.uid}`);
    }

    if (upperItems.includes('BODYSTRUCTURE')) {
        fetchParts.push('BODYSTRUCTURE ("TEXT" "PLAIN" NIL NIL NIL "7BIT" 0 0)');
    }

    if (upperItems === 'BODY[]' || upperItems === 'RFC822' || upperItems.includes('BODY.PEEK')) {
        const headers = Object.entries(msg.headers)
            .map(([k, v]) => `${k}: ${v}`)
            .join('\r\n');
        const fullBody = `${headers}\r\n\r\n${msg.body}`;
        const bodyLiteral = `{${fullBody.length}}\r\n${fullBody}`;
        fetchParts.push(`BODY[] ${bodyLiteral}`);
    } else if (upperItems.includes('BODY[HEADER]')) {
        const headers = Object.entries(msg.headers)
            .map(([k, v]) => `${k}: ${v}`)
            .join('\r\n');
        const headerLiteral = `{${headers.length}}\r\n${headers}`;
        fetchParts.push(`BODY[HEADER] ${headerLiteral}`);
    } else if (upperItems.includes('BODY[TEXT]')) {
        const bodyLiteral = `{${msg.body.length}}\r\n${msg.body}`;
        fetchParts.push(`BODY[TEXT] ${bodyLiteral}`);
    }

    return `(${fetchParts.join(' ')})`;
}

function validateCredentials(ctx: ServiceContext, username: string, password: string): boolean {
    try {
        const shadow = ctx.vfs.readFile('/etc/shadow');
        if (shadow === null) return false;
        for (const line of shadow.split('\n')) {
            const parts = line.split(':');
            if (parts[0] === username && parts[1] === password) {
                return true;
            }
        }
    } catch {
        // No shadow file
    }
    return false;
}

// ── Export Types ───────────────────────────────────────────────

export type { IMAPConfig, IMailbox, IMAPMessage };
