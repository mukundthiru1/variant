/**
 * VARIANT — SMTP/Mail Service Handler
 *
 * Simulacrum-level mail service for social engineering scenarios.
 * Handles email delivery, inbox management, and phishing simulation.
 *
 * What it does:
 *   - Manages per-account inboxes (stored in VFS as Maildir)
 *   - Delivers emails from WorldSpec.mail.inbox at boot
 *   - Delivers timed emails (deliverAtTick > 0) via dynamics
 *   - Validates sender/recipient addresses
 *   - Emits events when emails are read (for objective detection)
 *   - Tracks phishing interaction (opening malicious links/attachments)
 *   - Generates mail.log entries
 *
 * EXTENSIBILITY: All behavior configurable via ServiceConfig.config:
 *   - domain: Mail domain (e.g., 'megacorp.local')
 *   - maxInboxSize: Max messages per account
 *   - spamFilter: Whether the spam filter is enabled
 *   - spamFilterAccuracy: 0-1 (how well it catches phishing)
 *   - allowRelay: Whether the server is an open relay
 *   - customHeaders: Default headers added to all emails
 */

import type { ServiceHandler, ServiceRequest, ServiceResponse, ServiceContext } from './types';
import type { ServiceConfig, MailSystemSpec, MailMessageSpec } from '../../core/world/types';

// ── SMTP Config ────────────────────────────────────────────────

interface SMTPConfig {
    readonly domain: string;
    readonly maxInboxSize: number;
    readonly spamFilter: boolean;
    readonly spamFilterAccuracy: number;
    readonly allowRelay: boolean;
    readonly port: number;
    readonly logFile: string;
}

function resolveSMTPConfig(config: ServiceConfig): SMTPConfig {
    const c = config.config ?? {};
    return {
        domain: (c['domain'] as string) ?? 'variant.local',
        maxInboxSize: (c['maxInboxSize'] as number) ?? 100,
        spamFilter: (c['spamFilter'] as boolean) ?? false,
        spamFilterAccuracy: (c['spamFilterAccuracy'] as number) ?? 0.8,
        allowRelay: (c['allowRelay'] as boolean) ?? false,
        port: config.ports[0] ?? 25,
        logFile: (c['logFile'] as string) ?? '/var/log/mail.log',
    };
}

// ── Mailbox Management ─────────────────────────────────────────

/**
 * In-memory mailbox. Each account has a list of messages.
 * Messages are also written to VFS as Maildir for players who
 * prefer to read mail from the terminal.
 */
interface Mailbox {
    readonly address: string;
    readonly messages: MailMessageSpec[];
    unreadCount: number;
}

// ── SMTP Service Handler ───────────────────────────────────────

export function createSMTPService(
    config: ServiceConfig,
    mailSpec?: MailSystemSpec,
): ServiceHandler {
    const smtpConfig = resolveSMTPConfig(config);
    const mailboxes = new Map<string, Mailbox>();

    return {
        name: 'smtp',
        port: smtpConfig.port,
        protocol: 'tcp',

        start(ctx: ServiceContext): void {
            // Initialize mailboxes from WorldSpec
            if (mailSpec !== undefined) {
                for (const [address, account] of Object.entries(mailSpec.accounts)) {
                    if (account.machine === ctx.hostname || account.machine === '') {
                        mailboxes.set(address, {
                            address,
                            messages: [],
                            unreadCount: 0,
                        });
                    }
                }

                // Deliver pre-loaded inbox
                if (mailSpec.inbox !== undefined) {
                    for (const msg of mailSpec.inbox) {
                        const deliverTick = msg.deliverAtTick ?? 0;
                        if (deliverTick === 0) {
                            deliverMessage(ctx, msg);
                        }
                    }
                }
            }

            ctx.emit({
                type: 'service:custom',
                service: 'smtp',
                action: 'started',
                details: {
                    domain: smtpConfig.domain,
                    port: smtpConfig.port,
                    accounts: Array.from(mailboxes.keys()),
                },
            });
        },

        handle(request: ServiceRequest, ctx: ServiceContext): ServiceResponse | null {
            const cmd = parseSMTPCommand(request.payloadText);
            if (cmd === null) {
                return smtpResponse(220, `${smtpConfig.domain} ESMTP Postfix`);
            }

            switch (cmd.verb) {
                case 'EHLO':
                case 'HELO':
                    return smtpResponse(250, `${smtpConfig.domain} Hello ${cmd.args}`);

                case 'MAIL': {
                    const from = extractAddress(cmd.args);
                    if (from === null) return smtpResponse(501, 'Syntax error in parameters');
                    return smtpResponse(250, `OK sender=${from}`);
                }

                case 'RCPT': {
                    const to = extractAddress(cmd.args);
                    if (to === null) return smtpResponse(501, 'Syntax error in parameters');
                    if (!smtpConfig.allowRelay && !to.endsWith(`@${smtpConfig.domain}`)) {
                        writeMailLog(ctx, `rejected relay attempt: ${to} from ${request.sourceIP}`);
                        return smtpResponse(550, 'Relay access denied');
                    }
                    return smtpResponse(250, `OK recipient=${to}`);
                }

                case 'DATA':
                    return smtpResponse(354, 'End data with <CR><LF>.<CR><LF>');

                case 'QUIT':
                    return smtpResponse(221, 'Bye', true);

                case 'LIST': {
                    // Custom: list inbox for an address
                    const address = cmd.args.trim();
                    const mailbox = mailboxes.get(address);
                    if (mailbox === undefined) {
                        return smtpResponse(550, 'Unknown mailbox');
                    }

                    const listing = mailbox.messages.map((msg, i) =>
                        `${i + 1}. [${msg.malicious === true ? '⚠' : ' '}] ${msg.from} — ${msg.subject}`,
                    ).join('\r\n');

                    ctx.emit({
                        type: 'service:custom',
                        service: 'smtp',
                        action: 'inbox-listed',
                        details: { address, count: mailbox.messages.length },
                    });

                    return smtpResponse(
                        250,
                        `Inbox for ${address} (${mailbox.messages.length} messages):\r\n${listing}`,
                    );
                }

                case 'READ': {
                    // Custom: read a specific message
                    const parts = cmd.args.trim().split(' ');
                    const address = parts[0] ?? '';
                    const index = parseInt(parts[1] ?? '', 10) - 1;
                    const mailbox = mailboxes.get(address);

                    if (mailbox === undefined) {
                        return smtpResponse(550, 'Unknown mailbox');
                    }

                    const msg = mailbox.messages[index];
                    if (msg === undefined) {
                        return smtpResponse(550, 'No such message');
                    }

                    // Emit read event
                    ctx.emit({
                        type: 'service:custom',
                        service: 'smtp',
                        action: 'message-read',
                        details: {
                            address,
                            messageId: msg.id,
                            from: msg.from,
                            subject: msg.subject,
                            malicious: msg.malicious === true,
                        },
                    });

                    // If malicious and player reads it, emit phishing event
                    if (msg.malicious === true) {
                        ctx.emit({
                            type: 'service:custom',
                            service: 'smtp',
                            action: 'phishing-interaction',
                            details: {
                                messageId: msg.id,
                                maliciousAction: msg.maliciousAction ?? 'unknown',
                                address,
                            },
                        });
                    }

                    const body = `From: ${msg.from}\r\nTo: ${msg.to}\r\nSubject: ${msg.subject}\r\n`;
                    const headers = msg.headers !== undefined
                        ? Object.entries(msg.headers).map(([k, v]) => `${k}: ${v}`).join('\r\n') + '\r\n'
                        : '';

                    return smtpResponse(250, `${body}${headers}\r\n${msg.body}`);
                }

                default:
                    return smtpResponse(502, 'Command not implemented');
            }
        },

        stop(): void {
            mailboxes.clear();
        },
    };

    // ── Internal helpers ─────────────────────────────────────

    function deliverMessage(ctx: ServiceContext, msg: MailMessageSpec): void {
        const mailbox = mailboxes.get(msg.to);
        if (mailbox === undefined) {
            // Create mailbox on the fly
            mailboxes.set(msg.to, {
                address: msg.to,
                messages: [msg],
                unreadCount: 1,
            });
        } else {
            if (mailbox.messages.length < smtpConfig.maxInboxSize) {
                mailbox.messages.push(msg);
                mailbox.unreadCount++;
            }
        }

        // Write to VFS as Maildir
        const maildirPath = `/var/mail/${msg.to.split('@')[0] ?? 'unknown'}/new`;
        try {
            ctx.vfs.writeFile(
                `${maildirPath}/${msg.id}`,
                `From: ${msg.from}\nTo: ${msg.to}\nSubject: ${msg.subject}\n\n${msg.body}`,
            );
        } catch {
            // VFS directory might not exist — that's fine for simulation
        }

        writeMailLog(ctx, `delivered: to=${msg.to}, from=${msg.from}, subject="${msg.subject}"`);

        ctx.emit({
            type: 'service:custom',
            service: 'smtp',
            action: 'delivered',
            details: {
                messageId: msg.id,
                from: msg.from,
                to: msg.to,
                subject: msg.subject,
                malicious: msg.malicious === true,
            },
        });
    }

    function writeMailLog(ctx: ServiceContext, message: string): void {
        const timestamp = new Date().toUTCString();
        const entry = `${timestamp} ${ctx.hostname} postfix/smtp[${1000 + Math.floor(Math.random() * 9000)}]: ${message}`;

        try {
            const existing = ctx.vfs.readFile(smtpConfig.logFile);
            ctx.vfs.writeFile(smtpConfig.logFile, existing + '\n' + entry);
        } catch {
            ctx.vfs.writeFile(smtpConfig.logFile, entry);
        }
    }
}

// ── SMTP Helpers ───────────────────────────────────────────────

interface SMTPCommand {
    readonly verb: string;
    readonly args: string;
}

function parseSMTPCommand(text: string): SMTPCommand | null {
    const trimmed = text.trim();
    if (trimmed === '') return null;

    const spaceIdx = trimmed.indexOf(' ');
    if (spaceIdx === -1) {
        return { verb: trimmed.toUpperCase(), args: '' };
    }

    return {
        verb: trimmed.slice(0, spaceIdx).toUpperCase(),
        args: trimmed.slice(spaceIdx + 1),
    };
}

function extractAddress(args: string): string | null {
    // MAIL FROM:<user@domain> or RCPT TO:<user@domain>
    const match = args.match(/<([^>]+)>/);
    if (match !== null && match[1] !== undefined) return match[1];

    // Also accept bare address after FROM: or TO:
    const colonIdx = args.indexOf(':');
    if (colonIdx !== -1) {
        const addr = args.slice(colonIdx + 1).trim();
        if (addr.includes('@')) return addr;
    }

    return null;
}

function smtpResponse(code: number, message: string, close = false): ServiceResponse {
    return {
        payload: new TextEncoder().encode(`${code} ${message}\r\n`),
        close,
    };
}
