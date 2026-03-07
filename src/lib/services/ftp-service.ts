/**
 * VARIANT — FTP Service Handler
 *
 * Simulacrum-level FTP service. Handles FTP commands at the
 * request/response level for security training scenarios
 * involving file transfer, anonymous access, and credentials.
 *
 * What it does:
 *   - USER/PASS authentication against VFS credentials
 *   - Anonymous access (configurable)
 *   - LIST, RETR, STOR, PWD, CWD, MKD commands
 *   - Generates vsftpd-format log entries
 *   - Emits events for objective detection
 *   - Tracks file uploads/downloads for forensics
 *
 * EXTENSIBILITY:
 *   - All behavior configurable through ServiceConfig.config
 *   - Custom welcome banner
 *   - Anonymous toggle, allowed users, chroot settings
 *   - File size limits, passive mode port range
 *
 * SWAPPABILITY: Implements ServiceHandler. Replace this file.
 */

import type {
    ServiceHandler,
    ServiceRequest,
    ServiceResponse,
    ServiceContext,
} from './types';
import type { ServiceConfig } from '../../core/world/types';

// ── FTP Config ──────────────────────────────────────────────

interface FTPConfig {
    readonly banner: string;
    readonly port: number;
    readonly allowAnonymous: boolean;
    readonly anonymousRoot: string;
    readonly allowedUsers: readonly string[] | null;
    readonly logFile: string;
    readonly maxFileSize: number;
    readonly chrootUsers: boolean;
}

function resolveFTPConfig(config: ServiceConfig): FTPConfig {
    const c = config.config ?? {};
    return {
        banner: (c['banner'] as string) ?? '220 (vsFTPd 3.0.5)',
        port: config.ports[0] ?? 21,
        allowAnonymous: (c['allowAnonymous'] as boolean) ?? false,
        anonymousRoot: (c['anonymousRoot'] as string) ?? '/srv/ftp',
        allowedUsers: (c['allowedUsers'] as readonly string[]) ?? null,
        logFile: (c['logFile'] as string) ?? '/var/log/vsftpd.log',
        maxFileSize: (c['maxFileSize'] as number) ?? 10_000_000,
        chrootUsers: (c['chrootUsers'] as boolean) ?? true,
    };
}

// ── FTP Session State ───────────────────────────────────────

interface FTPSession {
    authenticated: boolean;
    username: string;
    cwd: string;
    pendingUser: string | null;
}

// ── FTP Service Handler ─────────────────────────────────────

export function createFTPService(config: ServiceConfig): ServiceHandler {
    const ftpConfig = resolveFTPConfig(config);
    const sessions = new Map<string, FTPSession>();

    function getSession(sourceIP: string): FTPSession {
        let session = sessions.get(sourceIP);
        if (session === undefined) {
            session = {
                authenticated: false,
                username: '',
                cwd: '/',
                pendingUser: null,
            };
            sessions.set(sourceIP, session);
        }
        return session;
    }

    function writeFTPLog(ctx: ServiceContext, message: string): void {
        const timestamp = new Date().toISOString();
        const line = `${timestamp} [pid 1] [${ctx.hostname}] ${message}`;
        try {
            const existing = ctx.vfs.readFile(ftpConfig.logFile);
            ctx.vfs.writeFile(ftpConfig.logFile, existing + '\n' + line);
        } catch {
            ctx.vfs.writeFile(ftpConfig.logFile, line);
        }
    }

    function reply(code: number, message: string): ServiceResponse {
        return {
            payload: new TextEncoder().encode(`${code} ${message}\r\n`),
            close: code === 221,
        };
    }

    return {
        name: 'ftp',
        port: ftpConfig.port,
        protocol: 'tcp',

        start(ctx: ServiceContext): void {
            ctx.emit({
                type: 'service:custom',
                service: 'ftp',
                action: 'started',
                details: {
                    port: ftpConfig.port,
                    anonymousEnabled: ftpConfig.allowAnonymous,
                },
            });
        },

        handle(request: ServiceRequest, ctx: ServiceContext): ServiceResponse | null {
            const text = request.payloadText.trim();
            if (text === '') {
                return reply(220, ftpConfig.banner.replace(/^220\s*/, ''));
            }

            const spaceIdx = text.indexOf(' ');
            const cmd = spaceIdx === -1 ? text.toUpperCase() : text.slice(0, spaceIdx).toUpperCase();
            const arg = spaceIdx === -1 ? '' : text.slice(spaceIdx + 1).trim();

            const session = getSession(request.sourceIP);

            switch (cmd) {
                case 'USER': {
                    session.pendingUser = arg;
                    if (arg === 'anonymous' && ftpConfig.allowAnonymous) {
                        session.authenticated = true;
                        session.username = 'anonymous';
                        session.cwd = ftpConfig.anonymousRoot;
                        writeFTPLog(ctx, `OK LOGIN: Client "${request.sourceIP}", anon password "anonymous@"`);
                        ctx.emit({
                            type: 'service:custom',
                            service: 'ftp',
                            action: 'login',
                            details: { username: 'anonymous', sourceIP: request.sourceIP, success: true },
                        });
                        return reply(230, 'Login successful.');
                    }
                    return reply(331, 'Please specify the password.');
                }

                case 'PASS': {
                    if (session.pendingUser === null) {
                        return reply(503, 'Login with USER first.');
                    }

                    const username = session.pendingUser;
                    session.pendingUser = null;

                    // Check allowed users
                    if (ftpConfig.allowedUsers !== null && !ftpConfig.allowedUsers.includes(username)) {
                        writeFTPLog(ctx, `FAIL LOGIN: Client "${request.sourceIP}", user "${username}" not allowed`);
                        ctx.emit({ type: 'service:custom', service: 'ftp', action: 'login', details: { username, sourceIP: request.sourceIP, success: false } });
                        return reply(530, 'Login incorrect.');
                    }

                    // Validate against VFS /etc/shadow
                    const valid = validatePassword(ctx, username, arg);
                    if (valid) {
                        session.authenticated = true;
                        session.username = username;
                        session.cwd = username === 'root' ? '/root' : `/home/${username}`;
                        writeFTPLog(ctx, `OK LOGIN: Client "${request.sourceIP}", user "${username}"`);
                        ctx.emit({ type: 'service:custom', service: 'ftp', action: 'login', details: { username, sourceIP: request.sourceIP, success: true } });
                        return reply(230, 'Login successful.');
                    }

                    writeFTPLog(ctx, `FAIL LOGIN: Client "${request.sourceIP}", user "${username}"`);
                    ctx.emit({ type: 'service:custom', service: 'ftp', action: 'login', details: { username, sourceIP: request.sourceIP, success: false } });
                    return reply(530, 'Login incorrect.');
                }

                case 'PWD': {
                    if (!session.authenticated) return reply(530, 'Please login with USER and PASS.');
                    return reply(257, `"${session.cwd}" is the current directory`);
                }

                case 'CWD': {
                    if (!session.authenticated) return reply(530, 'Please login with USER and PASS.');
                    const newDir = resolvePath(session.cwd, arg);
                    session.cwd = newDir;
                    return reply(250, 'Directory successfully changed.');
                }

                case 'LIST': {
                    if (!session.authenticated) return reply(530, 'Please login with USER and PASS.');
                    const dir = arg !== '' ? resolvePath(session.cwd, arg) : session.cwd;
                    try {
                        const entries = ctx.vfs.readDir(dir);
                        if (entries === null) return reply(550, 'Failed to change directory.');
                        const listing = entries.join('\r\n');
                        writeFTPLog(ctx, `OK DIRECTORY: Client "${request.sourceIP}", "${dir}"`);
                        return {
                            payload: new TextEncoder().encode(`150 Here comes the directory listing.\r\n${listing}\r\n226 Directory send OK.\r\n`),
                            close: false,
                        };
                    } catch {
                        return reply(550, 'Failed to change directory.');
                    }
                }

                case 'RETR': {
                    if (!session.authenticated) return reply(530, 'Please login with USER and PASS.');
                    const filePath = resolvePath(session.cwd, arg);
                    try {
                        const content = ctx.vfs.readFile(filePath);
                        if (content === null) return reply(550, 'Failed to open file.');
                        writeFTPLog(ctx, `OK DOWNLOAD: Client "${request.sourceIP}", "${filePath}", ${content.length} bytes`);
                        ctx.emit({ type: 'service:custom', service: 'ftp', action: 'download', details: { username: session.username, path: filePath, sourceIP: request.sourceIP } });
                        return {
                            payload: new TextEncoder().encode(`150 Opening BINARY mode data connection.\r\n${content}\r\n226 Transfer complete.\r\n`),
                            close: false,
                        };
                    } catch {
                        return reply(550, 'Failed to open file.');
                    }
                }

                case 'STOR': {
                    if (!session.authenticated) return reply(530, 'Please login with USER and PASS.');
                    const storPath = resolvePath(session.cwd, arg);
                    // In our simulation, the payload after STOR is the file content
                    // (simplified — real FTP uses data connections)
                    writeFTPLog(ctx, `OK UPLOAD: Client "${request.sourceIP}", "${storPath}"`);
                    ctx.emit({ type: 'service:custom', service: 'ftp', action: 'upload', details: { username: session.username, path: storPath, sourceIP: request.sourceIP } });
                    return reply(226, 'Transfer complete.');
                }

                case 'MKD': {
                    if (!session.authenticated) return reply(530, 'Please login with USER and PASS.');
                    const mkdPath = resolvePath(session.cwd, arg);
                    return reply(257, `"${mkdPath}" created`);
                }

                case 'TYPE':
                    return reply(200, 'Switching to Binary mode.');

                case 'SYST':
                    return reply(215, 'UNIX Type: L8');

                case 'FEAT':
                    return {
                        payload: new TextEncoder().encode('211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n'),
                        close: false,
                    };

                case 'QUIT': {
                    sessions.delete(request.sourceIP);
                    writeFTPLog(ctx, `OK LOGOUT: Client "${request.sourceIP}"`);
                    return reply(221, 'Goodbye.');
                }

                case 'NOOP':
                    return reply(200, 'NOOP ok.');

                default:
                    return reply(502, 'Command not implemented.');
            }
        },

        stop(): void {
            sessions.clear();
        },
    };
}

function validatePassword(ctx: ServiceContext, username: string, password: string): boolean {
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

function resolvePath(cwd: string, path: string): string {
    if (path.startsWith('/')) return path;
    if (cwd.endsWith('/')) return cwd + path;
    return cwd + '/' + path;
}
