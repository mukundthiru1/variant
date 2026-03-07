/**
 * VARIANT — SMB/CIFS Service Handler
 *
 * Simulated SMB/CIFS file sharing service for lateral movement
 * and file access scenarios. Supports share enumeration, file
 * access, and null session authentication.
 *
 * What it does:
 *   - List shares (IPC$, ADMIN$, C$, and custom shares)
 *   - Access files within shares with permission checking
 *   - Null session support (anonymous access)
 *   - Realistic error messages (STATUS_ACCESS_DENIED, etc.)
 *   - Session tracking per source IP
 *   - Emits events for objective detection
 *
 * EXTENSIBILITY: Configurable via ServiceConfig.config:
 *   - shares: Array of SMBShare definitions
 *   - allowNullSession: Allow anonymous access (default: true)
 *   - workgroup: NT domain/workgroup name (default: WORKGROUP)
 *   - serverName: NetBIOS server name (default: hostname)
 */

import type {
    ServiceHandler,
    ServiceRequest,
    ServiceResponse,
    ServiceContext,
} from './types';
import type { ServiceConfig } from '../../core/world/types';

// ── SMB Config ─────────────────────────────────────────────────

interface SMBConfig {
    readonly shares: readonly SMBShare[];
    readonly allowNullSession: boolean;
    readonly workgroup: string;
    readonly serverName: string;
    readonly port: number;
    readonly logFile: string;
}

interface SMBShare {
    readonly name: string;
    readonly path: string;
    readonly comment: string;
    readonly type: 'disk' | 'ipc' | 'admin';
    readonly allowNullSession: boolean;
    readonly readOnly: boolean;
    readonly hidden: boolean;
}

interface SMBSession {
    authenticated: boolean;
    username: string;
    connectedShares: Set<string>;
    currentShare: string;
    currentPath: string;
}

function resolveSMBConfig(config: ServiceConfig, hostname: string): SMBConfig {
    const c = config.config ?? {};
    return {
        shares: (c['shares'] as SMBShare[]) ?? getDefaultShares(),
        allowNullSession: (c['allowNullSession'] as boolean) ?? true,
        workgroup: (c['workgroup'] as string) ?? 'WORKGROUP',
        serverName: (c['serverName'] as string) ?? hostname,
        port: config.ports[0] ?? 445,
        logFile: (c['logFile'] as string) ?? '/var/log/samba/smbd.log',
    };
}

function getDefaultShares(): SMBShare[] {
    return [
        {
            name: 'IPC$',
            path: '',
            comment: 'Remote IPC',
            type: 'ipc',
            allowNullSession: true,
            readOnly: true,
            hidden: true,
        },
        {
            name: 'ADMIN$',
            path: '/windows',
            comment: 'Remote Admin',
            type: 'admin',
            allowNullSession: false,
            readOnly: false,
            hidden: true,
        },
        {
            name: 'C$',
            path: '/',
            comment: 'Default share',
            type: 'admin',
            allowNullSession: false,
            readOnly: false,
            hidden: true,
        },
        {
            name: 'Public',
            path: '/srv/samba/public',
            comment: 'Public Share',
            type: 'disk',
            allowNullSession: true,
            readOnly: false,
            hidden: false,
        },
        {
            name: 'Finance',
            path: '/srv/samba/finance',
            comment: 'Finance Department',
            type: 'disk',
            allowNullSession: false,
            readOnly: false,
            hidden: false,
        },
        {
            name: 'Backups',
            path: '/backups',
            comment: 'System Backups',
            type: 'disk',
            allowNullSession: false,
            readOnly: true,
            hidden: false,
        },
    ];
}

// ── SMB Protocol Constants ─────────────────────────────────────

const NT_STATUS = {
    SUCCESS: '0x00000000',
    ACCESS_DENIED: '0xC0000022',
    BAD_NETWORK_NAME: '0xC00000CC',
    INVALID_PARAMETER: '0xC000000D',
    NO_SUCH_FILE: '0xC000000F',
    OBJECT_NAME_NOT_FOUND: '0xC0000034',
    LOGON_FAILURE: '0xC000006D',
    ACCOUNT_RESTRICTION: '0xC000006E',
    INVALID_SID: '0xC0000078',
    PIPE_BROKEN: '0xC000014B',
};

// ── SMB Service Handler ────────────────────────────────────────

export function createSMBService(config: ServiceConfig): ServiceHandler {
    let smbConfig: SMBConfig;
    const sessions = new Map<string, SMBSession>();

    function getSession(sourceIP: string): SMBSession {
        let session = sessions.get(sourceIP);
        if (session === undefined) {
            session = {
                authenticated: false,
                username: '',
                connectedShares: new Set(),
                currentShare: '',
                currentPath: '',
            };
            sessions.set(sourceIP, session);
        }
        return session;
    }

    function writeSMBLog(ctx: ServiceContext, message: string): void {
        const timestamp = new Date().toISOString();
        const line = `[${timestamp}] smbd[${1000 + Math.floor(Math.random() * 9000)}]: ${message}`;
        try {
            const existing = ctx.vfs.readFile(smbConfig.logFile);
            ctx.vfs.writeFile(smbConfig.logFile, existing + '\n' + line);
        } catch {
            ctx.vfs.writeFile(smbConfig.logFile, line);
        }
    }

    function smbResponse(status: string, data: string, close = false): ServiceResponse {
        const statusName = Object.entries(NT_STATUS).find(([, v]) => v === status)?.[0] ?? 'UNKNOWN';
        return {
            payload: new TextEncoder().encode(`STATUS:${status} ${statusName}\r\n${data}`),
            close,
        };
    }

    return {
        name: 'smb',
        port: 445,
        protocol: 'tcp',

        start(ctx: ServiceContext): void {
            smbConfig = resolveSMBConfig(config, ctx.hostname);

            ctx.emit({
                type: 'service:custom',
                service: 'smb',
                action: 'started',
                details: {
                    port: smbConfig.port,
                    workgroup: smbConfig.workgroup,
                    serverName: smbConfig.serverName,
                    shareCount: smbConfig.shares.length,
                },
            });
        },

        handle(request: ServiceRequest, ctx: ServiceContext): ServiceResponse | null {
            // Delay config resolution if not done in start
            if (smbConfig === undefined) {
                smbConfig = resolveSMBConfig(config, ctx.hostname);
            }

            const text = request.payloadText.trim();

            // Initial connection - send SMB negotiate response
            if (text === '') {
                return {
                    payload: new TextEncoder().encode(
                        `SMB negotiate response:\r\n` +
                        `Dialect: SMB 2.1\r\n` +
                        `Server: ${smbConfig.serverName}\r\n` +
                        `Workgroup: ${smbConfig.workgroup}\r\n`,
                    ),
                    close: false,
                };
            }

            const session = getSession(request.sourceIP);
            const spaceIdx = text.indexOf(' ');
            const cmd = spaceIdx === -1 ? text.toUpperCase() : text.slice(0, spaceIdx).toUpperCase();
            const arg = spaceIdx === -1 ? '' : text.slice(spaceIdx + 1).trim();

            switch (cmd) {
                case 'SESSION_SETUP': {
                    // Parse: SESSION_SETUP username=<user> password=<pass>
                    const userMatch = arg.match(/username=(\S+)/i);
                    const passMatch = arg.match(/password=(\S+)/i);
                    const username = userMatch?.[1] ?? '';
                    const password = passMatch?.[1] ?? '';

                    // Null session
                    if (username === '' || username.toLowerCase() === 'guest') {
                        if (!smbConfig.allowNullSession) {
                            writeSMBLog(ctx, `denied null session from ${request.sourceIP}`);
                            ctx.emit({
                                type: 'service:custom',
                                service: 'smb',
                                action: 'session-setup',
                                details: { username: 'null', sourceIP: request.sourceIP, success: false },
                            });
                            return smbResponse(NT_STATUS.LOGON_FAILURE, 'Null sessions not allowed');
                        }
                        session.authenticated = true;
                        session.username = 'Guest';
                        writeSMBLog(ctx, `accepted null session from ${request.sourceIP}`);
                        ctx.emit({
                            type: 'service:custom',
                            service: 'smb',
                            action: 'session-setup',
                            details: { username: 'Guest', sourceIP: request.sourceIP, success: true, nullSession: true },
                        });
                        return smbResponse(NT_STATUS.SUCCESS, `Session established as Guest\r\nUID: 0x${(Math.floor(Math.random() * 65535)).toString(16).padStart(4, '0')}`);
                    }

                    // Authenticated session - validate against /etc/shadow
                    const valid = validateCredentials(ctx, username, password);
                    if (valid) {
                        session.authenticated = true;
                        session.username = username;
                        writeSMBLog(ctx, `session setup: user ${username} from ${request.sourceIP}`);
                        ctx.emit({
                            type: 'service:custom',
                            service: 'smb',
                            action: 'session-setup',
                            details: { username, sourceIP: request.sourceIP, success: true },
                        });
                        return smbResponse(NT_STATUS.SUCCESS, `Session established as ${username}\r\nUID: 0x${(Math.floor(Math.random() * 65535)).toString(16).padStart(4, '0')}`);
                    }

                    writeSMBLog(ctx, `session setup failed: user ${username} from ${request.sourceIP}`);
                    ctx.emit({
                        type: 'service:custom',
                        service: 'smb',
                        action: 'session-setup',
                        details: { username, sourceIP: request.sourceIP, success: false },
                    });
                    return smbResponse(NT_STATUS.LOGON_FAILURE, 'Authentication failed');
                }

                case 'TREE_CONNECT': {
                    // Parse: TREE_CONNECT share=<sharename>
                    const shareMatch = arg.match(/share=(.+)/i);
                    const shareName = shareMatch?.[1] ?? '';

                    if (!session.authenticated) {
                        return smbResponse(NT_STATUS.ACCESS_DENIED, 'Not authenticated');
                    }

                    const share = smbConfig.shares.find(s => s.name.toLowerCase() === shareName.toLowerCase());
                    if (share === undefined) {
                        writeSMBLog(ctx, `tree connect failed: share ${shareName} not found from ${request.sourceIP}`);
                        return smbResponse(NT_STATUS.BAD_NETWORK_NAME, `Share ${shareName} does not exist`);
                    }

                    // Check null session access
                    if (session.username === 'Guest' && !share.allowNullSession) {
                        writeSMBLog(ctx, `tree connect denied: share ${shareName} requires authentication from ${request.sourceIP}`);
                        return smbResponse(NT_STATUS.ACCESS_DENIED, 'STATUS_ACCESS_DENIED: Authentication required for this share');
                    }

                    session.connectedShares.add(share.name);
                    session.currentShare = share.name;
                    session.currentPath = share.path;

                    writeSMBLog(ctx, `tree connect: share ${shareName} by ${session.username} from ${request.sourceIP}`);
                    ctx.emit({
                        type: 'service:custom',
                        service: 'smb',
                        action: 'tree-connect',
                        details: { share: shareName, username: session.username, sourceIP: request.sourceIP },
                    });

                    return smbResponse(NT_STATUS.SUCCESS, `Connected to \\${smbConfig.serverName}\${share.name}\r\nShare type: ${share.type}\r\nAccess: ${share.readOnly ? 'READ ONLY' : 'READ/WRITE'}`);
                }

                case 'NET_SHARE_ENUM': {
                    // List all shares
                    if (!session.authenticated) {
                        return smbResponse(NT_STATUS.ACCESS_DENIED, 'Not authenticated');
                    }

                    const visibleShares = smbConfig.shares.filter(s => {
                        if (s.hidden && session.username === 'Guest') return false;
                        return true;
                    });

                    let output = `Share enumeration for \\${smbConfig.serverName}:\r\n`;
                    output += 'ShareName   Type     Comment\r\n';
                    output += '---------   ----     -------\r\n';

                    for (const share of visibleShares) {
                        const typeStr = share.type.toUpperCase().padEnd(8);
                        const nameStr = share.name.padEnd(11);
                        const nullIndicator = share.allowNullSession ? ' [NULL]' : '';
                        output += `${nameStr}${typeStr}${share.comment}${nullIndicator}\r\n`;
                    }

                    writeSMBLog(ctx, `share enumeration by ${session.username} from ${request.sourceIP}`);
                    ctx.emit({
                        type: 'service:custom',
                        service: 'smb',
                        action: 'share-enum',
                        details: { username: session.username, sourceIP: request.sourceIP, count: visibleShares.length },
                    });

                    return smbResponse(NT_STATUS.SUCCESS, output);
                }

                case 'QUERY_INFO': {
                    // Get info about current share or path
                    if (!session.authenticated) {
                        return smbResponse(NT_STATUS.ACCESS_DENIED, 'Not authenticated');
                    }

                    if (session.currentShare === '') {
                        return smbResponse(NT_STATUS.INVALID_PARAMETER, 'Not connected to a share');
                    }

                    const share = smbConfig.shares.find(s => s.name === session.currentShare);
                    if (share === undefined) {
                        return smbResponse(NT_STATUS.BAD_NETWORK_NAME, 'Share not found');
                    }

                    const info =
                        `Share: ${share.name}\r\n` +
                        `Path: ${share.path}\r\n` +
                        `Type: ${share.type}\r\n` +
                        `Comment: ${share.comment}\r\n` +
                        `ReadOnly: ${share.readOnly}\r\n` +
                        `NullSession: ${share.allowNullSession}\r\n`;

                    return smbResponse(NT_STATUS.SUCCESS, info);
                }

                case 'CREATE': {
                    // Access a file: CREATE path=<path>
                    if (!session.authenticated) {
                        return smbResponse(NT_STATUS.ACCESS_DENIED, 'Not authenticated');
                    }

                    const pathMatch = arg.match(/path=(.+)/i);
                    const filePath = pathMatch?.[1] ?? '';

                    if (session.currentShare === '') {
                        return smbResponse(NT_STATUS.INVALID_PARAMETER, 'Not connected to a share');
                    }

                    const share = smbConfig.shares.find(s => s.name === session.currentShare);
                    if (share === undefined) {
                        return smbResponse(NT_STATUS.BAD_NETWORK_NAME, 'Share not found');
                    }

                    // Check read-only
                    if (!share.readOnly) {
                        // Allow access
                    }

                    const fullPath = share.path + (share.path.endsWith('/') ? '' : '/') + filePath;
                    const content = ctx.vfs.readFile(fullPath);

                    if (content === null) {
                        // Try as directory
                        const entries = ctx.vfs.readDir(fullPath);
                        if (entries === null) {
                            return smbResponse(NT_STATUS.OBJECT_NAME_NOT_FOUND, `File not found: ${filePath}`);
                        }
                        const listing = entries.join('\r\n');
                        writeSMBLog(ctx, `directory listing: ${fullPath} by ${session.username}`);
                        return smbResponse(NT_STATUS.SUCCESS, `Directory listing of ${filePath}:\r\n${listing}`);
                    }

                    writeSMBLog(ctx, `file accessed: ${fullPath} by ${session.username}`);
                    ctx.emit({
                        type: 'file:access',
                        path: fullPath,
                        action: 'read',
                        user: session.username,
                    });

                    return smbResponse(NT_STATUS.SUCCESS, `File: ${filePath}\r\nSize: ${content.length} bytes\r\n\r\n${content}`);
                }

                case 'TREE_DISCONNECT': {
                    if (session.currentShare !== '') {
                        writeSMBLog(ctx, `tree disconnect: share ${session.currentShare} by ${session.username}`);
                        session.connectedShares.delete(session.currentShare);
                        session.currentShare = '';
                        session.currentPath = '';
                    }
                    return smbResponse(NT_STATUS.SUCCESS, 'Disconnected from share');
                }

                case 'LOGOFF': {
                    writeSMBLog(ctx, `logoff: user ${session.username} from ${request.sourceIP}`);
                    sessions.delete(request.sourceIP);
                    return smbResponse(NT_STATUS.SUCCESS, 'Logoff successful', true);
                }

                default:
                    return smbResponse(NT_STATUS.INVALID_PARAMETER, `Unknown command: ${cmd}`);
            }
        },

        stop(): void {
            sessions.clear();
        },
    };
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

export type { SMBConfig, SMBShare, SMBSession };
