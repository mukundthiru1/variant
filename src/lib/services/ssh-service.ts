/**
 * VARIANT — SSH Service Handler
 *
 * Simulacrum-level SSH service. Handles SSH login attempts
 * at the request/response level. For beginner/intermediate
 * levels that don't need a real SSH wire protocol.
 *
 * What it does:
 *   - Validates username/password against VFS /etc/shadow
 *   - Validates SSH key against VFS ~/.ssh/authorized_keys
 *   - Generates auth.log entries (real format, real timestamps)
 *   - Emits events for the objective detector
 *   - Tracks failed attempts for brute-force detection
 *   - Banner customization
 *
 * What Simulacrum+ adds on top:
 *   - Real SSH wire protocol via ProtocolHandler
 *   - Real SSH key exchange (KEX)
 *   - SCP/SFTP file transfer
 *
 * EXTENSIBILITY: All behavior is configurable through ServiceConfig.config:
 *   - banner: Custom SSH banner
 *   - maxAttempts: Max failed attempts before lockout (0 = unlimited)
 *   - lockoutDuration: Ticks to lock out after max attempts
 *   - hostKey: Custom host key fingerprint
 *   - allowedUsers: Whitelist of allowed usernames
 *   - deniedUsers: Blacklist of denied usernames
 *   - allowPasswordAuth: Enable/disable password auth
 *   - allowKeyAuth: Enable/disable key auth
 */

import type { ServiceHandler, ServiceRequest, ServiceResponse, ServiceContext, ServiceEvent } from './types';
import type { ServiceConfig } from '../../core/world/types';

// ── SSH Config ─────────────────────────────────────────────────

interface SSHConfig {
    readonly banner: string;
    readonly maxAttempts: number;
    readonly lockoutDurationTicks: number;
    readonly hostKeyFingerprint: string;
    readonly allowedUsers: readonly string[] | null;
    readonly deniedUsers: readonly string[];
    readonly allowPasswordAuth: boolean;
    readonly allowKeyAuth: boolean;
    readonly logFile: string;
    readonly port: number;
}

function resolveSSHConfig(config: ServiceConfig): SSHConfig {
    const c = config.config ?? {};
    return {
        banner: (c['banner'] as string) ?? 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6',
        maxAttempts: (c['maxAttempts'] as number) ?? 0,
        lockoutDurationTicks: (c['lockoutDuration'] as number) ?? 100,
        hostKeyFingerprint: (c['hostKey'] as string) ?? 'SHA256:abc123def456...',
        allowedUsers: (c['allowedUsers'] as readonly string[]) ?? null,
        deniedUsers: (c['deniedUsers'] as readonly string[]) ?? [],
        allowPasswordAuth: (c['allowPasswordAuth'] as boolean) ?? true,
        allowKeyAuth: (c['allowKeyAuth'] as boolean) ?? true,
        logFile: (c['logFile'] as string) ?? '/var/log/auth.log',
        port: config.ports[0] ?? 22,
    };
}

// ── SSH Service Handler ────────────────────────────────────────

export function createSSHService(config: ServiceConfig): ServiceHandler {
    const sshConfig = resolveSSHConfig(config);
    const failedAttempts = new Map<string, number>(); // IP -> count
    const lockedOut = new Map<string, number>(); // IP -> unlock tick
    let currentTick = 0;

    return {
        name: 'ssh',
        port: sshConfig.port,
        protocol: 'tcp',

        start(ctx: ServiceContext): void {
            // Listen for tick events to track lockout timeouts
            ctx.emit({
                type: 'service:custom',
                service: 'ssh',
                action: 'started',
                details: {
                    port: sshConfig.port,
                    banner: sshConfig.banner,
                },
            });
        },

        handle(request: ServiceRequest, ctx: ServiceContext): ServiceResponse | null {
            currentTick++;

            // Parse SSH auth request from payload
            const parsed = parseSSHRequest(request.payloadText);
            if (parsed === null) {
                // Send banner for initial connection
                return {
                    payload: new TextEncoder().encode(sshConfig.banner + '\r\n'),
                    close: false,
                };
            }

            // Check lockout
            if (isLockedOut(request.sourceIP)) {
                const authEvent: ServiceEvent = {
                    type: 'ssh:login',
                    username: parsed.username,
                    password: parsed.password ?? '',
                    sourceIP: request.sourceIP,
                    success: false,
                };
                ctx.emit(authEvent);

                writeAuthLog(ctx, request.sourceIP, parsed.username, false, 'locked out');

                return {
                    payload: new TextEncoder().encode('Permission denied (account locked).\r\n'),
                    close: true,
                };
            }

            // Check user allowlist/denylist
            if (sshConfig.deniedUsers.includes(parsed.username)) {
                recordFailure(request.sourceIP);
                writeAuthLog(ctx, request.sourceIP, parsed.username, false, 'user denied');

                ctx.emit({
                    type: 'ssh:login',
                    username: parsed.username,
                    password: parsed.password ?? '',
                    sourceIP: request.sourceIP,
                    success: false,
                });

                return {
                    payload: new TextEncoder().encode('Permission denied.\r\n'),
                    close: true,
                };
            }

            if (sshConfig.allowedUsers !== null && !sshConfig.allowedUsers.includes(parsed.username)) {
                recordFailure(request.sourceIP);
                writeAuthLog(ctx, request.sourceIP, parsed.username, false, 'user not allowed');

                ctx.emit({
                    type: 'ssh:login',
                    username: parsed.username,
                    password: parsed.password ?? '',
                    sourceIP: request.sourceIP,
                    success: false,
                });

                return {
                    payload: new TextEncoder().encode('Permission denied.\r\n'),
                    close: true,
                };
            }

            // Validate credentials
            const valid = validateCredentials(ctx, parsed);

            const authEvent: ServiceEvent = {
                type: 'ssh:login',
                username: parsed.username,
                password: parsed.password ?? '',
                sourceIP: request.sourceIP,
                success: valid,
            };
            ctx.emit(authEvent);

            if (valid) {
                failedAttempts.delete(request.sourceIP);
                writeAuthLog(ctx, request.sourceIP, parsed.username, true, '');

                return {
                    payload: new TextEncoder().encode(`Welcome to ${ctx.hostname}\r\nLast login: Thu Mar  5 14:22:31 2026 from ${request.sourceIP}\r\n`),
                    close: false,
                };
            } else {
                recordFailure(request.sourceIP);
                writeAuthLog(ctx, request.sourceIP, parsed.username, false, 'invalid credentials');

                return {
                    payload: new TextEncoder().encode('Permission denied, please try again.\r\n'),
                    close: true,
                };
            }
        },

        stop(): void {
            failedAttempts.clear();
            lockedOut.clear();
        },
    };

    // ── Internal helpers ─────────────────────────────────────

    function isLockedOut(ip: string): boolean {
        const unlockTick = lockedOut.get(ip);
        if (unlockTick === undefined) return false;
        if (currentTick >= unlockTick) {
            lockedOut.delete(ip);
            return false;
        }
        return true;
    }

    function recordFailure(ip: string): void {
        const count = (failedAttempts.get(ip) ?? 0) + 1;
        failedAttempts.set(ip, count);

        if (sshConfig.maxAttempts > 0 && count >= sshConfig.maxAttempts) {
            lockedOut.set(ip, currentTick + sshConfig.lockoutDurationTicks);
            failedAttempts.delete(ip);
        }
    }

    function validateCredentials(
        ctx: ServiceContext,
        parsed: ParsedSSHAuth,
    ): boolean {
        if (parsed.authType === 'password' && sshConfig.allowPasswordAuth) {
            // Check /etc/shadow (simplistic — just check if user/pass matches VFS)
            try {
                const shadow = ctx.vfs.readFile('/etc/shadow');
                if (shadow === null) throw new Error('no shadow');
                const lines = shadow.split('\n');
                for (const line of lines) {
                    const parts = line.split(':');
                    if (parts[0] === parsed.username) {
                        // In our simulation, passwords in shadow are plaintext
                        // (or the hash matches). Real shadow uses crypt(3).
                        // Level designers put the password in the VFS.
                        return parts[1] === parsed.password;
                    }
                }
            } catch {
                // No shadow file — fall through
            }
        }

        if (parsed.authType === 'key' && sshConfig.allowKeyAuth) {
            // Check ~/.ssh/authorized_keys
            try {
                const home = parsed.username === 'root' ? '/root' : `/home/${parsed.username}`;
                const authKeys = ctx.vfs.readFile(`${home}/.ssh/authorized_keys`);
                if (authKeys === null) throw new Error('no keys');
                return authKeys.includes(parsed.key ?? '');
            } catch {
                // No authorized_keys file
            }
        }

        return false;
    }

    function writeAuthLog(
        ctx: ServiceContext,
        sourceIP: string,
        username: string,
        success: boolean,
        reason: string,
    ): void {
        const timestamp = new Date().toUTCString();
        const message = success
            ? `${timestamp} ${ctx.hostname} sshd[${1000 + Math.floor(Math.random() * 9000)}]: Accepted password for ${username} from ${sourceIP} port ${sshConfig.port} ssh2`
            : `${timestamp} ${ctx.hostname} sshd[${1000 + Math.floor(Math.random() * 9000)}]: Failed password for ${username} from ${sourceIP} port ${sshConfig.port} ssh2${reason !== '' ? ` (${reason})` : ''}`;

        try {
            const existing = ctx.vfs.readFile(sshConfig.logFile);
            ctx.vfs.writeFile(sshConfig.logFile, existing + '\n' + message);
        } catch {
            ctx.vfs.writeFile(sshConfig.logFile, message);
        }
    }
}

// ── SSH Request Parser ─────────────────────────────────────────

interface ParsedSSHAuth {
    readonly username: string;
    readonly authType: 'password' | 'key';
    readonly password?: string;
    readonly key?: string;
}

/**
 * Parse an SSH authentication request.
 * In the Simulacrum, SSH auth comes as structured text:
 *   AUTH password <username> <password>
 *   AUTH key <username> <key-fingerprint>
 */
function parseSSHRequest(text: string): ParsedSSHAuth | null {
    const trimmed = text.trim();
    if (!trimmed.startsWith('AUTH ')) return null;

    const parts = trimmed.split(' ');
    if (parts.length < 4) return null;

    const authType = parts[1];
    const username = parts[2];

    if (authType === 'password') {
        return {
            username: username ?? '',
            authType: 'password',
            password: parts.slice(3).join(' '),
        };
    }

    if (authType === 'key') {
        return {
            username: username ?? '',
            authType: 'key',
            key: parts.slice(3).join(' '),
        };
    }

    return null;
}
