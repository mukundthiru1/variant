/**
 * VARIANT — Telnet Service Handler
 *
 * Simulated Telnet service for legacy protocol security scenarios.
 * Supports banner display, login authentication, and command execution
 * with cleartext credential capture for security training.
 *
 * What it does:
 *   - Displays banner on initial connection
 *   - Prompts for username/password
 *   - Validates credentials against VFS
 *   - Executes commands after authentication
 *   - Issues no encryption warnings
 *   - Captures credentials in cleartext for forensics
 *   - Emits events for objective detection
 *
 * EXTENSIBILITY: Configurable via ServiceConfig.config:
 *   - banner: Custom login banner (default: system info)
 *   - motd: Message of the day after login
 *   - allowRoot: Allow root login (default: true)
 *   - captureCredentials: Log cleartext creds (default: true)
 *   - loginPrompt: Custom username prompt
 *   - passwordPrompt: Custom password prompt
 */

import type {
    ServiceHandler,
    ServiceRequest,
    ServiceResponse,
    ServiceContext,
} from './types';
import type { ServiceConfig } from '../../core/world/types';

// ── Telnet Config ──────────────────────────────────────────────

interface TelnetConfig {
    readonly banner: string;
    readonly motd: string;
    readonly allowRoot: boolean;
    readonly captureCredentials: boolean;
    readonly loginPrompt: string;
    readonly passwordPrompt: string;
    readonly port: number;
    readonly logFile: string;
    readonly credentialLog: string;
    readonly maxAttempts: number;
}

interface TelnetSession {
    state: 'banner' | 'username' | 'password' | 'authenticated';
    username: string;
    password: string;
    pendingUser: string;
    attemptCount: number;
    lastCommand: string;
}

function resolveTelnetConfig(config: ServiceConfig, hostname: string): TelnetConfig {
    const c = config.config ?? {};
    return {
        banner: (c['banner'] as string) ?? getDefaultBanner(hostname),
        motd: (c['motd'] as string) ?? getDefaultMotd(hostname),
        allowRoot: (c['allowRoot'] as boolean) ?? true,
        captureCredentials: (c['captureCredentials'] as boolean) ?? true,
        loginPrompt: (c['loginPrompt'] as string) ?? 'login: ',
        passwordPrompt: (c['passwordPrompt'] as string) ?? 'Password: ',
        port: config.ports[0] ?? 23,
        logFile: (c['logFile'] as string) ?? '/var/log/telnetd.log',
        credentialLog: (c['credentialLog'] as string) ?? '/var/log/captured_creds.log',
        maxAttempts: (c['maxAttempts'] as number) ?? 3,
    };
}

function getDefaultBanner(hostname: string): string {
    return [
        '',
        `${hostname} telnet server`,
        'Connected to ' + hostname,
        '',
        '**** WARNING: THIS IS AN INSECURE PROTOCOL ****',
        '**** ALL DATA INCLUDING PASSWORDS IS TRANSMITTED IN CLEARTEXT ****',
        '**** PLEASE USE SSH INSTEAD FOR SECURE ACCESS ****',
        '',
    ].join('\r\n');
}

function getDefaultMotd(hostname: string): string {
    return [
        '',
        `Welcome to ${hostname}!`,
        '',
        '*** This system is for authorized use only ***',
        '',
        `Last login: ${new Date().toUTCString()}`,
        '',
    ].join('\r\n');
}

// ── Telnet Protocol Constants ──────────────────────────────────

const TELNET_COMMANDS: Record<number, string> = {
    255: 'IAC',  // Interpret As Command
    254: 'DONT',
    253: 'DO',
    252: 'WONT',
    251: 'WILL',
    250: 'SB',   // Subnegotiation Begin
    249: 'GA',   // Go Ahead
    248: 'EL',   // Erase Line
    247: 'EC',   // Erase Character
    246: 'AYT',  // Are You There
    245: 'AO',   // Abort Output
    244: 'IP',   // Interrupt Process
    243: 'BREAK',
    242: 'DM',   // Data Mark
    241: 'NOP',
    240: 'SE',   // Subnegotiation End
};

const TELNET_OPTIONS: Record<number, string> = {
    0: 'TRANSMIT-BINARY',
    1: 'ECHO',
    3: 'SUPPRESS-GO-AHEAD',
    5: 'STATUS',
    6: 'TIMING-MARK',
    24: 'TERMINAL-TYPE',
    31: 'WINDOW-SIZE',
    32: 'TERMINAL-SPEED',
    33: 'REMOTE-FLOW-CONTROL',
    34: 'LINEMODE',
    36: 'ENVIRONMENT',
};

// ── Telnet Service Handler ─────────────────────────────────────

export function createTelnetService(config: ServiceConfig): ServiceHandler {
    let telnetConfig: TelnetConfig;
    const sessions = new Map<string, TelnetSession>();

    function getSession(sourceIP: string): TelnetSession {
        let session = sessions.get(sourceIP);
        if (session === undefined) {
            session = {
                state: 'banner',
                username: '',
                password: '',
                pendingUser: '',
                attemptCount: 0,
                lastCommand: '',
            };
            sessions.set(sourceIP, session);
        }
        return session;
    }

    function writeTelnetLog(ctx: ServiceContext, message: string): void {
        const timestamp = new Date().toISOString();
        const line = `${timestamp} telnetd[${1000 + Math.floor(Math.random() * 9000)}]: ${message}`;
        try {
            const existing = ctx.vfs.readFile(telnetConfig.logFile);
            ctx.vfs.writeFile(telnetConfig.logFile, existing + '\n' + line);
        } catch {
            ctx.vfs.writeFile(telnetConfig.logFile, line);
        }
    }

    function captureCredentials(ctx: ServiceContext, sourceIP: string, username: string, password: string): void {
        if (!telnetConfig.captureCredentials) return;

        const timestamp = new Date().toISOString();
        const entry = `[${timestamp}] CAPTURED: source=${sourceIP} username="${username}" password="${password}" protocol=telnet`;
        try {
            const existing = ctx.vfs.readFile(telnetConfig.credentialLog);
            ctx.vfs.writeFile(telnetConfig.credentialLog, existing + '\n' + entry);
        } catch {
            ctx.vfs.writeFile(telnetConfig.credentialLog, entry);
        }
    }

    function telnetResponse(data: string, close = false): ServiceResponse {
        return {
            payload: new TextEncoder().encode(data.endsWith('\r\n') ? data : data + '\r\n'),
            close,
        };
    }

    function processCommand(ctx: ServiceContext, session: TelnetSession, cmd: string, sourceIP: string): string {
        const trimmed = cmd.trim().toLowerCase();
        const parts = trimmed.split(' ');
        const command = parts[0] ?? '';
        const args = parts.slice(1);

        session.lastCommand = cmd;

        switch (command) {
            case '':
                return '';

            case 'help':
            case '?':
                return [
                    'Available commands:',
                    '  help, ?     - Show this help',
                    '  whoami      - Show current user',
                    '  hostname    - Show system hostname',
                    '  date        - Show current date/time',
                    '  uptime      - Show system uptime',
                    '  ls          - List files',
                    '  cat <file>  - Display file contents',
                    '  pwd         - Print working directory',
                    '  id          - Show user identity',
                    '  uname       - Show system information',
                    '  clear       - Clear screen',
                    '  logout      - End session',
                    '  exit        - End session',
                    '',
                ].join('\r\n');

            case 'whoami':
                return session.username;

            case 'hostname':
                return ctx.hostname;

            case 'date':
                return new Date().toUTCString();

            case 'uptime':
                const days = Math.floor(Math.random() * 30) + 1;
                const hours = Math.floor(Math.random() * 24);
                const mins = Math.floor(Math.random() * 60);
                return `up ${days} days, ${hours}:${mins.toString().padStart(2, '0')}`;

            case 'pwd':
                return session.username === 'root' ? '/root' : `/home/${session.username}`;

            case 'id':
                const uid = session.username === 'root' ? '0' : String(1000 + Math.floor(Math.random() * 1000));
                const gid = session.username === 'root' ? '0' : '1000';
                return `uid=${uid}(${session.username}) gid=${gid} groups=${gid}(${session.username})`;

            case 'uname':
                if (args.includes('-a')) {
                    return `Linux ${ctx.hostname} 5.15.0-generic #1 SMP x86_64 GNU/Linux`;
                }
                return 'Linux';

            case 'clear':
                return '\x1b[2J\x1b[H';  // ANSI clear screen + home cursor

            case 'logout':
            case 'exit':
                sessions.delete(sourceIP);
                return 'logout\r\nConnection closed by foreign host.';

            case 'ls': {
                const path = args[0] ?? (session.username === 'root' ? '/root' : `/home/${session.username}`);
                try {
                    const entries = ctx.vfs.readDir(path);
                    if (entries === null) return `ls: cannot access '${path}': No such file or directory`;
                    return entries.join('  ');
                } catch {
                    return `ls: cannot access '${path}': Permission denied`;
                }
            }

            case 'cat': {
                if (args.length === 0) return 'cat: missing file operand';
                const filePath = args[0] ?? '';
                if (filePath === '') return 'cat: missing file operand';
                try {
                    // Resolve relative paths
                    const fullPath = filePath.startsWith('/') ? filePath :
                        (session.username === 'root' ? '/root/' : `/home/${session.username}/`) + filePath;
                    const content = ctx.vfs.readFile(fullPath);
                    if (content === null) return `cat: ${filePath}: No such file or directory`;

                    ctx.emit({
                        type: 'file:access',
                        path: fullPath,
                        action: 'read',
                        user: session.username,
                    });

                    return content;
                } catch {
                    return `cat: ${filePath}: Permission denied`;
                }
            }

            default:
                return `${command}: command not found`;
        }
    }

    return {
        name: 'telnet',
        port: 23,
        protocol: 'tcp',

        start(ctx: ServiceContext): void {
            telnetConfig = resolveTelnetConfig(config, ctx.hostname);

            ctx.emit({
                type: 'service:custom',
                service: 'telnet',
                action: 'started',
                details: {
                    port: telnetConfig.port,
                    captureCredentials: telnetConfig.captureCredentials,
                },
            });
        },

        handle(request: ServiceRequest, ctx: ServiceContext): ServiceResponse | null {
            // Delay config resolution if not done in start
            if (telnetConfig === undefined) {
                telnetConfig = resolveTelnetConfig(config, ctx.hostname);
            }

            const text = request.payloadText;
            const session = getSession(request.sourceIP);

            // Process Telnet commands (IAC sequences)
            if (text.includes('\xff')) {
                const processed = processTelnetCommands(text);
                if (processed.command !== '') {
                    writeTelnetLog(ctx, `telnet command from ${request.sourceIP}: ${processed.command}`);
                }
                // Continue with regular text after IAC processing
                if (processed.text === '') {
                    return {
                        payload: new Uint8Array(0),
                        close: false,
                    };
                }
            }

            // Clean the input (remove Telnet sequences and normalize)
            const cleanInput = text.replace(/\xff[\xfb-\xfe][\x00-\xff]/g, '')  // IAC WILL/WONT/DO/DONT
                .replace(/\xff\xfa[\s\S]*?\xff\xf0/g, '')  // IAC SB ... SE
                .replace(/\r\n/g, '\n')
                .replace(/\r/g, '\n')
                .trim();

            // Handle initial connection
            if (session.state === 'banner') {
                session.state = 'username';
                writeTelnetLog(ctx, `connection from ${request.sourceIP}`);
                return telnetResponse(telnetConfig.banner + '\r\n' + telnetConfig.loginPrompt, false);
            }

            switch (session.state) {
                case 'username': {
                    if (cleanInput === '') {
                        return telnetResponse(telnetConfig.loginPrompt, false);
                    }

                    session.pendingUser = cleanInput;
                    session.state = 'password';

                    // Capture the attempted username
                    writeTelnetLog(ctx, `login attempt from ${request.sourceIP}: username="${cleanInput}"`);

                    return {
                        payload: new TextEncoder().encode(telnetConfig.passwordPrompt),
                        close: false,
                    };
                }

                case 'password': {
                    const password = cleanInput;
                    const username = session.pendingUser;

                    // Check if root login is allowed
                    if (username === 'root' && !telnetConfig.allowRoot) {
                        writeTelnetLog(ctx, `root login denied from ${request.sourceIP}`);
                        session.state = 'username';
                        session.attemptCount++;
                        captureCredentials(ctx, request.sourceIP, username, password);

                        if (session.attemptCount >= telnetConfig.maxAttempts) {
                            sessions.delete(request.sourceIP);
                            return telnetResponse('Login failed\r\nToo many failed attempts.\r\nConnection closed.', true);
                        }

                        return telnetResponse('Login incorrect\r\n\r\n' + telnetConfig.loginPrompt, false);
                    }

                    // Validate credentials
                    const valid = validateCredentials(ctx, username, password);

                    // Always capture credentials for forensics
                    captureCredentials(ctx, request.sourceIP, username, password);

                    if (valid) {
                        session.username = username;
                        session.password = password;
                        session.state = 'authenticated';
                        session.attemptCount = 0;

                        writeTelnetLog(ctx, `successful login: username="${username}" from ${request.sourceIP}`);
                        ctx.emit({
                            type: 'service:custom',
                            service: 'telnet',
                            action: 'login',
                            details: { username, sourceIP: request.sourceIP, success: true },
                        });

                        const welcome = telnetConfig.motd + '\r\n' + `${username}@${ctx.hostname}:~$ `;
                        return telnetResponse(welcome, false);
                    }

                    session.state = 'username';
                    session.attemptCount++;

                    writeTelnetLog(ctx, `failed login: username="${username}" from ${request.sourceIP}`);
                    ctx.emit({
                        type: 'service:custom',
                        service: 'telnet',
                        action: 'login',
                        details: { username, sourceIP: request.sourceIP, success: false },
                    });

                    if (session.attemptCount >= telnetConfig.maxAttempts) {
                        sessions.delete(request.sourceIP);
                        return telnetResponse('Login incorrect\r\nToo many failed attempts.\r\nConnection closed.', true);
                    }

                    return telnetResponse('Login incorrect\r\n\r\n' + telnetConfig.loginPrompt, false);
                }

                case 'authenticated': {
                    if (cleanInput === '') {
                        return telnetResponse(`${session.username}@${ctx.hostname}:~$ `, false);
                    }

                    writeTelnetLog(ctx, `command from ${request.sourceIP} [${session.username}]: ${cleanInput}`);
                    ctx.emit({
                        type: 'service:custom',
                        service: 'telnet',
                        action: 'command',
                        details: { username: session.username, command: cleanInput, sourceIP: request.sourceIP },
                    });

                    const result = processCommand(ctx, session, cleanInput, request.sourceIP);

                    // Check if session was terminated
                    if (!sessions.has(request.sourceIP)) {
                        return telnetResponse(result, true);
                    }

                    return telnetResponse(result + '\r\n' + `${session.username}@${ctx.hostname}:~$ `, false);
                }

                default:
                    return telnetResponse('Error: Invalid session state', true);
            }
        },

        stop(): void {
            sessions.clear();
        },
    };
}

function processTelnetCommands(text: string): { command: string; text: string } {
    let command = '';
    let cleaned = '';

    for (let i = 0; i < text.length; i++) {
        if (text.charCodeAt(i) === 255) {  // IAC
            const cmd = text.charCodeAt(i + 1);
            const opt = text.charCodeAt(i + 2);

            if (cmd !== undefined && opt !== undefined) {
                const cmdName = TELNET_COMMANDS[cmd] ?? `CMD(${cmd})`;
                const optName = TELNET_OPTIONS[opt] ?? `OPT(${opt})`;
                command += `${cmdName} ${optName}; `;
                i += 2;
            }
        } else {
            cleaned += text[i];
        }
    }

    return { command: command.trim(), text: cleaned };
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

export type { TelnetConfig, TelnetSession };
