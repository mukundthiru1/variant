/**
 * VARIANT — Realistic Log Generator
 *
 * Generates log files that look like they span hours/days
 * of real system operation. Includes both signal (attack
 * indicators, errors) and noise (normal operations).
 *
 * Level designers configure:
 *   - Signal events: specific log entries that hint at
 *     the vulnerability or attack in progress
 *   - Noise templates: categories of normal log traffic
 *   - Time range: how far back logs should span
 *   - Volume: how many noise entries per hour
 *   - Usernames, IPs, services that appear in logs
 *
 * DESIGN: Pure functions. Input → VFS overlay. No side effects.
 * Every aspect is configurable. Nothing is hardcoded except
 * log formats (which match real Linux conventions).
 */

import type { VFSOverlay, VFSOverlayEntry } from '../vfs/types';

// ── Types ──────────────────────────────────────────────────────

export interface LogGeneratorConfig {
    /** Hostname for log entries. */
    readonly hostname: string;
    /**
     * Simulation "now" timestamp (Unix ms).
     * Logs are generated relative to this.
     * Default: Date.now()
     */
    readonly nowMs?: number;
    /** Log definitions. Each generates a separate log file. */
    readonly logs: readonly LogDefinition[];
}

export interface LogDefinition {
    /** Output file path (e.g., '/var/log/auth.log'). */
    readonly path: string;
    /** Log format. */
    readonly format: LogFormat;
    /** How many hours of logs to generate. Default: 72. */
    readonly hoursBack?: number;
    /** Average noise entries per hour. Default: 20. */
    readonly noisePerHour?: number;
    /** Signal events — the important log entries. */
    readonly signals: readonly LogSignal[];
    /** Noise templates — normal background traffic. */
    readonly noiseTemplates: readonly NoiseTemplate[];
}

export type LogFormat = 'syslog' | 'auth' | 'apache-access' | 'apache-error' | 'nginx-access' | 'nginx-error' | 'json' | 'raw';

/**
 * A signal event — a specific log entry placed at a specific time.
 * These are the entries the player needs to find or that hint at vulns.
 */
export interface LogSignal {
    /**
     * When this entry appears, in hours before "now".
     * 0 = now, 1 = 1 hour ago, 24 = yesterday.
     */
    readonly hoursAgo: number;
    /** The log message content. */
    readonly message: string;
    /** Severity (for syslog format). */
    readonly severity?: LogSeverity | undefined;
    /** Service/process name. */
    readonly service?: string | undefined;
    /** PID. */
    readonly pid?: number | undefined;
    /** Source IP (for access logs). */
    readonly sourceIP?: string | undefined;
    /** HTTP method (for access logs). */
    readonly method?: string | undefined;
    /** HTTP path (for access logs). */
    readonly httpPath?: string | undefined;
    /** HTTP status code (for access logs). */
    readonly statusCode?: number | undefined;
    /** Response size (for access logs). */
    readonly responseSize?: number | undefined;
    /** User agent (for access logs). */
    readonly userAgent?: string | undefined;
}

export type LogSeverity = 'emerg' | 'alert' | 'crit' | 'err' | 'warning' | 'notice' | 'info' | 'debug';

/**
 * A noise template — generates random but realistic log entries.
 * Level designers provide these to control what "normal" looks like.
 */
export interface NoiseTemplate {
    /** Weight (higher = more frequent). Default: 1. */
    readonly weight?: number;
    /** Template string with placeholders. */
    readonly template: string;
    /** Severity (for syslog). */
    readonly severity?: LogSeverity;
    /** Service name. */
    readonly service?: string;
    /** Variable pools for placeholder substitution. */
    readonly variables?: ReadonlyMap<string, readonly string[]>;
}

// ── Generator ──────────────────────────────────────────────────

export function generateLogs(config: LogGeneratorConfig): VFSOverlay {
    const files = new Map<string, VFSOverlayEntry>();
    const nowMs = config.nowMs ?? Date.now();

    for (const logDef of config.logs) {
        const content = generateLogFile(logDef, config.hostname, nowMs);
        files.set(logDef.path, { content, mode: 0o644 });
    }

    return { files };
}

function generateLogFile(
    logDef: LogDefinition,
    hostname: string,
    nowMs: number,
): string {
    const hoursBack = logDef.hoursBack ?? 72;
    const noisePerHour = logDef.noisePerHour ?? 20;

    // Build a timeline of entries: signals at their configured times,
    // noise distributed randomly throughout
    const entries: Array<{ timestamp: number; line: string }> = [];

    // Add signal entries at specific times
    for (const signal of logDef.signals) {
        const timestamp = nowMs - (signal.hoursAgo * 3600000);
        const line = formatLogEntry(logDef.format, hostname, timestamp, signal);
        entries.push({ timestamp, line });
    }

    // Generate noise entries distributed across the time range
    const startMs = nowMs - (hoursBack * 3600000);
    const totalNoise = noisePerHour * hoursBack;
    const rng = createSeededRNG(hostname + logDef.path);

    const totalWeight = logDef.noiseTemplates.reduce(
        (sum, t) => sum + (t.weight ?? 1), 0,
    );

    for (let i = 0; i < totalNoise; i++) {
        // Random time within range
        const timestamp = startMs + Math.floor(rng() * (nowMs - startMs));

        // Pick a template weighted by weight
        const template = pickWeighted(logDef.noiseTemplates, rng, totalWeight);
        if (template === null) continue;

        const message = expandTemplate(template, rng);

        const noiseSignal: LogSignal = {
            hoursAgo: 0, // unused, timestamp is absolute
            message,
            severity: template.severity ?? 'info',
            service: template.service,
        };

        const line = formatLogEntry(logDef.format, hostname, timestamp, noiseSignal);
        entries.push({ timestamp, line });
    }

    // Sort by timestamp
    entries.sort((a, b) => a.timestamp - b.timestamp);

    return entries.map(e => e.line).join('\n') + '\n';
}

// ── Formatters ─────────────────────────────────────────────────

function formatLogEntry(
    format: LogFormat,
    hostname: string,
    timestamp: number,
    signal: LogSignal,
): string {
    const date = new Date(timestamp);

    switch (format) {
        case 'syslog':
        case 'auth': {
            const ts = formatSyslogTimestamp(date);
            const svc = signal.service ?? 'kernel';
            const pid = signal.pid !== undefined ? `[${signal.pid}]` : '';
            return `${ts} ${hostname} ${svc}${pid}: ${signal.message}`;
        }

        case 'apache-access':
        case 'nginx-access': {
            const ip = signal.sourceIP ?? '127.0.0.1';
            const ts = formatApacheTimestamp(date);
            const method = signal.method ?? 'GET';
            const path = signal.httpPath ?? '/';
            const status = signal.statusCode ?? 200;
            const size = signal.responseSize ?? 0;
            const ua = signal.userAgent ?? 'Mozilla/5.0';
            return `${ip} - - [${ts}] "${method} ${path} HTTP/1.1" ${status} ${size} "-" "${ua}"`;
        }

        case 'apache-error': {
            const ts = formatApacheErrorTimestamp(date);
            const sev = signal.severity ?? 'error';
            return `[${ts}] [${sev}] [pid ${signal.pid ?? 1}] ${signal.message}`;
        }

        case 'nginx-error': {
            const ts = formatNginxErrorTimestamp(date);
            return `${ts} [${signal.severity ?? 'error'}] ${signal.pid ?? 1}#0: ${signal.message}`;
        }

        case 'json': {
            return JSON.stringify({
                timestamp: date.toISOString(),
                hostname,
                service: signal.service,
                severity: signal.severity ?? 'info',
                message: signal.message,
            });
        }

        case 'raw':
        default:
            return signal.message;
    }
}

function formatSyslogTimestamp(date: Date): string {
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
        'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const month = months[date.getMonth()]!;
    const day = String(date.getDate()).padStart(2, ' ');
    const h = String(date.getHours()).padStart(2, '0');
    const m = String(date.getMinutes()).padStart(2, '0');
    const s = String(date.getSeconds()).padStart(2, '0');
    return `${month} ${day} ${h}:${m}:${s}`;
}

function formatApacheTimestamp(date: Date): string {
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
        'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const d = String(date.getDate()).padStart(2, '0');
    const mon = months[date.getMonth()]!;
    const y = date.getFullYear();
    const h = String(date.getHours()).padStart(2, '0');
    const m = String(date.getMinutes()).padStart(2, '0');
    const s = String(date.getSeconds()).padStart(2, '0');
    return `${d}/${mon}/${y}:${h}:${m}:${s} +0000`;
}

function formatApacheErrorTimestamp(date: Date): string {
    const dow = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
        'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const dayName = dow[date.getDay()]!;
    const mon = months[date.getMonth()]!;
    const d = String(date.getDate()).padStart(2, '0');
    const h = String(date.getHours()).padStart(2, '0');
    const m = String(date.getMinutes()).padStart(2, '0');
    const s = String(date.getSeconds()).padStart(2, '0');
    return `${dayName} ${mon} ${d} ${h}:${m}:${s}.000000 ${date.getFullYear()}`;
}

function formatNginxErrorTimestamp(date: Date): string {
    const y = date.getFullYear();
    const mon = String(date.getMonth() + 1).padStart(2, '0');
    const d = String(date.getDate()).padStart(2, '0');
    const h = String(date.getHours()).padStart(2, '0');
    const m = String(date.getMinutes()).padStart(2, '0');
    const s = String(date.getSeconds()).padStart(2, '0');
    return `${y}/${mon}/${d} ${h}:${m}:${s}`;
}

// ── Template expansion ─────────────────────────────────────────

function expandTemplate(
    template: NoiseTemplate,
    rng: () => number,
): string {
    let message = template.template;

    if (template.variables !== undefined) {
        for (const [name, pool] of template.variables) {
            const placeholder = `{{${name}}}`;
            while (message.includes(placeholder)) {
                const value = pool[Math.floor(rng() * pool.length)]!;
                message = message.replace(placeholder, value);
            }
        }
    }

    return message;
}

// ── Seeded RNG ─────────────────────────────────────────────────

/**
 * Simple seeded PRNG for deterministic log generation.
 * Same seed = same logs every time. Makes tests deterministic.
 */
function createSeededRNG(seed: string): () => number {
    let state = 0;
    for (let i = 0; i < seed.length; i++) {
        state = ((state << 5) - state + seed.charCodeAt(i)) | 0;
    }
    // Ensure positive
    state = Math.abs(state) || 1;

    return () => {
        state = ((state * 1103515245 + 12345) | 0) >>> 0;
        return state / 0x100000000;
    };
}

function pickWeighted<T extends { readonly weight?: number }>(
    items: readonly T[],
    rng: () => number,
    totalWeight: number,
): T | null {
    if (items.length === 0) return null;

    let pick = rng() * totalWeight;
    for (const item of items) {
        pick -= (item.weight ?? 1);
        if (pick <= 0) return item;
    }
    return items[items.length - 1]!;
}

// ── Pre-built noise template libraries ─────────────────────────

/**
 * Pre-built noise templates for common log types.
 * Level designers can use these directly or override with custom ones.
 * These are just starting points — everything is configurable.
 */
export const NOISE_LIBRARIES = {

    authLog: [
        {
            template: 'pam_unix(sshd:session): session opened for user {{user}} by (uid=0)',
            service: 'sshd',
            severity: 'info' as LogSeverity,
            weight: 3,
            variables: new Map([['user', ['root', 'admin', 'deploy', 'www-data']]]),
        },
        {
            template: 'pam_unix(sshd:session): session closed for user {{user}}',
            service: 'sshd',
            severity: 'info' as LogSeverity,
            weight: 3,
            variables: new Map([['user', ['root', 'admin', 'deploy', 'www-data']]]),
        },
        {
            template: 'Failed password for {{user}} from {{ip}} port {{port}} ssh2',
            service: 'sshd',
            severity: 'info' as LogSeverity,
            weight: 1,
            variables: new Map([
                ['user', ['root', 'admin', 'test', 'guest']],
                ['ip', ['10.0.0.50', '192.168.1.100', '172.16.0.5']],
                ['port', ['22345', '33456', '44567', '55678']],
            ]),
        },
        {
            template: 'Accepted publickey for {{user}} from {{ip}} port {{port}} ssh2: RSA SHA256:{{hash}}',
            service: 'sshd',
            severity: 'info' as LogSeverity,
            weight: 2,
            variables: new Map([
                ['user', ['deploy', 'admin']],
                ['ip', ['10.0.0.1', '10.0.0.5']],
                ['port', ['12345', '23456']],
                ['hash', ['abc123def456', 'xyz789ghi012']],
            ]),
        },
        {
            template: 'CRON[{{pid}}]: pam_unix(cron:session): session opened for user {{user}} by (uid=0)',
            service: 'CRON',
            severity: 'info' as LogSeverity,
            weight: 4,
            variables: new Map([
                ['pid', ['1234', '2345', '3456', '4567']],
                ['user', ['root', 'www-data']],
            ]),
        },
    ] as readonly NoiseTemplate[],

    syslog: [
        {
            template: '-- MARK --',
            service: 'syslogd',
            severity: 'info' as LogSeverity,
            weight: 5,
        },
        {
            template: 'Started {{service}}',
            service: 'systemd',
            severity: 'info' as LogSeverity,
            weight: 1,
            variables: new Map([
                ['service', ['Daily apt download activities', 'Cleanup of Temporary Directories', 'Daily rotation of log files']],
            ]),
        },
        {
            template: 'logrotate: rotating {{log}}',
            service: 'logrotate',
            severity: 'info' as LogSeverity,
            weight: 1,
            variables: new Map([
                ['log', ['/var/log/syslog', '/var/log/auth.log', '/var/log/daemon.log']],
            ]),
        },
    ] as readonly NoiseTemplate[],

    apacheAccess: [
        {
            template: '',
            service: 'apache',
            weight: 5,
            variables: new Map([
                ['ip', ['10.0.0.50', '10.0.0.51', '192.168.1.100', '172.16.0.10']],
                ['path', ['/', '/index.html', '/about', '/css/style.css', '/js/app.js', '/images/logo.png', '/api/health', '/favicon.ico']],
                ['ua', [
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
                    'Googlebot/2.1 (+http://www.google.com/bot.html)',
                    'curl/7.88.1',
                ]],
            ]),
        },
    ] as readonly NoiseTemplate[],
} as const;
