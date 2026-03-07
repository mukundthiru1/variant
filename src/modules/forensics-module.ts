import type { EngineEvent, EventBus, Unsubscribe } from '../core/events';
import type { Capability, Module, SimulationContext } from '../core/modules';
import type { VirtualFilesystem, VFSFile } from '../lib/vfs/types';

const MODULE_ID = 'forensics';
const MODULE_VERSION = '1.0.0';

export interface TimelineEntry {
    readonly tick: number;
    readonly timestamp: number;
    readonly source: string;
    readonly action: string;
    readonly actor: string;
    readonly target: string;
    readonly detail: string;
    readonly severity: 'low' | 'medium' | 'high' | 'critical';
    readonly eventType: EngineEvent['type'];
}

export interface TimelineFilter {
    readonly machine?: string;
    readonly actor?: string;
    readonly severity?: TimelineEntry['severity'];
    readonly eventType?: EngineEvent['type'];
    readonly startTime?: number;
    readonly endTime?: number;
}

export interface AuthLogEntry {
    readonly timestamp: number;
    readonly machine: string;
    readonly service: string;
    readonly pid: number | null;
    readonly action: 'login' | 'sudo' | 'su' | 'other';
    readonly user: string | null;
    readonly sourceIP: string | null;
    readonly success: boolean | null;
    readonly targetUser: string | null;
    readonly command: string | null;
    readonly message: string;
    readonly raw: string;
}

export interface SyslogEntry {
    readonly timestamp: number;
    readonly machine: string;
    readonly service: string;
    readonly pid: number | null;
    readonly severity: string | null;
    readonly message: string;
    readonly raw: string;
}

export interface ApacheLogEntry {
    readonly timestamp: number;
    readonly sourceIP: string;
    readonly user: string | null;
    readonly method: string;
    readonly url: string;
    readonly protocol: string;
    readonly statusCode: number;
    readonly responseSize: number;
    readonly referrer: string;
    readonly userAgent: string;
    readonly raw: string;
}

export interface NginxLogEntry {
    readonly timestamp: number;
    readonly sourceIP: string;
    readonly user: string | null;
    readonly method: string;
    readonly url: string;
    readonly protocol: string;
    readonly statusCode: number;
    readonly responseSize: number;
    readonly referrer: string;
    readonly userAgent: string;
    readonly raw: string;
}

export interface BruteForceIndicator {
    readonly sourceIP: string;
    readonly machine: string;
    readonly failures: number;
    readonly users: readonly string[];
    readonly windowStart: number;
    readonly windowEnd: number;
    readonly severity: 'high' | 'critical';
}

export interface PrivescIndicator {
    readonly timestamp: number;
    readonly machine: string;
    readonly user: string;
    readonly method: 'sudo' | 'su';
    readonly targetUser: string;
    readonly command: string | null;
    readonly severity: 'high';
}

export interface LateralIndicator {
    readonly sourceIP: string;
    readonly firstSeen: number;
    readonly lastSeen: number;
    readonly machines: readonly string[];
    readonly accounts: readonly string[];
    readonly severity: 'high' | 'critical';
}

export interface ExfilIndicator {
    readonly timestamp: number;
    readonly sourceIP: string;
    readonly url: string;
    readonly responseSize: number;
    readonly reason: string;
    readonly severity: 'high' | 'critical';
}

export interface WebAttackIndicator {
    readonly timestamp: number;
    readonly sourceIP: string;
    readonly url: string;
    readonly attackType: 'sqli' | 'path-traversal' | 'xss';
    readonly pattern: string;
    readonly severity: 'high';
}

export interface EvidenceFile {
    readonly path: string;
    readonly category: 'log' | 'history' | 'temp' | 'crontab' | 'authorized-keys' | 'process' | 'other';
    readonly content: string;
    readonly size: number;
    readonly mtime: number;
    readonly mode: number;
    readonly owner: string;
    readonly group: string;
    readonly sha256: string;
}

export interface EvidenceBundle {
    readonly machine: string;
    readonly collectedAt: number;
    readonly fileCount: number;
    readonly totalBytes: number;
    readonly files: readonly EvidenceFile[];
    readonly hashes: Readonly<Record<string, string>>;
}

export type IncidentType =
    | 'brute-force'
    | 'privilege-escalation'
    | 'lateral-movement'
    | 'data-exfiltration'
    | 'web-attack'
    | 'multi-stage'
    | 'unknown';

export interface IncidentReport {
    readonly generatedAt: number;
    readonly incidentType: IncidentType;
    readonly executiveSummary: string;
    readonly timeline: readonly TimelineEntry[];
    readonly indicatorsOfCompromise: readonly string[];
    readonly affectedSystems: readonly string[];
    readonly recommendations: readonly string[];
}

const SYSLOG_LINE = /^([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\s:]+?)(?:\[(\d+)\])?:\s(.*)$/;
const APACHE_COMBINED = /^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s"]+)\s+([^"]+)"\s+(\d{3})\s+(\d+|-)\s+"([^"]*)"\s+"([^"]*)"$/;

function parseSyslogLikeTimestamp(value: string): number {
    const now = new Date();
    const year = now.getUTCFullYear();
    const parsed = new Date(`${value} ${year} UTC`);
    const ts = parsed.getTime();
    return Number.isFinite(ts) ? ts : Date.now();
}

function parseApacheTimestamp(value: string): number {
    // Example: 10/Oct/2000:13:55:36 -0700
    const match = /^(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s([+-]\d{4})$/.exec(value);
    if (match === null) return Date.now();

    const day = Number(match[1]);
    const monthStr = match[2]!;
    const year = Number(match[3]);
    const hour = Number(match[4]);
    const minute = Number(match[5]);
    const second = Number(match[6]);
    const offset = match[7]!;

    const months: Record<string, number> = {
        Jan: 0,
        Feb: 1,
        Mar: 2,
        Apr: 3,
        May: 4,
        Jun: 5,
        Jul: 6,
        Aug: 7,
        Sep: 8,
        Oct: 9,
        Nov: 10,
        Dec: 11,
    };

    const month = months[monthStr];
    if (month === undefined || !Number.isFinite(day) || !Number.isFinite(year)) {
        return Date.now();
    }

    const sign = offset.startsWith('-') ? -1 : 1;
    const offHours = Number(offset.slice(1, 3));
    const offMinutes = Number(offset.slice(3, 5));
    const totalOffsetMinutes = sign * ((offHours * 60) + offMinutes);

    const utc = Date.UTC(year, month, day, hour, minute, second);
    return utc - (totalOffsetMinutes * 60_000);
}

function eventTick(event: EngineEvent): number {
    if ('tick' in event && typeof event.tick === 'number') {
        return event.tick;
    }
    return Math.floor(event.timestamp / 1000);
}

function eventActor(event: EngineEvent): string {
    switch (event.type) {
        case 'auth:login': return event.user;
        case 'auth:escalate': return event.from;
        case 'auth:credential-found': return event.credentialId;
        case 'credential:registered': return event.credentialId;
        case 'credential:validated': return event.target.user;
        case 'credential:chain-extended': return event.parentId;
        case 'net:connect':
        case 'net:request':
        case 'net:response':
        case 'net:dns': return event.source;
        case 'fs:read':
        case 'fs:write':
        case 'fs:exec': return event.user;
        case 'defense:breach': return event.attacker;
        case 'defense:alert': return event.ruleId;
        case 'objective:progress':
        case 'objective:complete': return event.objectiveId;
        case 'sim:alert':
        case 'sim:noise': return event.source;
        case 'sim:tick': return `tick-${event.tick}`;
        case 'sim:gameover': return 'simulation';
        case 'lens:open':
        case 'lens:close': return event.lensType;
        case 'custom:forensics-timeline-result':
        case 'custom:forensics-report-result':
        case 'custom:forensics-anomalies-result': return 'forensics';
        default: return 'unknown';
    }
}

function eventTarget(event: EngineEvent): string {
    switch (event.type) {
        case 'auth:login': return event.machine;
        case 'auth:escalate': return `${event.machine}:${event.to}`;
        case 'auth:credential-found': return event.location;
        case 'credential:registered': return event.source.machine;
        case 'credential:validated': return `${event.target.machine}:${event.target.service}`;
        case 'credential:chain-extended': return event.childId;
        case 'net:request': return `${event.destination}${event.url}`;
        case 'net:connect': return `${event.host}:${event.port}`;
        case 'net:response': return event.url;
        case 'net:dns': return event.query;
        case 'fs:read':
        case 'fs:write':
        case 'fs:exec': return event.path;
        case 'defense:breach':
        case 'defense:alert': return event.machine;
        case 'objective:progress':
        case 'objective:complete': return event.objectiveId;
        case 'sim:alert': return event.message;
        case 'sim:noise': return event.machine;
        case 'sim:tick': return `tick-${event.tick}`;
        case 'sim:gameover': return event.reason;
        case 'lens:open': return event.target;
        case 'lens:close': return event.lensType;
        default: return 'n/a';
    }
}

function eventSource(event: EngineEvent): string {
    switch (event.type) {
        case 'auth:login':
        case 'auth:escalate':
        case 'auth:credential-found':
        case 'defense:breach':
        case 'defense:alert':
        case 'fs:read':
        case 'fs:write':
        case 'fs:exec':
            return event.machine;
        case 'net:request':
        case 'net:response':
        case 'net:dns':
        case 'net:connect':
        case 'sim:noise':
        case 'sim:alert':
            return event.source;
        case 'credential:registered': return event.source.machine;
        case 'credential:validated': return event.target.machine;
        case 'credential:chain-extended': return event.parentId;
        case 'objective:progress':
        case 'objective:complete':
            return 'objectives';
        case 'sim:tick':
        case 'sim:gameover':
            return 'simulation';
        case 'lens:open':
        case 'lens:close':
            return 'lens';
        default:
            return 'custom';
    }
}

function eventAction(event: EngineEvent): string {
    switch (event.type) {
        case 'auth:login': return event.success ? 'login-success' : 'login-failure';
        case 'auth:escalate': return `privilege-escalation:${event.method}`;
        case 'auth:credential-found': return 'credential-found';
        case 'credential:registered': return `credential-registered:${event.credentialType}`;
        case 'credential:validated': return `credential-validated:${event.credentialType}`;
        case 'credential:chain-extended': return `credential-chain:${event.mechanism}`;
        case 'net:request': return `${event.method} ${event.url}`;
        case 'net:response': return `http-response:${event.status}`;
        case 'net:dns': return `dns:${event.query}`;
        case 'net:connect': return `connect:${event.protocol}/${event.port}`;
        case 'fs:read': return 'file-read';
        case 'fs:write': return 'file-write';
        case 'fs:exec': return 'process-exec';
        case 'defense:breach': return `breach:${event.vector}`;
        case 'defense:alert': return `alert:${event.ruleId}`;
        case 'objective:progress': return 'objective-progress';
        case 'objective:complete': return 'objective-complete';
        case 'sim:tick': return 'tick';
        case 'sim:alert': return 'sim-alert';
        case 'sim:noise': return 'sim-noise';
        case 'sim:gameover': return 'gameover';
        case 'lens:open': return `lens-open:${event.lensType}`;
        case 'lens:close': return `lens-close:${event.lensType}`;
        default: return event.type;
    }
}

function eventDetail(event: EngineEvent): string {
    switch (event.type) {
        case 'auth:login':
            return `${event.service} login ${event.success ? 'accepted' : 'rejected'} for ${event.user}`;
        case 'auth:escalate':
            return `${event.from} escalated to ${event.to} via ${event.method}`;
        case 'auth:credential-found':
            return `Credential ${event.credentialId} found at ${event.location}`;
        case 'net:request':
            return `${event.source} -> ${event.destination} ${event.method} ${event.url}`;
        case 'net:connect':
            return `${event.source} connected to ${event.host}:${event.port} (${event.protocol})`;
        case 'fs:exec':
            return `${event.user} executed ${event.path} ${event.args.join(' ')}`.trim();
        case 'defense:breach':
            return `${event.attacker} breached ${event.machine} via ${event.vector}`;
        case 'defense:alert':
            return event.detail;
        case 'credential:validated':
            return `${event.credentialId} validated on ${event.target.machine}`;
        case 'sim:alert':
            return `${event.source}: ${event.message}`;
        case 'sim:gameover':
            return event.reason;
        case 'custom:forensics-timeline-result':
            return 'forensics timeline generated';
        case 'custom:forensics-report-result':
            return 'forensics report generated';
        case 'custom:forensics-anomalies-result':
            return 'forensics anomaly analysis generated';
        default:
            return event.type;
    }
}

function eventSeverity(event: EngineEvent): TimelineEntry['severity'] {
    switch (event.type) {
        case 'defense:breach': return 'critical';
        case 'defense:alert':
            if (event.severity === 'critical') return 'critical';
            if (event.severity === 'high') return 'high';
            if (event.severity === 'medium') return 'medium';
            return 'low';
        case 'auth:escalate': return 'high';
        case 'auth:login': return event.success ? 'low' : 'medium';
        case 'fs:write':
        case 'fs:exec': return 'medium';
        default: return 'low';
    }
}

function isPrivateIP(ip: string): boolean {
    return ip.startsWith('10.') || ip.startsWith('192.168.') || /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
}

function decodeURL(url: string): string {
    try {
        return decodeURIComponent(url);
    } catch {
        return url;
    }
}

function classifyEvidencePath(path: string): EvidenceFile['category'] {
    if (path.startsWith('/var/log/')) return 'log';
    if (path.endsWith('.bash_history')) return 'history';
    if (path.startsWith('/tmp/')) return 'temp';
    if (path.includes('/cron')) return 'crontab';
    if (path.endsWith('/authorized_keys')) return 'authorized-keys';
    if (path.startsWith('/proc/')) return 'process';
    return 'other';
}

function toFileNode(node: ReturnType<VirtualFilesystem['stat']>): VFSFile | null {
    if (node === null || node.type !== 'file') return null;
    return node;
}

function toHex32(value: number): string {
    return value.toString(16).padStart(8, '0');
}

// Pure TypeScript SHA-256 implementation for deterministic integrity hashing.
function sha256(content: string): string {
    const encoder = new TextEncoder();
    const msg = encoder.encode(content);
    const bitLen = msg.length * 8;

    const k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    const h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    const withOne = new Uint8Array(msg.length + 1);
    withOne.set(msg);
    withOne[msg.length] = 0x80;

    const paddedLen = Math.ceil((withOne.length + 8) / 64) * 64;
    const padded = new Uint8Array(paddedLen);
    padded.set(withOne);

    const view = new DataView(padded.buffer);
    const high = Math.floor(bitLen / 0x100000000);
    const low = bitLen >>> 0;
    view.setUint32(paddedLen - 8, high, false);
    view.setUint32(paddedLen - 4, low, false);

    const w = new Uint32Array(64);

    const rightRotate = (value: number, amount: number): number => (value >>> amount) | (value << (32 - amount));

    for (let i = 0; i < padded.length; i += 64) {
        for (let t = 0; t < 16; t++) {
            w[t] = view.getUint32(i + (t * 4), false);
        }
        for (let t = 16; t < 64; t++) {
            const s0 = rightRotate(w[t - 15]!, 7) ^ rightRotate(w[t - 15]!, 18) ^ (w[t - 15]! >>> 3);
            const s1 = rightRotate(w[t - 2]!, 17) ^ rightRotate(w[t - 2]!, 19) ^ (w[t - 2]! >>> 10);
            w[t] = (((w[t - 16]! + s0) | 0) + ((w[t - 7]! + s1) | 0)) >>> 0;
        }

        let a = h[0]!;
        let b = h[1]!;
        let c = h[2]!;
        let d = h[3]!;
        let e = h[4]!;
        let f = h[5]!;
        let g = h[6]!;
        let hh = h[7]!;

        for (let t = 0; t < 64; t++) {
            const s1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
            const ch = (e & f) ^ (~e & g);
            const temp1 = (((((hh + s1) | 0) + ((ch + k[t]!) | 0)) | 0) + w[t]!) >>> 0;
            const s0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = (s0 + maj) >>> 0;

            hh = g;
            g = f;
            f = e;
            e = (d + temp1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) >>> 0;
        }

        h[0] = (h[0]! + a) >>> 0;
        h[1] = (h[1]! + b) >>> 0;
        h[2] = (h[2]! + c) >>> 0;
        h[3] = (h[3]! + d) >>> 0;
        h[4] = (h[4]! + e) >>> 0;
        h[5] = (h[5]! + f) >>> 0;
        h[6] = (h[6]! + g) >>> 0;
        h[7] = (h[7]! + hh) >>> 0;
    }

    return h.map(v => toHex32(v)).join('');
}

export function buildTimeline(events: readonly EngineEvent[], filter?: TimelineFilter): TimelineEntry[] {
    const entries = events.map((event) => ({
        tick: eventTick(event),
        timestamp: event.timestamp,
        source: eventSource(event),
        action: eventAction(event),
        actor: eventActor(event),
        target: eventTarget(event),
        detail: eventDetail(event),
        severity: eventSeverity(event),
        eventType: event.type,
    }));

    entries.sort((a, b) => (a.timestamp - b.timestamp) || (a.tick - b.tick));

    if (filter === undefined) return entries;

    return entries.filter((entry) => {
        if (filter.machine !== undefined) {
            const matches = entry.source === filter.machine || entry.target.includes(filter.machine) || entry.detail.includes(filter.machine);
            if (!matches) return false;
        }
        if (filter.actor !== undefined && entry.actor !== filter.actor) return false;
        if (filter.severity !== undefined && entry.severity !== filter.severity) return false;
        if (filter.eventType !== undefined && entry.eventType !== filter.eventType) return false;
        if (filter.startTime !== undefined && entry.timestamp < filter.startTime) return false;
        if (filter.endTime !== undefined && entry.timestamp > filter.endTime) return false;
        return true;
    });
}

export function parseAuthLog(content: string): AuthLogEntry[] {
    const lines = content.split(/\r?\n/);
    const entries: AuthLogEntry[] = [];

    for (const rawLine of lines) {
        const line = rawLine.trim();
        if (line.length === 0) continue;

        const base = SYSLOG_LINE.exec(line);
        if (base === null) continue;

        const ts = parseSyslogLikeTimestamp(base[1]!);
        const machine = base[2]!;
        const service = base[3]!;
        const pid = base[4] === undefined ? null : Number(base[4]);
        const message = base[5]!;

        const failed = /Failed password for(?: invalid user)?\s+(\S+) from\s+(\d+\.\d+\.\d+\.\d+)/.exec(message);
        if (failed !== null) {
            entries.push({
                timestamp: ts,
                machine,
                service,
                pid,
                action: 'login',
                user: failed[1] ?? null,
                sourceIP: failed[2] ?? null,
                success: false,
                targetUser: null,
                command: null,
                message,
                raw: line,
            });
            continue;
        }

        const accepted = /Accepted (?:password|publickey) for\s+(\S+) from\s+(\d+\.\d+\.\d+\.\d+)/.exec(message);
        if (accepted !== null) {
            entries.push({
                timestamp: ts,
                machine,
                service,
                pid,
                action: 'login',
                user: accepted[1] ?? null,
                sourceIP: accepted[2] ?? null,
                success: true,
                targetUser: null,
                command: null,
                message,
                raw: line,
            });
            continue;
        }

        const sudo = /(\S+)\s*:\s*TTY=.*USER=(\S+)\s*;\s*COMMAND=(.+)$/.exec(message);
        if (sudo !== null) {
            entries.push({
                timestamp: ts,
                machine,
                service,
                pid,
                action: 'sudo',
                user: sudo[1] ?? null,
                sourceIP: null,
                success: true,
                targetUser: sudo[2] ?? null,
                command: sudo[3] ?? null,
                message,
                raw: line,
            });
            continue;
        }

        const su = /session opened for user\s+(\S+) by\s+(\S+)/.exec(message);
        if (su !== null) {
            entries.push({
                timestamp: ts,
                machine,
                service,
                pid,
                action: 'su',
                user: su[2] ?? null,
                sourceIP: null,
                success: true,
                targetUser: su[1] ?? null,
                command: null,
                message,
                raw: line,
            });
            continue;
        }

        entries.push({
            timestamp: ts,
            machine,
            service,
            pid,
            action: 'other',
            user: null,
            sourceIP: null,
            success: null,
            targetUser: null,
            command: null,
            message,
            raw: line,
        });
    }

    return entries.sort((a, b) => a.timestamp - b.timestamp);
}

export function parseSyslog(content: string): SyslogEntry[] {
    const lines = content.split(/\r?\n/);
    const entries: SyslogEntry[] = [];

    for (const rawLine of lines) {
        const line = rawLine.trim();
        if (line.length === 0) continue;

        const base = SYSLOG_LINE.exec(line);
        if (base === null) continue;

        const message = base[5]!;
        const severityMatch = /\b(emerg|alert|crit|err|warning|notice|info|debug)\b/i.exec(message);

        entries.push({
            timestamp: parseSyslogLikeTimestamp(base[1]!),
            machine: base[2]!,
            service: base[3]!,
            pid: base[4] === undefined ? null : Number(base[4]),
            severity: severityMatch?.[1]?.toLowerCase() ?? null,
            message,
            raw: line,
        });
    }

    return entries.sort((a, b) => a.timestamp - b.timestamp);
}

function parseCombinedAccessLog(content: string): ApacheLogEntry[] {
    const lines = content.split(/\r?\n/);
    const entries: ApacheLogEntry[] = [];

    for (const rawLine of lines) {
        const line = rawLine.trim();
        if (line.length === 0) continue;

        const match = APACHE_COMBINED.exec(line);
        if (match === null) continue;

        entries.push({
            sourceIP: match[1]!,
            user: match[2] === '-' ? null : match[2]!,
            timestamp: parseApacheTimestamp(match[3]!),
            method: match[4]!,
            url: match[5]!,
            protocol: match[6]!,
            statusCode: Number(match[7]),
            responseSize: match[8] === '-' ? 0 : Number(match[8]),
            referrer: match[9]!,
            userAgent: match[10]!,
            raw: line,
        });
    }

    return entries.sort((a, b) => a.timestamp - b.timestamp);
}

export function parseApacheLog(content: string): ApacheLogEntry[] {
    return parseCombinedAccessLog(content);
}

export function parseNginxLog(content: string): NginxLogEntry[] {
    return parseCombinedAccessLog(content).map(entry => ({ ...entry }));
}

export function detectBruteForce(
    authLogs: AuthLogEntry[],
    threshold: number = 5,
    windowMs: number = 5 * 60_000,
): BruteForceIndicator[] {
    const failures = authLogs
        .filter(entry => entry.action === 'login' && entry.success === false && entry.sourceIP !== null)
        .sort((a, b) => a.timestamp - b.timestamp);

    const grouped = new Map<string, AuthLogEntry[]>();
    for (const entry of failures) {
        const key = `${entry.machine}|${entry.sourceIP}`;
        const bucket = grouped.get(key) ?? [];
        bucket.push(entry);
        grouped.set(key, bucket);
    }

    const indicators: BruteForceIndicator[] = [];

    for (const [key, bucket] of grouped) {
        let start = 0;
        for (let end = 0; end < bucket.length; end++) {
            const endEntry = bucket[end]!;
            while (start <= end && (endEntry.timestamp - bucket[start]!.timestamp) > windowMs) {
                start++;
            }
            const count = end - start + 1;
            if (count >= threshold) {
                const window = bucket.slice(start, end + 1);
                const users = [...new Set(window.map(e => e.user).filter((u): u is string => u !== null))];
                const [machine, sourceIP = 'unknown'] = key.split('|');
                indicators.push({
                    sourceIP,
                    machine: machine ?? 'unknown',
                    failures: count,
                    users,
                    windowStart: window[0]!.timestamp,
                    windowEnd: window[window.length - 1]!.timestamp,
                    severity: count >= (threshold * 2) ? 'critical' : 'high',
                });
                start = end + 1;
            }
        }
    }

    return indicators.sort((a, b) => a.windowStart - b.windowStart);
}

export function detectPrivilegeEscalation(authLogs: AuthLogEntry[]): PrivescIndicator[] {
    return authLogs
        .filter(entry => (
            (entry.action === 'sudo' || entry.action === 'su')
            && entry.success === true
            && entry.targetUser === 'root'
            && entry.user !== null
        ))
        .map((entry) => ({
            timestamp: entry.timestamp,
            machine: entry.machine,
            user: entry.user ?? 'unknown',
            method: (entry.action === 'sudo' ? 'sudo' : 'su') as 'sudo' | 'su',
            targetUser: entry.targetUser ?? 'root',
            command: entry.command ?? '',
            severity: 'high' as const,
        }))
        .sort((a, b) => a.timestamp - b.timestamp);
}

export function detectLateralMovement(
    logs: AuthLogEntry[],
    windowMs: number = 30 * 60_000,
): LateralIndicator[] {
    const successfulInternal = logs
        .filter(entry => entry.action === 'login'
            && entry.success === true
            && entry.sourceIP !== null
            && isPrivateIP(entry.sourceIP))
        .sort((a, b) => a.timestamp - b.timestamp);

    const byIP = new Map<string, AuthLogEntry[]>();
    for (const entry of successfulInternal) {
        const sourceIP = entry.sourceIP;
        if (sourceIP === null) continue;
        const bucket = byIP.get(sourceIP) ?? [];
        bucket.push(entry);
        byIP.set(sourceIP, bucket);
    }

    const indicators: LateralIndicator[] = [];

    for (const [sourceIP, bucket] of byIP) {
        for (let i = 0; i < bucket.length; i++) {
            const base = bucket[i]!;
            const machines = new Set<string>([base.machine]);
            const accounts = new Set<string>();
            if (base.user !== null) accounts.add(base.user);
            let lastSeen = base.timestamp;

            for (let j = i + 1; j < bucket.length; j++) {
                const next = bucket[j]!;
                if ((next.timestamp - base.timestamp) > windowMs) break;
                machines.add(next.machine);
                if (next.user !== null) accounts.add(next.user);
                lastSeen = next.timestamp;
            }

            if (machines.size >= 2) {
                indicators.push({
                    sourceIP,
                    firstSeen: base.timestamp,
                    lastSeen,
                    machines: [...machines],
                    accounts: [...accounts],
                    severity: machines.size >= 3 ? 'critical' : 'high',
                });
                break;
            }
        }
    }

    return indicators.sort((a, b) => a.firstSeen - b.firstSeen);
}

export function detectDataExfiltration(
    accessLogs: ApacheLogEntry[],
    sizeThresholdBytes: number = 1_000_000,
): ExfilIndicator[] {
    const suspiciousPath = /\/(?:backup|dump|export|download|\.git|db)(?:\/|$)/i;

    return accessLogs
        .flatMap((entry) => {
            if (entry.statusCode < 200 || entry.statusCode >= 300) return [];

            if (entry.responseSize >= sizeThresholdBytes) {
                return [{
                    timestamp: entry.timestamp,
                    sourceIP: entry.sourceIP,
                    url: entry.url,
                    responseSize: entry.responseSize,
                    reason: 'Large outbound response size',
                    severity: entry.responseSize >= (sizeThresholdBytes * 5) ? 'critical' as const : 'high' as const,
                }];
            }

            if (suspiciousPath.test(entry.url) && entry.responseSize >= Math.floor(sizeThresholdBytes / 10)) {
                return [{
                    timestamp: entry.timestamp,
                    sourceIP: entry.sourceIP,
                    url: entry.url,
                    responseSize: entry.responseSize,
                    reason: 'Sensitive endpoint served unusually large response',
                    severity: 'high' as const,
                }];
            }

            return [];
        })
        .sort((a, b) => a.timestamp - b.timestamp);
}

export function detectWebAttacks(accessLogs: ApacheLogEntry[]): WebAttackIndicator[] {
    const indicators: WebAttackIndicator[] = [];

    const patterns = {
        sqli: [
            /\bunion(?:\s+all)?\s+select\b/i,
            /\b(?:or|and)\s+1=1\b/i,
            /information_schema/i,
            /(?:'|%27)\s*(?:or|and)/i,
        ],
        pathTraversal: [
            /\.\.\//,
            /%2e%2e%2f/i,
            /%252e%252e%252f/i,
        ],
        xss: [
            /<script/i,
            /%3cscript/i,
            /javascript:/i,
            /onerror=/i,
        ],
    };

    for (const entry of accessLogs) {
        const decoded = decodeURL(entry.url);

        const sqliPattern = patterns.sqli.find(rx => rx.test(decoded));
        if (sqliPattern !== undefined) {
            indicators.push({
                timestamp: entry.timestamp,
                sourceIP: entry.sourceIP,
                url: entry.url,
                attackType: 'sqli',
                pattern: sqliPattern.source,
                severity: 'high',
            });
            continue;
        }

        const traversalPattern = patterns.pathTraversal.find(rx => rx.test(decoded));
        if (traversalPattern !== undefined) {
            indicators.push({
                timestamp: entry.timestamp,
                sourceIP: entry.sourceIP,
                url: entry.url,
                attackType: 'path-traversal',
                pattern: traversalPattern.source,
                severity: 'high',
            });
            continue;
        }

        const xssPattern = patterns.xss.find(rx => rx.test(decoded));
        if (xssPattern !== undefined) {
            indicators.push({
                timestamp: entry.timestamp,
                sourceIP: entry.sourceIP,
                url: entry.url,
                attackType: 'xss',
                pattern: xssPattern.source,
                severity: 'high',
            });
        }
    }

    return indicators.sort((a, b) => a.timestamp - b.timestamp);
}

export function collectEvidence(vfs: VirtualFilesystem, machine: string): EvidenceBundle {
    const targets = new Set<string>([
        ...vfs.glob('/var/log/**'),
        ...vfs.glob('/home/*/.bash_history'),
        ...vfs.glob('/root/.bash_history'),
        ...vfs.glob('/tmp/*'),
        ...vfs.glob('/etc/cron.d/*'),
        ...vfs.glob('/var/spool/cron/*'),
        ...vfs.glob('/var/spool/cron/crontabs/*'),
        ...vfs.glob('/home/*/.ssh/authorized_keys'),
        ...vfs.glob('/root/.ssh/authorized_keys'),
        ...vfs.glob('/proc/*/cmdline'),
        ...vfs.glob('/proc/*/status'),
        ...vfs.glob('/var/run/processes/*'),
        '/etc/crontab',
    ]);

    const files: EvidenceFile[] = [];
    const hashes: Record<string, string> = {};
    let totalBytes = 0;

    for (const path of [...targets].sort()) {
        const node = toFileNode(vfs.stat(path));
        if (node === null) continue;

        const content = vfs.readFile(path);
        if (content === null) continue;

        const digest = sha256(content);
        hashes[path] = digest;
        totalBytes += node.size;

        files.push({
            path,
            category: classifyEvidencePath(path),
            content,
            size: node.size,
            mtime: node.mtime,
            mode: node.mode,
            owner: node.owner,
            group: node.group,
            sha256: digest,
        });
    }

    return {
        machine,
        collectedAt: Date.now(),
        fileCount: files.length,
        totalBytes,
        files,
        hashes,
    };
}

function classifyIncident(iocs: readonly string[]): IncidentType {
    const low = iocs.map(i => i.toLowerCase());
    const hasBrute = low.some(i => i.includes('brute force'));
    const hasPrivesc = low.some(i => i.includes('privilege escalation'));
    const hasLateral = low.some(i => i.includes('lateral movement'));
    const hasExfil = low.some(i => i.includes('data exfiltration'));
    const hasWeb = low.some(i => i.includes('web attack'));

    const count = [hasBrute, hasPrivesc, hasLateral, hasExfil, hasWeb].filter(Boolean).length;
    if (count >= 2) return 'multi-stage';
    if (hasBrute) return 'brute-force';
    if (hasPrivesc) return 'privilege-escalation';
    if (hasLateral) return 'lateral-movement';
    if (hasExfil) return 'data-exfiltration';
    if (hasWeb) return 'web-attack';
    return 'unknown';
}

export function generateIncidentReport(
    timeline: TimelineEntry[],
    evidence: EvidenceBundle,
): IncidentReport {
    const authLines = evidence.files
        .filter(file => file.path.endsWith('auth.log'))
        .flatMap(file => parseAuthLog(file.content));

    const accessLines = evidence.files
        .filter(file => file.path.endsWith('access.log'))
        .flatMap(file => parseApacheLog(file.content));

    const brute = detectBruteForce(authLines);
    const privesc = detectPrivilegeEscalation(authLines);
    const lateral = detectLateralMovement(authLines);
    const exfil = detectDataExfiltration(accessLines);
    const web = detectWebAttacks(accessLines);

    const iocs: string[] = [];
    if (brute.length > 0) iocs.push(`Brute force attempts detected (${brute.length})`);
    if (privesc.length > 0) iocs.push(`Privilege escalation to root detected (${privesc.length})`);
    if (lateral.length > 0) iocs.push(`Lateral movement detected (${lateral.length})`);
    if (exfil.length > 0) iocs.push(`Data exfiltration indicators detected (${exfil.length})`);
    if (web.length > 0) iocs.push(`Web attack patterns detected (${web.length})`);

    const affectedSystems = [...new Set([
        ...timeline.map(entry => entry.source),
        evidence.machine,
    ])].filter(v => v.length > 0 && v !== 'custom');

    const incidentType = classifyIncident(iocs);
    const executiveSummary = `${incidentType} incident assessment for ${evidence.machine}: ` +
        `${timeline.length} timeline events, ${evidence.fileCount} evidence files, ${iocs.length} IOC categories.`;

    const recommendations: string[] = [
        'Preserve chain-of-custody for all collected artifacts and re-verify SHA256 hashes before sharing.',
        'Reset affected credentials and enforce MFA for administrative access paths.',
        'Review host and network telemetry retention to ensure full attack reconstruction coverage.',
    ];

    if (incidentType === 'brute-force' || incidentType === 'multi-stage') {
        recommendations.push('Apply rate limiting and account lockout policy on SSH and remote auth services.');
    }
    if (incidentType === 'privilege-escalation' || incidentType === 'multi-stage') {
        recommendations.push('Audit sudoers/su access and remove unnecessary root-level privileges.');
    }
    if (incidentType === 'lateral-movement' || incidentType === 'multi-stage') {
        recommendations.push('Segment internal network and monitor east-west SSH authentication traffic.');
    }
    if (incidentType === 'data-exfiltration' || incidentType === 'multi-stage') {
        recommendations.push('Block suspicious outbound transfer channels and inspect high-volume responses.');
    }
    if (incidentType === 'web-attack' || incidentType === 'multi-stage') {
        recommendations.push('Deploy WAF signatures for SQLi/XSS/path traversal and patch vulnerable handlers.');
    }

    return {
        generatedAt: Date.now(),
        incidentType,
        executiveSummary,
        timeline: [...timeline].sort((a, b) => (a.timestamp - b.timestamp) || (a.tick - b.tick)),
        indicatorsOfCompromise: iocs,
        affectedSystems,
        recommendations,
    };
}

export function createForensicsModule(eventBus: EventBus): Module {
    const unsubscribers: Unsubscribe[] = [];
    const observedEvents: EngineEvent[] = [];

    return {
        id: MODULE_ID,
        type: 'defense',
        version: MODULE_VERSION,
        description: 'Forensics module — timeline reconstruction, log parsing, anomaly detection, evidence collection, and incident reporting',
        provides: [
            { name: 'forensics' },
            { name: 'timeline' },
            { name: 'log-analysis' },
        ] as readonly Capability[],
        requires: [] as readonly Capability[],

        init(context: SimulationContext): void {
            observedEvents.length = 0;

            context.services.register('forensics', {
                buildTimeline,
                parseAuthLog,
                parseSyslog,
                parseApacheLog,
                parseNginxLog,
                detectBruteForce,
                detectPrivilegeEscalation,
                detectLateralMovement,
                detectDataExfiltration,
                detectWebAttacks,
                collectEvidence,
                generateIncidentReport,
            });

            const streamUnsub = eventBus.onPrefix('*', (event) => {
                if (event.type.startsWith('custom:forensics-')) return;
                observedEvents.push(event);
                if (observedEvents.length > 50_000) {
                    observedEvents.shift();
                }
            });
            unsubscribers.push(streamUnsub);

            const queryUnsub = eventBus.onPrefix('custom:', (event) => {
                if (event.type === 'custom:forensics-build-timeline') {
                    const data = event.data as { filter?: TimelineFilter } | null;
                    const timeline = buildTimeline(observedEvents, data?.filter);
                    eventBus.emit({
                        type: 'custom:forensics-timeline-result',
                        data: { timeline },
                        timestamp: Date.now(),
                    });
                }

                if (event.type === 'custom:forensics-analyze-auth') {
                    const data = event.data as { content: string } | null;
                    const parsed = parseAuthLog(data?.content ?? '');
                    eventBus.emit({
                        type: 'custom:forensics-anomalies-result',
                        data: {
                            bruteForce: detectBruteForce(parsed),
                            privilegeEscalation: detectPrivilegeEscalation(parsed),
                            lateralMovement: detectLateralMovement(parsed),
                        },
                        timestamp: Date.now(),
                    });
                }

                if (event.type === 'custom:forensics-report') {
                    const timeline = buildTimeline(observedEvents);
                    const data = event.data as { evidence: EvidenceBundle } | null;
                    if (data?.evidence !== undefined) {
                        eventBus.emit({
                            type: 'custom:forensics-report-result',
                            data: { report: generateIncidentReport(timeline, data.evidence) },
                            timestamp: Date.now(),
                        });
                    }
                }
            });
            unsubscribers.push(queryUnsub);
        },

        destroy(): void {
            for (const unsub of unsubscribers) {
                unsub();
            }
            unsubscribers.length = 0;
            observedEvents.length = 0;
        },
    };
}
