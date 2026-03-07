/**
 * VARIANT — Credential Flow Module
 *
 * Centralized, deterministic registry for discoverable credentials and
 * derivation/validation state used by credential-based attack chains.
 */

import type { Module, SimulationContext, Capability, ServiceLocator } from '../core/modules';
import type { EventBus, Unsubscribe } from '../core/events';
import type { CredentialEntry, CredentialTarget, CredentialType as WorldCredentialType } from '../core/world/types';

export const MODULE_ID = 'credential-flow';
export const VERSION = '1.0.0';
const MODULE_VERSION = VERSION;

export type CredentialType =
    | 'password'
    | 'ssh-key'
    | 'token'
    | 'hash'
    | 'certificate'
    | 'api-key'
    | 'cookie'
    | 'kerberos-ticket';

export interface CredentialSource {
    readonly module: string;
    readonly machine: string;
    readonly path: string;
    readonly method: string;
    readonly tick: number;
}

export interface AuthTarget {
    readonly machine: string;
    readonly service: string;
    readonly user: string;
    readonly port?: number;
}

export interface DiscoveredCredential {
    readonly id: string;
    readonly type: CredentialType;
    readonly value: string;
    readonly username?: string;
    readonly source: CredentialSource;
    readonly targets: readonly AuthTarget[];
    readonly status: 'raw' | 'cracked' | 'validated' | 'expired';
    readonly derivedFrom?: string;
}

export interface CredentialChainLink {
    readonly parentId: string;
    readonly childId: string;
    readonly mechanism: string;
    readonly tick: number;
}

export interface CredentialFilter {
    readonly id?: string;
    readonly type?: CredentialType;
    readonly sourceMachine?: string;
    readonly sourcePath?: string;
    readonly sourceMethod?: string;
    readonly username?: string;
    readonly status?: DiscoveredCredential['status'];
    readonly targetMachine?: string;
    readonly targetService?: string;
    readonly targetUser?: string;
    readonly targetPort?: number;
    readonly derivedFrom?: string;
}

export interface AuthResult {
    readonly success: boolean;
    readonly reason: 'ok' | 'not-found' | 'invalid-target' | 'expired';
    readonly credential?: DiscoveredCredential;
    readonly matchedTarget?: AuthTarget;
}

export interface CredentialStore {
    register(cred: DiscoveredCredential): string;
    get(id: string): DiscoveredCredential | undefined;
    query(filter: CredentialFilter): readonly DiscoveredCredential[];
    validate(credId: string, target: AuthTarget): AuthResult;
    getChain(credId: string): readonly CredentialChainLink[];
}

interface SeedCredential {
    readonly type: CredentialType;
    readonly value: string;
    readonly username?: string;
    readonly source: CredentialSource;
    readonly status: DiscoveredCredential['status'];
    readonly targets: readonly AuthTarget[];
    readonly derivedFrom?: string;
}

interface ScanPattern {
    readonly type: CredentialType;
    readonly method: string;
    readonly regex: RegExp;
    readonly mapValue: (match: RegExpMatchArray) => string;
}

interface EnvCredentialHint {
    username?: string;
    envUser?: string;
}

// ── Scanners ────────────────────────────────────────────────

const AWS_PATTERN = /\bAKIA[0-9A-Z]{16,}\b/g;
const SSH_PRIVATE_KEY_PATTERN = /-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----/g;
const JWT_PATTERN = /\beyJ[a-zA-Z0-9_\-\.\/+=]+\.[a-zA-Z0-9_\-\.\/+=]+\.[a-zA-Z0-9_\-\.\/+=]+\b/g;
const PASSWORD_PATTERN = /(?:^|[\s\"'])((?:[A-Za-z][A-Za-z0-9_]*[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|pwd|passphrase)\s*[=:]\s*)([^\s\"'`]+)(?=\s|$|[\"'`])/gim;
const API_KEY_PATTERN = /(?:^|[\s\"'])((?:api[_-]?(?:key|token)|access[_-]?key|secret[_-]?key|bearer|x-api-key)\s*[=:]\s*)([^\s\"'`]+)(?=\s|$|[\"'`])/gim;
const DB_CONN_PATTERN = /\b(?:mysql|postgres(?:ql)?|mongodb|redis|mssql):\/\/(?:[^:\s@]+):([^\@\s\/]+)@[^\s\"'`]+/gim;
const ENV_PATTERN = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/gm;

const SCAN_PATTERNS: readonly ScanPattern[] = [
    { type: 'api-key', method: 'aws-key-regex', regex: AWS_PATTERN, mapValue: (match) => match[0] ?? '' },
    { type: 'ssh-key', method: 'ssh-private-key-regex', regex: SSH_PRIVATE_KEY_PATTERN, mapValue: (match) => match[0] ?? '' },
    { type: 'token', method: 'jwt-regex', regex: JWT_PATTERN, mapValue: (match) => match[0] ?? '' },
    { type: 'password', method: 'password-assignment-regex', regex: PASSWORD_PATTERN, mapValue: (match) => match[2] ?? '' },
    { type: 'api-key', method: 'api-key-regex', regex: API_KEY_PATTERN, mapValue: (match) => match[2] ?? '' },
    { type: 'password', method: 'db-connection-regex', regex: DB_CONN_PATTERN, mapValue: (match) => match[1] ?? '' },
];

// ── Hash helper (stable) ────────────────────────────────────

function hashString(input: string): string {
    let hash = 5381;
    for (let i = 0; i < input.length; i++) {
        hash = ((hash << 5) + hash + input.charCodeAt(i)) & 0xffffffff;
    }
    return (hash >>> 0).toString(16).padStart(8, '0');
}

function normalizeCredentialType(type: WorldCredentialType | string): CredentialType {
    if (type === 'api-token') return 'api-key';
    if (type === 'jwt-secret') return 'token';
    if (type === 'database-password') return 'password';

    const normalized = type.toLowerCase();
    if (normalized.includes('hash')) return 'hash';
    if (normalized.includes('token') || normalized.includes('jwt')) return 'token';
    if (normalized.includes('kerberos')) return 'kerberos-ticket';
    if (normalized.includes('api')) return 'api-key';
    if (normalized.includes('ssh')) return 'ssh-key';
    if (normalized.includes('cookie')) return 'cookie';
    if (normalized.includes('cert')) return 'certificate';

    return 'password';
}

function sanitizeCredentialValue(raw: string): string {
    return raw.trim().replace(/["'`]/g, '');
}

function deterministicCredentialId(
    type: CredentialType,
    value: string,
    source: CredentialSource,
): string {
    return `${type}-${hashString(`${type}|${value}|${source.module}|${source.machine}|${source.path}|${source.method}|${source.tick}`)}`;
}

function targetFromWorld(target: CredentialTarget | undefined): AuthTarget | null {
    if (target === undefined) return null;

    return {
        machine: target.machine,
        service: target.service,
        user: target.user,
        ...(target.port !== undefined ? { port: target.port } : {}),
    };
}

function sourceFromWorld(entry: CredentialEntry, tick = 0): CredentialSource {
    return {
        module: 'world-spec',
        machine: entry.foundAt.machine,
        path: entry.foundAt.path ?? entry.foundAt.env ?? entry.foundAt.service ?? '/unknown',
        method: entry.foundAt.method ?? 'discover',
        tick,
    };
}

function makeFromSeed(seed: SeedCredential): DiscoveredCredential {
    const id = deterministicCredentialId(seed.type, seed.value, seed.source);
    return {
        id,
        type: seed.type,
        value: seed.value,
        ...(seed.username !== undefined ? { username: seed.username } : {}),
        source: { ...seed.source },
        targets: seed.targets,
        status: seed.status,
        ...(seed.derivedFrom !== undefined ? { derivedFrom: seed.derivedFrom } : {}),
    };
}

function toDiscoveredFromEntry(entry: CredentialEntry): DiscoveredCredential {
    const source = sourceFromWorld(entry, 0);
    const normalizedType = normalizeCredentialType(entry.type);
    const target = targetFromWorld(entry.validAt);

    return makeFromSeed({
        type: normalizedType,
        value: entry.value,
        source,
        status: 'raw',
        targets: target === null ? [] : [target],
    });
}

function cloneCredential(cred: DiscoveredCredential): DiscoveredCredential {
    return {
        id: cred.id,
        type: cred.type,
        value: cred.value,
        ...(cred.username !== undefined ? { username: cred.username } : {}),
        source: { ...cred.source },
        targets: cred.targets.map((target) => ({ ...target })),
        status: cred.status,
        ...(cred.derivedFrom !== undefined ? { derivedFrom: cred.derivedFrom } : {}),
    };
}

function mergeStatus(
    existing: DiscoveredCredential['status'],
    incoming: DiscoveredCredential['status'],
): DiscoveredCredential['status'] {
    if (existing === 'expired' || incoming === 'expired') {
        return existing === 'expired' ? existing : incoming;
    }

    const weight: Record<Exclude<DiscoveredCredential['status'], 'expired'>, number> = {
        raw: 0,
        cracked: 1,
        validated: 2,
    };

    return weight[incoming] > weight[existing] ? incoming : existing;
}

function mergeTargets(existing: readonly AuthTarget[], incoming: readonly AuthTarget[]): readonly AuthTarget[] {
    const merged = existing.map((target) => ({ ...target }));

    for (const candidate of incoming) {
        const already = merged.some((known) => (
            known.machine === candidate.machine
            && known.service === candidate.service
            && known.user === candidate.user
            && known.port === candidate.port
        ));

        if (!already) {
            merged.push({ ...candidate });
        }
    }

    return merged;
}

function matchTarget(stored: AuthTarget, requested: AuthTarget): boolean {
    if (stored.machine !== requested.machine) return false;
    if (stored.service !== requested.service) return false;
    if (stored.user !== requested.user) return false;
    if (requested.port !== undefined && stored.port !== undefined && stored.port !== requested.port) return false;
    if (requested.port !== undefined && stored.port === undefined) return false;

    return true;
}

function credentialMatchesFilter(cred: DiscoveredCredential, filter: CredentialFilter): boolean {
    if (filter.id !== undefined && cred.id !== filter.id) return false;
    if (filter.type !== undefined && cred.type !== filter.type) return false;
    if (filter.status !== undefined && cred.status !== filter.status) return false;
    if (filter.username !== undefined && cred.username !== filter.username) return false;
    if (filter.sourceMachine !== undefined && cred.source.machine !== filter.sourceMachine) return false;
    if (filter.sourcePath !== undefined && cred.source.path !== filter.sourcePath) return false;
    if (filter.sourceMethod !== undefined && cred.source.method !== filter.sourceMethod) return false;
    if (filter.derivedFrom !== undefined && cred.derivedFrom !== filter.derivedFrom) return false;

    if (filter.targetMachine !== undefined) {
        const has = cred.targets.some((target) => target.machine === filter.targetMachine);
        if (!has) return false;
    }

    if (filter.targetService !== undefined) {
        const has = cred.targets.some((target) => target.service === filter.targetService);
        if (!has) return false;
    }

    if (filter.targetUser !== undefined) {
        const has = cred.targets.some((target) => target.user === filter.targetUser);
        if (!has) return false;
    }

    if (filter.targetPort !== undefined) {
        const has = cred.targets.some((target) => target.port === filter.targetPort);
        if (!has) return false;
    }

    return true;
}

function parseEnvHints(content: string): EnvCredentialHint {
    const hints: EnvCredentialHint = {};

    for (const match of content.matchAll(ENV_PATTERN)) {
        const key = match[1];
        const value = match[2];
        if (key === undefined || value === undefined) continue;

        const lower = key.toLowerCase();
        if (lower.includes('user') || lower.includes('username') || lower.includes('db_user')) {
            hints.username = sanitizeCredentialValue(value);
            continue;
        }

        if (lower === 'user' || lower.includes('dbuser')) {
            hints.envUser = sanitizeCredentialValue(value);
        }
    }

    return hints;
}

function envKeyToType(key: string): 'password' | 'api-key' | 'cookie' | null {
    const lower = key.toLowerCase();

    if (lower.includes('password') || lower.includes('passwd') || lower.includes('passphrase')) {
        return 'password';
    }

    if (lower.includes('token') || lower.includes('api_key') || lower.includes('apikey')) {
        return 'api-key';
    }

    if (lower.includes('cookie')) {
        return 'cookie';
    }

    return null;
}

/**
 * Detect likely credentials from arbitrary content.
 */
export function scanForCredentials(content: string, source: CredentialSource): DiscoveredCredential[] {
    const found: DiscoveredCredential[] = [];
    const ids = new Set<string>();
    const envHints = parseEnvHints(content);
    const envUser = envHints.username ?? envHints.envUser;

    for (const pattern of SCAN_PATTERNS) {
        pattern.regex.lastIndex = 0;

        for (const match of content.matchAll(pattern.regex)) {
            const value = sanitizeCredentialValue(pattern.mapValue(match));
            if (value === '') continue;

            const discovered = makeFromSeed({
                type: pattern.type,
                value,
                ...(envUser === undefined ? {} : { username: envUser }),
                source,
                status: 'raw',
                targets: [],
            });

            if (ids.has(discovered.id)) continue;
            ids.add(discovered.id);
            found.push(discovered);
        }
    }

    for (const match of content.matchAll(ENV_PATTERN)) {
        const key = match[1];
        const value = match[2];
        if (key === undefined || value === undefined) continue;

        const candidateType = envKeyToType(key);
        if (candidateType === null) continue;

        const cleanedValue = sanitizeCredentialValue(value);
        if (cleanedValue === '') continue;

        const envSource: CredentialSource = {
            ...source,
            method: 'env-file',
        };

        const envDiscovered = makeFromSeed({
            type: candidateType,
            value: cleanedValue,
            ...(envUser === undefined ? {} : { username: envUser }),
            source: envSource,
            status: 'raw',
            targets: [],
        });

        if (ids.has(envDiscovered.id)) continue;
        ids.add(envDiscovered.id);
        found.push(envDiscovered);
    }

    return found;
}

/**
 * Crack a hashed credential with candidate list.
 */
export function crackHash(hashCred: DiscoveredCredential, wordlist?: readonly string[]): DiscoveredCredential | null {
    if (hashCred.type !== 'hash') return null;

    const candidates = wordlist ?? [];
    for (const candidate of candidates) {
        const cleartext = candidate.trim();
        if (cleartext === '') continue;

        if (hashString(cleartext) === hashCred.value || cleartext === hashCred.value) {
            return makeFromSeed({
                type: 'password',
                value: cleartext,
                ...(hashCred.username !== undefined ? { username: hashCred.username } : {}),
                source: {
                    module: MODULE_ID,
                    machine: hashCred.source.machine,
                    path: hashCred.source.path,
                    method: 'crack-hash',
                    tick: hashCred.source.tick,
                },
                status: 'cracked',
                targets: hashCred.targets,
                derivedFrom: hashCred.id,
            });
        }
    }

    return null;
}

/**
 * Derive token-like material from an existing credential.
 */
export function deriveToken(cred: DiscoveredCredential, tokenType: string): DiscoveredCredential {
    const derivedType: CredentialType = tokenType === 'kerberos-ticket'
        ? 'kerberos-ticket'
        : (tokenType === 'jwt' || tokenType === 'token' ? 'token' : 'api-key');

    const derivedValue = `${derivedType}.${hashString(`${cred.id}|${tokenType}|${cred.value}`)}`;
    return makeFromSeed({
        type: derivedType,
        value: derivedValue,
        ...(cred.username !== undefined ? { username: cred.username } : {}),
        source: {
            module: MODULE_ID,
            machine: cred.source.machine,
            path: cred.source.path,
            method: `derive:${tokenType}`,
            tick: cred.source.tick,
        },
        status: 'raw',
        targets: cred.targets,
        derivedFrom: cred.id,
    });
}

// ── Module factory ─────────────────────────────────────────

export function createCredentialFlowModule(
    initialCredentials: readonly CredentialEntry[],
    eventBus: EventBus,
): Module & CredentialStore {
    const discovered = new Map<string, DiscoveredCredential>();
    const catalog = new Map<string, CredentialEntry>();
    const unsubs: Unsubscribe[] = [];
    let activeBus = eventBus;

    for (const entry of initialCredentials) {
        catalog.set(entry.id, entry);
    }

    function normalizeForStorage(input: DiscoveredCredential): DiscoveredCredential {
        const normalizedType = normalizeCredentialType(input.type);
        const source: CredentialSource = {
            module: input.source.module,
            machine: input.source.machine,
            path: input.source.path,
            method: input.source.method,
            tick: input.source.tick,
        };
        const value = sanitizeCredentialValue(input.value);

        return {
            id: deterministicCredentialId(normalizedType, value, source),
            type: normalizedType,
            value,
            ...(input.username !== undefined ? { username: input.username } : {}),
            source,
            targets: input.targets.map((target) => ({ ...target })),
            status: input.status,
            ...(input.derivedFrom !== undefined ? { derivedFrom: input.derivedFrom } : {}),
        };
    }

    function register(cred: DiscoveredCredential): string {
        const normalized = normalizeForStorage(cred);
        const existing = discovered.get(normalized.id);

        if (existing === undefined) {
            discovered.set(normalized.id, normalized);
            activeBus.emit({
                type: 'credential:registered',
                credentialId: normalized.id,
                credentialType: normalized.type,
                source: { ...normalized.source },
                status: normalized.status,
                timestamp: Date.now(),
            });

            if (normalized.derivedFrom !== undefined) {
                activeBus.emit({
                    type: 'credential:chain-extended',
                    parentId: normalized.derivedFrom,
                    childId: normalized.id,
                    mechanism: normalized.source.method,
                    tick: normalized.source.tick,
                    timestamp: Date.now(),
                });
            }

            return normalized.id;
        }

        const merged: DiscoveredCredential = {
            ...existing,
            ...normalized,
            ...(existing.derivedFrom === undefined && normalized.derivedFrom !== undefined
                ? { derivedFrom: normalized.derivedFrom }
                : {}),
            ...(normalized.username === undefined ? {} : { username: normalized.username }),
            status: mergeStatus(existing.status, normalized.status),
            targets: mergeTargets(existing.targets, normalized.targets),
        };

        if (
            merged.status !== existing.status
            || merged.targets.length !== existing.targets.length
            || merged.username !== existing.username
            || merged.derivedFrom !== existing.derivedFrom
        ) {
            discovered.set(normalized.id, merged);
        }

        return normalized.id;
    }

    function get(id: string): DiscoveredCredential | undefined {
        const item = discovered.get(id);
        return item === undefined ? undefined : cloneCredential(item);
    }

    function query(filter: CredentialFilter): readonly DiscoveredCredential[] {
        const results: DiscoveredCredential[] = [];

        for (const cred of discovered.values()) {
            if (credentialMatchesFilter(cred, filter)) {
                results.push(cloneCredential(cred));
            }
        }

        return Object.freeze(results);
    }

    function validate(credId: string, target: AuthTarget): AuthResult {
        const found = discovered.get(credId);
        if (found === undefined) {
            return { success: false, reason: 'not-found' };
        }

        if (found.status === 'expired') {
            return {
                success: false,
                reason: 'expired',
                credential: cloneCredential(found),
            };
        }

        const matched = found.targets.find((candidate) => matchTarget(candidate, target));
        if (matched === undefined) {
            return {
                success: false,
                reason: 'invalid-target',
                credential: cloneCredential(found),
            };
        }

        const updated: DiscoveredCredential = {
            ...found,
            status: 'validated',
            targets: mergeTargets(found.targets, [matched]),
        };
        discovered.set(credId, updated);

        activeBus.emit({
            type: 'credential:validated',
            credentialId: credId,
            credentialType: found.type,
            target: { ...matched },
            timestamp: Date.now(),
        });

        return {
            success: true,
            reason: 'ok',
            credential: cloneCredential(updated),
            matchedTarget: { ...matched },
        };
    }

    function getChain(credId: string): readonly CredentialChainLink[] {
        const chain: CredentialChainLink[] = [];
        let cursor = discovered.get(credId);

        while (cursor !== undefined && cursor.derivedFrom !== undefined) {
            chain.unshift({
                parentId: cursor.derivedFrom,
                childId: cursor.id,
                mechanism: cursor.source.method,
                tick: cursor.source.tick,
            });
            cursor = discovered.get(cursor.derivedFrom);
        }

        return Object.freeze(chain);
    }

    function handleAuthCredentialFound(event: {
        readonly credentialId: string;
        readonly machine: string;
        readonly location: string;
        readonly timestamp: number;
    }): void {
        const entry = catalog.get(event.credentialId);
        if (entry === undefined) return;

        const discoveredEntry = toDiscoveredFromEntry(entry);
        register({
            ...discoveredEntry,
            source: {
                ...discoveredEntry.source,
                module: MODULE_ID,
                machine: event.machine,
                path: event.location,
                method: 'auth:credential-found',
                tick: event.timestamp,
            },
        });
    }

    function handleFsRead(event: {
        readonly path: string;
        readonly machine: string;
        readonly timestamp: number;
        readonly content?: unknown;
    }): void {
        if (typeof event.content !== 'string') return;

        const source: CredentialSource = {
            module: MODULE_ID,
            machine: event.machine,
            path: event.path,
            method: 'fs:read',
            tick: event.timestamp,
        };

        const discovered = scanForCredentials(event.content, source);
        for (const cred of discovered) {
            register(cred);
        }
    }

    const capabilityStore = {
        register,
        get,
        query,
        validate,
        getChain,
    };

    const module: Module & CredentialStore = {
        id: MODULE_ID,
        type: 'service',
        version: MODULE_VERSION,
        description: 'Stores discovered credentials and tracks derivation lineage.',

        provides: [
            { name: 'credential-store' },
            { name: 'credential-flow' },
        ] as readonly Capability[],
        requires: [] as readonly Capability[],

        init(context: SimulationContext): void {
            activeBus = context.events;
            const services: ServiceLocator = context.services;

            if (!services.has('credential-store')) {
                services.register('credential-store', capabilityStore);
            }

            unsubs.push(activeBus.on('auth:credential-found', (event) => {
                handleAuthCredentialFound({
                    credentialId: event.credentialId,
                    machine: event.machine,
                    location: event.location,
                    timestamp: event.timestamp,
                });
            }));

            unsubs.push(activeBus.on('fs:read', (event) => {
                handleFsRead({
                    path: event.path,
                    machine: event.machine,
                    timestamp: event.timestamp,
                    content: (event as { content?: unknown }).content,
                });
            }));
        },

        destroy(): void {
            for (const unsub of unsubs) {
                unsub();
            }
            unsubs.length = 0;
        },

        register,
        get,
        query,
        validate,
        getChain,
    };

    return module;
}
