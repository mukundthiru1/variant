/**
 * VARIANT — Session Management Module
 *
 * Tracks authenticated sessions, per-machine authentication state,
 * session timeout/replay/hijacking patterns, and attack-facilitating signals.
 *
 * SECURITY NOTES:
 * - Session identifiers are deterministic and therefore predictable
 *   unless additional randomization is added externally.
 * - Session fixation and replay are intentionally modelled as attack
 *   opportunities with explicit simulation helpers.
 */

import type { Module, SimulationContext, Capability, ServiceLocator } from '../core/modules';
import type { EventBus } from '../core/events';

// ── Module ID and version ──────────────────────────────────────

const MODULE_ID = 'session-manager';
const MODULE_VERSION = '1.0.0';
const SESSION_PREFIX = 'sm';

// ── Public contract types ─────────────────────────────────────

export type SessionProtocol = 'ssh' | 'http' | 'rdp' | 'smb' | 'k8s' | (string & {});

export type SessionStatus = 'active' | 'idle' | 'expired' | 'hijacked';

export interface Session {
    readonly id: string;
    readonly machine: string;
    readonly user: string;
    readonly protocol: SessionProtocol;
    readonly startTick: number;
    readonly lastActivity: number;
    readonly status: SessionStatus;
    readonly sourceIp?: string;
    readonly credential?: string;
    readonly metadata: Record<string, unknown>;
}

export interface SessionFilter {
    readonly id?: string;
    readonly machine?: string;
    readonly user?: string;
    readonly protocol?: SessionProtocol;
    readonly status?: SessionStatus;
    readonly sourceIp?: string;
    readonly credential?: string;
    readonly minStartTick?: number;
    readonly maxStartTick?: number;
    readonly minLastActivity?: number;
    readonly maxLastActivity?: number;
}

export interface MachineAuthState {
    readonly machine: string;
    readonly loggedInUsers: readonly string[];
    readonly activeSessions: readonly string[];
    readonly failedAttempts: Readonly<Record<string, number>>;
    readonly lockouts: readonly string[];
    readonly authenticatedServices: Readonly<Record<string, readonly string[]>>;
}

export interface SessionStore {
    createSession(machine: string, user: string, protocol: SessionProtocol, credential?: string): Session;
    getSession(id: string): Session | undefined;
    getSessions(filter: SessionFilter): readonly Session[];
    destroySession(id: string): void;
    hijackSession(id: string, newUser: string): boolean;
    stealSession(sourceSession: string): Session | null;
    getAuthState(machine: string): MachineAuthState;
}

export interface SessionModuleConfig {
    /**
     * Maximum lifetime in ticks before a session expires, per protocol.
     */
    readonly protocolTimeouts?: Readonly<Record<string, number>>;

    /**
     * Fraction of timeout after which a session becomes idle.
     * Default: 0.5 (50%).
     */
    readonly idleThresholdRatio?: number;

    /**
     * Concurrent session threshold that triggers anomaly reporting.
     * Default: 3.
     */
    readonly maxConcurrentSessionsPerUser?: number;

    /**
     * Failed login attempts before user is marked lockout.
     * Default: 3.
     */
    readonly maxFailedAttempts?: number;

    /**
     * Lockout duration in ticks.
     * Default: 8.
     */
    readonly lockoutTicks?: number;
}

// ── Internal structures ───────────────────────────────────────

interface MutableSession {
    id: string;
    machine: string;
    user: string;
    protocol: SessionProtocol;
    startTick: number;
    lastActivity: number;
    status: SessionStatus;
    sourceIp?: string;
    credential?: string;
    metadata: Record<string, unknown>;
    service?: string;
}

interface InternalMachineAuthState {
    readonly userSessionCounts: Map<string, number>;
    readonly activeSessions: Set<string>;
    readonly failedAttempts: Map<string, number>;
    readonly lockoutUntil: Map<string, number>;
    readonly userServices: Map<string, Map<string, number>>;
}

const DEFAULT_PROTOCOL_TIMEOUTS: Readonly<Record<string, number>> = Object.freeze({
    ssh: 28,
    http: 16,
    rdp: 40,
    smb: 32,
    k8s: 24,
    default: 24,
});
const FALLBACK_PROTOCOL_TIMEOUT = 24;

const DEFAULT_IDLE_THRESHOLD_RATIO = 0.5;
const DEFAULT_MAX_CONCURRENT_PER_USER = 3;
const DEFAULT_MAX_FAILED_ATTEMPTS = 3;
const DEFAULT_LOCKOUT_TICKS = 8;

function makeHash(input: string): string {
    let hash = 5381;
    for (let i = 0; i < input.length; i++) {
        hash = ((hash << 5) + hash + input.charCodeAt(i)) & 0xffffffff;
    }
    return (hash >>> 0).toString(16).padStart(8, '0');
}

function normalizeProtocol(protocol: string): SessionProtocol {
    const lowered = protocol.toLowerCase();
    if (lowered === 'ssh' || lowered === 'telnet') return 'ssh';
    if (lowered === 'http' || lowered === 'https') return 'http';
    if (lowered === 'rdp' || lowered === 'mstsc') return 'rdp';
    if (lowered === 'smb' || lowered === 'netbios') return 'smb';
    if (lowered === 'k8s' || lowered === 'kubernetes') return 'k8s';
    return lowered as SessionProtocol;
}

function sanitizeIdPart(value: string): string {
    const safe = value.trim().toLowerCase().replace(/[^a-z0-9._-]/g, '-');
    if (safe.length === 0) return 'x';
    return safe.slice(0, 24).replace(/-+/g, '-');
}

function cloneRecord(session: MutableSession): Session {
    return Object.freeze({
        id: session.id,
        machine: session.machine,
        user: session.user,
        protocol: session.protocol,
        startTick: session.startTick,
        lastActivity: session.lastActivity,
        status: session.status,
        ...(session.sourceIp === undefined ? {} : { sourceIp: session.sourceIp }),
        ...(session.credential === undefined ? {} : { credential: session.credential }),
        metadata: Object.freeze({ ...session.metadata }),
    }) as Session;
}

function makeSessionId(
    seed: string,
    seq: number,
    machine: string,
    user: string,
    protocol: string,
): string {
    const compact = `${machine}|${user}|${protocol}|${seq}`;
    return `${SESSION_PREFIX}-${sanitizeIdPart(seed)}-${sanitizeIdPart(machine)}-${sanitizeIdPart(protocol)}-${seq.toString(36)}-${makeHash(compact).slice(0, 10)}`;
}

function defaultClock(): number {
    return Date.now();
}

// ── Factory ───────────────────────────────────────────────────

export function createSessionModule(
    eventBus: EventBus,
    moduleConfig?: SessionModuleConfig,
): Module & SessionStore {
    const cfg: Required<SessionModuleConfig> = {
        protocolTimeouts: { ...DEFAULT_PROTOCOL_TIMEOUTS, ...(moduleConfig?.protocolTimeouts ?? {}) },
        idleThresholdRatio: moduleConfig?.idleThresholdRatio ?? DEFAULT_IDLE_THRESHOLD_RATIO,
        maxConcurrentSessionsPerUser: moduleConfig?.maxConcurrentSessionsPerUser ?? DEFAULT_MAX_CONCURRENT_PER_USER,
        maxFailedAttempts: moduleConfig?.maxFailedAttempts ?? DEFAULT_MAX_FAILED_ATTEMPTS,
        lockoutTicks: moduleConfig?.lockoutTicks ?? DEFAULT_LOCKOUT_TICKS,
    };

    const sessions = new Map<string, MutableSession>();
    const machineStates = new Map<string, InternalMachineAuthState>();
    const sessionSeqBySeed = new Map<string, number>();
    const durationByUser = new Map<string, number>();
    const subscriptions: Array<() => void> = [];
    const unmodifiableProtocolTimeouts = new Map<string, number>(Object.entries(cfg.protocolTimeouts));
    const startClock = defaultClock;
    let currentTick = 0;
    let activeBus: EventBus = eventBus;
    const serviceStore = { createSession, getSession, getSessions, destroySession, hijackSession, stealSession, getAuthState };

    function getOrCreateMachineState(machine: string): InternalMachineAuthState {
        const existing = machineStates.get(machine);
        if (existing !== undefined) return existing;

        const created: InternalMachineAuthState = {
            userSessionCounts: new Map(),
            activeSessions: new Set(),
            failedAttempts: new Map(),
            lockoutUntil: new Map(),
            userServices: new Map(),
        };
        machineStates.set(machine, created);
        return created;
    }

    function normalizeFilterNumber(value: unknown): number | null {
        if (typeof value !== 'number' || !Number.isFinite(value)) return null;
        return value;
    }

    function isSessionExpired(session: MutableSession, tick: number): boolean {
        const configuredTimeout = unmodifiableProtocolTimeouts.get(session.protocol);
        if (configuredTimeout !== undefined && configuredTimeout <= 0) {
            return false;
        }

        const fallbackTimeout = unmodifiableProtocolTimeouts.get('default');
        const timeout = configuredTimeout ?? fallbackTimeout;
        if (timeout === undefined || timeout <= 0) {
            return false;
        }
        return tick - session.lastActivity >= timeout;
    }

    function idleThreshold(timeout: number): number {
        const ratio = cfg.idleThresholdRatio;
        if (Number.isFinite(ratio) && ratio > 0) {
            return Math.max(1, Math.floor(timeout * ratio));
        }
        return Math.max(1, Math.floor(timeout / 2));
    }

    function registerMachineSession(session: MutableSession): void {
        const state = getOrCreateMachineState(session.machine);
        state.activeSessions.add(session.id);

        const current = state.userSessionCounts.get(session.user) ?? 0;
        state.userSessionCounts.set(session.user, current + 1);

        if (session.service !== undefined && session.service.length > 0) {
            const serviceCount = state.userServices.get(session.user) ?? new Map<string, number>();
            serviceCount.set(session.service, (serviceCount.get(session.service) ?? 0) + 1);
            state.userServices.set(session.user, serviceCount);
        }
    }

    function unregisterMachineSession(session: MutableSession): void {
        const state = getOrCreateMachineState(session.machine);
        state.activeSessions.delete(session.id);

        const current = state.userSessionCounts.get(session.user) ?? 0;
        if (current <= 1) {
            state.userSessionCounts.delete(session.user);
        } else {
            state.userSessionCounts.set(session.user, current - 1);
        }

        if (session.service !== undefined && session.service.length > 0) {
            const serviceCount = state.userServices.get(session.user) ?? new Map<string, number>();
            const oldCount = serviceCount.get(session.service) ?? 0;
            if (oldCount <= 1) {
                serviceCount.delete(session.service);
            } else {
                serviceCount.set(session.service, oldCount - 1);
            }

            if (serviceCount.size === 0) {
                state.userServices.delete(session.user);
            } else {
                state.userServices.set(session.user, serviceCount);
            }
        }
    }

    function emitCreated(session: Session): void {
        activeBus.emit({
            type: 'custom:session-created',
            data: { session },
            timestamp: startClock(),
        });
    }

    function emitExpired(session: Session, duration: number): void {
        activeBus.emit({
            type: 'custom:session-expired',
            data: { session, duration },
            timestamp: startClock(),
        });
    }

    function emitHijacked(session: Session, oldUser: string, newUser: string): void {
        activeBus.emit({
            type: 'custom:session-hijacked',
            data: { session, oldUser, newUser },
            timestamp: startClock(),
        });
    }

    function emitAuthAnomaly(machine: string, user: string, activeSessions: number): void {
        activeBus.emit({
            type: 'custom:session-anomaly',
            data: { machine, user, activeSessions },
            timestamp: startClock(),
        });
    }

    function cleanupExpiredLockouts(machine: string): void {
        const state = machineStates.get(machine);
        if (state === undefined) return;

        for (const [user, unlockAt] of state.lockoutUntil.entries()) {
            if (currentTick >= unlockAt) {
                state.lockoutUntil.delete(user);
            }
        }
    }

    function isLocked(machine: string, user: string): boolean {
        const state = machineStates.get(machine);
        if (state === undefined) return false;

        const lockedUntil = state.lockoutUntil.get(user);
        return lockedUntil !== undefined && lockedUntil > currentTick;
    }

    function recordFailedLogin(machine: string, user: string): void {
        const state = getOrCreateMachineState(machine);
        state.failedAttempts.set(user, (state.failedAttempts.get(user) ?? 0) + 1);

        const attempts = state.failedAttempts.get(user) ?? 0;
        if (attempts >= cfg.maxFailedAttempts) {
            const unlockedAt = currentTick + cfg.lockoutTicks;
            state.lockoutUntil.set(user, unlockedAt);
        }
    }

    function resetFailedAttempts(machine: string, user: string): void {
        const state = getOrCreateMachineState(machine);
        state.failedAttempts.delete(user);
        state.lockoutUntil.delete(user);
    }

    function getProtocolTimeout(protocol: string): number {
        const timeout = unmodifiableProtocolTimeouts.get(protocol);
        if (timeout !== undefined) {
            return timeout;
        }

        const fallbackTimeout = unmodifiableProtocolTimeouts.get('default');
        if (fallbackTimeout !== undefined) {
            return fallbackTimeout;
        }

        return FALLBACK_PROTOCOL_TIMEOUT;
    }

    function expireSession(session: MutableSession, reason: 'timeout' | 'forced'): void {
        const existing = sessions.get(session.id);
        if (existing === undefined) return;

        unregisterMachineSession(session);
        sessions.delete(session.id);

        const duration = Math.max(0, currentTick - session.startTick);
        durationByUser.set(session.user, (durationByUser.get(session.user) ?? 0) + duration);

        if (reason === 'timeout') {
            session.status = 'expired';
            emitExpired(cloneRecord(session), duration);
        }
    }

    function resolveTimeoutSession(session: MutableSession): boolean {
        if (session.status === 'expired') return false;

        if (isSessionExpired(session, currentTick)) {
            expireSession(session, 'timeout');
            return true;
        }

        const timeout = getProtocolTimeout(session.protocol);
        if (session.status === 'active' && currentTick - session.lastActivity >= idleThreshold(timeout)) {
            session.status = 'idle';
        }

        return false;
    }

    function nextSessionId(machine: string, user: string, protocol: string, credential?: string): string {
        const seed = `${machine}|${protocol}|${user}|${credential ?? ''}`;
        const seq = (sessionSeqBySeed.get(seed) ?? 0) + 1;
        sessionSeqBySeed.set(seed, seq);
        return makeSessionId(seed, seq, machine, user, protocol);
    }

    function createSession(
        machine: string,
        user: string,
        protocol: SessionProtocol,
        credential?: string,
        service?: string,
        metadata: Record<string, unknown> = {},
    ): Session {
        const now = currentTick;
        const normalizedProtocol = normalizeProtocol(protocol);
        const session: MutableSession = {
            id: nextSessionId(machine, user, normalizedProtocol, credential),
            machine,
            user,
            protocol: normalizedProtocol,
            startTick: now,
            lastActivity: now,
            status: 'active',
            ...(metadata['sourceIp'] === undefined ? {} : { sourceIp: String(metadata['sourceIp']) }),
            ...(credential === undefined ? {} : { credential }),
            metadata: {
                createTick: now,
                protocol: normalizedProtocol,
                source: 'module',
                ...metadata,
            },
            ...(service === undefined ? {} : { service }),
        };

        sessions.set(session.id, session);
        registerMachineSession(session);

        const state = getOrCreateMachineState(machine);
        const userActiveSessions = state.userSessionCounts.get(user) ?? 0;
        if (userActiveSessions > cfg.maxConcurrentSessionsPerUser) {
            emitAuthAnomaly(machine, user, userActiveSessions);
        }

        emitCreated(cloneRecord(session));
        return cloneRecord(session);
    }

    function getSession(id: string): Session | undefined {
        const session = sessions.get(id);
        return session === undefined ? undefined : cloneRecord(session);
    }

    function getSessions(filter: SessionFilter): readonly Session[] {
        const out: Session[] = [];
        const machineFilter = filter.machine;
        const userFilter = filter.user;
        const protocolFilter = filter.protocol;
        const statusFilter = filter.status;
        const sourceIpFilter = filter.sourceIp;
        const credentialFilter = filter.credential;
        const minStart = normalizeFilterNumber(filter.minStartTick);
        const maxStart = normalizeFilterNumber(filter.maxStartTick);
        const minLast = normalizeFilterNumber(filter.minLastActivity);
        const maxLast = normalizeFilterNumber(filter.maxLastActivity);

        for (const session of sessions.values()) {
            if (filter.id !== undefined && session.id !== filter.id) continue;
            if (machineFilter !== undefined && session.machine !== machineFilter) continue;
            if (userFilter !== undefined && session.user !== userFilter) continue;
            if (protocolFilter !== undefined && session.protocol !== protocolFilter) continue;
            if (statusFilter !== undefined && session.status !== statusFilter) continue;
            if (sourceIpFilter !== undefined && session.sourceIp !== sourceIpFilter) continue;
            if (credentialFilter !== undefined && session.credential !== credentialFilter) continue;
            if (minStart !== null && session.startTick < minStart) continue;
            if (maxStart !== null && session.startTick > maxStart) continue;
            if (minLast !== null && session.lastActivity < minLast) continue;
            if (maxLast !== null && session.lastActivity > maxLast) continue;
            out.push(cloneRecord(session));
        }

        return Object.freeze(out);
    }

    function destroySession(id: string): void {
        const session = sessions.get(id);
        if (session === undefined) return;
        unregisterMachineSession(session);
        sessions.delete(id);
    }

    function hijackSession(id: string, newUser: string): boolean {
        const session = sessions.get(id);
        if (session === undefined) return false;
        if (session.status === 'expired') return false;
        if (session.user === newUser) return false;

        const oldUser = session.user;
        unregisterMachineSession(session);

        session.user = newUser;
        session.status = 'hijacked';
        session.lastActivity = currentTick;
        session.metadata = {
            ...session.metadata,
            hijackedAtTick: currentTick,
            hijackedFromUser: oldUser,
            hijackReason: 'session-manipulation',
        };

        registerMachineSession(session);
        emitHijacked(cloneRecord(session), oldUser, newUser);
        return true;
    }

    function stealSession(sourceSession: string): Session | null {
        const source = sessions.get(sourceSession);
        if (source === undefined || source.status === 'expired') return null;

        const stolenMetadata = {
            stolenFrom: sourceSession,
            sourceUser: source.user,
            stolenAt: currentTick,
            replayedFrom: sourceSession,
        };
        const stolen = createSession(
            source.machine,
            source.user,
            source.protocol,
            source.credential,
            source.service,
            {
                ...stolenMetadata,
                sourceIp: source.sourceIp,
            },
        );

        source.metadata = {
            ...source.metadata,
            stolenCount: (source.metadata['stolenCount'] as number | undefined)
                ? (source.metadata['stolenCount'] as number) + 1
                : 1,
            lastStealTick: currentTick,
        };

        return stolen;
    }

    function getAuthState(machine: string): MachineAuthState {
        cleanupExpiredLockouts(machine);
        const state = machineStates.get(machine);
        if (state === undefined) {
            return {
                machine,
                loggedInUsers: Object.freeze([]),
                activeSessions: Object.freeze([]),
                failedAttempts: Object.freeze({}),
                lockouts: Object.freeze([]),
                authenticatedServices: Object.freeze({}),
            };
        }

        const loggedInUsers = Object.freeze(
            Array.from(state.userSessionCounts.entries())
                .filter(([, count]) => count > 0)
                .map(([user]) => user)
                .sort(),
        );

        const activeSessions = Object.freeze(
            Array.from(state.activeSessions).filter((sessionId) => sessions.has(sessionId)),
        );

        const failedAttempts = Object.fromEntries(state.failedAttempts.entries());
        const lockouts = Object.freeze(
            Array.from(state.lockoutUntil.entries())
                .filter(([, unlockAt]) => unlockAt > currentTick)
                .map(([user]) => user)
                .sort(),
        );

        const authenticatedServices: Record<string, readonly string[]> = {};
        for (const [user, serviceCountByProtocol] of state.userServices.entries()) {
            authenticatedServices[user] = Object.freeze(Array.from(serviceCountByProtocol.keys()).sort());
        }

        return {
            machine,
            loggedInUsers,
            activeSessions,
            failedAttempts: Object.freeze(failedAttempts),
            lockouts,
            authenticatedServices: Object.freeze(authenticatedServices),
        };
    }

    function processAuthLogin(event: {
        readonly user: string;
        readonly machine: string;
        readonly service: string;
        readonly success: boolean;
        readonly timestamp: number;
        readonly sourceIp?: string;
    }): void {
        if (isLocked(event.machine, event.user)) {
            return;
        }

        if (!event.success) {
            recordFailedLogin(event.machine, event.user);
            return;
        }

        resetFailedAttempts(event.machine, event.user);
        const protocol = normalizeProtocol(event.service);
        createSession(
            event.machine,
            event.user,
            protocol,
            undefined,
            event.service,
            { sourceIp: event.sourceIp, createFromEventAt: event.timestamp, source: 'auth-login', lastEventAt: event.timestamp },
        );
    }

    function processAuthLogout(event: {
        readonly user: string;
        readonly machine: string;
        readonly service?: string;
    }): void {
        const state = getOrCreateMachineState(event.machine);
        const sessionIds = Array.from(state.activeSessions);
        for (const id of sessionIds) {
            const session = sessions.get(id);
            if (session !== undefined && session.user === event.user) {
                if (event.service === undefined || event.service === session.service) {
                    destroySession(id);
                }
            }
        }
    }

    const module: Module & SessionStore = {
        id: MODULE_ID,
        type: 'engine',
        version: MODULE_VERSION,
        description: 'Session management engine component with auth-state tracking and hijacking helpers',

        provides: [
            { name: 'session' },
            { name: 'auth-state' },
        ] as const satisfies readonly Capability[],
        requires: [] as const satisfies readonly Capability[],

        init(context: SimulationContext): void {
            activeBus = context.events;
            currentTick = context.tick;

            const services: ServiceLocator = context.services;
            if (!services.has('session-manager')) {
                services.register('session-manager', serviceStore);
            }

            subscriptions.push(context.events.on('auth:login', (event) => {
                const sourceIp = (event as { sourceIp?: string }).sourceIp;
                processAuthLogin({
                    user: event.user,
                    machine: event.machine,
                    service: event.service,
                    success: event.success,
                    timestamp: event.timestamp,
                    ...(sourceIp !== undefined ? { sourceIp } : {}),
                });
            }));

            subscriptions.push(context.events.on('auth:logout', (event) => {
                const service = (event as { service?: string }).service;
                processAuthLogout({
                    user: event.user,
                    machine: event.machine,
                    ...(service !== undefined ? { service } : {}),
                });
            }));
        },

        destroy(): void {
            for (const unsub of subscriptions) {
                unsub();
            }
            subscriptions.length = 0;
            sessions.clear();
            machineStates.clear();
            sessionSeqBySeed.clear();
            durationByUser.clear();
        },

        onTick(tick: number, _context: SimulationContext): void {
            currentTick = tick;
            for (const machine of machineStates.keys()) {
                cleanupExpiredLockouts(machine);
            }

            const snapshot = Array.from(sessions.values());
            for (const session of snapshot) {
                resolveTimeoutSession(session);
            }
        },

        createSession,
        getSession,
        getSessions,
        destroySession,
        hijackSession,
        stealSession,
        getAuthState,
    };

    return module;
}
