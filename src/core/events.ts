/**
 * VARIANT — Event Bus Types
 *
 * The communication backbone for the entire simulation.
 * Every action emits events. Modules subscribe. Nothing is coupled.
 *
 * SECURITY INVARIANT: Events are typed. Modules cannot emit arbitrary
 * event types — only members of the EngineEvent union. Custom events
 * are namespaced under 'custom:' to prevent type confusion.
 *
 * EXTENSIBILITY: Adding a new event type = adding a union member.
 * Existing subscribers are unchanged. TypeScript exhaustiveness
 * checking catches unhandled events at compile time.
 */

// ── Filesystem events ──────────────────────────────────────────
export interface FsReadEvent {
    readonly type: 'fs:read';
    readonly machine: string;
    readonly path: string;
    readonly user: string;
    readonly timestamp: number;
    /** WorldSpec machine ID (set by engine, differs from hostname). */
    readonly worldMachine?: string;
}

export interface FsWriteEvent {
    readonly type: 'fs:write';
    readonly machine: string;
    readonly path: string;
    readonly user: string;
    readonly timestamp: number;
}

export interface FsExecEvent {
    readonly type: 'fs:exec';
    readonly machine: string;
    readonly path: string;
    readonly args: readonly string[];
    readonly user: string;
    readonly timestamp: number;
}

// ── Network events ─────────────────────────────────────────────
export interface NetRequestEvent {
    readonly type: 'net:request';
    readonly method: string;
    readonly url: string;
    readonly source: string;
    readonly destination: string;
    readonly timestamp: number;
}

export interface NetResponseEvent {
    readonly type: 'net:response';
    readonly url: string;
    readonly status: number;
    readonly source: string;
    readonly timestamp: number;
}

export interface NetDnsEvent {
    readonly type: 'net:dns';
    readonly query: string;
    readonly result: string;
    readonly source: string;
    readonly timestamp: number;
}

export interface NetConnectEvent {
    readonly type: 'net:connect';
    readonly host: string;
    readonly port: number;
    readonly source: string;
    readonly protocol: 'tcp' | 'udp' | (string & {});
    readonly timestamp: number;
}

// ── Auth events ────────────────────────────────────────────────
export interface AuthLoginEvent {
    readonly type: 'auth:login';
    readonly user: string;
    readonly machine: string;
    readonly service: string;
    readonly success: boolean;
    readonly timestamp: number;
}

export interface AuthLogoutEvent {
    readonly type: 'auth:logout';
    readonly user: string;
    readonly machine: string;
    readonly service?: string;
    readonly reason?: 'timeout' | 'manual' | 'admin' | (string & {});
    readonly sourceIp?: string;
    readonly timestamp: number;
}

export interface AuthEscalateEvent {
    readonly type: 'auth:escalate';
    readonly machine: string;
    readonly from: string;
    readonly to: string;
    readonly method: string;
    readonly timestamp: number;
    /** WorldSpec machine ID (set by engine, differs from hostname). */
    readonly worldMachine?: string;
}

export interface AuthCredentialFoundEvent {
    readonly type: 'auth:credential-found';
    readonly credentialId: string;
    readonly machine: string;
    readonly location: string;
    readonly timestamp: number;
}

export interface CredentialRegisteredEvent {
    readonly type: 'credential:registered';
    readonly credentialId: string;
    readonly credentialType:
        | 'password'
        | 'ssh-key'
        | 'token'
        | 'hash'
        | 'certificate'
        | 'api-key'
        | 'cookie'
        | 'kerberos-ticket';
    readonly source: {
        readonly module: string;
        readonly machine: string;
        readonly path: string;
        readonly method: string;
        readonly tick: number;
    };
    readonly status: 'raw' | 'cracked' | 'validated' | 'expired';
    readonly timestamp: number;
}

export interface CredentialValidatedEvent {
    readonly type: 'credential:validated';
    readonly credentialId: string;
    readonly credentialType:
        | 'password'
        | 'ssh-key'
        | 'token'
        | 'hash'
        | 'certificate'
        | 'api-key'
        | 'cookie'
        | 'kerberos-ticket';
    readonly target: {
        readonly machine: string;
        readonly service: string;
        readonly user: string;
        readonly port?: number;
    };
    readonly timestamp: number;
}

export interface CredentialChainExtendedEvent {
    readonly type: 'credential:chain-extended';
    readonly parentId: string;
    readonly childId: string;
    readonly mechanism: string;
    readonly tick: number;
    readonly timestamp: number;
}

// ── Objective events ───────────────────────────────────────────
export interface ObjectiveProgressEvent {
    readonly type: 'objective:progress';
    readonly objectiveId: string;
    readonly detail: string;
    readonly timestamp: number;
}

export interface ObjectiveCompleteEvent {
    readonly type: 'objective:complete';
    readonly objectiveId: string;
    readonly timestamp: number;
}

// ── Defense events ─────────────────────────────────────────────
export interface DefenseBreachEvent {
    readonly type: 'defense:breach';
    readonly machine: string;
    readonly vector: string;
    readonly attacker: string;
    readonly timestamp: number;
}

export interface DefenseAlertEvent {
    readonly type: 'defense:alert';
    readonly machine: string;
    readonly ruleId: string;
    readonly severity: 'low' | 'medium' | 'high' | 'critical' | (string & {});
    readonly detail: string;
    readonly timestamp: number;
}

// ── Simulation events ──────────────────────────────────────────
export interface SimTickEvent {
    readonly type: 'sim:tick';
    readonly tick: number;
    readonly timestamp: number;
}

export interface SimAlertEvent {
    readonly type: 'sim:alert';
    readonly source: string;
    readonly message: string;
    readonly timestamp: number;
}

export interface SimNoiseEvent {
    readonly type: 'sim:noise';
    readonly source: string;
    readonly machine: string;
    readonly amount: number;
    readonly timestamp: number;
}

export interface SimGameOverEvent {
    readonly type: 'sim:gameover';
    readonly reason: string;
    readonly timestamp: number;
}

// ── Lens events ────────────────────────────────────────────────
export interface LensOpenEvent {
    readonly type: 'lens:open';
    readonly lensType: string;
    readonly target: string;
    readonly timestamp: number;
}

export interface LensCloseEvent {
    readonly type: 'lens:close';
    readonly lensType: string;
    readonly timestamp: number;
}

// ── Custom events (module-defined) ─────────────────────────────
export interface CustomEvent {
    readonly type: `custom:${string}`;
    readonly data: unknown;
    readonly timestamp: number;
}

// ── Union ──────────────────────────────────────────────────────
export type EngineEvent =
    | FsReadEvent
    | FsWriteEvent
    | FsExecEvent
    | NetRequestEvent
    | NetResponseEvent
    | NetDnsEvent
    | NetConnectEvent
    | AuthLoginEvent
    | AuthLogoutEvent
    | AuthEscalateEvent
    | AuthCredentialFoundEvent
    | CredentialRegisteredEvent
    | CredentialValidatedEvent
    | CredentialChainExtendedEvent
    | ObjectiveProgressEvent
    | ObjectiveCompleteEvent
    | DefenseBreachEvent
    | DefenseAlertEvent
    | SimTickEvent
    | SimAlertEvent
    | SimNoiseEvent
    | SimGameOverEvent
    | LensOpenEvent
    | LensCloseEvent
    | CustomEvent;

// ── Event type extractor ───────────────────────────────────────
export type EventType = EngineEvent['type'];

// ── Subscription ───────────────────────────────────────────────
export type Unsubscribe = () => void;

export type EventHandler<T extends EngineEvent = EngineEvent> = (event: T) => void;

/**
 * Extract the event type matching a given type string.
 * Used for type-safe subscription:
 *   bus.on('auth:login', (event) => { event.user }) // event is AuthLoginEvent
 */
export type EventByType<T extends EventType> = Extract<EngineEvent, { readonly type: T }>;

/**
 * Event bus contract.
 *
 * SECURITY: The event log has a bounded size (configurable) to prevent
 * memory exhaustion from malicious or buggy modules emitting events in a loop.
 *
 * SECURITY: Custom events are namespaced — modules cannot forge core events.
 */
export interface EventBus {
    /**
     * Emit an event to all subscribers.
     * The event is also appended to the event log (bounded).
     */
    emit(event: EngineEvent): void;

    /**
     * Subscribe to events matching a specific type.
     * Returns an unsubscribe function.
     *
     * Pattern matching:
     *   'auth:login'  → exact match
     *   'auth:*'      → prefix match (all auth events)
     *   '*'           → all events
     */
    on<T extends EventType>(type: T, handler: EventHandler<EventByType<T>>): Unsubscribe;

    /**
     * Subscribe to all events matching a prefix.
     */
    onPrefix(prefix: string, handler: EventHandler): Unsubscribe;

    /**
     * Get all logged events, optionally filtered by type prefix.
     */
    getLog(filter?: string): readonly EngineEvent[];

    /**
     * Clear the event log.
     */
    clearLog(): void;

    /**
     * Subscribe to exactly one event of the given type,
     * then auto-unsubscribe. Returns an unsubscribe function
     * that can cancel the subscription before it fires.
     */
    once<T extends EventType>(type: T, handler: EventHandler<EventByType<T>>): Unsubscribe;

    /**
     * Returns a Promise that resolves with the next event
     * matching the given type. Optionally accepts a predicate
     * to filter which event satisfies the wait.
     *
     * Usage:
     *   const event = await bus.waitFor('auth:login');
     *   const rootLogin = await bus.waitFor('auth:login', e => e.user === 'root');
     */
    waitFor<T extends EventType>(
        type: T,
        predicate?: (event: EventByType<T>) => boolean,
    ): Promise<EventByType<T>>;

    /**
     * Remove all subscribers. Used during teardown.
     */
    removeAllListeners(): void;
}
