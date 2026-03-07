/**
 * VARIANT — Configurable State Machine Types
 *
 * A reusable finite state machine primitive for modeling:
 *   - Machine compromise states (clean → scanned → exploited → owned)
 *   - Alert levels (green → yellow → orange → red)
 *   - Attack phases (recon → initial-access → lateral → exfil)
 *   - Any custom game state transitions
 *
 * CONFIGURABILITY:
 *   - States, transitions, and guards are all data-driven
 *   - Transition guards are pure functions (no side effects)
 *   - Entry/exit actions emit events
 *   - State machines can be composed hierarchically
 *
 * SWAPPABILITY: The StateMachine interface is the only contract.
 * Replace the implementation without touching consumers.
 */

// ── State Definition ────────────────────────────────────────

/**
 * A state in the state machine.
 */
export interface StateDefinition {
    /** Unique state ID within this machine. */
    readonly id: string;

    /** Human-readable label. */
    readonly label: string;

    /** Optional metadata for UI rendering. */
    readonly metadata?: Readonly<Record<string, unknown>>;

    /** Tags for querying/filtering states. */
    readonly tags?: readonly string[];
}

// ── Transition Definition ───────────────────────────────────

/**
 * A transition between states.
 */
export interface TransitionDefinition {
    /** Unique transition ID. */
    readonly id: string;

    /** Source state ID. */
    readonly from: string;

    /** Target state ID. */
    readonly to: string;

    /** Event type that triggers this transition. */
    readonly trigger: string;

    /** Optional guard condition (must return true to allow transition). */
    readonly guard?: TransitionGuard;

    /** Optional priority (higher = checked first when multiple transitions match). */
    readonly priority?: number;

    /** Description of this transition. */
    readonly description?: string;
}

/**
 * A guard function that determines whether a transition is allowed.
 * Receives the current context (arbitrary data from the trigger).
 */
export type TransitionGuard = (context: Readonly<Record<string, unknown>>) => boolean;

// ── State Machine Configuration ─────────────────────────────

/**
 * Complete state machine configuration.
 * Pure data — no executable code except guard functions.
 */
export interface StateMachineConfig {
    /** Unique state machine ID. */
    readonly id: string;

    /** Human-readable name. */
    readonly name: string;

    /** All states. */
    readonly states: readonly StateDefinition[];

    /** All transitions. */
    readonly transitions: readonly TransitionDefinition[];

    /** Initial state ID. */
    readonly initialState: string;

    /** Optional: state IDs that are terminal (no outgoing transitions). */
    readonly terminalStates?: readonly string[];
}

// ── State Machine Interface ─────────────────────────────────

/**
 * A running state machine instance.
 */
export interface StateMachine {
    /** The machine configuration ID. */
    readonly id: string;

    /** Get the current state. */
    getCurrentState(): StateDefinition;

    /** Get the current state ID. */
    getCurrentStateId(): string;

    /**
     * Attempt a transition triggered by an event.
     * Returns the new state if the transition succeeded,
     * or null if no valid transition exists.
     */
    transition(
        trigger: string,
        context?: Readonly<Record<string, unknown>>,
    ): StateDefinition | null;

    /**
     * Get available transitions from the current state.
     */
    getAvailableTransitions(): readonly TransitionDefinition[];

    /**
     * Get available transitions that pass their guards.
     */
    getValidTransitions(
        context?: Readonly<Record<string, unknown>>,
    ): readonly TransitionDefinition[];

    /**
     * Check if a specific transition is valid right now.
     */
    canTransition(
        trigger: string,
        context?: Readonly<Record<string, unknown>>,
    ): boolean;

    /**
     * Check if the machine is in a terminal state.
     */
    isTerminal(): boolean;

    /**
     * Get the transition history.
     */
    getHistory(): readonly TransitionRecord[];

    /**
     * Reset the machine to its initial state.
     */
    reset(): void;

    /**
     * Subscribe to state changes.
     */
    onTransition(listener: TransitionListener): () => void;

    /**
     * Get the machine configuration.
     */
    getConfig(): StateMachineConfig;
}

/**
 * Record of a transition that occurred.
 */
export interface TransitionRecord {
    readonly transitionId: string;
    readonly from: string;
    readonly to: string;
    readonly trigger: string;
    readonly timestamp: number;
    readonly context?: Readonly<Record<string, unknown>>;
}

/**
 * Listener called when a transition occurs.
 */
export type TransitionListener = (record: TransitionRecord) => void;

// ── State Machine Registry ──────────────────────────────────

/**
 * Registry for managing multiple state machines.
 * Each machine instance is identified by a composite key (machineId + instanceId).
 */
export interface StateMachineRegistry {
    /** Register a state machine configuration. */
    registerConfig(config: StateMachineConfig): void;

    /** Create a new instance from a registered config. */
    createInstance(configId: string, instanceId: string): StateMachine;

    /** Get an instance by its composite key. */
    getInstance(configId: string, instanceId: string): StateMachine | undefined;

    /** Get all instances of a config. */
    getInstances(configId: string): readonly StateMachine[];

    /** Destroy an instance. */
    destroyInstance(configId: string, instanceId: string): boolean;

    /** List all registered config IDs. */
    listConfigs(): readonly string[];

    /** Get a registered config. */
    getConfig(id: string): StateMachineConfig | undefined;
}
