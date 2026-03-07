/**
 * VARIANT — Timer/Clock System Types
 *
 * Manages simulation time: real-time vs sim-time separation,
 * countdowns, time-limited objectives, and speed control.
 *
 * The timer system is what creates urgency. A defense scenario
 * with "defend for 300 ticks" needs a visible countdown.
 * A stealth mission with "extract within 5 minutes" needs
 * a real-time clock.
 *
 * DESIGN:
 *   - SimTime (ticks) and WallTime (ms) are independent
 *   - Speed multiplier controls the ratio
 *   - Named timers can be created/destroyed at runtime
 *   - Countdown timers fire events on expiry
 *   - Stopwatch timers measure elapsed time
 *
 * EXTENSIBILITY:
 *   - Custom timer types
 *   - Timer-triggered events
 *   - Time-based scoring modifiers
 *
 * SWAPPABILITY: Pure types. No implementation here.
 */

// ── Timer Types ─────────────────────────────────────────────

export type TimerType =
    | 'countdown'   // Counts down to zero, fires on expiry
    | 'stopwatch'   // Counts up, measures duration
    | 'interval'    // Fires repeatedly at interval
    | 'oneshot';    // Fires once after delay

export type TimerState = 'running' | 'paused' | 'expired' | 'stopped';

export interface TimerDefinition {
    /** Unique timer ID. */
    readonly id: string;

    /** Human-readable label. */
    readonly label: string;

    /** Timer type. */
    readonly type: TimerType;

    /** Duration in ticks (for countdown/oneshot). */
    readonly durationTicks: number;

    /** Interval in ticks (for interval timers). */
    readonly intervalTicks: number;

    /** Auto-start when created? */
    readonly autoStart: boolean;

    /** Is this timer visible to the player? */
    readonly visible: boolean;

    /** What happens when this timer expires. */
    readonly onExpiry: TimerExpiry | null;

    /** Warning thresholds (tick counts remaining) for visual alerts. */
    readonly warnings: readonly number[];
}

// ── Timer Expiry Actions ────────────────────────────────────

export type TimerExpiry =
    | GameOverExpiry
    | EventExpiry
    | ObjectiveExpiry
    | CustomExpiry;

export interface GameOverExpiry {
    readonly kind: 'game-over';
    readonly reason: string;
}

export interface EventExpiry {
    readonly kind: 'emit-event';
    readonly eventType: string;
    readonly eventData: unknown;
}

export interface ObjectiveExpiry {
    readonly kind: 'fail-objective';
    readonly objectiveId: string;
}

export interface CustomExpiry {
    readonly kind: 'custom';
    readonly type: string;
    readonly config: Readonly<Record<string, unknown>>;
}

// ── Timer Instance ──────────────────────────────────────────

export interface TimerInstance {
    readonly id: string;
    readonly label: string;
    readonly type: TimerType;
    readonly state: TimerState;
    readonly visible: boolean;

    /** Ticks elapsed since start. */
    readonly elapsedTicks: number;

    /** Ticks remaining (countdown only). */
    readonly remainingTicks: number;

    /** Total duration in ticks. */
    readonly durationTicks: number;

    /** Progress as 0.0-1.0 (elapsed/duration). */
    readonly progress: number;

    /** How many times this timer has fired (interval). */
    readonly fireCount: number;

    /** Is the timer in warning zone? */
    readonly warning: boolean;
}

// ── Timer Clock ─────────────────────────────────────────────

export interface TimerClock {
    /** Create a timer from a definition. */
    create(definition: TimerDefinition): TimerInstance;

    /** Start a timer. */
    start(timerId: string): boolean;

    /** Pause a timer. */
    pause(timerId: string): boolean;

    /** Resume a paused timer. */
    resume(timerId: string): boolean;

    /** Stop and reset a timer. */
    stop(timerId: string): boolean;

    /** Remove a timer entirely. */
    remove(timerId: string): boolean;

    /** Get a timer instance. */
    get(timerId: string): TimerInstance | null;

    /** Get all timers. */
    getAll(): readonly TimerInstance[];

    /** Get all visible timers (for UI). */
    getVisible(): readonly TimerInstance[];

    /**
     * Advance all running timers by one tick.
     * Returns IDs of timers that expired or fired.
     */
    tick(): readonly TimerEvent[];

    /** Subscribe to timer events. */
    onTimer(handler: (event: TimerEvent) => void): () => void;

    /** Clear all timers. */
    clear(): void;
}

// ── Timer Events ────────────────────────────────────────────

export type TimerEventKind = 'expired' | 'fired' | 'warning' | 'started' | 'paused' | 'resumed' | 'stopped';

export interface TimerEvent {
    readonly timerId: string;
    readonly kind: TimerEventKind;
    readonly tick: number;
    readonly expiry: TimerExpiry | null;
}
