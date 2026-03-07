/**
 * VARIANT — Hint System Types
 *
 * Progressive hint engine. Hints have tiers (free → expensive),
 * contextual triggers (unlocked after N failed attempts or
 * specific events), and score penalties.
 *
 * Beyond simple "use hint" buttons, the system supports:
 *   - Contextual hints that appear based on player behavior
 *   - Multi-tier hints (nudge → direction → answer)
 *   - Hint cooldowns (can't spam hints)
 *   - Per-objective hints
 *   - Trigger conditions (only show after player tried X)
 *
 * EXTENSIBILITY:
 *   - Custom trigger conditions via the 'custom' type
 *   - Custom hint renderers (text, code snippet, diagram)
 *   - Hint pack plugins that add domain-specific hints
 *
 * SWAPPABILITY: Pure types. No implementation here.
 */

// ── Hint Definition ─────────────────────────────────────────

/**
 * A hint available in a level.
 * Hints are authored in the WorldSpec by level designers.
 */
export interface HintDefinition {
    /** Unique hint ID. */
    readonly id: string;

    /** Which objective this hint helps with. null = general. */
    readonly objectiveId: string | null;

    /** Hint tier — higher = more revealing, higher penalty. */
    readonly tier: HintTier;

    /** Score penalty for using this hint. */
    readonly penalty: number;

    /** The hint content. */
    readonly content: HintContent;

    /**
     * When does this hint become available?
     * null = always available.
     */
    readonly trigger: HintTrigger | null;

    /** Cooldown in ticks before this hint can be used again. */
    readonly cooldownTicks: number;

    /** Display order within the same objective/tier. */
    readonly order: number;
}

export type HintTier =
    | 'nudge'       // Very subtle — "Have you looked at the config?"
    | 'direction'   // Points the right way — "Check the SQL query on /login"
    | 'technique'   // Names the technique — "Try SQL injection with UNION"
    | 'solution';   // Gives the answer — "Use ' UNION SELECT * FROM users --"

export interface HintContent {
    /** Short title shown in the hint list. */
    readonly title: string;

    /** Full hint text revealed when used. */
    readonly text: string;

    /** Optional code snippet. */
    readonly code?: string;

    /** Optional diagram/visual reference. */
    readonly visual?: string;

    /** Category tag for filtering. */
    readonly category: string;
}

// ── Hint Triggers ───────────────────────────────────────────

export type HintTrigger =
    | TickTrigger
    | AttemptsTrigger
    | EventTrigger
    | ObjectiveTrigger
    | CompoundTrigger
    | CustomTrigger;

export interface TickTrigger {
    readonly kind: 'after-ticks';
    /** Hint unlocks after this many ticks have passed. */
    readonly ticks: number;
}

export interface AttemptsTrigger {
    readonly kind: 'after-attempts';
    /** Hint unlocks after the player has tried N commands. */
    readonly attempts: number;
    /** Optional: only count attempts matching this pattern. */
    readonly commandPattern?: string;
}

export interface EventTrigger {
    readonly kind: 'after-event';
    /** Hint unlocks after this event type has been emitted. */
    readonly eventType: string;
    /** Optional: match specific event data. */
    readonly matchData?: Readonly<Record<string, unknown>>;
}

export interface ObjectiveTrigger {
    readonly kind: 'after-objective';
    /** Hint unlocks after this objective is completed. */
    readonly objectiveId: string;
}

export interface CompoundTrigger {
    readonly kind: 'compound';
    /** All conditions must be met. */
    readonly conditions: readonly HintTrigger[];
}

export interface CustomTrigger {
    readonly kind: 'custom';
    readonly type: string;
    readonly config: Readonly<Record<string, unknown>>;
}

// ── Hint Engine ─────────────────────────────────────────────

export interface HintState {
    /** Is this hint available (trigger met)? */
    readonly available: boolean;
    /** Has this hint been used? */
    readonly used: boolean;
    /** Tick when last used (for cooldown). */
    readonly lastUsedTick: number | null;
    /** Number of times used. */
    readonly useCount: number;
}

export interface HintEngine {
    /** Register hints from a level spec. */
    loadHints(hints: readonly HintDefinition[]): void;

    /** Get all hints for an objective (or general hints if null). */
    getHintsForObjective(objectiveId: string | null): readonly HintDefinition[];

    /** Get the state of a specific hint. */
    getHintState(hintId: string): HintState | null;

    /** Get all available (unlocked, not on cooldown) hints. */
    getAvailableHints(): readonly HintDefinition[];

    /** Use a hint. Returns the content, or null if not available. */
    useHint(hintId: string, currentTick: number): HintContent | null;

    /** Evaluate triggers against current simulation state. */
    evaluateTriggers(currentTick: number, commandCount: number, completedObjectives: ReadonlySet<string>): void;

    /** Notify the engine about an event (for event triggers). */
    notifyEvent(eventType: string, eventData: unknown): void;

    /** Get total penalty incurred from hints. */
    getTotalPenalty(): number;

    /** Reset all hint state. */
    reset(): void;
}
