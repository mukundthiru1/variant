/**
 * VARIANT — Stealth System Types
 *
 * Maps player actions to noise events. Every command, network
 * request, and file access has a noise signature. The stealth
 * system aggregates noise and determines detection probability.
 *
 * EXTENSIBILITY: NoiseProfile is open — third-party modules
 * register custom noise rules via the NoiseRuleRegistry.
 *
 * MODULARITY: The stealth system is a pure function layer.
 * It receives events, computes noise, emits sim:noise events.
 * Swap this module without touching anything else.
 */

// ── Noise Categories ────────────────────────────────────────

export type NoiseCategory =
    | 'reconnaissance'     // port scans, directory enum, DNS queries
    | 'credential-access'  // brute force, password spray
    | 'exploitation'       // exploit payloads, injection attempts
    | 'lateral-movement'   // SSH to new host, pivoting
    | 'exfiltration'       // large data transfers, DNS tunneling
    | 'persistence'        // cron jobs, service installs
    | 'privilege-escalation' // sudo, SUID exploitation
    | 'defense-evasion'    // log deletion, timestamp manipulation
    | 'command-control'    // C2 callbacks, reverse shells
    | (string & {});       // open union for extensibility

// ── Noise Rule ──────────────────────────────────────────────

/**
 * A noise rule defines how a specific action generates noise.
 *
 * Rules are matched against events by type + optional conditions.
 * When matched, they produce a noise amount that accumulates
 * on the player's noise meter.
 */
export interface NoiseRule {
    /** Unique rule ID. Convention: 'category/action'. */
    readonly id: string;

    /** Human-readable description. */
    readonly description: string;

    /** Noise category for grouping and reporting. */
    readonly category: NoiseCategory;

    /**
     * Event type to match. Supports prefix matching:
     * 'net:connect'  — exact match
     * 'net:*'        — all net events
     */
    readonly eventPattern: string;

    /**
     * Optional condition function. Receives the event and returns
     * true if the rule should fire. Allows fine-grained matching
     * (e.g., only fire for port scans above a threshold).
     */
    readonly condition?: NoiseCondition;

    /**
     * Base noise amount (0-100). Higher = louder.
     * Actual noise is modified by the player's stealth modifiers.
     */
    readonly baseNoise: number;

    /**
     * Cooldown in milliseconds. If set, this rule won't fire
     * again within the cooldown window. Prevents noise spam
     * from rapid repeated actions.
     */
    readonly cooldownMs?: number;

    /**
     * If true, noise scales with the number of events in a window.
     * E.g., one SSH attempt = low noise, 100 attempts = high noise.
     */
    readonly scalable?: boolean;

    /**
     * Scale factor for scalable rules. Noise = baseNoise * log2(count) * scaleFactor.
     * Default: 1.0.
     */
    readonly scaleFactor?: number;

    /**
     * Window size in ms for counting events (scalable rules).
     * Default: 60000 (1 minute).
     */
    readonly windowMs?: number;
}

/**
 * Condition predicate for noise rules.
 * Receives the raw event data and returns whether the rule matches.
 */
export type NoiseCondition = (eventData: Readonly<Record<string, unknown>>) => boolean;

// ── Stealth Profile ─────────────────────────────────────────

/**
 * A stealth profile defines modifiers that reduce noise
 * from certain categories. Tools and techniques can grant
 * stealth bonuses.
 */
export interface StealthModifier {
    /** ID of the modifier. */
    readonly id: string;

    /** Description. */
    readonly description: string;

    /**
     * Categories this modifier reduces noise for.
     * '*' = all categories.
     */
    readonly categories: readonly (NoiseCategory | '*')[];

    /**
     * Multiplier applied to noise. 0.0 = silent, 1.0 = no change, 2.0 = double noise.
     * Must be >= 0.
     */
    readonly multiplier: number;

    /** Whether this modifier is currently active. */
    readonly active: boolean;
}

// ── Noise State ─────────────────────────────────────────────

/**
 * Current noise state, tracked per-machine and aggregated globally.
 */
export interface NoiseState {
    /** Total accumulated noise across all categories. */
    readonly totalNoise: number;

    /** Noise breakdown by category. */
    readonly byCategory: Readonly<Record<string, number>>;

    /** Noise breakdown by machine. */
    readonly byMachine: Readonly<Record<string, number>>;

    /** Detection probability (0-1). Derived from total noise. */
    readonly detectionProbability: number;

    /** Whether the player has been detected. */
    readonly detected: boolean;

    /** Active stealth modifiers. */
    readonly activeModifiers: readonly StealthModifier[];

    /** History of noise events (bounded). */
    readonly history: readonly NoiseEntry[];
}

/**
 * A single noise entry in the history.
 */
export interface NoiseEntry {
    readonly timestamp: number;
    readonly ruleId: string;
    readonly category: NoiseCategory;
    readonly rawNoise: number;
    readonly adjustedNoise: number;
    readonly machine: string;
    readonly eventType: string;
}

// ── Detection Thresholds ────────────────────────────────────

/**
 * Configurable detection thresholds.
 * These control when the defender AI "notices" the player.
 */
export interface DetectionConfig {
    /**
     * Noise threshold for detection probability calculation.
     * Below this, detection probability is 0.
     * Default: 50.
     */
    readonly noiseFloor: number;

    /**
     * Noise level at which detection is certain (probability = 1.0).
     * Default: 500.
     */
    readonly noiseCeiling: number;

    /**
     * Detection curve. How detection probability scales between
     * floor and ceiling.
     * 'linear' — linear interpolation
     * 'quadratic' — slow start, fast finish
     * 'logarithmic' — fast start, slow finish
     * Default: 'quadratic'.
     */
    readonly curve: 'linear' | 'quadratic' | 'logarithmic';

    /**
     * Noise decay rate per tick. Noise slowly decreases over time
     * if the player is quiet.
     * Default: 1.0 per tick.
     */
    readonly decayPerTick: number;

    /**
     * Maximum history entries to retain.
     * Default: 1000.
     */
    readonly maxHistory: number;
}

// ── Noise Rule Registry ─────────────────────────────────────

/**
 * Registry for noise rules. Append-only to prevent
 * rule poisoning at runtime.
 */
export interface NoiseRuleRegistry {
    /** Register a noise rule. Throws if ID already exists. */
    register(rule: NoiseRule): void;

    /** Register multiple rules at once. */
    registerAll(rules: readonly NoiseRule[]): void;

    /** Get a rule by ID. */
    get(id: string): NoiseRule | undefined;

    /** Get all rules. */
    getAll(): readonly NoiseRule[];

    /** Get rules matching an event type. */
    getMatchingRules(eventType: string): readonly NoiseRule[];

    /** Get rules by category. */
    getByCategory(category: NoiseCategory): readonly NoiseRule[];
}
