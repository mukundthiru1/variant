/**
 * VARIANT — Event Correlation Engine Types
 *
 * Detects complex multi-event patterns by correlating events
 * across time windows. Used for:
 *   - Attack chain detection (scan → exploit → escalate)
 *   - Behavioral anomaly detection (N failed logins in T seconds)
 *   - Multi-step objective completion tracking
 *   - SIEM-style alert correlation
 *
 * DESIGN:
 *   Correlation rules define event sequences with timing constraints.
 *   The engine maintains sliding windows of events and matches
 *   them against registered patterns.
 *
 * CONFIGURABILITY:
 *   - Window sizes, thresholds, and patterns are all configurable
 *   - Correlation strategies are swappable (sequence, threshold, unique)
 *   - Custom matchers can be registered
 *
 * SWAPPABILITY: The CorrelationEngine interface is the only contract.
 */

// ── Correlation Rule ────────────────────────────────────────

/**
 * A correlation rule defines a pattern of events to detect.
 */
export interface CorrelationRule {
    /** Unique rule ID. */
    readonly id: string;

    /** Human-readable name. */
    readonly name: string;

    /** Description. */
    readonly description?: string;

    /** The correlation strategy. */
    readonly strategy: CorrelationStrategy;

    /** Time window in milliseconds. Events outside the window are discarded. */
    readonly windowMs: number;

    /** What to do when the pattern matches. */
    readonly actions: readonly CorrelationAction[];

    /** Whether this rule can fire more than once. Default: true. */
    readonly repeatable?: boolean;

    /** Cooldown in milliseconds between firings. Default: 0. */
    readonly cooldownMs?: number;

    /** Whether this rule is enabled. Default: true. */
    readonly enabled?: boolean;

    /** Severity when this rule fires. */
    readonly severity?: 'info' | 'low' | 'medium' | 'high' | 'critical';

    /** Tags for filtering. */
    readonly tags?: readonly string[];
}

// ── Correlation Strategies ──────────────────────────────────

export type CorrelationStrategy =
    | SequenceStrategy
    | ThresholdStrategy
    | UniqueStrategy;

/**
 * Sequence: events must occur in a specific order within the window.
 * Example: port-scan → exploit-attempt → privilege-escalation
 */
export interface SequenceStrategy {
    readonly type: 'sequence';
    /** Ordered list of event type patterns to match. */
    readonly steps: readonly SequenceStep[];
    /** Whether all steps must come from the same source. */
    readonly sameSource?: boolean;
}

export interface SequenceStep {
    /** Event type to match (exact or prefix with *). */
    readonly eventType: string;
    /** Optional: fact conditions on the event. */
    readonly conditions?: readonly StepCondition[];
}

export interface StepCondition {
    /** Field path in the event object. */
    readonly field: string;
    /** Comparison operator. */
    readonly operator: '==' | '!=' | 'contains' | 'matches';
    /** Value to compare against. */
    readonly value: string | number | boolean;
}

/**
 * Threshold: fires when N events of a type occur within the window.
 * Example: 5 failed logins within 60 seconds
 */
export interface ThresholdStrategy {
    readonly type: 'threshold';
    /** Event type to count. */
    readonly eventType: string;
    /** Minimum count to trigger. */
    readonly threshold: number;
    /** Optional: group by a field (e.g., sourceIP). */
    readonly groupBy?: string;
    /** Optional: conditions each event must meet. */
    readonly conditions?: readonly StepCondition[];
}

/**
 * Unique: fires when N unique values of a field are seen within the window.
 * Example: connections to 10 unique ports within 30 seconds (port scan)
 */
export interface UniqueStrategy {
    readonly type: 'unique';
    /** Event type to watch. */
    readonly eventType: string;
    /** Field to extract unique values from. */
    readonly uniqueField: string;
    /** Minimum unique count to trigger. */
    readonly threshold: number;
    /** Optional: group by a field. */
    readonly groupBy?: string;
}

// ── Correlation Actions ─────────────────────────────────────

export interface CorrelationAction {
    /** Action type. */
    readonly type: string;
    /** Action parameters. */
    readonly params: Readonly<Record<string, unknown>>;
}

// ── Correlation Engine Interface ────────────────────────────

/**
 * An event for the correlation engine to process.
 */
export interface CorrelationEvent {
    /** Event type string. */
    readonly type: string;
    /** Timestamp in milliseconds. */
    readonly timestamp: number;
    /** Event data fields. */
    readonly fields: Readonly<Record<string, unknown>>;
}

/**
 * Result of a correlation match.
 */
export interface CorrelationMatch {
    readonly ruleId: string;
    readonly ruleName: string;
    readonly severity: string;
    readonly matchedEvents: readonly CorrelationEvent[];
    readonly timestamp: number;
    readonly actions: readonly CorrelationAction[];
}

/**
 * The correlation engine.
 */
export interface CorrelationEngine {
    /** Add a correlation rule. */
    addRule(rule: CorrelationRule): void;

    /** Remove a rule by ID. */
    removeRule(id: string): boolean;

    /** Get all rules. */
    getRules(): readonly CorrelationRule[];

    /** Enable/disable a rule. */
    setRuleEnabled(id: string, enabled: boolean): boolean;

    /**
     * Process an event. Returns any matches that fired.
     */
    processEvent(event: CorrelationEvent): readonly CorrelationMatch[];

    /** Get recent matches. */
    getRecentMatches(limit?: number): readonly CorrelationMatch[];

    /** Clear all event windows and match history. */
    reset(): void;

    /** Register a custom action handler. */
    registerActionHandler(
        type: string,
        handler: (params: Readonly<Record<string, unknown>>, match: CorrelationMatch) => void,
    ): void;
}
