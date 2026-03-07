/**
 * VARIANT — Rule Engine Types
 *
 * Declarative rule evaluation system for:
 *   - Objective completion conditions
 *   - Custom scoring rules
 *   - Defense alert rules (ISL-style)
 *   - Access control rules
 *   - Event correlation rules
 *
 * DESIGN:
 *   Rules are pure data (WorldSpec-compatible). No executable code.
 *   Each rule has:
 *     1. Conditions — what must be true
 *     2. Actions — what happens when conditions are met
 *     3. Configuration — how the rule behaves
 *
 *   Conditions are composed using logical operators (AND, OR, NOT).
 *   The rule engine evaluates conditions against a fact set.
 *
 * CONFIGURABILITY:
 *   - Condition types are extensible via registry
 *   - Action types are extensible via registry
 *   - Rules can be enabled/disabled at runtime
 *   - Rules can fire once or repeatedly
 *
 * SWAPPABILITY: The RuleEngine interface is stable.
 * Replace the implementation without touching consumers.
 */

// ── Facts ───────────────────────────────────────────────────

/**
 * A fact is a key-value pair representing a piece of game state.
 * Facts are the inputs to rule conditions.
 */
export type FactSet = Readonly<Record<string, unknown>>;

// ── Conditions ──────────────────────────────────────────────

/**
 * A condition that can be evaluated against a fact set.
 * Conditions are composable via AND, OR, NOT.
 */
export type RuleCondition =
    | ComparisonCondition
    | LogicalCondition
    | ExistsCondition
    | ContainsCondition
    | MatchCondition
    | CustomCondition;

export interface ComparisonCondition {
    readonly type: 'compare';
    /** Fact key to check. */
    readonly fact: string;
    /** Comparison operator. */
    readonly operator: '==' | '!=' | '>' | '<' | '>=' | '<=';
    /** Value to compare against. */
    readonly value: string | number | boolean;
}

export interface LogicalCondition {
    readonly type: 'and' | 'or' | 'not';
    /** Sub-conditions. For 'not', only the first is used. */
    readonly conditions: readonly RuleCondition[];
}

export interface ExistsCondition {
    readonly type: 'exists';
    /** Fact key to check for existence. */
    readonly fact: string;
}

export interface ContainsCondition {
    readonly type: 'contains';
    /** Fact key (must be a string or array). */
    readonly fact: string;
    /** Value to search for. */
    readonly value: string | number;
}

export interface MatchCondition {
    readonly type: 'match';
    /** Fact key (must be a string). */
    readonly fact: string;
    /** Regex pattern to match. */
    readonly pattern: string;
    /** Regex flags. */
    readonly flags?: string;
}

export interface CustomCondition {
    readonly type: 'custom';
    /** Custom condition type name (looked up in registry). */
    readonly name: string;
    /** Parameters for the custom condition evaluator. */
    readonly params: Readonly<Record<string, unknown>>;
}

// ── Actions ─────────────────────────────────────────────────

/**
 * An action to execute when a rule fires.
 * Actions are dispatched to registered handlers.
 */
export interface RuleAction {
    /** Action type (e.g., 'emit-event', 'set-fact', 'score-points'). */
    readonly type: string;
    /** Action parameters. */
    readonly params: Readonly<Record<string, unknown>>;
}

// ── Rule Definition ─────────────────────────────────────────

/**
 * A complete rule definition.
 * Pure data — WorldSpec-compatible.
 */
export interface RuleDefinition {
    /** Unique rule ID. */
    readonly id: string;

    /** Human-readable name. */
    readonly name: string;

    /** Description of what this rule does. */
    readonly description?: string;

    /** When to evaluate: 'continuous' = every tick, 'event' = on specific events. */
    readonly evaluationMode: 'continuous' | 'event';

    /** For event mode: which event types trigger evaluation. */
    readonly triggerEvents?: readonly string[];

    /** The condition tree. */
    readonly condition: RuleCondition;

    /** Actions to execute when the rule fires. */
    readonly actions: readonly RuleAction[];

    /** Whether this rule can fire more than once. Default: false. */
    readonly repeatable?: boolean;

    /** Priority (higher = evaluated first). Default: 0. */
    readonly priority?: number;

    /** Whether this rule is enabled. Default: true. */
    readonly enabled?: boolean;

    /** Tags for grouping/filtering. */
    readonly tags?: readonly string[];
}

// ── Rule Engine Interface ───────────────────────────────────

/**
 * The rule engine evaluates rules against facts.
 */
export interface RuleEngine {
    /** Add a rule. */
    addRule(rule: RuleDefinition): void;

    /** Remove a rule by ID. */
    removeRule(id: string): boolean;

    /** Get a rule by ID. */
    getRule(id: string): RuleDefinition | undefined;

    /** Get all rules. */
    getAllRules(): readonly RuleDefinition[];

    /** Enable/disable a rule. */
    setRuleEnabled(id: string, enabled: boolean): boolean;

    /**
     * Evaluate all continuous rules against the current fact set.
     * Returns IDs of rules that fired.
     */
    evaluate(facts: FactSet): readonly RuleFiring[];

    /**
     * Evaluate event-triggered rules.
     * Returns IDs of rules that fired.
     */
    evaluateForEvent(eventType: string, facts: FactSet): readonly RuleFiring[];

    /**
     * Evaluate a single condition against facts.
     * Useful for testing conditions in isolation.
     */
    evaluateCondition(condition: RuleCondition, facts: FactSet): boolean;

    /** Reset all fire counters (for rules that have already fired). */
    reset(): void;

    /** Register a custom condition evaluator. */
    registerConditionType(
        name: string,
        evaluator: CustomConditionEvaluator,
    ): void;

    /** Register a custom action handler. */
    registerActionHandler(
        type: string,
        handler: ActionHandler,
    ): void;
}

/**
 * A rule that fired, with its actions.
 */
export interface RuleFiring {
    readonly ruleId: string;
    readonly actions: readonly RuleAction[];
    readonly timestamp: number;
}

/**
 * A custom condition evaluator.
 */
export type CustomConditionEvaluator = (
    params: Readonly<Record<string, unknown>>,
    facts: FactSet,
) => boolean;

/**
 * An action handler — executes an action when a rule fires.
 */
export type ActionHandler = (
    params: Readonly<Record<string, unknown>>,
    facts: FactSet,
) => void;
