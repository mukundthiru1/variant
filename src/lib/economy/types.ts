/**
 * VARIANT — Economy Engine Type Definitions
 *
 * Resource constraints that transform cybersecurity from puzzles into
 * management simulation. Every decision has a cost. Every resource
 * is finite. Players must optimize risk-adjusted ROI, not just solve.
 *
 * RESOURCES: budget (dollars), staff (person-hours), patchWindows
 * (scheduled downtime slots), alertCapacity (analyst bandwidth),
 * reputation (organizational trust), custom (open extension).
 *
 * USE CASES:
 * - SOC analyst: triage alerts with limited staff, budget for tools
 * - IR lead: allocate response resources under time pressure
 * - CISO simulation: balance security spend vs business risk
 * - Red team: operate within engagement budget/scope constraints
 *
 * SWAPPABILITY: Implements EconomyEngine interface. Replace this file.
 */

// ── Resource Types ──────────────────────────────────────────────

/** A named resource with current/max values and regeneration. */
export interface ResourceDefinition {
    /** Unique resource ID. */
    readonly id: string;

    /** Human-readable label. */
    readonly label: string;

    /** Resource category for UI grouping. */
    readonly category: ResourceCategory;

    /** Starting amount. */
    readonly initial: number;

    /** Maximum capacity. */
    readonly max: number;

    /** Amount regenerated per tick (0 = no regen). */
    readonly regenPerTick: number;

    /** Whether this resource is visible to the player. */
    readonly visible: boolean;

    /** Unit label for display (e.g., '$', 'hrs', 'slots'). */
    readonly unit: string;

    /** What happens when this resource hits zero. */
    readonly onDepleted: DepletionAction | null;
}

export type ResourceCategory =
    | 'budget'          // monetary resources
    | 'staff'           // personnel bandwidth
    | 'time'            // time windows, maintenance slots
    | 'capacity'        // alert capacity, processing bandwidth
    | 'reputation'      // organizational trust, credibility
    | (string & {});    // open for extensions

export type DepletionAction =
    | { readonly kind: 'game-over'; readonly reason: string }
    | { readonly kind: 'emit-event'; readonly eventType: string; readonly data: Record<string, unknown> }
    | { readonly kind: 'disable-action'; readonly actionId: string }
    | { readonly kind: 'penalty'; readonly amount: number; readonly targetResource: string }
    | { readonly kind: 'custom'; readonly handler: string; readonly params: Record<string, unknown> };

// ── Resource State ──────────────────────────────────────────────

/** Current state of a single resource. */
export interface ResourceState {
    readonly id: string;
    readonly current: number;
    readonly max: number;
    readonly spent: number;       // total spent over session
    readonly earned: number;      // total earned over session
    readonly depleted: boolean;   // hit zero at least once
}

// ── Cost/Income Definitions ─────────────────────────────────────

/** A cost specification — what an action costs to perform. */
export interface ActionCost {
    /** Action ID this cost applies to. */
    readonly actionId: string;

    /** Human-readable action label. */
    readonly label: string;

    /** Resource costs. Key = resource ID, value = amount consumed. */
    readonly costs: Readonly<Record<string, number>>;

    /** Optional: resources produced (e.g., investigation yields intel). */
    readonly produces?: Readonly<Record<string, number>>;

    /** Cooldown in ticks before this action can be used again. */
    readonly cooldownTicks: number;

    /** Whether the player must explicitly confirm this action's cost. */
    readonly requireConfirmation: boolean;
}

/** Recurring income/expense — applied automatically each tick/interval. */
export interface RecurringFlow {
    readonly id: string;
    readonly label: string;

    /** Resource ID to affect. */
    readonly resourceId: string;

    /** Amount per interval (positive = income, negative = expense). */
    readonly amount: number;

    /** Interval in ticks. */
    readonly intervalTicks: number;

    /** Whether this flow is currently active. */
    readonly active: boolean;
}

// ── Transaction Log ─────────────────────────────────────────────

/** A recorded resource transaction. */
export interface ResourceTransaction {
    readonly tick: number;
    readonly resourceId: string;
    readonly amount: number;      // positive = gain, negative = spend
    readonly reason: string;
    readonly actionId: string | null;
    readonly balanceAfter: number;
}

// ── Economy Engine Interface ────────────────────────────────────

/**
 * The economy engine manages all resource constraints.
 *
 * SECURITY: Resources cannot go below 0 (unless explicitly allowed).
 * All transactions are logged for audit/replay.
 *
 * EXTENSIBILITY: Custom resource types and depletion actions can be
 * added without schema changes. The engine is data-driven.
 */
export interface EconomyEngine {
    /** Load resource definitions for a level. */
    loadResources(definitions: readonly ResourceDefinition[]): void;

    /** Load action cost definitions. */
    loadActionCosts(costs: readonly ActionCost[]): void;

    /** Load recurring flows. */
    loadRecurringFlows(flows: readonly RecurringFlow[]): void;

    /** Get current state of a resource. */
    getResource(id: string): ResourceState | null;

    /** Get all resource states. */
    getAllResources(): readonly ResourceState[];

    /** Check if an action can be afforded (all costs met). */
    canAfford(actionId: string): boolean;

    /** Get the cost breakdown for an action. */
    getActionCost(actionId: string): ActionCost | null;

    /**
     * Spend resources for an action. Returns true if successful.
     * Fails if insufficient resources. Logs the transaction.
     */
    spend(actionId: string, tick: number): boolean;

    /**
     * Directly modify a resource (for rewards, penalties, events).
     * Returns the new balance.
     */
    adjust(resourceId: string, amount: number, reason: string, tick: number): number;

    /** Advance the economy by one tick (apply regen, recurring flows). */
    tick(currentTick: number): readonly ResourceTransaction[];

    /** Get transaction history, optionally filtered by resource. */
    getTransactions(resourceId?: string): readonly ResourceTransaction[];

    /** Check if any resource is depleted. */
    hasDepleted(): boolean;

    /** Get all depletion events that occurred this tick. */
    getDepletionEvents(): readonly DepletionAction[];

    /** Toggle a recurring flow on/off. */
    setFlowActive(flowId: string, active: boolean): boolean;

    /** Subscribe to resource changes. */
    onTransaction(handler: (tx: ResourceTransaction) => void): () => void;

    /** Subscribe to depletion events. */
    onDepleted(handler: (resourceId: string, action: DepletionAction | null) => void): () => void;

    /** Reset all resources to initial values. */
    reset(): void;
}
