/**
 * VARIANT — Objective Evaluator Registry
 *
 * Pluggable objective evaluation. The built-in objective detector
 * handles 'find-file', 'read-data', 'escalate', etc. But the
 * 'custom' objective type delegates to this registry.
 *
 * Third-party packages register their own evaluators here.
 * Level designers reference them in WorldSpec by evaluator ID.
 * Adding a new objective type = register an evaluator.
 * Zero core changes.
 *
 * SECURITY: Evaluators receive a read-only SimulationContext.
 * They return a result — they cannot mutate the simulation.
 *
 * EXTENSIBILITY:
 *   - Register evaluators by string ID
 *   - Evaluators receive arbitrary params from ObjectiveSpec
 *   - Evaluators subscribe to events and emit completion
 *   - Evaluators can be async (for complex multi-step objectives)
 */

import type { EventBus, Unsubscribe } from '../core/events';

// ── Evaluator Types ────────────────────────────────────────────

/**
 * Result of an objective evaluation.
 */
export interface ObjectiveEvaluationResult {
    /** Whether the objective is complete. */
    readonly completed: boolean;
    /** Progress string for the player (e.g., '2/3 flags found'). */
    readonly progress?: string;
    /** Score multiplier (1.0 = normal, >1 for bonus, <1 for penalty). */
    readonly scoreMultiplier?: number;
    /** Additional data for the scoring engine. */
    readonly metadata?: Readonly<Record<string, unknown>>;
}

/**
 * Context provided to objective evaluators.
 * Read-only simulation access + event bus subscription.
 */
export interface ObjectiveEvaluatorContext {
    readonly events: EventBus;
    /** Subscribe to an event type. Returns unsubscribe function. */
    subscribe(eventType: string, handler: (event: Readonly<Record<string, unknown>>) => void): Unsubscribe;
    /** Emit objective progress. */
    reportProgress(progress: string): void;
    /** Mark the objective as complete. */
    markComplete(result?: Partial<ObjectiveEvaluationResult>): void;
}

/**
 * An objective evaluator.
 * Receives params from the WorldSpec and a context.
 * Subscribes to events, evaluates conditions, and reports completion.
 */
export interface ObjectiveEvaluator {
    /** Unique evaluator ID. */
    readonly id: string;
    /** Human-readable name. */
    readonly displayName: string;
    /** Description of what this evaluator checks. */
    readonly description: string;

    /**
     * Start evaluating. Called when the objective is initialized.
     * The evaluator subscribes to events and evaluates conditions.
     * Returns a cleanup function called when the objective is done.
     */
    start(
        params: Readonly<Record<string, string | number | boolean>>,
        ctx: ObjectiveEvaluatorContext,
    ): (() => void) | void;
}

// ── Evaluator Registry ─────────────────────────────────────────

/**
 * Registry for objective evaluators.
 * The objective detector queries this to instantiate custom evaluators.
 */
export interface ObjectiveEvaluatorRegistry {
    /** Register an evaluator. Append-only. */
    register(evaluator: ObjectiveEvaluator): void;
    /** Get an evaluator by ID. */
    get(id: string): ObjectiveEvaluator | undefined;
    /** Check if an evaluator is registered. */
    has(id: string): boolean;
    /** List all registered evaluator IDs. */
    list(): readonly string[];
    /** Get all evaluator metadata. */
    getAll(): readonly ObjectiveEvaluator[];
}

/**
 * Create an objective evaluator registry.
 */
export function createObjectiveEvaluatorRegistry(): ObjectiveEvaluatorRegistry {
    const evaluators = new Map<string, ObjectiveEvaluator>();

    return {
        register(evaluator: ObjectiveEvaluator): void {
            if (evaluators.has(evaluator.id)) {
                throw new Error(
                    `ObjectiveEvaluatorRegistry: evaluator '${evaluator.id}' is already registered. ` +
                    `Evaluator registrations are append-only.`,
                );
            }
            if (evaluator.id.length === 0) {
                throw new Error('ObjectiveEvaluatorRegistry: evaluator ID must be non-empty.');
            }
            evaluators.set(evaluator.id, evaluator);
        },

        get(id: string): ObjectiveEvaluator | undefined {
            return evaluators.get(id);
        },

        has(id: string): boolean {
            return evaluators.has(id);
        },

        list(): readonly string[] {
            return Object.freeze(Array.from(evaluators.keys()));
        },

        getAll(): readonly ObjectiveEvaluator[] {
            return Object.freeze(Array.from(evaluators.values()));
        },
    };
}

// ── Built-in Evaluators ────────────────────────────────────────

/**
 * Register built-in objective evaluators.
 * These are available for all levels without additional configuration.
 */
export function registerBuiltinEvaluators(registry: ObjectiveEvaluatorRegistry): void {
    // Detect when player reads a specific file
    registry.register({
        id: 'detect-file-read',
        displayName: 'File Read Detector',
        description: 'Completes when the player reads a specific file on a specific machine',
        start(params, ctx) {
            const targetPath = params['path'] as string;
            const targetMachine = params['machine'] as string;

            const unsub = ctx.subscribe('fs:read', (event) => {
                if (event['path'] === targetPath && event['machine'] === targetMachine) {
                    ctx.markComplete();
                }
            });

            return unsub;
        },
    });

    // Detect when player executes a specific command
    registry.register({
        id: 'detect-command',
        displayName: 'Command Detector',
        description: 'Completes when the player executes a command matching a pattern',
        start(params, ctx) {
            const pattern = params['pattern'] as string;
            const regex = new RegExp(pattern);

            const unsub = ctx.subscribe('shell:command', (event) => {
                if (regex.test(String(event['command'] ?? ''))) {
                    ctx.markComplete();
                }
            });

            return unsub;
        },
    });

    // Detect network traffic between specific machines
    registry.register({
        id: 'detect-traffic',
        displayName: 'Traffic Detector',
        description: 'Completes when specific network traffic is observed',
        start(params, ctx) {
            const fromIP = params['fromIP'] as string;
            const toIP = params['toIP'] as string;
            const port = params['port'] as number;

            const unsub = ctx.subscribe('net:packet', (event) => {
                if (event['sourceIP'] === fromIP && event['destIP'] === toIP && event['destPort'] === port) {
                    ctx.markComplete();
                }
            });

            return unsub;
        },
    });

    // Multi-step: collect N items
    registry.register({
        id: 'collect-items',
        displayName: 'Item Collector',
        description: 'Completes when N items matching a pattern are found',
        start(params, ctx) {
            const targetEvent = params['event'] as string;
            const requiredCount = params['count'] as number;
            const collected = new Set<string>();

            const unsub = ctx.subscribe(targetEvent, (event) => {
                const itemId = String(event['itemId'] ?? event['path'] ?? event['id'] ?? JSON.stringify(event));
                collected.add(itemId);
                ctx.reportProgress(`${collected.size}/${requiredCount} collected`);

                if (collected.size >= requiredCount) {
                    ctx.markComplete();
                }
            });

            return unsub;
        },
    });

    // Time-based: survive for N ticks without triggering a condition
    registry.register({
        id: 'survive-clean',
        displayName: 'Clean Survival',
        description: 'Completes when the player survives N ticks without triggering a failure event',
        start(params, ctx) {
            const duration = params['ticks'] as number;
            const failureEvent = params['failureEvent'] as string;
            let failed = false;
            let tickCount = 0;

            const unsubFail = ctx.subscribe(failureEvent, () => {
                failed = true;
            });

            const unsubTick = ctx.subscribe('sim:tick', () => {
                if (failed) return;
                tickCount++;
                ctx.reportProgress(`${tickCount}/${duration} ticks survived`);

                if (tickCount >= duration) {
                    ctx.markComplete();
                }
            });

            return () => {
                unsubFail();
                unsubTick();
            };
        },
    });

    // Detect phishing awareness (player correctly identifies malicious emails)
    registry.register({
        id: 'phishing-detection',
        displayName: 'Phishing Detection',
        description: 'Completes when the player correctly flags malicious emails without falling for them',
        start(params, ctx) {
            const requiredFlags = (params['requiredFlags'] as number) ?? 1;
            let correctFlags = 0;
            let fellForPhishing = false;

            const unsubFlag = ctx.subscribe('service:custom', (event) => {
                if (event['service'] === 'smtp' && event['action'] === 'phishing-flagged') {
                    correctFlags++;
                    ctx.reportProgress(`${correctFlags}/${requiredFlags} phishing emails flagged`);

                    if (correctFlags >= requiredFlags && !fellForPhishing) {
                        ctx.markComplete({ scoreMultiplier: 1.2 });
                    }
                }

                if (event['service'] === 'smtp' && event['action'] === 'phishing-interaction') {
                    fellForPhishing = true;
                    ctx.reportProgress('Fell for phishing — objective failed');
                }
            });

            return unsubFlag;
        },
    });
}
