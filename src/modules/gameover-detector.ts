/**
 * VARIANT — Game Over Detector Module
 *
 * Watches for conditions that end the game (defense mode).
 * When a GameOverCondition from the WorldSpec is triggered,
 * emits sim:gameover and the engine transitions to 'failed'.
 *
 * Game Over Conditions:
 *   - machine-compromised  → auth:escalate on a defended machine
 *   - data-exfiltrated     → net:request with stolen data
 *   - service-down         → service stays dead for N ticks
 *   - credential-leaked    → auth:credential-found by attacker
 *   - noise-detected       → sim:noise above threshold
 *
 * SECURITY: Read-only event bus access. Cannot mutate anything.
 * MODULARITY: Swappable. The engine doesn't hardcode any
 * game-over logic.
 */

import type { Module, SimulationContext, Capability } from '../core/modules';
import type { Unsubscribe, EventBus } from '../core/events';
import type { GameOverCondition } from '../core/world/types';

// ── Module ID ──────────────────────────────────────────────────

const MODULE_ID = 'gameover-detector';
const MODULE_VERSION = '2.0.0';

// ── Custom Condition Handler Registry ──────────────────────────

/**
 * A handler for a custom game-over condition.
 * Receives the condition's params and event bus. Must call
 * the provided `triggerGameOver(reason)` when the condition is met.
 * Returns an unsubscribe/cleanup function.
 */
export type GameOverConditionHandler = (
    params: Readonly<Record<string, unknown>>,
    events: EventBus,
    triggerGameOver: (reason: string) => void,
) => (() => void) | void;

/**
 * Registry for custom game-over condition handlers.
 * Third-party packages register their handlers here.
 * Adding a new game-over condition = register a handler. Zero core changes.
 */
export interface GameOverConditionHandlerRegistry {
    /** Register a handler for a custom condition. */
    register(name: string, handler: GameOverConditionHandler): void;
    /** Get a handler by name. */
    get(name: string): GameOverConditionHandler | undefined;
    /** Check if a handler is registered. */
    has(name: string): boolean;
    /** List all registered handler names. */
    list(): readonly string[];
}

/**
 * Create a custom game-over condition handler registry.
 */
export function createGameOverConditionHandlerRegistry(): GameOverConditionHandlerRegistry {
    const handlers = new Map<string, GameOverConditionHandler>();

    return {
        register(name: string, handler: GameOverConditionHandler): void {
            if (handlers.has(name)) {
                throw new Error(
                    `GameOverConditionHandlerRegistry: handler '${name}' ` +
                    `is already registered. Registrations are append-only.`,
                );
            }
            if (name.length === 0) {
                throw new Error('GameOverConditionHandlerRegistry: handler name must be non-empty.');
            }
            handlers.set(name, handler);
        },

        get(name: string): GameOverConditionHandler | undefined {
            return handlers.get(name);
        },

        has(name: string): boolean {
            return handlers.has(name);
        },

        list(): readonly string[] {
            return Object.freeze(Array.from(handlers.keys()));
        },
    };
}

// ── Factory ────────────────────────────────────────────────────

export function createGameOverDetector(
    customRegistry?: GameOverConditionHandlerRegistry,
): Module {
    const unsubscribers: Unsubscribe[] = [];
    let gameOverFired = false;

    function fireGameOver(events: EventBus, reason: string): void {
        if (gameOverFired) return;
        gameOverFired = true;

        events.emit({
            type: 'sim:gameover',
            reason,
            timestamp: Date.now(),
        });
    }

    function setupCondition(
        condition: GameOverCondition,
        events: EventBus,
    ): void {
        switch (condition.type) {
            case 'machine-compromised':
                setupMachineCompromised(condition.machine, events);
                break;
            case 'data-exfiltrated':
                setupDataExfiltrated(condition.data, events);
                break;
            case 'service-down':
                setupServiceDown(condition.machine, condition.service, condition.durationTicks, events);
                break;
            case 'credential-leaked':
                setupCredentialLeaked(condition.credentialId, events);
                break;
            case 'noise-detected':
                setupNoiseDetected(condition.threshold, events);
                break;
            case 'custom': {
                const handler = customRegistry?.get(condition.handler);
                if (handler !== undefined) {
                    const cleanup = handler(condition.params, events, (reason) => fireGameOver(events, reason));
                    if (cleanup !== undefined) {
                        unsubscribers.push(cleanup);
                    }
                }
                break;
            }
        }
    }

    function setupMachineCompromised(machine: string, events: EventBus): void {
        const unsub = events.on('auth:escalate', (event) => {
            if (event.machine === machine && event.to === 'root') {
                fireGameOver(events, `Machine '${machine}' was compromised — attacker gained root`);
            }
        });
        unsubscribers.push(unsub);
    }

    function setupDataExfiltrated(dataId: string, events: EventBus): void {
        const unsub = events.on('net:request', (event) => {
            if (event.url.includes(dataId)) {
                fireGameOver(events, `Sensitive data '${dataId}' was exfiltrated`);
            }
        });
        unsubscribers.push(unsub);
    }

    function setupServiceDown(
        machine: string,
        service: string,
        durationTicks: number,
        events: EventBus,
    ): void {
        let downSince: number | null = null;

        const alertUnsub = events.on('defense:alert', (event) => {
            if (event.machine === machine && event.ruleId === `service-down:${service}`) {
                downSince = 0;
            }
        });

        const tickUnsub = events.on('sim:tick', () => {
            if (downSince !== null) {
                downSince++;
                if (downSince >= durationTicks) {
                    fireGameOver(events, `Service '${service}' on '${machine}' was down for ${durationTicks} ticks`);
                }
            }
        });

        unsubscribers.push(alertUnsub, tickUnsub);
    }

    function setupCredentialLeaked(credentialId: string, events: EventBus): void {
        const unsub = events.on('auth:credential-found', (event) => {
            if (event.credentialId === credentialId) {
                fireGameOver(events, `Credential '${credentialId}' was leaked`);
            }
        });
        unsubscribers.push(unsub);
    }

    function setupNoiseDetected(threshold: number, events: EventBus): void {
        let totalNoise = 0;

        const unsub = events.on('sim:noise', (event) => {
            totalNoise += event.amount;
            if (totalNoise >= threshold) {
                fireGameOver(events, `Detection threshold exceeded (noise: ${totalNoise}/${threshold})`);
            }
        });
        unsubscribers.push(unsub);
    }

    // ── Module interface ──────────────────────────────────────

    const module: Module = {
        id: MODULE_ID,
        type: 'engine',
        version: MODULE_VERSION,
        description: 'Monitors for game-over conditions in defense mode',

        provides: [{ name: 'gameover-detection' }] as readonly Capability[],
        requires: [] as readonly Capability[],

        init(context: SimulationContext): void {
            gameOverFired = false;

            const gameOver = context.world.gameOver;
            if (gameOver === undefined) return;

            for (const condition of gameOver.conditions) {
                setupCondition(condition, context.events);
            }
        },

        destroy(): void {
            for (const unsub of unsubscribers) {
                unsub();
            }
            unsubscribers.length = 0;
            gameOverFired = false;
        },
    };

    return module;
}
