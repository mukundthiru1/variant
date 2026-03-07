/**
 * VARIANT — Dynamics Engine Module
 *
 * Executes dynamic world changes during gameplay:
 *   - Timed events: fire at specific tick numbers (with optional repeat)
 *   - Reactive events: fire when a trigger event occurs (with optional once)
 *
 * Dynamic actions include:
 *   - spawn-process: Add a background process to a VM
 *   - modify-file: Change a file on a VM
 *   - alert: Display a message to the player
 *   - rotate-credential: Change a credential value
 *   - send-email: Deliver an email (triggers mail system)
 *   - npc-action: Trigger an NPC behavior
 *   - start-service: Start a service on a machine
 *   - stop-service: Stop a service on a machine
 *   - inject-traffic: Generate network traffic between machines
 *   - open-lens: Open a UI lens for the player
 *   - custom: Extensible — delegates to registered handlers
 *
 * This makes levels feel alive — the sysadmin rotates credentials,
 * attacker bots probe at intervals, services restart, logs rotate,
 * phishing emails arrive, NPCs react to intrusion.
 *
 * SECURITY: Dynamics are declarative (from WorldSpec). They do NOT
 * execute arbitrary code. Each action type is handled by a specific,
 * bounded handler.
 *
 * EXTENSIBILITY: The 'custom' action type delegates to a
 * DynamicActionHandlerRegistry. Third-party packages register
 * their own action handlers. Adding a new dynamic action =
 * register a handler. Zero core changes.
 *
 * MODULARITY: Swappable module. Communicates via events only.
 */

import type { Module, SimulationContext, Capability } from '../core/modules';
import type { Unsubscribe, EventBus } from '../core/events';
import type { DynamicsSpec, DynamicAction, TimedEvent, ReactiveEvent } from '../core/world/types';

// ── Module ID ──────────────────────────────────────────────────

const MODULE_ID = 'dynamics-engine';
const MODULE_VERSION = '2.0.0';

// ── Custom Action Handler Registry ─────────────────────────────

/**
 * A handler for a custom dynamic action.
 * Receives the action string and arbitrary params, plus the event bus.
 */
export type DynamicActionHandler = (
    action: string,
    params: Readonly<Record<string, unknown>>,
    events: EventBus,
) => void;

/**
 * Registry for custom dynamic action handlers.
 * Third-party packages register their handlers here.
 */
export interface DynamicActionHandlerRegistry {
    /** Register a handler for a custom action. */
    register(action: string, handler: DynamicActionHandler): void;
    /** Get a handler for a custom action. */
    get(action: string): DynamicActionHandler | undefined;
    /** Check if a handler is registered. */
    has(action: string): boolean;
    /** List all registered action names. */
    list(): readonly string[];
}

/**
 * Create a custom action handler registry.
 */
export function createDynamicActionHandlerRegistry(): DynamicActionHandlerRegistry {
    const handlers = new Map<string, DynamicActionHandler>();

    return {
        register(action: string, handler: DynamicActionHandler): void {
            if (handlers.has(action)) {
                throw new Error(
                    `DynamicActionHandlerRegistry: handler for action '${action}' ` +
                    `is already registered. Registrations are append-only.`,
                );
            }
            if (action.length === 0) {
                throw new Error('DynamicActionHandlerRegistry: action name must be non-empty.');
            }
            handlers.set(action, handler);
        },

        get(action: string): DynamicActionHandler | undefined {
            return handlers.get(action);
        },

        has(action: string): boolean {
            return handlers.has(action);
        },

        list(): readonly string[] {
            return Object.freeze(Array.from(handlers.keys()));
        },
    };
}

// ── Factory ────────────────────────────────────────────────────

export function createDynamicsEngine(
    customRegistry?: DynamicActionHandlerRegistry,
): Module {
    const unsubscribers: Unsubscribe[] = [];

    /**
     * Track timed events. For non-repeating events, once fired they
     * are marked. For repeating events, we track the next fire tick.
     */
    const firedTimedEvents = new Set<number>();
    const nextRepeatTick = new Map<number, number>();

    function executeAction(action: DynamicAction, events: EventBus): void {
        switch (action.type) {
            case 'spawn-process':
                events.emit({
                    type: 'custom:dynamics-spawn',
                    data: { machine: action.machine, process: action.process },
                    timestamp: Date.now(),
                });
                break;

            case 'modify-file':
                events.emit({
                    type: 'custom:dynamics-modify-file',
                    data: { machine: action.machine, path: action.path, content: action.content },
                    timestamp: Date.now(),
                });
                break;

            case 'alert':
                events.emit({
                    type: 'sim:alert',
                    source: MODULE_ID,
                    message: `[${action.severity.toUpperCase()}] ${action.message}`,
                    timestamp: Date.now(),
                });
                break;

            case 'rotate-credential':
                events.emit({
                    type: 'custom:dynamics-rotate-cred',
                    data: { credentialId: action.credentialId, newValue: action.newValue },
                    timestamp: Date.now(),
                });
                break;

            case 'send-email':
                events.emit({
                    type: 'custom:dynamics-send-email',
                    data: { to: action.to, template: action.template, delay: action.delay ?? 0 },
                    timestamp: Date.now(),
                });
                break;

            case 'npc-action':
                events.emit({
                    type: 'custom:dynamics-npc-action',
                    data: { npc: action.npc, action: action.action, params: action.params ?? {} },
                    timestamp: Date.now(),
                });
                break;

            case 'start-service':
                events.emit({
                    type: 'custom:dynamics-start-service',
                    data: { machine: action.machine, service: action.service },
                    timestamp: Date.now(),
                });
                break;

            case 'stop-service':
                events.emit({
                    type: 'custom:dynamics-stop-service',
                    data: { machine: action.machine, service: action.service },
                    timestamp: Date.now(),
                });
                break;

            case 'inject-traffic':
                events.emit({
                    type: 'custom:dynamics-inject-traffic',
                    data: {
                        fromMachine: action.fromMachine,
                        toMachine: action.toMachine,
                        pattern: action.pattern,
                    },
                    timestamp: Date.now(),
                });
                break;

            case 'open-lens':
                events.emit({
                    type: 'custom:dynamics-open-lens',
                    data: {
                        lensType: action.lensType,
                        targetMachine: action.targetMachine,
                        config: action.config ?? {},
                    },
                    timestamp: Date.now(),
                });
                break;

            case 'custom': {
                // Delegate to the custom action handler registry
                const handler = customRegistry?.get(action.action);
                if (handler !== undefined) {
                    handler(action.action, action.params, events);
                } else {
                    // Emit as a generic custom event — someone may listen
                    events.emit({
                        type: `custom:dynamics-${action.action}`,
                        data: action.params,
                        timestamp: Date.now(),
                    });
                }
                break;
            }
        }
    }

    function setupTimedEvents(
        timedEvents: readonly TimedEvent[],
        events: EventBus,
    ): void {
        const unsub = events.on('sim:tick', (tickEvent) => {
            for (let i = 0; i < timedEvents.length; i++) {
                const timed = timedEvents[i];
                if (timed === undefined) continue;

                // Check if this is a repeating event
                if (timed.repeatInterval !== undefined && timed.repeatInterval > 0) {
                    // Get or initialize the next fire tick
                    if (!nextRepeatTick.has(i)) {
                        nextRepeatTick.set(i, timed.tick);
                    }

                    const nextTick = nextRepeatTick.get(i);
                    if (nextTick !== undefined && tickEvent.tick >= nextTick) {
                        executeAction(timed.action, events);
                        nextRepeatTick.set(i, nextTick + timed.repeatInterval);
                    }
                } else {
                    // Non-repeating: fire once
                    if (firedTimedEvents.has(i)) continue;

                    if (tickEvent.tick >= timed.tick) {
                        firedTimedEvents.add(i);
                        executeAction(timed.action, events);
                    }
                }
            }
        });
        unsubscribers.push(unsub);
    }

    function setupReactiveEvents(
        reactiveEvents: readonly ReactiveEvent[],
        events: EventBus,
    ): void {
        const firedOnce = new Set<number>();

        for (let i = 0; i < reactiveEvents.length; i++) {
            const reactive = reactiveEvents[i];
            if (reactive === undefined) continue;
            const triggerType = reactive.trigger;

            const handler = () => {
                // Check once flag
                if (reactive.once === true) {
                    if (firedOnce.has(i)) return;
                    firedOnce.add(i);
                }
                executeAction(reactive.action, events);
            };

            // Use prefix matching for broad triggers, exact for specific
            if (triggerType.endsWith(':')) {
                const unsub = events.onPrefix(triggerType, handler);
                unsubscribers.push(unsub);
            } else if (triggerType === '*') {
                const unsub = events.onPrefix('', handler);
                unsubscribers.push(unsub);
            } else {
                const prefix = triggerType.split(':')[0];
                if (prefix === undefined) continue;
                const unsub = events.onPrefix(`${prefix}:`, (event) => {
                    if (event.type === triggerType) {
                        handler();
                    }
                });
                unsubscribers.push(unsub);
            }
        }
    }

    // ── Module interface ──────────────────────────────────────

    const module: Module = {
        id: MODULE_ID,
        type: 'dynamics',
        version: MODULE_VERSION,
        description: 'Executes timed and reactive dynamic world changes with extensible action handlers',

        provides: [{ name: 'dynamics' }] as readonly Capability[],
        requires: [] as readonly Capability[],

        init(context: SimulationContext): void {
            firedTimedEvents.clear();
            nextRepeatTick.clear();

            const dynamics: DynamicsSpec | undefined = context.world.dynamics;
            if (dynamics === undefined) return;

            if (dynamics.timedEvents !== undefined && dynamics.timedEvents.length > 0) {
                setupTimedEvents(dynamics.timedEvents, context.events);
            }

            if (dynamics.reactiveEvents !== undefined && dynamics.reactiveEvents.length > 0) {
                setupReactiveEvents(dynamics.reactiveEvents, context.events);
            }
        },

        destroy(): void {
            for (const unsub of unsubscribers) {
                unsub();
            }
            unsubscribers.length = 0;
            firedTimedEvents.clear();
            nextRepeatTick.clear();
        },
    };

    return module;
}
