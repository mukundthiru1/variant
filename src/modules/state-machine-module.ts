/**
 * VARIANT — State Machine Module
 *
 * Tracks machine compromise states, alert levels, and attack phases
 * via the configurable state machine. Listens to simulation events
 * and automatically triggers transitions based on event patterns.
 *
 * Each machine in the simulation gets its own state machine instance.
 * State transitions emit custom events so other modules can react.
 *
 * EXTENSIBILITY:
 *   - Custom state configs via StateMachineModuleConfig
 *   - Custom transition triggers via event patterns
 *   - Multiple independent state machines (compromise, alert, phase)
 *
 * SWAPPABILITY: Implements Module interface. Replace this file.
 */

import type { Module, SimulationContext, Capability } from '../core/modules';
import type { Unsubscribe, EngineEvent } from '../core/events';
import { createStateMachineRegistry } from '../lib/state-machine/state-machine';
import type {
    StateMachine,
    StateMachineConfig,
    StateMachineRegistry,
} from '../lib/state-machine/types';

// ── Module ID ──────────────────────────────────────────────

const MODULE_ID = 'state-machine-module';
const MODULE_VERSION = '1.0.0';

// ── Config ────────────────────────────────────────────────

/**
 * A transition trigger maps an event pattern to a state transition.
 * When the event fires, the module attempts the transition on the
 * specified machine's state machine.
 */
export interface TransitionTrigger {
    /** Event type to listen for. Supports prefix matching with '*'. */
    readonly eventPattern: string;
    /** Extract machine ID from the event. Field name to read. */
    readonly machineField: string;
    /** The trigger string to pass to the state machine's transition method. */
    readonly trigger: string;
    /** Optional context to pass to the transition. */
    readonly context?: Readonly<Record<string, unknown>>;
}

export interface StateMachineModuleConfig {
    /** State machine configuration for compromise tracking. */
    readonly compromiseStates?: StateMachineConfig;
    /** State machine configuration for alert levels. */
    readonly alertStates?: StateMachineConfig;
    /** Event-driven transition triggers. */
    readonly triggers?: readonly TransitionTrigger[];
}

// ── Built-in State Configs ────────────────────────────────

function defaultCompromiseConfig(): StateMachineConfig {
    return {
        id: 'compromise',
        name: 'Compromise State',
        states: [
            { id: 'clean', label: 'Clean' },
            { id: 'probed', label: 'Probed' },
            { id: 'accessed', label: 'Accessed' },
            { id: 'escalated', label: 'Escalated' },
            { id: 'persisted', label: 'Persisted' },
            { id: 'exfiltrated', label: 'Exfiltrated' },
        ],
        initialState: 'clean',
        terminalStates: ['exfiltrated'],
        transitions: [
            { id: 'probe', from: 'clean', to: 'probed', trigger: 'probe' },
            { id: 'access', from: 'probed', to: 'accessed', trigger: 'access' },
            { id: 'escalate', from: 'accessed', to: 'escalated', trigger: 'escalate' },
            { id: 'persist', from: 'escalated', to: 'persisted', trigger: 'persist' },
            { id: 'exfiltrate', from: 'persisted', to: 'exfiltrated', trigger: 'exfiltrate' },
            // Skip states for advanced attackers
            { id: 'direct-access', from: 'clean', to: 'accessed', trigger: 'direct-access' },
            { id: 'exploit-escalate', from: 'probed', to: 'escalated', trigger: 'exploit-escalate' },
            { id: 'quick-persist', from: 'accessed', to: 'persisted', trigger: 'quick-persist' },
        ],
    };
}

function defaultAlertConfig(): StateMachineConfig {
    return {
        id: 'alert-level',
        name: 'Alert Level',
        states: [
            { id: 'green', label: 'Green' },
            { id: 'yellow', label: 'Yellow' },
            { id: 'orange', label: 'Orange' },
            { id: 'red', label: 'Red' },
            { id: 'critical', label: 'Critical' },
        ],
        initialState: 'green',
        terminalStates: ['critical'],
        transitions: [
            { id: 'elevate-green', from: 'green', to: 'yellow', trigger: 'elevate' },
            { id: 'elevate-yellow', from: 'yellow', to: 'orange', trigger: 'elevate' },
            { id: 'elevate-orange', from: 'orange', to: 'red', trigger: 'elevate' },
            { id: 'elevate-red', from: 'red', to: 'critical', trigger: 'elevate' },
            // De-escalation
            { id: 'deescalate-yellow', from: 'yellow', to: 'green', trigger: 'de-escalate' },
            { id: 'deescalate-orange', from: 'orange', to: 'yellow', trigger: 'de-escalate' },
            { id: 'deescalate-red', from: 'red', to: 'orange', trigger: 'de-escalate' },
        ],
    };
}

function defaultTriggers(): readonly TransitionTrigger[] {
    return [
        { eventPattern: 'net:connect', machineField: 'source', trigger: 'probe' },
        { eventPattern: 'auth:login', machineField: 'machine', trigger: 'access' },
        { eventPattern: 'auth:escalate', machineField: 'machine', trigger: 'escalate' },
        { eventPattern: 'defense:breach', machineField: 'machine', trigger: 'direct-access' },
    ];
}

// ── Factory ────────────────────────────────────────────────

export function createStateMachineModule(moduleConfig?: StateMachineModuleConfig): Module {
    const cfg = moduleConfig ?? {};
    const unsubscribers: Unsubscribe[] = [];
    let registry: StateMachineRegistry | null = null;
    // key: `${configId}:${machineId}` → StateMachine
    const machineFSMs = new Map<string, StateMachine>();

    function getOrCreateFSM(machineId: string, configId: string): StateMachine | null {
        const key = `${configId}:${machineId}`;
        const existing = machineFSMs.get(key);
        if (existing !== undefined) return existing;

        if (registry === null) return null;
        try {
            const fsm = registry.createInstance(configId, key);
            machineFSMs.set(key, fsm);
            return fsm;
        } catch {
            // Config not registered or instance already exists
            return registry.getInstance(configId, key) ?? null;
        }
    }

    const module: Module = {
        id: MODULE_ID,
        type: 'engine',
        version: MODULE_VERSION,
        description: 'State machine module — tracks machine compromise states and alert levels via configurable FSMs',

        provides: [
            { name: 'state-machine' },
            { name: 'compromise-tracking' },
            { name: 'alert-levels' },
        ] as readonly Capability[],
        requires: [] as readonly Capability[],

        init(context: SimulationContext): void {
            registry = createStateMachineRegistry();

            // Register state machine configs
            const compromiseConfig = cfg.compromiseStates ?? defaultCompromiseConfig();
            const alertConfig = cfg.alertStates ?? defaultAlertConfig();
            registry.registerConfig(compromiseConfig);
            registry.registerConfig(alertConfig);

            // Set up event-driven triggers
            const triggers = cfg.triggers ?? defaultTriggers();

            for (const triggerDef of triggers) {
                const handler = (event: EngineEvent) => {
                    const machineId = extractField(event, triggerDef.machineField);
                    if (machineId === null) return;

                    const fsm = getOrCreateFSM(machineId, 'compromise');
                    if (fsm === null) return;

                    const prevState = fsm.getCurrentStateId();
                    const result = fsm.transition(triggerDef.trigger, triggerDef.context);
                    if (result !== null) {
                        context.events.emit({
                            type: 'custom:state-transition',
                            data: {
                                machineId,
                                configId: 'compromise',
                                trigger: triggerDef.trigger,
                                fromState: prevState,
                                toState: fsm.getCurrentStateId(),
                            },
                            timestamp: Date.now(),
                        });
                    }
                };

                if (triggerDef.eventPattern.endsWith('*')) {
                    const prefix = triggerDef.eventPattern.slice(0, -1);
                    const unsub = context.events.onPrefix(prefix, handler);
                    unsubscribers.push(unsub);
                } else {
                    const prefix = triggerDef.eventPattern.split(':')[0];
                    if (prefix !== undefined) {
                        const unsub = context.events.onPrefix(`${prefix}:`, (event) => {
                            if (event.type === triggerDef.eventPattern) {
                                handler(event);
                            }
                        });
                        unsubscribers.push(unsub);
                    }
                }
            }

            // Handle alert level transitions from defense:alert events
            const alertUnsub = context.events.onPrefix('defense:', (event) => {
                if (event.type !== 'defense:alert') return;
                const alertEvent = event as Extract<EngineEvent, { type: 'defense:alert' }>;
                const machineId = alertEvent.machine;

                const fsm = getOrCreateFSM(machineId, 'alert-level');
                if (fsm === null) return;

                // Elevate on high/critical alerts
                if (alertEvent.severity === 'high' || alertEvent.severity === 'critical') {
                    fsm.transition('elevate');
                }
            });
            unsubscribers.push(alertUnsub);

            // Handle custom events for state queries
            const customUnsub = context.events.onPrefix('custom:', (event) => {
                if (event.type === 'custom:state-query') {
                    const data = event.data as { machineId: string; configId: string } | null;
                    if (data === null || typeof data !== 'object') return;

                    const fsm = getOrCreateFSM(data.machineId, data.configId);
                    context.events.emit({
                        type: 'custom:state-query-result',
                        data: {
                            machineId: data.machineId,
                            configId: data.configId,
                            currentState: fsm?.getCurrentStateId() ?? null,
                            history: fsm?.getHistory() ?? [],
                        },
                        timestamp: Date.now(),
                    });
                }
            });
            unsubscribers.push(customUnsub);
        },

        destroy(): void {
            for (const unsub of unsubscribers) {
                unsub();
            }
            unsubscribers.length = 0;
            machineFSMs.clear();
            if (registry !== null) {
                for (const configId of registry.listConfigs()) {
                    for (const instance of registry.getInstances(configId)) {
                        registry.destroyInstance(configId, instance.id);
                    }
                }
            }
            registry = null;
        },
    };

    return module;
}

function extractField(event: EngineEvent, field: string): string | null {
    if (field in event) {
        const val = (event as unknown as Record<string, unknown>)[field];
        if (typeof val === 'string') return val;
    }
    return null;
}
