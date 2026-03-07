/**
 * VARIANT — State Machine Implementation
 *
 * Pure, configurable, composable finite state machine.
 *
 * SWAPPABILITY: Replace this file. The interface in types.ts is stable.
 */

import type {
    StateMachineConfig,
    StateMachine,
    StateDefinition,
    TransitionDefinition,
    TransitionRecord,
    TransitionListener,
    StateMachineRegistry,
} from './types';

// ── State Machine Factory ──────────────────────────────────

export function createStateMachine(config: StateMachineConfig): StateMachine {
    // Validate config
    const stateMap = new Map<string, StateDefinition>();
    for (const state of config.states) {
        if (stateMap.has(state.id)) {
            throw new Error(`StateMachine '${config.id}': duplicate state ID '${state.id}'`);
        }
        stateMap.set(state.id, state);
    }

    const initialState = stateMap.get(config.initialState);
    if (initialState === undefined) {
        throw new Error(
            `StateMachine '${config.id}': initial state '${config.initialState}' not found`,
        );
    }

    const terminalSet = new Set(config.terminalStates ?? []);

    // Build transition lookup: from-state → transitions sorted by priority desc
    const transitionsByState = new Map<string, TransitionDefinition[]>();
    for (const t of config.transitions) {
        if (!stateMap.has(t.from)) {
            throw new Error(
                `StateMachine '${config.id}': transition '${t.id}' references unknown state '${t.from}'`,
            );
        }
        if (!stateMap.has(t.to)) {
            throw new Error(
                `StateMachine '${config.id}': transition '${t.id}' references unknown state '${t.to}'`,
            );
        }

        const list = transitionsByState.get(t.from) ?? [];
        list.push(t);
        transitionsByState.set(t.from, list);
    }

    // Sort transitions by priority (higher first)
    for (const [, list] of transitionsByState) {
        list.sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
    }

    // Runtime state
    let currentStateId = config.initialState;
    const history: TransitionRecord[] = [];
    const listeners = new Set<TransitionListener>();

    const machine: StateMachine = {
        id: config.id,

        getCurrentState(): StateDefinition {
            return stateMap.get(currentStateId)!;
        },

        getCurrentStateId(): string {
            return currentStateId;
        },

        transition(
            trigger: string,
            context?: Readonly<Record<string, unknown>>,
        ): StateDefinition | null {
            const transitions = transitionsByState.get(currentStateId);
            if (transitions === undefined) return null;

            const ctx = context ?? {};

            for (const t of transitions) {
                if (t.trigger !== trigger) continue;
                if (t.guard !== undefined && !t.guard(ctx)) continue;

                // Transition is valid — execute it
                const record: TransitionRecord = {
                    transitionId: t.id,
                    from: currentStateId,
                    to: t.to,
                    trigger,
                    timestamp: Date.now(),
                    ...(Object.keys(ctx).length > 0 ? { context: ctx } : {}),
                };

                currentStateId = t.to;
                history.push(record);

                // Notify listeners
                for (const listener of listeners) {
                    listener(record);
                }

                return stateMap.get(t.to) ?? null;
            }

            return null;
        },

        getAvailableTransitions(): readonly TransitionDefinition[] {
            return transitionsByState.get(currentStateId) ?? [];
        },

        getValidTransitions(
            context?: Readonly<Record<string, unknown>>,
        ): readonly TransitionDefinition[] {
            const transitions = transitionsByState.get(currentStateId);
            if (transitions === undefined) return [];

            const ctx = context ?? {};
            return transitions.filter(t =>
                t.guard === undefined || t.guard(ctx),
            );
        },

        canTransition(
            trigger: string,
            context?: Readonly<Record<string, unknown>>,
        ): boolean {
            const transitions = transitionsByState.get(currentStateId);
            if (transitions === undefined) return false;

            const ctx = context ?? {};
            return transitions.some(t =>
                t.trigger === trigger && (t.guard === undefined || t.guard(ctx)),
            );
        },

        isTerminal(): boolean {
            return terminalSet.has(currentStateId);
        },

        getHistory(): readonly TransitionRecord[] {
            return [...history];
        },

        reset(): void {
            currentStateId = config.initialState;
            history.length = 0;
        },

        onTransition(listener: TransitionListener): () => void {
            listeners.add(listener);
            return () => { listeners.delete(listener); };
        },

        getConfig(): StateMachineConfig {
            return config;
        },
    };

    return machine;
}

// ── State Machine Registry ─────────────────────────────────

export function createStateMachineRegistry(): StateMachineRegistry {
    const configs = new Map<string, StateMachineConfig>();
    const instances = new Map<string, Map<string, StateMachine>>();

    return {
        registerConfig(config: StateMachineConfig): void {
            if (configs.has(config.id)) {
                throw new Error(
                    `StateMachineRegistry: config '${config.id}' already registered`,
                );
            }
            configs.set(config.id, config);
        },

        createInstance(configId: string, instanceId: string): StateMachine {
            const config = configs.get(configId);
            if (config === undefined) {
                throw new Error(
                    `StateMachineRegistry: config '${configId}' not registered`,
                );
            }

            let configInstances = instances.get(configId);
            if (configInstances === undefined) {
                configInstances = new Map();
                instances.set(configId, configInstances);
            }

            if (configInstances.has(instanceId)) {
                throw new Error(
                    `StateMachineRegistry: instance '${instanceId}' of config '${configId}' already exists`,
                );
            }

            const machine = createStateMachine(config);
            configInstances.set(instanceId, machine);
            return machine;
        },

        getInstance(configId: string, instanceId: string): StateMachine | undefined {
            return instances.get(configId)?.get(instanceId);
        },

        getInstances(configId: string): readonly StateMachine[] {
            const configInstances = instances.get(configId);
            if (configInstances === undefined) return [];
            return [...configInstances.values()];
        },

        destroyInstance(configId: string, instanceId: string): boolean {
            const configInstances = instances.get(configId);
            if (configInstances === undefined) return false;
            return configInstances.delete(instanceId);
        },

        listConfigs(): readonly string[] {
            return [...configs.keys()];
        },

        getConfig(id: string): StateMachineConfig | undefined {
            return configs.get(id);
        },
    };
}
