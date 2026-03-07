import { describe, it, expect, vi } from 'vitest';
import {
    createStateMachine,
    createStateMachineRegistry,
} from '../src/lib/state-machine/state-machine';
import type { StateMachineConfig } from '../src/lib/state-machine/types';

// ── Test Configs ────────────────────────────────────────────

function createCompromiseConfig(): StateMachineConfig {
    return {
        id: 'machine-compromise',
        name: 'Machine Compromise State',
        states: [
            { id: 'clean', label: 'Clean' },
            { id: 'scanned', label: 'Scanned', tags: ['recon'] },
            { id: 'exploited', label: 'Exploited', tags: ['compromised'] },
            { id: 'owned', label: 'Fully Owned', tags: ['compromised', 'critical'] },
        ],
        transitions: [
            { id: 'scan', from: 'clean', to: 'scanned', trigger: 'port-scan' },
            { id: 'exploit', from: 'scanned', to: 'exploited', trigger: 'exploit-success' },
            { id: 'direct-exploit', from: 'clean', to: 'exploited', trigger: 'exploit-success', priority: -1 },
            { id: 'escalate', from: 'exploited', to: 'owned', trigger: 'privesc-success' },
        ],
        initialState: 'clean',
        terminalStates: ['owned'],
    };
}

function createAlertConfig(): StateMachineConfig {
    return {
        id: 'alert-level',
        name: 'SOC Alert Level',
        states: [
            { id: 'green', label: 'Normal' },
            { id: 'yellow', label: 'Suspicious Activity' },
            { id: 'orange', label: 'Active Incident' },
            { id: 'red', label: 'Critical Breach' },
        ],
        transitions: [
            { id: 'g-y', from: 'green', to: 'yellow', trigger: 'anomaly-detected' },
            { id: 'y-o', from: 'yellow', to: 'orange', trigger: 'incident-confirmed' },
            { id: 'o-r', from: 'orange', to: 'red', trigger: 'breach-detected' },
            { id: 'y-g', from: 'yellow', to: 'green', trigger: 'all-clear' },
            { id: 'o-y', from: 'orange', to: 'yellow', trigger: 'incident-contained' },
        ],
        initialState: 'green',
    };
}

// ── State Machine Tests ─────────────────────────────────────

describe('State Machine', () => {
    describe('Basic Transitions', () => {
        it('starts in initial state', () => {
            const sm = createStateMachine(createCompromiseConfig());
            expect(sm.getCurrentStateId()).toBe('clean');
            expect(sm.getCurrentState().label).toBe('Clean');
        });

        it('transitions on valid trigger', () => {
            const sm = createStateMachine(createCompromiseConfig());
            const result = sm.transition('port-scan');
            expect(result).not.toBeNull();
            expect(result!.id).toBe('scanned');
            expect(sm.getCurrentStateId()).toBe('scanned');
        });

        it('returns null for invalid trigger', () => {
            const sm = createStateMachine(createCompromiseConfig());
            const result = sm.transition('nonexistent');
            expect(result).toBeNull();
            expect(sm.getCurrentStateId()).toBe('clean');
        });

        it('chains transitions correctly', () => {
            const sm = createStateMachine(createCompromiseConfig());
            sm.transition('port-scan');
            sm.transition('exploit-success');
            sm.transition('privesc-success');
            expect(sm.getCurrentStateId()).toBe('owned');
        });

        it('respects transition priority', () => {
            const sm = createStateMachine(createCompromiseConfig());
            // 'exploit-success' from 'clean' has priority -1 (lower than default 0)
            // but 'scan' has no priority set (defaults to 0)
            // When both are available, higher priority wins
            const result = sm.transition('exploit-success');
            expect(result).not.toBeNull();
            expect(result!.id).toBe('exploited');
        });
    });

    describe('Guards', () => {
        it('blocks transition when guard fails', () => {
            const config: StateMachineConfig = {
                id: 'guarded',
                name: 'Guarded Machine',
                states: [
                    { id: 'a', label: 'A' },
                    { id: 'b', label: 'B' },
                ],
                transitions: [{
                    id: 'a-b',
                    from: 'a',
                    to: 'b',
                    trigger: 'go',
                    guard: (ctx) => (ctx['allowed'] as boolean) === true,
                }],
                initialState: 'a',
            };

            const sm = createStateMachine(config);
            expect(sm.transition('go', { allowed: false })).toBeNull();
            expect(sm.getCurrentStateId()).toBe('a');

            expect(sm.transition('go', { allowed: true })).not.toBeNull();
            expect(sm.getCurrentStateId()).toBe('b');
        });

        it('canTransition checks guards', () => {
            const config: StateMachineConfig = {
                id: 'guarded2',
                name: 'Guarded',
                states: [
                    { id: 'x', label: 'X' },
                    { id: 'y', label: 'Y' },
                ],
                transitions: [{
                    id: 'x-y', from: 'x', to: 'y', trigger: 'go',
                    guard: (ctx) => (ctx['score'] as number) > 100,
                }],
                initialState: 'x',
            };

            const sm = createStateMachine(config);
            expect(sm.canTransition('go', { score: 50 })).toBe(false);
            expect(sm.canTransition('go', { score: 200 })).toBe(true);
        });
    });

    describe('Terminal States', () => {
        it('reports terminal state correctly', () => {
            const sm = createStateMachine(createCompromiseConfig());
            expect(sm.isTerminal()).toBe(false);

            sm.transition('port-scan');
            sm.transition('exploit-success');
            sm.transition('privesc-success');
            expect(sm.isTerminal()).toBe(true);
        });
    });

    describe('History', () => {
        it('records transition history', () => {
            const sm = createStateMachine(createCompromiseConfig());
            sm.transition('port-scan');
            sm.transition('exploit-success');

            const history = sm.getHistory();
            expect(history.length).toBe(2);
            expect(history[0]!.from).toBe('clean');
            expect(history[0]!.to).toBe('scanned');
            expect(history[0]!.trigger).toBe('port-scan');
            expect(history[1]!.from).toBe('scanned');
            expect(history[1]!.to).toBe('exploited');
        });

        it('includes context in history when provided', () => {
            const config: StateMachineConfig = {
                id: 'ctx-test',
                name: 'Context Test',
                states: [
                    { id: 'a', label: 'A' },
                    { id: 'b', label: 'B' },
                ],
                transitions: [
                    { id: 'a-b', from: 'a', to: 'b', trigger: 'go' },
                ],
                initialState: 'a',
            };

            const sm = createStateMachine(config);
            sm.transition('go', { exploit: 'CVE-2024-1234' });

            const history = sm.getHistory();
            expect(history[0]!.context).toEqual({ exploit: 'CVE-2024-1234' });
        });
    });

    describe('Available Transitions', () => {
        it('lists available transitions from current state', () => {
            const sm = createStateMachine(createAlertConfig());
            const transitions = sm.getAvailableTransitions();
            expect(transitions.length).toBe(1);
            expect(transitions[0]!.trigger).toBe('anomaly-detected');
        });

        it('lists valid transitions (guards passing)', () => {
            const config: StateMachineConfig = {
                id: 'multi',
                name: 'Multi Transition',
                states: [
                    { id: 'a', label: 'A' },
                    { id: 'b', label: 'B' },
                    { id: 'c', label: 'C' },
                ],
                transitions: [
                    { id: 'a-b', from: 'a', to: 'b', trigger: 'go', guard: () => true },
                    { id: 'a-c', from: 'a', to: 'c', trigger: 'alt', guard: () => false },
                ],
                initialState: 'a',
            };

            const sm = createStateMachine(config);
            const valid = sm.getValidTransitions();
            expect(valid.length).toBe(1);
            expect(valid[0]!.id).toBe('a-b');
        });
    });

    describe('Bidirectional Transitions', () => {
        it('supports going back to previous states', () => {
            const sm = createStateMachine(createAlertConfig());

            sm.transition('anomaly-detected');
            expect(sm.getCurrentStateId()).toBe('yellow');

            sm.transition('all-clear');
            expect(sm.getCurrentStateId()).toBe('green');
        });

        it('supports multi-step escalation and de-escalation', () => {
            const sm = createStateMachine(createAlertConfig());

            sm.transition('anomaly-detected');
            sm.transition('incident-confirmed');
            expect(sm.getCurrentStateId()).toBe('orange');

            sm.transition('incident-contained');
            expect(sm.getCurrentStateId()).toBe('yellow');
        });
    });

    describe('Reset', () => {
        it('resets to initial state and clears history', () => {
            const sm = createStateMachine(createCompromiseConfig());
            sm.transition('port-scan');
            sm.transition('exploit-success');

            sm.reset();
            expect(sm.getCurrentStateId()).toBe('clean');
            expect(sm.getHistory().length).toBe(0);
        });
    });

    describe('Listeners', () => {
        it('notifies listeners on transition', () => {
            const sm = createStateMachine(createCompromiseConfig());
            const listener = vi.fn();
            sm.onTransition(listener);

            sm.transition('port-scan');
            expect(listener).toHaveBeenCalledTimes(1);
            expect(listener).toHaveBeenCalledWith(
                expect.objectContaining({
                    from: 'clean',
                    to: 'scanned',
                    trigger: 'port-scan',
                }),
            );
        });

        it('supports unsubscription', () => {
            const sm = createStateMachine(createCompromiseConfig());
            const listener = vi.fn();
            const unsub = sm.onTransition(listener);

            sm.transition('port-scan');
            unsub();
            sm.transition('exploit-success');

            expect(listener).toHaveBeenCalledTimes(1);
        });

        it('does not notify on failed transitions', () => {
            const sm = createStateMachine(createCompromiseConfig());
            const listener = vi.fn();
            sm.onTransition(listener);

            sm.transition('nonexistent');
            expect(listener).not.toHaveBeenCalled();
        });
    });

    describe('Validation', () => {
        it('throws on duplicate state IDs', () => {
            expect(() => createStateMachine({
                id: 'bad', name: 'Bad',
                states: [
                    { id: 'a', label: 'A' },
                    { id: 'a', label: 'A2' },
                ],
                transitions: [],
                initialState: 'a',
            })).toThrow(/duplicate state/i);
        });

        it('throws on unknown initial state', () => {
            expect(() => createStateMachine({
                id: 'bad', name: 'Bad',
                states: [{ id: 'a', label: 'A' }],
                transitions: [],
                initialState: 'nonexistent',
            })).toThrow(/initial state/i);
        });

        it('throws on transition with unknown from state', () => {
            expect(() => createStateMachine({
                id: 'bad', name: 'Bad',
                states: [{ id: 'a', label: 'A' }],
                transitions: [
                    { id: 't1', from: 'x', to: 'a', trigger: 'go' },
                ],
                initialState: 'a',
            })).toThrow(/unknown state/i);
        });

        it('throws on transition with unknown to state', () => {
            expect(() => createStateMachine({
                id: 'bad', name: 'Bad',
                states: [{ id: 'a', label: 'A' }],
                transitions: [
                    { id: 't1', from: 'a', to: 'x', trigger: 'go' },
                ],
                initialState: 'a',
            })).toThrow(/unknown state/i);
        });
    });

    describe('Config Access', () => {
        it('exposes the original config', () => {
            const config = createCompromiseConfig();
            const sm = createStateMachine(config);
            expect(sm.getConfig()).toBe(config);
        });

        it('exposes machine ID', () => {
            const sm = createStateMachine(createCompromiseConfig());
            expect(sm.id).toBe('machine-compromise');
        });
    });
});

// ── Registry Tests ──────────────────────────────────────────

describe('State Machine Registry', () => {
    it('registers and creates instances', () => {
        const registry = createStateMachineRegistry();
        registry.registerConfig(createCompromiseConfig());

        const instance = registry.createInstance('machine-compromise', 'web-server');
        expect(instance.getCurrentStateId()).toBe('clean');
    });

    it('retrieves instances', () => {
        const registry = createStateMachineRegistry();
        registry.registerConfig(createCompromiseConfig());
        registry.createInstance('machine-compromise', 'web-server');

        const instance = registry.getInstance('machine-compromise', 'web-server');
        expect(instance).not.toBeUndefined();
    });

    it('creates independent instances', () => {
        const registry = createStateMachineRegistry();
        registry.registerConfig(createCompromiseConfig());

        const a = registry.createInstance('machine-compromise', 'server-a');
        const b = registry.createInstance('machine-compromise', 'server-b');

        a.transition('port-scan');
        expect(a.getCurrentStateId()).toBe('scanned');
        expect(b.getCurrentStateId()).toBe('clean');
    });

    it('lists all instances of a config', () => {
        const registry = createStateMachineRegistry();
        registry.registerConfig(createCompromiseConfig());
        registry.createInstance('machine-compromise', 'a');
        registry.createInstance('machine-compromise', 'b');

        expect(registry.getInstances('machine-compromise').length).toBe(2);
    });

    it('destroys instances', () => {
        const registry = createStateMachineRegistry();
        registry.registerConfig(createCompromiseConfig());
        registry.createInstance('machine-compromise', 'a');

        expect(registry.destroyInstance('machine-compromise', 'a')).toBe(true);
        expect(registry.getInstance('machine-compromise', 'a')).toBeUndefined();
    });

    it('throws on duplicate config registration', () => {
        const registry = createStateMachineRegistry();
        registry.registerConfig(createCompromiseConfig());
        expect(() => registry.registerConfig(createCompromiseConfig())).toThrow();
    });

    it('throws on unregistered config', () => {
        const registry = createStateMachineRegistry();
        expect(() => registry.createInstance('nonexistent', 'a')).toThrow();
    });

    it('throws on duplicate instance ID', () => {
        const registry = createStateMachineRegistry();
        registry.registerConfig(createCompromiseConfig());
        registry.createInstance('machine-compromise', 'a');
        expect(() => registry.createInstance('machine-compromise', 'a')).toThrow();
    });

    it('lists registered configs', () => {
        const registry = createStateMachineRegistry();
        registry.registerConfig(createCompromiseConfig());
        registry.registerConfig(createAlertConfig());
        expect(registry.listConfigs()).toEqual(['machine-compromise', 'alert-level']);
    });

    it('retrieves config by ID', () => {
        const registry = createStateMachineRegistry();
        registry.registerConfig(createCompromiseConfig());
        const config = registry.getConfig('machine-compromise');
        expect(config).not.toBeUndefined();
        expect(config!.name).toBe('Machine Compromise State');
    });
});
