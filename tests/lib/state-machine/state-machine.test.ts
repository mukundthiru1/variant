/**
 * VARIANT — State Machine tests
 */
import { describe, it, expect } from 'vitest';
import { createStateMachine, createStateMachineRegistry } from '../../../src/lib/state-machine/state-machine';
import type { StateMachineConfig } from '../../../src/lib/state-machine/types';

function trafficLightConfig(): StateMachineConfig {
    return {
        id: 'traffic-light',
        name: 'Traffic Light',
        states: [
            { id: 'green', label: 'Green' },
            { id: 'yellow', label: 'Yellow' },
            { id: 'red', label: 'Red' },
        ],
        transitions: [
            { id: 't1', from: 'green', to: 'yellow', trigger: 'timer' },
            { id: 't2', from: 'yellow', to: 'red', trigger: 'timer' },
            { id: 't3', from: 'red', to: 'green', trigger: 'timer' },
        ],
        initialState: 'green',
    };
}

function compromiseConfig(): StateMachineConfig {
    return {
        id: 'compromise',
        name: 'Machine Compromise',
        states: [
            { id: 'clean', label: 'Clean' },
            { id: 'scanned', label: 'Scanned' },
            { id: 'exploited', label: 'Exploited' },
            { id: 'owned', label: 'Fully Owned' },
        ],
        transitions: [
            { id: 't1', from: 'clean', to: 'scanned', trigger: 'scan' },
            { id: 't2', from: 'scanned', to: 'exploited', trigger: 'exploit' },
            { id: 't3', from: 'exploited', to: 'owned', trigger: 'escalate' },
        ],
        initialState: 'clean',
        terminalStates: ['owned'],
    };
}

describe('StateMachine', () => {
    it('starts in initial state', () => {
        const sm = createStateMachine(trafficLightConfig());
        expect(sm.getCurrentStateId()).toBe('green');
        expect(sm.getCurrentState().label).toBe('Green');
    });

    it('transitions on valid trigger', () => {
        const sm = createStateMachine(trafficLightConfig());
        const result = sm.transition('timer');
        expect(result).not.toBeNull();
        expect(result!.id).toBe('yellow');
        expect(sm.getCurrentStateId()).toBe('yellow');
    });

    it('returns null on invalid trigger', () => {
        const sm = createStateMachine(trafficLightConfig());
        expect(sm.transition('invalid')).toBeNull();
        expect(sm.getCurrentStateId()).toBe('green');
    });

    it('cycles through states', () => {
        const sm = createStateMachine(trafficLightConfig());
        sm.transition('timer'); // → yellow
        sm.transition('timer'); // → red
        sm.transition('timer'); // → green
        expect(sm.getCurrentStateId()).toBe('green');
    });

    it('records transition history', () => {
        const sm = createStateMachine(trafficLightConfig());
        sm.transition('timer');
        sm.transition('timer');

        const history = sm.getHistory();
        expect(history.length).toBe(2);
        expect(history[0]!.from).toBe('green');
        expect(history[0]!.to).toBe('yellow');
        expect(history[1]!.from).toBe('yellow');
        expect(history[1]!.to).toBe('red');
    });

    it('detects terminal state', () => {
        const sm = createStateMachine(compromiseConfig());
        expect(sm.isTerminal()).toBe(false);

        sm.transition('scan');
        sm.transition('exploit');
        sm.transition('escalate');
        expect(sm.isTerminal()).toBe(true);
    });

    it('lists available transitions', () => {
        const sm = createStateMachine(trafficLightConfig());
        const available = sm.getAvailableTransitions();
        expect(available.length).toBe(1);
        expect(available[0]!.trigger).toBe('timer');
    });

    it('canTransition checks trigger validity', () => {
        const sm = createStateMachine(trafficLightConfig());
        expect(sm.canTransition('timer')).toBe(true);
        expect(sm.canTransition('invalid')).toBe(false);
    });

    it('reset returns to initial state', () => {
        const sm = createStateMachine(trafficLightConfig());
        sm.transition('timer');
        sm.transition('timer');

        sm.reset();
        expect(sm.getCurrentStateId()).toBe('green');
        expect(sm.getHistory().length).toBe(0);
    });

    // ── Guards ─────────────────────────────────────────────────

    it('transition guard blocks when false', () => {
        const config: StateMachineConfig = {
            id: 'guarded',
            name: 'Guarded',
            states: [
                { id: 'locked', label: 'Locked' },
                { id: 'unlocked', label: 'Unlocked' },
            ],
            transitions: [
                {
                    id: 't1', from: 'locked', to: 'unlocked', trigger: 'unlock',
                    guard: (ctx) => ctx['hasKey'] === true,
                },
            ],
            initialState: 'locked',
        };
        const sm = createStateMachine(config);

        expect(sm.transition('unlock', { hasKey: false })).toBeNull();
        expect(sm.getCurrentStateId()).toBe('locked');

        expect(sm.transition('unlock', { hasKey: true })).not.toBeNull();
        expect(sm.getCurrentStateId()).toBe('unlocked');
    });

    it('getValidTransitions respects guards', () => {
        const config: StateMachineConfig = {
            id: 'guarded',
            name: 'Guarded',
            states: [
                { id: 'a', label: 'A' },
                { id: 'b', label: 'B' },
                { id: 'c', label: 'C' },
            ],
            transitions: [
                { id: 't1', from: 'a', to: 'b', trigger: 'go', guard: () => true },
                { id: 't2', from: 'a', to: 'c', trigger: 'go', guard: () => false },
            ],
            initialState: 'a',
        };
        const sm = createStateMachine(config);

        expect(sm.getAvailableTransitions().length).toBe(2);
        expect(sm.getValidTransitions().length).toBe(1);
    });

    // ── Listeners ──────────────────────────────────────────────

    it('notifies transition listeners', () => {
        const sm = createStateMachine(trafficLightConfig());
        const records: string[] = [];

        const unsub = sm.onTransition((record) => {
            records.push(`${record.from}→${record.to}`);
        });

        sm.transition('timer');
        sm.transition('timer');
        expect(records).toEqual(['green→yellow', 'yellow→red']);

        unsub();
        sm.transition('timer');
        expect(records.length).toBe(2); // no new notification
    });

    // ── Priority ───────────────────────────────────────────────

    it('higher priority transition wins', () => {
        const config: StateMachineConfig = {
            id: 'priority',
            name: 'Priority',
            states: [
                { id: 'start', label: 'Start' },
                { id: 'low', label: 'Low' },
                { id: 'high', label: 'High' },
            ],
            transitions: [
                { id: 't1', from: 'start', to: 'low', trigger: 'go', priority: 1 },
                { id: 't2', from: 'start', to: 'high', trigger: 'go', priority: 10 },
            ],
            initialState: 'start',
        };
        const sm = createStateMachine(config);
        sm.transition('go');
        expect(sm.getCurrentStateId()).toBe('high');
    });

    // ── Config Access ──────────────────────────────────────────

    it('getConfig returns the configuration', () => {
        const config = trafficLightConfig();
        const sm = createStateMachine(config);
        expect(sm.getConfig().id).toBe('traffic-light');
    });

    // ── Validation ─────────────────────────────────────────────

    it('throws for duplicate state IDs', () => {
        expect(() => createStateMachine({
            id: 'bad',
            name: 'Bad',
            states: [{ id: 'a', label: 'A' }, { id: 'a', label: 'A2' }],
            transitions: [],
            initialState: 'a',
        })).toThrow();
    });

    it('throws for unknown initial state', () => {
        expect(() => createStateMachine({
            id: 'bad',
            name: 'Bad',
            states: [{ id: 'a', label: 'A' }],
            transitions: [],
            initialState: 'nonexistent',
        })).toThrow();
    });

    it('throws for transition referencing unknown state', () => {
        expect(() => createStateMachine({
            id: 'bad',
            name: 'Bad',
            states: [{ id: 'a', label: 'A' }],
            transitions: [{ id: 't1', from: 'a', to: 'b', trigger: 'go' }],
            initialState: 'a',
        })).toThrow();
    });
});

describe('StateMachineRegistry', () => {
    it('registers config and creates instances', () => {
        const reg = createStateMachineRegistry();
        reg.registerConfig(trafficLightConfig());

        const sm = reg.createInstance('traffic-light', 'intersection-1');
        expect(sm.getCurrentStateId()).toBe('green');
    });

    it('retrieves instances', () => {
        const reg = createStateMachineRegistry();
        reg.registerConfig(trafficLightConfig());
        reg.createInstance('traffic-light', 'i1');

        expect(reg.getInstance('traffic-light', 'i1')).not.toBeUndefined();
        expect(reg.getInstance('traffic-light', 'i2')).toBeUndefined();
    });

    it('lists all instances of a config', () => {
        const reg = createStateMachineRegistry();
        reg.registerConfig(trafficLightConfig());
        reg.createInstance('traffic-light', 'i1');
        reg.createInstance('traffic-light', 'i2');

        expect(reg.getInstances('traffic-light').length).toBe(2);
    });

    it('destroys instances', () => {
        const reg = createStateMachineRegistry();
        reg.registerConfig(trafficLightConfig());
        reg.createInstance('traffic-light', 'i1');

        expect(reg.destroyInstance('traffic-light', 'i1')).toBe(true);
        expect(reg.destroyInstance('traffic-light', 'i1')).toBe(false);
    });

    it('lists configs', () => {
        const reg = createStateMachineRegistry();
        reg.registerConfig(trafficLightConfig());
        reg.registerConfig(compromiseConfig());

        expect(reg.listConfigs().length).toBe(2);
    });

    it('throws on duplicate config', () => {
        const reg = createStateMachineRegistry();
        reg.registerConfig(trafficLightConfig());
        expect(() => reg.registerConfig(trafficLightConfig())).toThrow();
    });

    it('throws on unknown config for instance creation', () => {
        const reg = createStateMachineRegistry();
        expect(() => reg.createInstance('nonexistent', 'i1')).toThrow();
    });

    it('throws on duplicate instance', () => {
        const reg = createStateMachineRegistry();
        reg.registerConfig(trafficLightConfig());
        reg.createInstance('traffic-light', 'i1');
        expect(() => reg.createInstance('traffic-light', 'i1')).toThrow();
    });
});
