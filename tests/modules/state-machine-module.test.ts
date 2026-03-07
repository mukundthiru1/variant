import { describe, it, expect } from 'vitest';
import { createStateMachineModule } from '../../src/modules/state-machine-module';
import type { SimulationContext } from '../../src/core/modules';
import { createServiceLocator } from '../../src/core/modules';
import type { EventBus, EngineEvent } from '../../src/core/events';
import { createEventBus } from '../../src/core/event-bus';
import type { WorldSpec } from '../../src/core/world/types';
import { stubFabric } from '../helpers';

// ── Minimal EventBus ─────────────────────────────────────────

function createTestEventBus(): EventBus & { emitted: EngineEvent[] } {
    const inner = createEventBus(10_000);
    const emitted: EngineEvent[] = [];

    const bus: EventBus & { emitted: EngineEvent[] } = {
        emitted,
        emit(event: EngineEvent): void {
            emitted.push(event);
            inner.emit(event);
        },
        on: inner.on.bind(inner),
        once: inner.once.bind(inner),
        waitFor: inner.waitFor.bind(inner),
        onPrefix: inner.onPrefix.bind(inner),
        getLog: inner.getLog.bind(inner),
        clearLog: inner.clearLog.bind(inner),
        removeAllListeners: inner.removeAllListeners.bind(inner),
    };

    return bus;
}

function createTestContext(events: EventBus): SimulationContext {
    return {
        vms: new Map(),
        fabric: stubFabric(),
        events,
        world: {
            id: 'test', name: 'Test', version: '1.0.0', description: 'Test',
            machines: [], objectives: [],
            scoring: { maxScore: 1000, hintPenalty: 50, timeBonus: false, stealthBonus: false, tiers: [] },
        } as unknown as WorldSpec,
        tick: 0,
        services: createServiceLocator(),
    };
}

describe('State Machine Module', () => {
    function setup(config?: Parameters<typeof createStateMachineModule>[0]) {
        const events = createTestEventBus();
        const ctx = createTestContext(events);
        const mod = createStateMachineModule(config);
        mod.init(ctx);
        return { events, ctx, mod };
    }

    it('initializes and destroys without error', () => {
        const { mod } = setup();
        expect(mod.id).toBe('state-machine-module');
        expect(mod.type).toBe('engine');
        mod.destroy();
    });

    it('provides state-machine and compromise-tracking capabilities', () => {
        const { mod } = setup();
        expect(mod.provides.some(p => p.name === 'state-machine')).toBe(true);
        expect(mod.provides.some(p => p.name === 'compromise-tracking')).toBe(true);
        mod.destroy();
    });

    it('transitions compromise state on net:connect events', () => {
        const { events, mod } = setup();

        events.emit({
            type: 'net:connect',
            host: '10.0.0.5',
            port: 22,
            source: 'attacker-machine',
            protocol: 'tcp' as const,
            timestamp: Date.now(),
        });

        const transitions = events.emitted.filter(e => e.type === 'custom:state-transition');
        expect(transitions.length).toBe(1);
        const data = (transitions[0] as { data: { fromState: string; toState: string } }).data;
        expect(data.fromState).toBe('clean');
        expect(data.toState).toBe('probed');

        mod.destroy();
    });

    it('transitions compromise state on auth:login events', () => {
        const { events, mod } = setup();

        // First probe to get to 'probed' state
        events.emit({
            type: 'net:connect',
            host: '10.0.0.5',
            port: 22,
            source: 'target-machine',
            protocol: 'tcp' as const,
            timestamp: Date.now(),
        });

        // Then login to get to 'accessed'
        events.emit({
            type: 'auth:login',
            user: 'admin',
            machine: 'target-machine',
            service: 'ssh',
            success: true,
            timestamp: Date.now(),
        });

        const transitions = events.emitted.filter(e => e.type === 'custom:state-transition');
        expect(transitions.length).toBe(2);
        const secondData = (transitions[1] as { data: { fromState: string; toState: string } }).data;
        expect(secondData.fromState).toBe('probed');
        expect(secondData.toState).toBe('accessed');

        mod.destroy();
    });

    it('transitions compromise state on auth:escalate events', () => {
        const { events, mod } = setup();

        // Probe → access → escalate
        events.emit({ type: 'net:connect', host: '10.0.0.5', port: 22, source: 'target', protocol: 'tcp' as const, timestamp: Date.now() });
        events.emit({ type: 'auth:login', user: 'admin', machine: 'target', service: 'ssh', success: true, timestamp: Date.now() });
        events.emit({ type: 'auth:escalate', machine: 'target', from: 'admin', to: 'root', method: 'sudo', timestamp: Date.now() });

        const transitions = events.emitted.filter(e => e.type === 'custom:state-transition');
        expect(transitions.length).toBe(3);
        const thirdData = (transitions[2] as { data: { fromState: string; toState: string } }).data;
        expect(thirdData.fromState).toBe('accessed');
        expect(thirdData.toState).toBe('escalated');

        mod.destroy();
    });

    it('handles defense:breach with direct-access transition', () => {
        const { events, mod } = setup();

        events.emit({
            type: 'defense:breach',
            machine: 'web-01',
            vector: 'sqli',
            attacker: 'hacker',
            timestamp: Date.now(),
        });

        const transitions = events.emitted.filter(e => e.type === 'custom:state-transition');
        expect(transitions.length).toBe(1);
        const data = (transitions[0] as { data: { fromState: string; toState: string; trigger: string } }).data;
        expect(data.trigger).toBe('direct-access');
        expect(data.toState).toBe('accessed');

        mod.destroy();
    });

    it('does not transition when no valid transition exists', () => {
        const { events, mod } = setup();

        // auth:escalate with no prior state change — machine is still 'clean'
        // 'escalate' trigger doesn't exist from 'clean'
        events.emit({
            type: 'auth:escalate',
            machine: 'some-machine',
            from: 'user',
            to: 'root',
            method: 'exploit',
            timestamp: Date.now(),
        });

        const transitions = events.emitted.filter(e => e.type === 'custom:state-transition');
        expect(transitions.length).toBe(0);

        mod.destroy();
    });

    it('maintains separate state per machine', () => {
        const { events, mod } = setup();

        events.emit({ type: 'net:connect', host: '10.0.0.5', port: 22, source: 'machine-A', protocol: 'tcp' as const, timestamp: Date.now() });
        events.emit({ type: 'net:connect', host: '10.0.0.6', port: 22, source: 'machine-B', protocol: 'tcp' as const, timestamp: Date.now() });

        const transitions = events.emitted.filter(e => e.type === 'custom:state-transition');
        expect(transitions.length).toBe(2);

        // Both should independently move from clean → probed
        for (const t of transitions) {
            const data = (t as { data: { fromState: string; toState: string } }).data;
            expect(data.fromState).toBe('clean');
            expect(data.toState).toBe('probed');
        }

        mod.destroy();
    });

    it('responds to state-query custom events', () => {
        const { events, mod } = setup();

        // Create some state
        events.emit({ type: 'net:connect', host: '10.0.0.5', port: 22, source: 'query-target', protocol: 'tcp' as const, timestamp: Date.now() });

        // Query the state
        events.emit({
            type: 'custom:state-query',
            data: { machineId: 'query-target', configId: 'compromise' },
            timestamp: Date.now(),
        });

        const queryResult = events.emitted.find(e => e.type === 'custom:state-query-result');
        expect(queryResult).toBeDefined();
        const resultData = (queryResult as { data: { currentState: string } }).data;
        expect(resultData.currentState).toBe('probed');

        mod.destroy();
    });

    it('elevates alert level on high-severity defense:alert', () => {
        const { events, mod } = setup();

        events.emit({
            type: 'defense:alert',
            machine: 'alert-target',
            ruleId: 'test-rule',
            severity: 'high' as const,
            detail: 'Something bad',
            timestamp: Date.now(),
        });

        // Query alert level state
        events.emit({
            type: 'custom:state-query',
            data: { machineId: 'alert-target', configId: 'alert-level' },
            timestamp: Date.now(),
        });

        const queryResult = events.emitted.find(e => e.type === 'custom:state-query-result');
        expect(queryResult).toBeDefined();
        const resultData = (queryResult as { data: { currentState: string } }).data;
        expect(resultData.currentState).toBe('yellow');

        mod.destroy();
    });
});
