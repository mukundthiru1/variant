/**
 * VARIANT — Process Monitor Module tests
 */
import { describe, it, expect } from 'vitest';
import { createProcessMonitor } from '../../src/modules/process-monitor';
import type { SimulationContext } from '../../src/core/modules';
import { createServiceLocator } from '../../src/core/modules';
import type { EventBus, EngineEvent } from '../../src/core/events';
import { createEventBus } from '../../src/core/event-bus';
import type { WorldSpec } from '../../src/core/world/types';
import { stubFabric } from '../helpers';

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

function setup(config?: { anomalyCheckInterval?: number; autoBootstrap?: boolean }) {
    const events = createTestEventBus();
    const world = {
        machines: {
            'web-01': {
                hostname: 'web-01',
                services: [
                    { name: 'http', command: 'nginx', ports: [80], autostart: true },
                    { name: 'ssh', command: 'sshd', ports: [22], autostart: true },
                ],
            },
            'db-01': {
                hostname: 'db-01',
                services: [
                    { name: 'mysql', command: 'mysqld', ports: [3306], autostart: true },
                ],
            },
        },
    } as unknown as WorldSpec;

    const ctx: SimulationContext = {
        vms: new Map(),
        fabric: stubFabric(),
        events,
        world,
        tick: 0,
        services: createServiceLocator(),
    };

    const mod = createProcessMonitor(config);
    mod.init(ctx);

    return { events, ctx, mod };
}

describe('ProcessMonitor', () => {
    it('initializes and destroys cleanly', () => {
        const { mod } = setup();
        expect(mod.id).toBe('process-monitor');
        expect(mod.type).toBe('defense');
        mod.destroy();
    });

    it('provides process-monitoring and process-tree capabilities', () => {
        const { mod } = setup();
        expect(mod.provides.some(p => p.name === 'process-monitoring')).toBe(true);
        expect(mod.provides.some(p => p.name === 'process-tree')).toBe(true);
        mod.destroy();
    });

    it('bootstraps process trees for each machine on init', () => {
        const { events, mod } = setup();

        events.emit({
            type: 'custom:process-query',
            data: { machine: 'web-01' },
            timestamp: Date.now(),
        });

        const result = events.emitted.find(e => e.type === 'custom:process-query-result');
        expect(result).toBeDefined();
        const data = (result as EngineEvent & { data: { machine: string; count: number } }).data;
        expect(data.machine).toBe('web-01');
        expect(data.count).toBeGreaterThan(0);

        mod.destroy();
    });

    it('bootstraps trees for all machines', () => {
        const { events, mod } = setup();

        events.emit({
            type: 'custom:process-query',
            data: { machine: 'db-01' },
            timestamp: Date.now(),
        });

        const result = events.emitted.find(e => e.type === 'custom:process-query-result');
        expect(result).toBeDefined();
        const data = (result as EngineEvent & { data: { machine: string; count: number } }).data;
        expect(data.machine).toBe('db-01');
        expect(data.count).toBeGreaterThan(0);

        mod.destroy();
    });

    it('skips bootstrap when autoBootstrap is false', () => {
        const { events, mod } = setup({ autoBootstrap: false });

        events.emit({
            type: 'custom:process-query',
            data: { machine: 'web-01' },
            timestamp: Date.now(),
        });

        const result = events.emitted.find(e => e.type === 'custom:process-query-result');
        expect(result).toBeUndefined();

        mod.destroy();
    });

    it('spawns processes via custom:dynamics-spawn events', () => {
        const { events, mod } = setup();

        events.emit({
            type: 'custom:dynamics-spawn',
            data: {
                machine: 'web-01',
                process: {
                    name: 'malware',
                    command: '/tmp/malware',
                },
            },
            timestamp: Date.now(),
        });

        // Clear emitted to only get query result
        events.emitted.length = 0;
        events.emit({
            type: 'custom:process-query',
            data: { machine: 'web-01' },
            timestamp: Date.now(),
        });

        const result = events.emitted.find(e => e.type === 'custom:process-query-result');
        expect(result).toBeDefined();
        const data = (result as EngineEvent & { data: { psAux: string } }).data;
        expect(data.psAux).toContain('malware');

        mod.destroy();
    });

    it('runs anomaly detection on configured interval', () => {
        const { ctx, mod } = setup({ anomalyCheckInterval: 5 });

        // Tick several times — should not crash
        for (let i = 0; i < 10; i++) {
            mod.onTick!(i, ctx);
        }

        mod.destroy();
    });

    it('ticks all process trees without error', () => {
        const { ctx, mod } = setup();

        mod.onTick!(1, ctx);
        mod.onTick!(2, ctx);
        mod.onTick!(3, ctx);

        mod.destroy();
    });

    it('ignores spawn for unknown machines', () => {
        const { events, mod } = setup();

        // Should not throw
        events.emit({
            type: 'custom:dynamics-spawn',
            data: {
                machine: 'unknown-machine',
                process: { name: 'test', command: '/bin/test' },
            },
            timestamp: Date.now(),
        });

        mod.destroy();
    });

    it('cleans up on destroy', () => {
        const { events, mod } = setup();
        mod.destroy();

        events.emit({
            type: 'custom:process-query',
            data: { machine: 'web-01' },
            timestamp: Date.now(),
        });

        const result = events.emitted.find(e => e.type === 'custom:process-query-result');
        expect(result).toBeUndefined();
    });
});
