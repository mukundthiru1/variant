import { describe, it, expect } from 'vitest';
import { createTrafficGenerator } from '../../src/modules/traffic-generator';
import type { TrafficPattern } from '../../src/modules/traffic-generator';
import type { SimulationContext } from '../../src/core/modules';
import { createServiceLocator } from '../../src/core/modules';
import type { VMInstance } from '../../src/core/vm/types';
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

function createTestContext(events: EventBus, machineIds: string[] = []): SimulationContext {
    const vms = new Map<string, VMInstance>();
    for (const id of machineIds) {
        vms.set(id, { id, status: 'running' } as unknown as VMInstance);
    }

    return {
        vms,
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

describe('Traffic Generator Module', () => {
    it('initializes and destroys without error', () => {
        const events = createTestEventBus();
        const ctx = createTestContext(events);
        const mod = createTrafficGenerator({ autoGenerate: false });
        mod.init(ctx);
        expect(mod.id).toBe('traffic-generator');
        expect(mod.type).toBe('actor');
        mod.destroy();
    });

    it('provides traffic-generation capability', () => {
        const mod = createTrafficGenerator();
        expect(mod.provides.some(p => p.name === 'traffic-generation')).toBe(true);
    });

    it('generates web-browse traffic at correct intervals', () => {
        const events = createTestEventBus();
        const ctx = createTestContext(events);

        const pattern: TrafficPattern = {
            id: 'test-web',
            type: 'web-browse',
            sourceMachine: 'workstation',
            destination: 'example.com',
            intervalTicks: 5,
        };

        const mod = createTrafficGenerator({ patterns: [pattern], autoGenerate: false });
        mod.init(ctx);

        // Tick 0 — should fire (start tick defaults to 0)
        mod.onTick!(0, ctx);
        const requests0 = events.emitted.filter(e => e.type === 'net:request');
        expect(requests0.length).toBe(1);

        // Tick 3 — should not fire (interval is 5)
        mod.onTick!(3, ctx);
        const requests3 = events.emitted.filter(e => e.type === 'net:request');
        expect(requests3.length).toBe(1); // Still 1

        // Tick 5 — should fire
        mod.onTick!(5, ctx);
        const requests5 = events.emitted.filter(e => e.type === 'net:request');
        expect(requests5.length).toBe(2);

        mod.destroy();
    });

    it('generates dns-query traffic', () => {
        const events = createTestEventBus();
        const ctx = createTestContext(events);

        const pattern: TrafficPattern = {
            id: 'test-dns',
            type: 'dns-query',
            sourceMachine: 'workstation',
            destination: 'dns-server',
            intervalTicks: 1,
        };

        const mod = createTrafficGenerator({ patterns: [pattern], autoGenerate: false });
        mod.init(ctx);
        mod.onTick!(0, ctx);

        const dnsEvents = events.emitted.filter(e => e.type === 'net:dns');
        expect(dnsEvents.length).toBe(1);

        mod.destroy();
    });

    it('generates internal-api traffic', () => {
        const events = createTestEventBus();
        const ctx = createTestContext(events);

        const pattern: TrafficPattern = {
            id: 'test-api',
            type: 'internal-api',
            sourceMachine: 'app-01',
            destination: 'db-01',
            intervalTicks: 1,
        };

        const mod = createTrafficGenerator({ patterns: [pattern], autoGenerate: false });
        mod.init(ctx);
        mod.onTick!(0, ctx);

        const requests = events.emitted.filter(e => e.type === 'net:request');
        expect(requests.length).toBe(1);

        mod.destroy();
    });

    it('generates heartbeat traffic', () => {
        const events = createTestEventBus();
        const ctx = createTestContext(events);

        const pattern: TrafficPattern = {
            id: 'test-heartbeat',
            type: 'heartbeat',
            sourceMachine: 'monitor',
            destination: 'web-01',
            intervalTicks: 1,
            port: 8080,
        };

        const mod = createTrafficGenerator({ patterns: [pattern], autoGenerate: false });
        mod.init(ctx);
        mod.onTick!(0, ctx);

        const connects = events.emitted.filter(e => e.type === 'net:connect');
        expect(connects.length).toBe(1);
        const connect = connects[0] as Extract<EngineEvent, { type: 'net:connect' }>;
        expect(connect.port).toBe(8080);

        mod.destroy();
    });

    it('generates mail traffic', () => {
        const events = createTestEventBus();
        const ctx = createTestContext(events);

        const pattern: TrafficPattern = {
            id: 'test-mail',
            type: 'mail',
            sourceMachine: 'mail-01',
            destination: 'mail-02',
            intervalTicks: 1,
        };

        const mod = createTrafficGenerator({ patterns: [pattern], autoGenerate: false });
        mod.init(ctx);
        mod.onTick!(0, ctx);

        const connects = events.emitted.filter(e => e.type === 'net:connect');
        expect(connects.length).toBe(1);
        const connect = connects[0] as Extract<EngineEvent, { type: 'net:connect' }>;
        expect(connect.port).toBe(25);

        mod.destroy();
    });

    it('generates ssh-session traffic', () => {
        const events = createTestEventBus();
        const ctx = createTestContext(events);

        const pattern: TrafficPattern = {
            id: 'test-ssh',
            type: 'ssh-session',
            sourceMachine: 'admin-box',
            destination: 'web-01',
            intervalTicks: 1,
        };

        const mod = createTrafficGenerator({ patterns: [pattern], autoGenerate: false });
        mod.init(ctx);
        mod.onTick!(0, ctx);

        const connects = events.emitted.filter(e => e.type === 'net:connect');
        expect(connects.length).toBe(1);
        const connect = connects[0] as Extract<EngineEvent, { type: 'net:connect' }>;
        expect(connect.port).toBe(22);

        mod.destroy();
    });

    it('generates custom traffic type events', () => {
        const events = createTestEventBus();
        const ctx = createTestContext(events);

        const pattern: TrafficPattern = {
            id: 'test-custom',
            type: 'iot-telemetry',
            sourceMachine: 'sensor-01',
            destination: 'gateway',
            intervalTicks: 1,
            data: { metric: 'temperature' },
        };

        const mod = createTrafficGenerator({ patterns: [pattern], autoGenerate: false });
        mod.init(ctx);
        mod.onTick!(0, ctx);

        const custom = events.emitted.filter(e => e.type === 'custom:traffic-iot-telemetry');
        expect(custom.length).toBe(1);

        mod.destroy();
    });

    it('respects startTick', () => {
        const events = createTestEventBus();
        const ctx = createTestContext(events);

        const pattern: TrafficPattern = {
            id: 'test-delayed',
            type: 'heartbeat',
            sourceMachine: 'monitor',
            destination: 'web-01',
            intervalTicks: 5,
            startTick: 10,
        };

        const mod = createTrafficGenerator({ patterns: [pattern], autoGenerate: false });
        mod.init(ctx);

        mod.onTick!(0, ctx);
        expect(events.emitted.filter(e => e.type === 'net:connect').length).toBe(0);

        mod.onTick!(10, ctx);
        expect(events.emitted.filter(e => e.type === 'net:connect').length).toBe(1);

        mod.destroy();
    });

    it('respects stopTick', () => {
        const events = createTestEventBus();
        const ctx = createTestContext(events);

        const pattern: TrafficPattern = {
            id: 'test-stop',
            type: 'heartbeat',
            sourceMachine: 'monitor',
            destination: 'web-01',
            intervalTicks: 1,
            stopTick: 2,
        };

        const mod = createTrafficGenerator({ patterns: [pattern], autoGenerate: false });
        mod.init(ctx);

        mod.onTick!(0, ctx);
        mod.onTick!(1, ctx);
        mod.onTick!(2, ctx);
        mod.onTick!(3, ctx); // Should not fire (past stopTick)

        const connects = events.emitted.filter(e => e.type === 'net:connect');
        expect(connects.length).toBe(3); // 0, 1, 2

        mod.destroy();
    });

    it('auto-generates patterns when machines exist', () => {
        const events = createTestEventBus();
        const ctx = createTestContext(events, ['web-01', 'db-01']);

        const mod = createTrafficGenerator({ autoGenerate: true });
        mod.init(ctx);

        // Run a few ticks to generate traffic
        for (let i = 0; i <= 30; i++) {
            mod.onTick!(i, ctx);
        }

        // Should have generated DNS, heartbeat, and web traffic
        const totalEvents = events.emitted.filter(e =>
            e.type === 'net:dns' || e.type === 'net:connect' || e.type === 'net:request',
        );
        expect(totalEvents.length).toBeGreaterThan(0);

        mod.destroy();
    });

    it('handles multiple patterns concurrently', () => {
        const events = createTestEventBus();
        const ctx = createTestContext(events);

        const patterns: TrafficPattern[] = [
            { id: 'p1', type: 'dns-query', sourceMachine: 'a', destination: 'dns', intervalTicks: 1 },
            { id: 'p2', type: 'heartbeat', sourceMachine: 'a', destination: 'b', intervalTicks: 1 },
        ];

        const mod = createTrafficGenerator({ patterns, autoGenerate: false });
        mod.init(ctx);
        mod.onTick!(0, ctx);

        const dns = events.emitted.filter(e => e.type === 'net:dns');
        const connects = events.emitted.filter(e => e.type === 'net:connect');
        expect(dns.length).toBe(1);
        expect(connects.length).toBe(1);

        mod.destroy();
    });
});
