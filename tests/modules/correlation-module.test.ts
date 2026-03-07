import { describe, it, expect } from 'vitest';
import { createCorrelationModule } from '../../src/modules/correlation-module';
import type { SimulationContext } from '../../src/core/modules';
import { createServiceLocator } from '../../src/core/modules';
import type { EventBus, EngineEvent, EventHandler, EventType, EventByType } from '../../src/core/events';
import type { WorldSpec } from '../../src/core/world/types';
import { stubFabric } from '../helpers';

// ── Minimal EventBus ─────────────────────────────────────────

function createTestEventBus(): EventBus & { emitted: EngineEvent[] } {
    const handlers = new Map<string, Set<EventHandler>>();
    const prefixHandlers = new Map<string, Set<EventHandler>>();
    const emitted: EngineEvent[] = [];

    const bus: EventBus & { emitted: EngineEvent[] } = {
        emitted,
        emit(event: EngineEvent): void {
            emitted.push(event);
            const exact = handlers.get(event.type);
            if (exact) for (const h of exact) h(event);
            for (const [prefix, set] of prefixHandlers) {
                if (prefix === '' || event.type.startsWith(prefix)) {
                    for (const h of set) h(event);
                }
            }
        },
        on<T extends EventType>(type: T, handler: EventHandler<EventByType<T>>): () => void {
            const set = handlers.get(type) ?? new Set();
            set.add(handler as EventHandler);
            handlers.set(type, set);
            return () => { set.delete(handler as EventHandler); };
        },
        once<T extends EventType>(type: T, handler: EventHandler<EventByType<T>>): () => void {
            let unsub: (() => void) | null = null;
            unsub = bus.on(type, ((event: EventByType<T>) => {
                if (unsub !== null) unsub();
                handler(event);
            }) as EventHandler<EventByType<T>>);
            return unsub;
        },
        waitFor<T extends EventType>(
            type: T,
            predicate?: (event: EventByType<T>) => boolean,
        ): Promise<EventByType<T>> {
            return new Promise<EventByType<T>>((resolve) => {
                let unsub: (() => void) | null = null;
                unsub = bus.on(type, ((event: EventByType<T>) => {
                    if (predicate !== undefined && !predicate(event)) return;
                    if (unsub !== null) unsub();
                    resolve(event);
                }) as EventHandler<EventByType<T>>);
            });
        },
        onPrefix(prefix: string, handler: EventHandler): () => void {
            const set = prefixHandlers.get(prefix) ?? new Set();
            set.add(handler);
            prefixHandlers.set(prefix, set);
            return () => { set.delete(handler); };
        },
        getLog: () => [],
        clearLog: () => {},
        removeAllListeners: () => { handlers.clear(); prefixHandlers.clear(); },
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

describe('Correlation Module', () => {
    function setup(config?: Parameters<typeof createCorrelationModule>[0]) {
        const events = createTestEventBus();
        const ctx = createTestContext(events);
        const mod = createCorrelationModule(config);
        mod.init(ctx);
        return { events, ctx, mod };
    }

    it('initializes and destroys without error', () => {
        const { mod } = setup();
        expect(mod.id).toBe('correlation-module');
        expect(mod.type).toBe('defense');
        mod.destroy();
    });

    it('provides correlation capability', () => {
        const { mod } = setup();
        expect(mod.provides.some(p => p.name === 'correlation')).toBe(true);
        mod.destroy();
    });

    it('detects brute force via threshold rule', () => {
        const { events, mod } = setup({ loadBuiltinRules: true });

        const now = Date.now();
        // Emit 5 failed logins (threshold is 5)
        for (let i = 0; i < 5; i++) {
            events.emit({
                type: 'auth:login',
                user: 'admin',
                machine: 'web-01',
                service: 'ssh',
                success: false,
                timestamp: now + i * 100,
            });
        }

        const alerts = events.emitted.filter(e => e.type === 'defense:alert');
        expect(alerts.length).toBeGreaterThanOrEqual(1);

        mod.destroy();
    });

    it('detects attack chain via sequence rule', () => {
        const { events, mod } = setup({ loadBuiltinRules: true });

        const now = Date.now();

        events.emit({
            type: 'net:connect',
            host: '10.0.0.5',
            port: 22,
            source: 'attacker',
            protocol: 'tcp' as const,
            timestamp: now,
        });

        events.emit({
            type: 'auth:login',
            user: 'admin',
            machine: 'web-01',
            service: 'ssh',
            success: true,
            timestamp: now + 1000,
        });

        events.emit({
            type: 'auth:escalate',
            machine: 'web-01',
            from: 'admin',
            to: 'root',
            method: 'sudo',
            timestamp: now + 2000,
        });

        const alerts = events.emitted.filter(e => e.type === 'defense:alert');
        expect(alerts.length).toBeGreaterThanOrEqual(1);

        mod.destroy();
    });

    it('supports custom rules via config', () => {
        const { events, mod } = setup({
            loadBuiltinRules: false,
            rules: [{
                id: 'custom-threshold',
                name: 'Custom Threshold',
                strategy: {
                    type: 'threshold',
                    eventType: 'fs:read',
                    threshold: 2,
                },
                windowMs: 60_000,
                actions: [{ type: 'alert', params: { message: 'Too many reads' } }],
            }],
        });

        const now = Date.now();
        events.emit({ type: 'fs:read', machine: 'web-01', path: '/etc/passwd', user: 'attacker', timestamp: now });
        events.emit({ type: 'fs:read', machine: 'web-01', path: '/etc/shadow', user: 'attacker', timestamp: now + 100 });

        const alerts = events.emitted.filter(e => e.type === 'defense:alert');
        expect(alerts.length).toBeGreaterThanOrEqual(1);

        mod.destroy();
    });

    it('responds to correlation-query custom events', () => {
        const { events, mod } = setup({ loadBuiltinRules: true });

        events.emit({
            type: 'custom:correlation-query',
            data: null,
            timestamp: Date.now(),
        });

        const queryResult = events.emitted.find(e => e.type === 'custom:correlation-query-result');
        expect(queryResult).toBeDefined();

        mod.destroy();
    });

    it('supports runtime rule addition via custom events', () => {
        const { events, mod } = setup({ loadBuiltinRules: false });

        events.emit({
            type: 'custom:correlation-add-rule',
            data: {
                rule: {
                    id: 'runtime-rule',
                    name: 'Runtime Rule',
                    strategy: { type: 'threshold', eventType: 'auth:login', threshold: 1 },
                    windowMs: 60_000,
                    actions: [{ type: 'alert', params: { message: 'Runtime alert' } }],
                },
            },
            timestamp: Date.now(),
        });

        events.emit({
            type: 'auth:login',
            user: 'test',
            machine: 'test-machine',
            service: 'ssh',
            success: true,
            timestamp: Date.now(),
        });

        const alerts = events.emitted.filter(e => e.type === 'defense:alert');
        expect(alerts.length).toBeGreaterThanOrEqual(1);

        mod.destroy();
    });

    it('ignores sim:tick and custom events', () => {
        const { events, mod } = setup({ loadBuiltinRules: false });

        events.emit({ type: 'sim:tick', tick: 1, timestamp: Date.now() });
        events.emit({ type: 'custom:something', data: null, timestamp: Date.now() });

        const alerts = events.emitted.filter(e => e.type === 'defense:alert');
        expect(alerts.length).toBe(0);

        mod.destroy();
    });
});
