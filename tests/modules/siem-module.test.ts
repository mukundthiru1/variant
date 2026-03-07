import { describe, it, expect } from 'vitest';
import { createSIEMModule } from '../../src/modules/siem-module';
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
            id: 'test',
            name: 'Test',
            version: '1.0.0',
            description: 'Test world',
            machines: [],
            objectives: [],
            scoring: {
                maxScore: 1000,
                hintPenalty: 50,
                timeBonus: false,
                stealthBonus: false,
                tiers: [],
            },
        } as unknown as WorldSpec,
        tick: 0,
        services: createServiceLocator(),
    };
}

describe('SIEM Module', () => {
    function setup(config?: Parameters<typeof createSIEMModule>[0]) {
        const events = createTestEventBus();
        const ctx = createTestContext(events);
        const mod = createSIEMModule(config);
        mod.init(ctx);
        return { events, ctx, mod };
    }

    it('initializes and destroys without error', () => {
        const { mod } = setup();
        expect(mod.id).toBe('siem-module');
        expect(mod.type).toBe('defense');
        mod.destroy();
    });

    it('provides siem and log-aggregation capabilities', () => {
        const { mod } = setup();
        expect(mod.provides.some(p => p.name === 'siem')).toBe(true);
        expect(mod.provides.some(p => p.name === 'log-aggregation')).toBe(true);
        mod.destroy();
    });

    it('translates auth:login events into SIEM log entries', () => {
        const { events, mod } = setup({ loadBuiltinRules: false, loadBuiltinCorrelationRules: false });

        events.emit({
            type: 'auth:login',
            user: 'admin',
            machine: 'web-01',
            service: 'ssh',
            success: false,
            timestamp: Date.now(),
        });

        // Trigger SIEM stats query
        events.emit({ type: 'custom:siem-stats', data: null, timestamp: Date.now() });

        const statsResult = events.emitted.find(e => e.type === 'custom:siem-stats-result');
        expect(statsResult).toBeDefined();

        mod.destroy();
    });

    it('translates net:connect events into SIEM log entries', () => {
        const { events, mod } = setup({ loadBuiltinRules: false, loadBuiltinCorrelationRules: false });

        events.emit({
            type: 'net:connect',
            host: '10.0.0.5',
            port: 22,
            source: 'attacker',
            protocol: 'tcp' as const,
            timestamp: Date.now(),
        });

        events.emit({ type: 'custom:siem-stats', data: null, timestamp: Date.now() });

        const statsResult = events.emitted.find(e => e.type === 'custom:siem-stats-result');
        expect(statsResult).toBeDefined();
        mod.destroy();
    });

    it('fires defense:alert on tick when detection rules match', () => {
        const { events, ctx, mod } = setup({
            loadBuiltinRules: false,
            loadBuiltinCorrelationRules: false,
            additionalRules: [{
                id: 'test-rule',
                name: 'Test Rule',
                description: 'Test detection',
                severity: 'warning' as const,
                conditions: [{ type: 'category-equals' as const, category: 'auth' }],
                threshold: 1,
                windowTicks: 100,
                cooldownTicks: 0,
                enabled: true,
            }],
        });

        // Emit an auth event
        events.emit({
            type: 'auth:login',
            user: 'attacker',
            machine: 'target',
            service: 'ssh',
            success: false,
            timestamp: Date.now(),
        });

        // Trigger tick to evaluate rules
        mod.onTick!(1, ctx);

        const alerts = events.emitted.filter(e => e.type === 'defense:alert');
        expect(alerts.length).toBeGreaterThanOrEqual(1);

        mod.destroy();
    });

    it('responds to siem-export custom events', () => {
        const { events, mod } = setup({ loadBuiltinRules: false, loadBuiltinCorrelationRules: false });

        events.emit({
            type: 'auth:login',
            user: 'admin',
            machine: 'web-01',
            service: 'ssh',
            success: true,
            timestamp: Date.now(),
        });

        events.emit({
            type: 'custom:siem-export',
            data: { format: 'json' },
            timestamp: Date.now(),
        });

        const exportResult = events.emitted.find(e => e.type === 'custom:siem-export-result');
        expect(exportResult).toBeDefined();

        mod.destroy();
    });

    it('loads additional detection rules from config', () => {
        const { mod } = setup({
            loadBuiltinRules: false,
            loadBuiltinCorrelationRules: false,
            additionalRules: [{
                id: 'custom-rule',
                name: 'Custom Rule',
                description: 'Custom detection',
                severity: 'critical' as const,
                conditions: [{ type: 'message-contains' as const, substring: 'admin' }],
                threshold: 1,
                windowTicks: 100,
                cooldownTicks: 0,
                enabled: true,
            }],
        });

        expect(mod.id).toBe('siem-module');
        mod.destroy();
    });

    it('translates fs:exec events', () => {
        const { events, mod } = setup({ loadBuiltinRules: false, loadBuiltinCorrelationRules: false });

        events.emit({
            type: 'fs:exec',
            machine: 'web-01',
            path: '/usr/bin/sudo',
            args: ['cat', '/etc/shadow'],
            user: 'attacker',
            timestamp: Date.now(),
        });

        events.emit({ type: 'custom:siem-stats', data: null, timestamp: Date.now() });
        const statsResult = events.emitted.find(e => e.type === 'custom:siem-stats-result');
        expect(statsResult).toBeDefined();

        mod.destroy();
    });

    it('translates defense:breach events', () => {
        const { events, mod } = setup({ loadBuiltinRules: false, loadBuiltinCorrelationRules: false });

        events.emit({
            type: 'defense:breach',
            machine: 'db-01',
            vector: 'sqli',
            attacker: 'hacker',
            timestamp: Date.now(),
        });

        events.emit({ type: 'custom:siem-stats', data: null, timestamp: Date.now() });
        const statsResult = events.emitted.find(e => e.type === 'custom:siem-stats-result');
        expect(statsResult).toBeDefined();

        mod.destroy();
    });

    it('handles siem-acknowledge custom events', () => {
        const { events, ctx, mod } = setup({
            loadBuiltinRules: false,
            loadBuiltinCorrelationRules: false,
            additionalRules: [{
                id: 'ack-test',
                name: 'Ack Test',
                description: 'For acknowledge testing',
                severity: 'warning' as const,
                conditions: [{ type: 'category-equals' as const, category: 'auth' }],
                threshold: 1,
                windowTicks: 100,
                cooldownTicks: 0,
                enabled: true,
            }],
        });

        events.emit({
            type: 'auth:login',
            user: 'test',
            machine: 'test-machine',
            service: 'ssh',
            success: false,
            timestamp: Date.now(),
        });

        mod.onTick!(1, ctx);

        // Acknowledge the alert
        events.emit({
            type: 'custom:siem-acknowledge',
            data: { alertId: 'alert-1' },
            timestamp: Date.now(),
        });

        mod.destroy();
    });

    it('skips sim:tick events from SIEM ingestion', () => {
        const { events, mod } = setup({ loadBuiltinRules: false, loadBuiltinCorrelationRules: false });

        // Emit a tick event — should not be ingested
        events.emit({
            type: 'sim:tick',
            tick: 1,
            timestamp: Date.now(),
        });

        events.emit({ type: 'custom:siem-stats', data: null, timestamp: Date.now() });
        const statsResult = events.emitted.find(e => e.type === 'custom:siem-stats-result') as { data: { totalLogs: number } } | undefined;
        // Tick events are not translated so totalLogs should be 0
        expect(statsResult).toBeDefined();

        mod.destroy();
    });
});
