import { describe, it, expect } from 'vitest';
import { createNPCEngine } from '../../src/modules/npc-engine';
import type { NPCDefinition } from '../../src/lib/npc/types';
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

const testNPC: NPCDefinition = {
    id: 'npc-admin',
    name: 'Admin',
    username: 'admin',
    role: 'admin',
    machine: 'web-01',
    schedule: [
        { tick: 5, type: { kind: 'login', method: 'ssh', success: true } },
        { tick: 10, type: { kind: 'command', command: 'ls -la /var/log' } },
        { tick: 15, type: { kind: 'logout' } },
    ],
    recurring: [
        {
            intervalTicks: 10,
            action: { kind: 'log', logFile: '/var/log/cron.log', message: 'CRON: backup complete' },
            startTick: 0,
        },
    ],
};

describe('NPC Engine Module', () => {
    function setup(npcs: NPCDefinition[] = [testNPC]) {
        const events = createTestEventBus();
        const ctx = createTestContext(events);
        const mod = createNPCEngine({ npcs });
        mod.init(ctx);
        return { events, ctx, mod };
    }

    it('initializes and destroys without error', () => {
        const { mod } = setup();
        expect(mod.id).toBe('npc-engine');
        expect(mod.type).toBe('actor');
        mod.destroy();
    });

    it('provides npc capability', () => {
        const { mod } = setup();
        expect(mod.provides.some(p => p.name === 'npc')).toBe(true);
        mod.destroy();
    });

    it('executes scheduled login action at correct tick', () => {
        const { events, ctx, mod } = setup();

        mod.onTick!(5, ctx);

        const loginEvents = events.emitted.filter(e => e.type === 'auth:login');
        expect(loginEvents.length).toBe(1);
        const login = loginEvents[0] as Extract<EngineEvent, { type: 'auth:login' }>;
        expect(login.user).toBe('admin');
        expect(login.machine).toBe('web-01');
        expect(login.success).toBe(true);

        mod.destroy();
    });

    it('executes scheduled command action at correct tick', () => {
        const { events, ctx, mod } = setup();

        mod.onTick!(10, ctx);

        const execEvents = events.emitted.filter(e => e.type === 'fs:exec');
        expect(execEvents.length).toBe(1);
        const exec = execEvents[0] as Extract<EngineEvent, { type: 'fs:exec' }>;
        expect(exec.path).toBe('ls');
        expect(exec.user).toBe('admin');

        mod.destroy();
    });

    it('executes scheduled logout action at correct tick', () => {
        const { events, ctx, mod } = setup();

        mod.onTick!(15, ctx);

        const logoutEvents = events.emitted.filter(e => e.type === 'custom:npc-logout');
        expect(logoutEvents.length).toBe(1);

        mod.destroy();
    });

    it('does not fire scheduled actions at wrong tick', () => {
        const { events, ctx, mod } = setup();

        mod.onTick!(3, ctx);

        const loginEvents = events.emitted.filter(e => e.type === 'auth:login');
        expect(loginEvents.length).toBe(0);

        mod.destroy();
    });

    it('executes recurring actions at correct intervals', () => {
        const { events, ctx, mod } = setup();

        mod.onTick!(0, ctx);
        const firstLog = events.emitted.filter(e => e.type === 'custom:npc-log');
        expect(firstLog.length).toBe(1);

        mod.onTick!(10, ctx);
        const secondLog = events.emitted.filter(e => e.type === 'custom:npc-log');
        expect(secondLog.length).toBe(2);

        mod.destroy();
    });

    it('does not fire recurring actions between intervals', () => {
        const { events, ctx, mod } = setup();

        mod.onTick!(0, ctx);
        mod.onTick!(5, ctx); // Should not fire (interval is 10)

        const logs = events.emitted.filter(e => e.type === 'custom:npc-log');
        expect(logs.length).toBe(1);

        mod.destroy();
    });

    it('handles NPC with file-modify action', () => {
        const npc: NPCDefinition = {
            id: 'npc-writer',
            name: 'Writer',
            username: 'writer',
            role: 'employee',
            machine: 'files-01',
            schedule: [
                { tick: 1, type: { kind: 'file-modify', path: '/tmp/test.txt', content: 'hello', modification: 'create' } },
            ],
        };

        const { events, ctx, mod } = setup([npc]);
        mod.onTick!(1, ctx);

        const writes = events.emitted.filter(e => e.type === 'fs:write');
        expect(writes.length).toBe(1);
        const write = writes[0] as Extract<EngineEvent, { type: 'fs:write' }>;
        expect(write.path).toBe('/tmp/test.txt');
        expect(write.user).toBe('writer');

        mod.destroy();
    });

    it('handles NPC with alert action', () => {
        const npc: NPCDefinition = {
            id: 'npc-alerter',
            name: 'Alerter',
            username: 'system',
            role: 'service-account',
            machine: 'mon-01',
            schedule: [
                { tick: 1, type: { kind: 'alert', message: 'Disk space low', severity: 'warning' } },
            ],
        };

        const { events, ctx, mod } = setup([npc]);
        mod.onTick!(1, ctx);

        const alerts = events.emitted.filter(e => e.type === 'sim:alert');
        expect(alerts.length).toBe(1);

        mod.destroy();
    });

    it('handles NPC with network action', () => {
        const npc: NPCDefinition = {
            id: 'npc-scanner',
            name: 'Scanner',
            username: 'scanner',
            role: 'attacker',
            machine: 'ext-01',
            schedule: [
                { tick: 1, type: { kind: 'network', target: 'web-01', port: 80, protocol: 'tcp', activity: 'scan' } },
            ],
        };

        const { events, ctx, mod } = setup([npc]);
        mod.onTick!(1, ctx);

        const connects = events.emitted.filter(e => e.type === 'net:connect');
        expect(connects.length).toBe(1);

        mod.destroy();
    });

    it('handles brute force attacker with multiple attempts', () => {
        const npc: NPCDefinition = {
            id: 'npc-brute',
            name: 'Brute Forcer',
            username: 'root',
            role: 'attacker',
            machine: 'web-01',
            schedule: [
                { tick: 1, type: { kind: 'login', method: 'ssh', success: false, attempts: 3 } },
            ],
        };

        const { events, ctx, mod } = setup([npc]);
        mod.onTick!(1, ctx);

        const logins = events.emitted.filter(e => e.type === 'auth:login');
        expect(logins.length).toBe(3); // 1 initial + 2 additional
        expect(logins.every(e => (e as Extract<EngineEvent, { type: 'auth:login' }>).success === false)).toBe(true);

        mod.destroy();
    });

    it('handles NPC with custom action', () => {
        const npc: NPCDefinition = {
            id: 'npc-custom',
            name: 'Custom',
            username: 'custom',
            role: 'custom',
            machine: 'custom-01',
            schedule: [
                { tick: 1, type: { kind: 'custom', action: 'my-action', params: { key: 'value' } } },
            ],
        };

        const { events, ctx, mod } = setup([npc]);
        mod.onTick!(1, ctx);

        const custom = events.emitted.filter(e => e.type === 'custom:npc-my-action');
        expect(custom.length).toBe(1);

        mod.destroy();
    });

    it('handles multiple NPCs independently', () => {
        const npc1: NPCDefinition = {
            id: 'npc-1', name: 'NPC 1', username: 'user1', role: 'employee', machine: 'web-01',
            schedule: [{ tick: 1, type: { kind: 'login', method: 'ssh', success: true } }],
        };
        const npc2: NPCDefinition = {
            id: 'npc-2', name: 'NPC 2', username: 'user2', role: 'employee', machine: 'web-02',
            schedule: [{ tick: 1, type: { kind: 'login', method: 'ssh', success: true } }],
        };

        const { events, ctx, mod } = setup([npc1, npc2]);
        mod.onTick!(1, ctx);

        const logins = events.emitted.filter(e => e.type === 'auth:login');
        expect(logins.length).toBe(2);

        mod.destroy();
    });
});
