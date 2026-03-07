/**
 * VARIANT — Session Module Tests
 */

import { describe, it, expect, afterEach } from 'vitest';
import { createEventBus } from '../../src/core/event-bus';
import type { EngineEvent, EventBus } from '../../src/core/events';
import type { SessionFilter, SessionStore, SessionModuleConfig } from '../../src/modules/session-module';
import { createSessionModule } from '../../src/modules/session-module';
import type { Module, SimulationContext, ServiceLocator } from '../../src/core/modules';
import type { WorldSpec } from '../../src/core/world/types';
import { stubFabric, stubServices } from '../helpers';

interface TestEventBus extends EventBus {
    emitted: EngineEvent[];
}

function createTestEventBus(): TestEventBus {
    const emitted: EngineEvent[] = [];
    const inner = createEventBus(10_000);

    return {
        emitted,
        emit(event): void {
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
}

const WORLD: WorldSpec = {
    version: '2.0',
    trust: 'community',
    meta: {
        title: 'Session Manager Test',
        scenario: 'session-manager',
        briefing: [],
        difficulty: 'beginner',
        mode: 'attack',
        vulnClasses: [],
        tags: [],
        estimatedMinutes: 5,
        author: { name: 'unit-test', id: 'unit', type: 'santh' },
    },
    machines: {},
    startMachine: 'web',
    network: { segments: [], edges: [] },
    credentials: [],
    objectives: [],
    modules: [],
    scoring: {
        maxScore: 1000,
        timeBonus: false,
        stealthBonus: false,
        hintPenalty: 25,
        tiers: [],
    },
    hints: [],
};

function makeContext(events: EventBus, services: ServiceLocator = stubServices()): SimulationContext {
    return {
        vms: new Map(),
        fabric: stubFabric(),
        events,
        world: WORLD,
        tick: 0,
        services,
    };
}

    describe('Session Manager Module', () => {
        let events: TestEventBus;
        let service!: SessionStore & Module;
        let activeContext!: SimulationContext;

        function setup(config?: SessionModuleConfig) {
            events = createTestEventBus();
            const module = createSessionModule(events, config);
            activeContext = makeContext(events, stubServices());
            module.init(activeContext);

            service = module;
            return { module, context: activeContext };
        }

    afterEach(() => {
        if (service?.destroy !== undefined) {
            service.destroy();
        }
    });

    it('creates module metadata', () => {
        const { module } = setup();
        expect(module.id).toBe('session-manager');
        expect(module.version).toBe('1.0.0');
        expect(module.provides.map((cap) => cap.name)).toEqual(expect.arrayContaining(['session', 'auth-state']));
    });

    it('creates and retrieves a session', () => {
        setup();

        const created = service.createSession('web', 'alice', 'ssh');
        const fetched = service.getSession(created.id);

        expect(fetched).toBeDefined();
        expect(fetched?.machine).toBe('web');
        expect(fetched?.user).toBe('alice');
        expect(fetched?.protocol).toBe('ssh');
        expect(fetched?.status).toBe('active');
        expect(events.emitted.some((event) => event.type === 'custom:session-created')).toBe(true);
    });

    it('filters sessions by machine, user, and protocol', () => {
        setup();

        const s1 = service.createSession('web', 'alice', 'ssh');
        const s2 = service.createSession('db', 'alice', 'http');
        const s3 = service.createSession('web', 'bob', 'ssh');
        const byMachine = service.getSessions({ machine: 'web' } as SessionFilter);
        const byUser = service.getSessions({ user: 'alice' } as SessionFilter);
        const byProtocol = service.getSessions({ protocol: 'ssh' } as SessionFilter);

        expect(byMachine).toHaveLength(2);
        expect(byMachine.some((s) => s.id === s1.id)).toBe(true);
        expect(byMachine.some((s) => s.id === s3.id)).toBe(true);
        expect(byUser).toHaveLength(2);
        expect(byProtocol).toHaveLength(2);
        expect(byProtocol.some((s) => s.id === s2.id)).toBe(false);
    });

    it('uses deterministic IDs (predictable sequence)', () => {
        setup();

        const first = service.createSession('web', 'alice', 'ssh');
        const second = service.createSession('web', 'alice', 'ssh');

        const firstSeq = Number.parseInt(first.id.split('-').at(-2) ?? '0', 36);
        const secondSeq = Number.parseInt(second.id.split('-').at(-2) ?? '0', 36);

        expect(second.id).not.toBe(first.id);
        expect(secondSeq).toBe(firstSeq + 1);
    });

    it('expires sessions on tick and emits session-expired', () => {
        setup({ protocolTimeouts: { ssh: 2 } });

        const session = service.createSession('web', 'alice', 'ssh');
        service.onTick!(1, activeContext);

        const beforeExpire = service.getSession(session.id);
        expect(beforeExpire).toBeDefined();

        service.onTick!(2, activeContext);

        const afterExpire = service.getSession(session.id);
        expect(afterExpire).toBeUndefined();

        const expiredEvents = events.emitted.filter((event) => event.type === 'custom:session-expired');
        expect(expiredEvents).toHaveLength(1);
        const expired = expiredEvents[0] as { data: { duration: number } };
        expect(expired.data.duration).toBeGreaterThanOrEqual(2);
    });

    it('marks sessions idle after inactivity threshold', () => {
        setup({ protocolTimeouts: { ssh: 10 } });

        const session = service.createSession('web', 'alice', 'ssh');
        service.onTick!(5, activeContext);

        const updated = service.getSession(session.id);
        expect(updated?.status).toBe('idle');
    });

    it('creates sessions from auth:login and destroys them on auth:logout', () => {
        setup();

        events.emit({
            type: 'auth:login',
            user: 'alice',
            machine: 'db',
            service: 'ssh',
            success: true,
            timestamp: 100,
        });

        let authState = service.getAuthState('db');
        expect(authState.loggedInUsers).toContain('alice');
        expect(authState.activeSessions).toHaveLength(1);

        events.emit({
            type: 'auth:logout',
            user: 'alice',
            machine: 'db',
            service: 'ssh',
            timestamp: 110,
        });

        authState = service.getAuthState('db');
        expect(authState.loggedInUsers).not.toContain('alice');
        expect(authState.activeSessions).toHaveLength(0);
    });

    it('tracks failed attempts and lockout state', () => {
        setup({ maxFailedAttempts: 2 });

        events.emit({
            type: 'auth:login',
            user: 'mallory',
            machine: 'db',
            service: 'ssh',
            success: false,
            timestamp: 100,
        });

        events.emit({
            type: 'auth:login',
            user: 'mallory',
            machine: 'db',
            service: 'ssh',
            success: false,
            timestamp: 101,
        });

        const state = service.getAuthState('db');
        expect(state.failedAttempts['mallory']).toBe(2);
        expect(state.lockouts).toContain('mallory');
    });

    it('warns on excessive concurrent sessions for the same user', () => {
        setup({ maxConcurrentSessionsPerUser: 2 });

        service.createSession('web', 'alice', 'ssh');
        service.createSession('web', 'alice', 'ssh');
        service.createSession('web', 'alice', 'ssh');

        const anomaly = events.emitted.filter((event) => event.type === 'custom:session-anomaly');
        expect(anomaly).toHaveLength(1);

        const state = service.getAuthState('web');
        expect(state.loggedInUsers).toContain('alice');
        expect(state.activeSessions.length).toBe(3);
    });

    it('hijacks a session to another user', () => {
        setup();

        const session = service.createSession('web', 'alice', 'ssh');

        const wasHijacked = service.hijackSession(session.id, 'bob');
        expect(wasHijacked).toBe(true);

        const updated = service.getSession(session.id);
        expect(updated?.user).toBe('bob');
        expect(updated?.status).toBe('hijacked');

        const eventsHijack = events.emitted.filter((event) => event.type === 'custom:session-hijacked');
        expect(eventsHijack).toHaveLength(1);
        const hijackEvent = eventsHijack[0] as { data: { oldUser: string; newUser: string } };
        expect(hijackEvent.data.oldUser).toBe('alice');
        expect(hijackEvent.data.newUser).toBe('bob');
    });

    it('returns false when hijack target does not exist', () => {
        setup();

        const result = service.hijackSession('missing-session', 'bob');
        expect(result).toBe(false);
    });

    it('does not allow replaying expired sessions', () => {
        setup({ protocolTimeouts: { ssh: 1 } });

        const session = service.createSession('web', 'alice', 'ssh');
        service.onTick!(1, activeContext);
        expect(service.getSession(session.id)).toBeUndefined();

        const stolen = service.stealSession(session.id);
        expect(stolen).toBeNull();
    });

    it('steals an active session into a new copy', () => {
        setup();

        const original = service.createSession('web', 'alice', 'ssh');
        const stolen = service.stealSession(original.id);

        expect(stolen).not.toBeNull();
        expect(stolen?.id).not.toBe(original.id);
        expect(stolen?.machine).toBe('web');
        expect(stolen?.user).toBe('alice');

        const total = service.getSessions({ machine: 'web', user: 'alice' });
        expect(total).toHaveLength(2);
    });

    it('handles auth:logout optionally scoped to a service', () => {
        setup();

        events.emit({
            type: 'auth:login',
            user: 'alice',
            machine: 'web',
            service: 'ssh',
            success: true,
            timestamp: 1000,
        });
        events.emit({
            type: 'auth:login',
            user: 'alice',
            machine: 'web',
            service: 'http',
            success: true,
            timestamp: 1000,
        });

        const before = service.getAuthState('web');
        expect(before.activeSessions).toHaveLength(2);

        events.emit({
            type: 'auth:logout',
            user: 'alice',
            machine: 'web',
            service: 'ssh',
            timestamp: 1001,
        });

        const after = service.getSessions({ machine: 'web', user: 'alice' });
        expect(after).toHaveLength(1);
    });

    it('returns session store via service locator', () => {
        const services = stubServices();
        events = createTestEventBus();
        const module = createSessionModule(events, {});

        const context = makeContext(events, services);
        module.init(context);
        service = module;

        const store = context.services.get<SessionStore>('session-manager');
        expect(store).toBeDefined();

        const created = store?.createSession('web', 'alice', 'http');
        expect(created).toBeDefined();
        expect(store?.getSession(created?.id as string)?.machine).toBe('web');

        module.destroy();
    });

    it('captures per-machine authenticated services', () => {
        setup();

        events.emit({
            type: 'auth:login',
            user: 'alice',
            machine: 'web',
            service: 'http',
            success: true,
            timestamp: 1200,
        });
        events.emit({
            type: 'auth:login',
            user: 'alice',
            machine: 'web',
            service: 'k8s',
            success: true,
            timestamp: 1201,
        });

        const state = service.getAuthState('web');
        expect(state.authenticatedServices['alice']).toEqual(expect.arrayContaining(['http', 'k8s']));
    });

    it('destroys sessions cleanly and updates auth state', () => {
        setup();

        const s1 = service.createSession('web', 'alice', 'ssh');
        const s2 = service.createSession('web', 'alice', 'rdp');

        let authState = service.getAuthState('web');
        expect(authState.activeSessions).toHaveLength(2);

        service.destroySession(s1.id);

        authState = service.getAuthState('web');
        expect(authState.activeSessions).toHaveLength(1);
        expect(authState.loggedInUsers).toContain('alice');

        expect(service.getSession(s1.id)).toBeUndefined();
        expect(service.getSession(s2.id)).toBeDefined();
    });
});
