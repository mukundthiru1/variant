/**
 * VARIANT — Dynamics Engine Tests
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createDynamicsEngine } from '../../src/modules/dynamics-engine';
import { createEventBus } from '../../src/core/event-bus';
import type { SimulationContext } from '../../src/core/modules';
import { createServiceLocator } from '../../src/core/modules';
import type { EventBus, EngineEvent } from '../../src/core/events';
import type { WorldSpec, DynamicsSpec } from '../../src/core/world/types';

// ── Helpers ────────────────────────────────────────────────────

function makeContext(dynamics: DynamicsSpec | undefined, events: EventBus): SimulationContext {
    return {
        vms: new Map(),
        fabric: {
            getTrafficLog: () => [],
            getStats: () => ({ totalFrames: 0, droppedFrames: 0, bytesRouted: 0, dnsQueries: 0, activeConnections: 0 }),
            tap: () => () => { },
            addDNSRecord: () => { },
            registerExternal: () => { },
            getExternalHandler: () => undefined,
            getExternalDomains: () => [],
        },
        events,
        world: {
            version: '2.0',
            trust: 'community',
            meta: { title: 'test', scenario: 'test', briefing: [], difficulty: 'beginner', mode: 'attack', vulnClasses: [], tags: [], estimatedMinutes: 5, author: { name: 'test', id: 'test', type: 'santh' } },
            machines: {},
            startMachine: 'player',
            network: { segments: [], edges: [] },
            credentials: [],
            objectives: [],
            dynamics,
            modules: [],
            scoring: { maxScore: 1000, timeBonus: false, stealthBonus: false, hintPenalty: 50, tiers: [] },
            hints: [],
        } as unknown as WorldSpec,
        tick: 0,
        services: createServiceLocator(),
    };
}

// ── Tests ──────────────────────────────────────────────────────

describe('DynamicsEngine', () => {
    let events: EventBus;
    let engine: ReturnType<typeof createDynamicsEngine>;

    beforeEach(() => {
        events = createEventBus();
        engine = createDynamicsEngine();
    });

    afterEach(() => {
        engine.destroy();
    });

    it('fires timed alert at correct tick', () => {
        const ctx = makeContext({
            timedEvents: [
                {
                    tick: 5,
                    action: { type: 'alert', message: 'Credential rotation imminent', severity: 'warning' },
                },
            ],
        }, events);

        engine.init(ctx);

        const alerts: EngineEvent[] = [];
        events.on('sim:alert', (e) => alerts.push(e));

        // Ticks 1-4: no alert
        for (let i = 1; i <= 4; i++) {
            events.emit({ type: 'sim:tick', tick: i, timestamp: Date.now() });
        }
        expect(alerts.length).toBe(0);

        // Tick 5: alert fires
        events.emit({ type: 'sim:tick', tick: 5, timestamp: Date.now() });
        expect(alerts.length).toBe(1);
    });

    it('fires timed events only once', () => {
        const ctx = makeContext({
            timedEvents: [
                {
                    tick: 2,
                    action: { type: 'alert', message: 'Alert!', severity: 'info' },
                },
            ],
        }, events);

        engine.init(ctx);

        const alerts: EngineEvent[] = [];
        events.on('sim:alert', (e) => alerts.push(e));

        events.emit({ type: 'sim:tick', tick: 2, timestamp: Date.now() });
        events.emit({ type: 'sim:tick', tick: 3, timestamp: Date.now() });
        events.emit({ type: 'sim:tick', tick: 4, timestamp: Date.now() });

        expect(alerts.length).toBe(1);
    });

    it('fires credential rotation as custom event', () => {
        const ctx = makeContext({
            timedEvents: [
                {
                    tick: 10,
                    action: { type: 'rotate-credential', credentialId: 'admin-pass', newValue: 'NewP@ss2024!' },
                },
            ],
        }, events);

        engine.init(ctx);

        const customs: EngineEvent[] = [];
        events.onPrefix('custom:', (e) => customs.push(e));

        events.emit({ type: 'sim:tick', tick: 10, timestamp: Date.now() });

        expect(customs.length).toBe(1);
        expect(customs[0]!.type).toBe('custom:dynamics-rotate-cred');
    });

    it('does nothing without dynamics spec', () => {
        const ctx = makeContext(undefined, events);
        engine.init(ctx);

        const alerts: EngineEvent[] = [];
        events.on('sim:alert', (e) => alerts.push(e));

        events.emit({ type: 'sim:tick', tick: 1, timestamp: Date.now() });
        expect(alerts.length).toBe(0);
    });

    it('cleans up on destroy', () => {
        const ctx = makeContext({
            timedEvents: [
                { tick: 1, action: { type: 'alert', message: 'Test', severity: 'info' } },
            ],
        }, events);

        engine.init(ctx);
        engine.destroy();

        const alerts: EngineEvent[] = [];
        events.on('sim:alert', (e) => alerts.push(e));

        events.emit({ type: 'sim:tick', tick: 1, timestamp: Date.now() });
        expect(alerts.length).toBe(0);
    });

    it('handles reactive events on trigger', () => {
        const ctx = makeContext({
            reactiveEvents: [
                {
                    trigger: 'auth:login',
                    action: { type: 'alert', message: 'Login detected!', severity: 'warning' },
                },
            ],
        }, events);

        engine.init(ctx);

        const alerts: EngineEvent[] = [];
        events.on('sim:alert', (e) => alerts.push(e));

        events.emit({
            type: 'auth:login',
            user: 'admin',
            machine: 'web',
            service: 'ssh',
            success: true,
            timestamp: Date.now(),
        });

        expect(alerts.length).toBe(1);
    });
});
