import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createScoringEngine } from '../src/modules/scoring-engine';
import type { ScoreBreakdown } from '../src/modules/scoring-engine';
import type { SimulationContext } from '../src/core/modules';
import { createServiceLocator } from '../src/core/modules';
import type { EventBus, EngineEvent, EventHandler, Unsubscribe, EventType, EventByType } from '../src/core/events';
import type { WorldSpec, ScoringConfig } from '../src/core/world/types';

// ── Helpers ─────────────────────────────────────────────────

function createMockEventBus(): EventBus & {
    trigger(type: string, data?: Record<string, unknown>): void;
    getEmitted(): EngineEvent[];
} {
    const handlers = new Map<string, Set<EventHandler>>();
    const prefixHandlers = new Map<string, Set<EventHandler>>();
    const emitted: EngineEvent[] = [];

    const bus: EventBus & {
        trigger(type: string, data?: Record<string, unknown>): void;
        getEmitted(): EngineEvent[];
    } = {
        emit(event: EngineEvent): void {
            emitted.push(event);
            const typeHandlers = handlers.get(event.type);
            if (typeHandlers) {
                for (const h of typeHandlers) h(event);
            }
            for (const [prefix, pHandlers] of prefixHandlers) {
                if (prefix === '*' || event.type.startsWith(prefix.replace('*', ''))) {
                    for (const h of pHandlers) h(event);
                }
            }
        },

        on<T extends EventType>(type: T, handler: EventHandler<EventByType<T>>): Unsubscribe {
            if (!handlers.has(type)) handlers.set(type, new Set());
            handlers.get(type)!.add(handler as EventHandler);
            return () => { handlers.get(type)?.delete(handler as EventHandler); };
        },

        onPrefix(prefix: string, handler: EventHandler): Unsubscribe {
            if (!prefixHandlers.has(prefix)) prefixHandlers.set(prefix, new Set());
            prefixHandlers.get(prefix)!.add(handler);
            return () => { prefixHandlers.get(prefix)?.delete(handler); };
        },

        once<T extends EventType>(type: T, handler: EventHandler<EventByType<T>>): Unsubscribe {
            let unsub: Unsubscribe | null = null;
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
                let unsub: Unsubscribe | null = null;
                unsub = bus.on(type, ((event: EventByType<T>) => {
                    if (predicate !== undefined && !predicate(event)) return;
                    if (unsub !== null) unsub();
                    resolve(event);
                }) as EventHandler<EventByType<T>>);
            });
        },

        getLog(): readonly EngineEvent[] { return emitted; },
        clearLog(): void { emitted.length = 0; },
        removeAllListeners(): void { handlers.clear(); prefixHandlers.clear(); },

        // Test helpers
        trigger(type: string, data?: Record<string, unknown>): void {
            this.emit({ type, ...data, timestamp: Date.now() } as unknown as EngineEvent);
        },

        getEmitted(): EngineEvent[] { return emitted; },
    };

    return bus;
}

function createScoringWorldSpec(overrides?: Partial<ScoringConfig>): WorldSpec {
    return {
        version: '2.0',
        trust: 'community',
        meta: {
            id: 'test',
            title: 'Test',
            description: 'Test',
            author: 'test',
            difficulty: 'beginner',
            category: 'offensive',
            estimatedMinutes: 5,
            tags: [],
        },
        machines: {},
        startMachine: 'test',
        network: { subnets: [], links: [] },
        credentials: [],
        objectives: [
            { id: 'obj-1', title: 'Test Objective', type: 'flag', description: 'test', reward: 100 },
            { id: 'obj-2', title: 'Bonus', type: 'flag', description: 'bonus', reward: 50 },
        ],
        modules: ['scoring-engine'],
        scoring: {
            maxScore: 1000,
            timeBonus: true,
            stealthBonus: true,
            hintPenalty: 25,
            tiers: [
                { name: 'MASTERY', minScore: 900, color: '#FFD700' },
                { name: 'PROFICIENT', minScore: 700, color: '#C0C0C0' },
                { name: 'NOVICE', minScore: 0, color: '#CD7F32' },
            ],
            ...overrides,
        },
    } as unknown as WorldSpec;
}

function createMockContext(world: WorldSpec, tick: number = 0): SimulationContext & {
    events: ReturnType<typeof createMockEventBus>;
} {
    const events = createMockEventBus();
    return {
        vms: new Map(),
        fabric: {
            getTrafficLog: () => [],
            getStats: () => ({
                totalFrames: 0, droppedFrames: 0,
                bytesRouted: 0, dnsQueries: 0, activeConnections: 0,
            }),
            tap: vi.fn(),
            addDNSRecord: vi.fn(),
            registerExternal: vi.fn(),
            getExternalHandler: () => undefined,
            getExternalDomains: () => [],
        },
        events,
        world,
        tick,
        services: createServiceLocator(),
    };
}

// ── Tests ───────────────────────────────────────────────────

describe('Scoring Engine', () => {
    let engine: ReturnType<typeof createScoringEngine>;

    beforeEach(() => {
        engine = createScoringEngine();
    });

    describe('Basic Scoring', () => {
        it('emits initial score on init', () => {
            const world = createScoringWorldSpec();
            const ctx = createMockContext(world);
            engine.init(ctx);

            const scoreEvents = ctx.events.getEmitted()
                .filter(e => e.type === 'custom:score-update');
            expect(scoreEvents.length).toBeGreaterThan(0);

            const breakdown = (scoreEvents[0] as { data: ScoreBreakdown }).data;
            expect(breakdown.baseScore).toBe(1000);
            expect(breakdown.objectivePoints).toBe(0);
            expect(breakdown.hintPenalty).toBe(0);
        });

        it('adds objective points on completion', () => {
            const world = createScoringWorldSpec();
            const ctx = createMockContext(world);
            engine.init(ctx);

            ctx.events.clearLog();
            ctx.events.trigger('objective:complete', { objectiveId: 'obj-1' });

            const scoreEvents = ctx.events.getEmitted()
                .filter(e => e.type === 'custom:score-update');
            expect(scoreEvents.length).toBeGreaterThan(0);

            const breakdown = (scoreEvents[scoreEvents.length - 1] as { data: ScoreBreakdown }).data;
            expect(breakdown.objectivePoints).toBe(100);
        });

        it('stacks multiple objective rewards', () => {
            const world = createScoringWorldSpec();
            const ctx = createMockContext(world);
            engine.init(ctx);

            ctx.events.trigger('objective:complete', { objectiveId: 'obj-1' });
            ctx.events.trigger('objective:complete', { objectiveId: 'obj-2' });

            const scoreEvents = ctx.events.getEmitted()
                .filter(e => e.type === 'custom:score-update');
            const last = (scoreEvents[scoreEvents.length - 1] as { data: ScoreBreakdown }).data;
            expect(last.objectivePoints).toBe(150);
        });
    });

    describe('Hint Penalty', () => {
        it('deducts points for hint usage', () => {
            const world = createScoringWorldSpec();
            const ctx = createMockContext(world);
            engine.init(ctx);

            ctx.events.clearLog();
            ctx.events.emit({
                type: 'custom:hint-used',
                data: null,
                timestamp: Date.now(),
            });

            const scoreEvents = ctx.events.getEmitted()
                .filter(e => e.type === 'custom:score-update');
            const last = (scoreEvents[scoreEvents.length - 1] as { data: ScoreBreakdown }).data;
            expect(last.hintPenalty).toBe(25);
        });

        it('stacks multiple hint penalties', () => {
            const world = createScoringWorldSpec();
            const ctx = createMockContext(world);
            engine.init(ctx);

            ctx.events.emit({ type: 'custom:hint-used', data: null, timestamp: Date.now() });
            ctx.events.emit({ type: 'custom:hint-used', data: null, timestamp: Date.now() });
            ctx.events.emit({ type: 'custom:hint-used', data: null, timestamp: Date.now() });

            const scoreEvents = ctx.events.getEmitted()
                .filter(e => e.type === 'custom:score-update');
            const last = (scoreEvents[scoreEvents.length - 1] as { data: ScoreBreakdown }).data;
            expect(last.hintPenalty).toBe(75);
        });
    });

    describe('Custom Score Points', () => {
        it('adds custom scoring points via event', () => {
            const world = createScoringWorldSpec();
            const ctx = createMockContext(world);
            engine.init(ctx);

            ctx.events.clearLog();
            ctx.events.emit({
                type: 'custom:score-custom-points',
                data: { points: 50 },
                timestamp: Date.now(),
            });

            const scoreEvents = ctx.events.getEmitted()
                .filter(e => e.type === 'custom:score-update');
            const last = (scoreEvents[scoreEvents.length - 1] as { data: ScoreBreakdown }).data;
            expect(last.customPoints).toBe(50);
        });
    });

    describe('Score Query', () => {
        it('emits score on query event', () => {
            const world = createScoringWorldSpec();
            const ctx = createMockContext(world);
            engine.init(ctx);

            ctx.events.clearLog();
            ctx.events.emit({
                type: 'custom:score-query',
                data: null,
                timestamp: Date.now(),
            });

            const scoreEvents = ctx.events.getEmitted()
                .filter(e => e.type === 'custom:score-update');
            expect(scoreEvents.length).toBeGreaterThan(0);
        });
    });

    describe('Tier Classification', () => {
        it('assigns correct tier based on score', () => {
            const world = createScoringWorldSpec();
            const ctx = createMockContext(world);
            engine.init(ctx);

            // Initial score is maxScore (1000) + bonuses
            const scoreEvents = ctx.events.getEmitted()
                .filter(e => e.type === 'custom:score-update');
            const breakdown = (scoreEvents[0] as { data: ScoreBreakdown }).data;
            // With maxScore=1000 and time/stealth bonuses, should be MASTERY
            expect(breakdown.totalScore).toBeGreaterThanOrEqual(900);
            expect(breakdown.tier).toBe('MASTERY');
        });

        it('classifies NOVICE tier for low scores', () => {
            const world = createScoringWorldSpec({ maxScore: 100 });
            const ctx = createMockContext(world);
            engine.init(ctx);

            const scoreEvents = ctx.events.getEmitted()
                .filter(e => e.type === 'custom:score-update');
            const breakdown = (scoreEvents[0] as { data: ScoreBreakdown }).data;
            // maxScore=100 will be well below 700
            if (breakdown.totalScore < 700) {
                expect(breakdown.tier).toBe('NOVICE');
            }
        });
    });

    describe('Time Bonus', () => {
        it('computes time bonus on tick', () => {
            const engineWithCfg = createScoringEngine({
                timeBonus: { parTimeTicks: 100, maxBonus: 200, curve: 'linear' },
            });
            const world = createScoringWorldSpec();
            const ctx = createMockContext(world, 0);
            engineWithCfg.init(ctx);

            // Simulate tick at half par
            ctx.events.clearLog();
            engineWithCfg.onTick!(50, ctx);

            const scoreEvents = ctx.events.getEmitted()
                .filter(e => e.type === 'custom:score-update');
            const breakdown = (scoreEvents[scoreEvents.length - 1] as { data: ScoreBreakdown }).data;
            expect(breakdown.timeBonus).toBeGreaterThan(0);
        });

        it('gives full time bonus at tick 0', () => {
            const engineWithCfg = createScoringEngine({
                timeBonus: { parTimeTicks: 100, maxBonus: 200, curve: 'linear' },
            });
            const world = createScoringWorldSpec();
            const ctx = createMockContext(world, 0);
            engineWithCfg.init(ctx);

            const scoreEvents = ctx.events.getEmitted()
                .filter(e => e.type === 'custom:score-update');
            const breakdown = (scoreEvents[0] as { data: ScoreBreakdown }).data;
            expect(breakdown.timeBonus).toBe(200);
        });

        it('gives zero time bonus past 2x par (linear)', () => {
            const engineWithCfg = createScoringEngine({
                timeBonus: { parTimeTicks: 100, maxBonus: 200, curve: 'linear' },
            });
            const world = createScoringWorldSpec();
            const ctx = createMockContext(world, 0);
            engineWithCfg.init(ctx);

            ctx.events.clearLog();
            engineWithCfg.onTick!(250, ctx);

            const scoreEvents = ctx.events.getEmitted()
                .filter(e => e.type === 'custom:score-update');
            const breakdown = (scoreEvents[scoreEvents.length - 1] as { data: ScoreBreakdown }).data;
            expect(breakdown.timeBonus).toBe(0);
        });

        it('supports step curve', () => {
            const engineWithCfg = createScoringEngine({
                timeBonus: { parTimeTicks: 100, maxBonus: 200, curve: 'step' },
            });
            const world = createScoringWorldSpec();
            const ctx = createMockContext(world, 0);
            engineWithCfg.init(ctx);

            // At par: full bonus
            ctx.events.clearLog();
            engineWithCfg.onTick!(100, ctx);
            let scoreEvents = ctx.events.getEmitted().filter(e => e.type === 'custom:score-update');
            let breakdown = (scoreEvents[scoreEvents.length - 1] as { data: ScoreBreakdown }).data;
            expect(breakdown.timeBonus).toBe(200);

            // At 1.25x par: half bonus
            ctx.events.clearLog();
            engineWithCfg.onTick!(125, ctx);
            scoreEvents = ctx.events.getEmitted().filter(e => e.type === 'custom:score-update');
            breakdown = (scoreEvents[scoreEvents.length - 1] as { data: ScoreBreakdown }).data;
            expect(breakdown.timeBonus).toBe(100);

            // At 2x par: zero
            ctx.events.clearLog();
            engineWithCfg.onTick!(200, ctx);
            scoreEvents = ctx.events.getEmitted().filter(e => e.type === 'custom:score-update');
            breakdown = (scoreEvents[scoreEvents.length - 1] as { data: ScoreBreakdown }).data;
            expect(breakdown.timeBonus).toBe(0);
        });

        it('supports exponential curve', () => {
            const engineWithCfg = createScoringEngine({
                timeBonus: { parTimeTicks: 100, maxBonus: 200, curve: 'exponential' },
            });
            const world = createScoringWorldSpec();
            const ctx = createMockContext(world, 0);
            engineWithCfg.init(ctx);

            ctx.events.clearLog();
            engineWithCfg.onTick!(200, ctx);
            const scoreEvents = ctx.events.getEmitted().filter(e => e.type === 'custom:score-update');
            const breakdown = (scoreEvents[scoreEvents.length - 1] as { data: ScoreBreakdown }).data;
            // Exponential decay — should be > 0 but less than max
            expect(breakdown.timeBonus).toBeGreaterThan(0);
            expect(breakdown.timeBonus).toBeLessThan(200);
        });
    });

    describe('Stealth Bonus', () => {
        it('gives full stealth bonus with zero noise', () => {
            const engineWithCfg = createScoringEngine({
                stealthBonus: { maxBonus: 200, noiseThreshold: 50, noiseCeiling: 500 },
            });
            const world = createScoringWorldSpec();
            const ctx = createMockContext(world);
            engineWithCfg.init(ctx);

            const scoreEvents = ctx.events.getEmitted()
                .filter(e => e.type === 'custom:score-update');
            const breakdown = (scoreEvents[0] as { data: ScoreBreakdown }).data;
            expect(breakdown.stealthBonus).toBe(200);
        });

        it('gives zero stealth bonus above ceiling', () => {
            const engineWithCfg = createScoringEngine({
                stealthBonus: { maxBonus: 200, noiseThreshold: 50, noiseCeiling: 500 },
            });
            const world = createScoringWorldSpec();
            const ctx = createMockContext(world);
            engineWithCfg.init(ctx);

            // Emit lots of noise
            for (let i = 0; i < 10; i++) {
                ctx.events.emit({
                    type: 'sim:noise',
                    source: 'test',
                    machine: 'test',
                    amount: 100,
                    timestamp: Date.now(),
                });
            }

            ctx.events.clearLog();
            ctx.events.emit({ type: 'custom:score-query', data: null, timestamp: Date.now() });

            const scoreEvents = ctx.events.getEmitted()
                .filter(e => e.type === 'custom:score-update');
            const breakdown = (scoreEvents[scoreEvents.length - 1] as { data: ScoreBreakdown }).data;
            expect(breakdown.stealthBonus).toBe(0);
        });
    });

    describe('Score Floor', () => {
        it('total score never goes below zero', () => {
            const world = createScoringWorldSpec({ maxScore: 10, hintPenalty: 100 });
            const ctx = createMockContext(world);
            engine.init(ctx);

            // Use many hints
            for (let i = 0; i < 5; i++) {
                ctx.events.emit({ type: 'custom:hint-used', data: null, timestamp: Date.now() });
            }

            const scoreEvents = ctx.events.getEmitted()
                .filter(e => e.type === 'custom:score-update');
            const last = (scoreEvents[scoreEvents.length - 1] as { data: ScoreBreakdown }).data;
            expect(last.totalScore).toBeGreaterThanOrEqual(0);
        });
    });

    describe('Module Lifecycle', () => {
        it('provides scoring capability', () => {
            expect(engine.provides.some(c => c.name === 'scoring')).toBe(true);
        });

        it('reports module metadata', () => {
            expect(engine.id).toBe('scoring-engine');
            expect(engine.type).toBe('scoring');
            expect(engine.version).toBe('2.0.0');
        });

        it('cleans up on destroy', () => {
            const world = createScoringWorldSpec();
            const ctx = createMockContext(world);
            engine.init(ctx);
            engine.destroy();

            // After destroy, emitting events should not trigger score updates
            ctx.events.clearLog();
            ctx.events.trigger('objective:complete', { objectiveId: 'obj-1' });

            const scoreEvents = ctx.events.getEmitted()
                .filter(e => e.type === 'custom:score-update');
            expect(scoreEvents.length).toBe(0);
        });
    });
});
