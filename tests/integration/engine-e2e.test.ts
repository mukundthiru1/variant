import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import { createSimulation, _resetSimIdCounter } from '../../src/core/engine';
import { DEMO_01 } from '../../src/levels/demo-01';
import { createModuleRegistry } from '../../src/core/modules';
import { createObjectiveDetector } from '../../src/modules/objective-detector';
import { createScoringEngine } from '../../src/modules/scoring-engine';

// Minimal fake VMBackend that satisfies the VMBackend contract used by the
// engine. It's intentionally simple — boots immediately and exposes the
// required hooks so the engine can wire fabric ↔ backend.
function makeFakeBackend() {
    const frameHandlers = new Map<string, ((frame: Uint8Array) => void)[]>();

    return {
    async boot(config: any) {
            const id = `vm-${Math.random().toString(36).slice(2, 9)}`;
            const vm = { id, config, state: 'running' } as const;
            frameHandlers.set(vm.id, []);
            return vm as any;
        },

        attachTerminal() {
            return {
                sendToVM() { /* no-op */ },
                onOutput: () => () => { /* unsub */ },
            };
        },

        sendFrame(vm: any, frame: Uint8Array) {
            // Deliver a frame back into the registered handlers to simulate
            // the VM receiving frames. For tests we just call handlers if any.
            const handlers = frameHandlers.get(vm.id) ?? [];
            for (const h of handlers) {
                try { h(frame); } catch { /* swallow */ }
            }
        },

        onFrame(vm: any, handler: (frame: Uint8Array) => void) {
            const handlers = frameHandlers.get(vm.id) ?? [];
            handlers.push(handler);
            frameHandlers.set(vm.id, handlers);
            let unsub = false;
            return () => {
                if (unsub) return; unsub = true;
                const arr = frameHandlers.get(vm.id) ?? [];
                const idx = arr.indexOf(handler);
                if (idx !== -1) arr.splice(idx, 1);
            };
        },

        async applyOverlay() { return; },
        async snapshot() { throw new Error('not implemented'); },
        async restore() { throw new Error('not implemented'); },
        async reset() { return; },
        destroy() { /* no-op */ },
    };
}

// Helper: shallow clone and allow quick modifications for tests
function cloneWorld(w: any) {
    return JSON.parse(JSON.stringify(w));
}

describe('Engine — end-to-end integration', () => {
    let sim: ReturnType<typeof createSimulation> | null = null;
    let registry = createModuleRegistry();

    beforeEach(() => {
        _resetSimIdCounter();
        registry = createModuleRegistry();
        registry.register('objective-detector', createObjectiveDetector);
        registry.register('scoring-engine', createScoringEngine);
        sim = null;
    });

    afterEach(() => {
        try { sim?.destroy(); } catch { /* ignore */ }
        sim = null;
    });

    it('1) Simulation creates and boots successfully with demo-01 WorldSpec', async () => {
        const world = cloneWorld(DEMO_01);
        world.tickIntervalMs = 100; // faster ticks for tests

        sim = createSimulation({ worldSpec: world, backend: makeFakeBackend(), imageBaseUrl: 'https://img', biosUrl: 'https://b', vgaBiosUrl: 'https://vga', moduleRegistry: registry });
        await sim.boot();

        const state = sim.getState();
        expect(state.phase).toBe('running');
        expect(sim.getPlayerTerminal()).not.toBeNull();
    });

    it('2) Event bus receives sim:tick events during run', async () => {
        const world = cloneWorld(DEMO_01);
        world.tickIntervalMs = 100;
        const backend = makeFakeBackend();
        sim = createSimulation({ worldSpec: world, backend, imageBaseUrl: 'https://img', biosUrl: 'https://b', vgaBiosUrl: 'https://vga', moduleRegistry: registry });
        await sim.boot();

        let ticks = 0;
        const unsub = sim.events.on('sim:tick', () => { ticks++; });

        await new Promise(r => setTimeout(r, 350));
        unsub();
        expect(ticks).toBeGreaterThanOrEqual(2);
    });

    it('3) Modules are loaded and initialized', async () => {
        const calls: string[] = [];

        registry.register('mod-init-test', () => ({
            id: 'mod-init-test', type: 'engine', version: '0.0.1', description: 'test', provides: [], requires: [],
            init() { calls.push('init'); },
            destroy() { calls.push('destroy'); },
        } as any));

        const world = cloneWorld(DEMO_01);
        world.modules = ['mod-init-test'];
        world.tickIntervalMs = 100;

        sim = createSimulation({ worldSpec: world, backend: makeFakeBackend(), imageBaseUrl: 'https://img', biosUrl: 'https://b', vgaBiosUrl: 'https://vga', moduleRegistry: registry });
        await sim.boot();

        expect(calls).toContain('init');
    });

    it('4) getState() returns valid SimulationState after boot', async () => {
        const world = cloneWorld(DEMO_01);
        world.tickIntervalMs = 100;
        sim = createSimulation({ worldSpec: world, backend: makeFakeBackend(), imageBaseUrl: 'https://img', biosUrl: 'https://b', vgaBiosUrl: 'https://vga', moduleRegistry: registry });
        await sim.boot();

        const st = sim.getState();
        expect(st.phase).toBe('running');
        expect(typeof st.tick).toBe('number');
        expect(typeof st.startTime).toBe('number');
        expect(typeof st.elapsedMs).toBe('number');
        expect(typeof st.score).toBe('number');
        expect(typeof st.hintsUsed).toBe('number');
        expect(st.objectiveStatus instanceof Map).toBe(true);
    });

    it('5) Pause/resume changes phase', async () => {
        const world = cloneWorld(DEMO_01);
        world.tickIntervalMs = 100;
        sim = createSimulation({ worldSpec: world, backend: makeFakeBackend(), imageBaseUrl: 'https://img', biosUrl: 'https://b', vgaBiosUrl: 'https://vga', moduleRegistry: registry });
        await sim.boot();

        sim.pause();
        expect(sim.getState().phase).toBe('paused');
        sim.resume();
        expect(sim.getState().phase).toBe('running');
    });

    it('6) useHint() returns hints and decrements remaining', async () => {
        const world = cloneWorld(DEMO_01);
        world.tickIntervalMs = 100;
        sim = createSimulation({ worldSpec: world, backend: makeFakeBackend(), imageBaseUrl: 'https://img', biosUrl: 'https://b', vgaBiosUrl: 'https://vga', moduleRegistry: registry });
        await sim.boot();

        const first = sim.useHint();
        expect(typeof first).toBe('string');
        const second = sim.useHint();
        expect(typeof second).toBe('string');
        // consume remaining
        sim.useHint();
        expect(sim.useHint()).toBeNull();
    });

    it('7) destroy() cleans up all resources', async () => {
        const world = cloneWorld(DEMO_01);
        world.tickIntervalMs = 100;
        sim = createSimulation({ worldSpec: world, backend: makeFakeBackend(), imageBaseUrl: 'https://img', biosUrl: 'https://b', vgaBiosUrl: 'https://vga', moduleRegistry: registry });
        await sim.boot();

        sim.destroy();
        expect(sim.getState().phase).toBe('destroyed');
        expect(sim.events.getLog().length).toBe(0);
    });

    it('8) Invalid WorldSpec rejects at creation', () => {
        expect(() => createSimulation({ worldSpec: {}, backend: makeFakeBackend(), imageBaseUrl: '', biosUrl: '', vgaBiosUrl: '' })).toThrow();
    });

    it('9) Multiple tick cycles process correctly', async () => {
        const world = cloneWorld(DEMO_01);
        world.tickIntervalMs = 100;
        sim = createSimulation({ worldSpec: world, backend: makeFakeBackend(), imageBaseUrl: 'https://img', biosUrl: 'https://b', vgaBiosUrl: 'https://vga', moduleRegistry: registry });
        await sim.boot();

        const observed: number[] = [];
        sim.events.on('sim:tick', (e: any) => observed.push(e.tick));

        await new Promise(r => setTimeout(r, 350));
        expect(observed.length).toBeGreaterThanOrEqual(2);
        expect(observed[0]).toBeGreaterThanOrEqual(1);
    });

    it('10) Score updates when objectives are completed (scoring module emits updates)', async () => {
        registry.register('scoring-test', () => {
            let score = DEMO_01.scoring.maxScore;
            return {
                id: 'scoring-test', type: 'scoring', version: '0.1', description: 'scoring', provides: [], requires: [],
                init(context: any) {
                    context.events.on('objective:complete', (_ev: any) => {
                        score += 10; // arbitrary reward
                        context.events.emit({ type: 'custom:score-updated', data: { score }, timestamp: Date.now() } as any);
                    });
                    context.events.on('custom:hint-used', () => {
                        score -= (context.world.scoring?.hintPenalty ?? 0);
                        context.events.emit({ type: 'custom:score-updated', data: { score }, timestamp: Date.now() } as any);
                    });
                },
                destroy() { /* noop */ },
            } as any;
        });

        const world = cloneWorld(DEMO_01);
        world.modules = ['scoring-test'];
        world.tickIntervalMs = 100;
        sim = createSimulation({ worldSpec: world, backend: makeFakeBackend(), imageBaseUrl: 'https://img', biosUrl: 'https://b', vgaBiosUrl: 'https://vga', moduleRegistry: registry });
        await sim.boot();

        const p = sim.events.waitFor('custom:score-updated');
        // trigger objective completion
        sim.events.emit({ type: 'objective:complete', objectiveId: 'find-backup', timestamp: Date.now() } as any);
        const ev: any = await p;
        expect(ev.data.score).toBeGreaterThanOrEqual(0);
    });

    it('11) Game over detection triggers', async () => {
        const world = cloneWorld(DEMO_01);
        world.tickIntervalMs = 100;
        // add a noise-detected game over condition
        world.gameOver = { conditions: [{ type: 'noise-detected', threshold: 5 }], message: 'Too noisy' };

        sim = createSimulation({ worldSpec: world, backend: makeFakeBackend(), imageBaseUrl: 'https://img', biosUrl: 'https://b', vgaBiosUrl: 'https://vga', moduleRegistry: registry });
        await sim.boot();

        const p = sim.events.waitFor('sim:gameover');
        sim.events.emit({ type: 'sim:noise', source: 'test', machine: 'web-server', amount: 6, timestamp: Date.now() } as any);
        const ev: any = await p;
        expect(ev.reason).toContain('Too noisy');
    });

    it('12) Event log accumulates correctly', async () => {
        const world = cloneWorld(DEMO_01);
        world.tickIntervalMs = 100;
        sim = createSimulation({ worldSpec: world, backend: makeFakeBackend(), imageBaseUrl: 'https://img', biosUrl: 'https://b', vgaBiosUrl: 'https://vga', moduleRegistry: registry });
        await sim.boot();

        sim.events.emit({ type: 'custom:foo', data: { x: 1 }, timestamp: Date.now() } as any);
        sim.events.emit({ type: 'custom:bar', data: { y: 2 }, timestamp: Date.now() } as any);

        const all = sim.events.getLog();
        expect(all.some(e => e.type === 'custom:foo')).toBe(true);
        expect(all.some(e => e.type === 'custom:bar')).toBe(true);
    });

    it('13) Fabric stats return valid data', async () => {
        const world = cloneWorld(DEMO_01);
        world.tickIntervalMs = 100;
        sim = createSimulation({ worldSpec: world, backend: makeFakeBackend(), imageBaseUrl: 'https://img', biosUrl: 'https://b', vgaBiosUrl: 'https://vga', moduleRegistry: registry });
        await sim.boot();

        const stats = sim.fabric.getStats();
        expect(typeof stats.totalFrames).toBe('number');
        expect(typeof stats.activeConnections).toBe('number');
        expect(stats.activeConnections).toBeGreaterThanOrEqual(1);
    });

    it('14) Module lifecycle hooks fire in order (init, tick, destroy)', async () => {
        const order: string[] = [];

        registry.register('lifecycle-a', () => ({
            id: 'lifecycle-a', type: 'engine', version: '1', description: '', provides: [], requires: [],
            init(_ctx: any) { order.push('a:init'); },
            onAllInitialized(_ctx: any) { order.push('a:onAllInitialized'); },
            onSimulationStart(_ctx: any) { order.push('a:onSimulationStart'); },
            onPreTick(_t: number, _ctx: any) { order.push('a:onPreTick'); },
            onTick(_t: number, _ctx: any) { order.push('a:onTick'); },
            onPostTick(_t: number, _ctx: any) { order.push('a:onPostTick'); },
            onPause() { order.push('a:onPause'); },
            onResume() { order.push('a:onResume'); },
            onSimulationEnd(_ctx: any) { order.push('a:onSimulationEnd'); },
            destroy() { order.push('a:destroy'); },
        } as any));

        const world = cloneWorld(DEMO_01);
        world.modules = ['lifecycle-a'];
        world.tickIntervalMs = 100;

        sim = createSimulation({ worldSpec: world, backend: makeFakeBackend(), imageBaseUrl: 'https://img', biosUrl: 'https://b', vgaBiosUrl: 'https://vga', moduleRegistry: registry });
        await sim.boot();

        // allow a tick to run
        await new Promise(r => setTimeout(r, 220));

        sim.pause();
        sim.resume();
        sim.destroy();

        // check that init, onSimulationStart, tick hooks, and destroy were called
        expect(order.some(o => o === 'a:init')).toBe(true);
        expect(order.some(o => o === 'a:onSimulationStart')).toBe(true);
        expect(order.some(o => o === 'a:onTick')).toBe(true);
        expect(order.some(o => o === 'a:destroy')).toBe(true);
    });

    it('15) ServiceLocator is accessible through context', async () => {
        const seen: boolean[] = [false];

        registry.register('producer', () => ({
            id: 'producer', type: 'service', version: '1', description: '', provides: [{ name: 'test-svc' }], requires: [],
            init(ctx: any) { ctx.services.register('test-svc', { v: 1 }); },
            destroy() { },
        } as any));

        registry.register('consumer', () => ({
            id: 'consumer', type: 'service', version: '1', description: '', provides: [], requires: [{ name: 'test-svc' }],
            init(ctx: any) { seen[0] = !!ctx.services.get('test-svc'); },
            destroy() { },
        } as any));

        const world = cloneWorld(DEMO_01);
        world.modules = ['producer', 'consumer'];
        world.tickIntervalMs = 100;

        sim = createSimulation({ worldSpec: world, backend: makeFakeBackend(), imageBaseUrl: 'https://img', biosUrl: 'https://b', vgaBiosUrl: 'https://vga', moduleRegistry: registry });
        await sim.boot();

        expect(seen[0]).toBe(true);
    });
});
