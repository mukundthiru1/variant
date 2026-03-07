/**
 * VARIANT — Simulation Engine Tests
 *
 * Tests the simulation lifecycle, WorldSpec validation gate,
 * objective tracking, hint system, and cleanup.
 *
 * Uses a mock VMBackend to avoid needing v86 in tests.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createSimulation } from '../../src/core/engine';
import type { VMBackend, VMBootConfig, VMInstance, TerminalIO, FilesystemOverlay, VMSnapshot } from '../../src/core/vm/types';
import type { Unsubscribe } from '../../src/core/events';

// ── Mock VMBackend ─────────────────────────────────────────────

function createMockBackend(): VMBackend {
    let nextId = 0;

    const backend: VMBackend = {
        async boot(_config: VMBootConfig): Promise<VMInstance> {
            const id = `mock-vm-${nextId++}`;
            return { id, config: _config, state: 'running' };
        },

        attachTerminal(_vm: VMInstance): TerminalIO {
            const handlers = new Set<(byte: number) => void>();
            return {
                sendToVM(_data: string | Uint8Array): void {
                    // Mock: no-op
                },
                onOutput(handler: (byte: number) => void): Unsubscribe {
                    handlers.add(handler);
                    return () => { handlers.delete(handler); };
                },
            };
        },

        sendFrame(_vm: VMInstance, _frame: Uint8Array): void {
            // Mock: no-op
        },

        onFrame(_vm: VMInstance, _handler: (frame: Uint8Array) => void): Unsubscribe {
            return () => { };
        },

        async applyOverlay(_vm: VMInstance, _overlay: FilesystemOverlay): Promise<void> {
            // Mock: no-op
        },

        async snapshot(vm: VMInstance): Promise<VMSnapshot> {
            return { vmId: vm.id, timestamp: Date.now(), data: new ArrayBuffer(0) };
        },

        async restore(_vm: VMInstance, _snapshot: VMSnapshot): Promise<void> {
            // Mock: no-op
        },

        async reset(_vm: VMInstance): Promise<void> {
            // Mock: no-op
        },

        destroy(_vm: VMInstance): void {
            // Mock: no-op
        },
    };

    return backend;
}

// ── Minimal valid WorldSpec for tests ──────────────────────────

function testWorldSpec(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
        version: '2.0',
        trust: 'community',
        meta: {
            title: 'Test Level',
            scenario: 'Testing',
            briefing: ['Test briefing'],
            difficulty: 'beginner',
            mode: 'attack',
            vulnClasses: ['test'],
            tags: ['test'],
            estimatedMinutes: 5,
            author: { name: 'Test', id: 'test', type: 'santh' },
        },
        machines: {
            'player-vm': {
                hostname: 'test-vm',
                image: 'alpine-test',
                memoryMB: 64,
                role: 'player',
                interfaces: [{ ip: '10.0.1.5', segment: 'test-net' }],
            },
        },
        startMachine: 'player-vm',
        network: {
            segments: [{ id: 'test-net', subnet: '10.0.1.0/24' }],
            edges: [],
        },
        credentials: [],
        objectives: [
            {
                id: 'obj-1',
                title: 'Find the flag',
                description: 'Find the flag file',
                type: 'find-file',
                required: true,
                order: 1,
                details: { kind: 'find-file', machine: 'player-vm', path: '/flag.txt' },
            },
        ],
        modules: [],
        scoring: {
            maxScore: 100,
            timeBonus: false,
            stealthBonus: false,
            hintPenalty: 10,
            tiers: [{ name: 'COMPLETE', minScore: 50, color: '#00ff41' }],
        },
        hints: ['Look in the root directory', 'The file is called flag.txt'],
        ...overrides,
    };
}

// ── Tests ──────────────────────────────────────────────────────

describe('Simulation Engine', () => {
    let backend: VMBackend;

    beforeEach(() => {
        backend = createMockBackend();
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it('creates a simulation from valid WorldSpec', () => {
        const sim = createSimulation({
            worldSpec: testWorldSpec(),
            backend,
            imageBaseUrl: '/images',
            biosUrl: '/bios.bin',
            vgaBiosUrl: '/vga.bin',
        });

        expect(sim.id).toMatch(/^sim-/);
        expect(sim.world).toBeDefined();
        expect(sim.getState().phase).toBe('created');
    });

    it('rejects invalid WorldSpec', () => {
        expect(() => {
            createSimulation({
                worldSpec: { version: '1.0' },
                backend,
                imageBaseUrl: '/images',
                biosUrl: '/bios.bin',
                vgaBiosUrl: '/vga.bin',
            });
        }).toThrow('WorldSpec validation failed');
    });

    it('boots all VMs and transitions to running', async () => {
        const sim = createSimulation({
            worldSpec: testWorldSpec(),
            backend,
            imageBaseUrl: '/images',
            biosUrl: '/bios.bin',
            vgaBiosUrl: '/vga.bin',
        });

        await sim.boot();
        expect(sim.getState().phase).toBe('running');
    });

    it('returns player terminal after boot', async () => {
        const sim = createSimulation({
            worldSpec: testWorldSpec(),
            backend,
            imageBaseUrl: '/images',
            biosUrl: '/bios.bin',
            vgaBiosUrl: '/vga.bin',
        });

        await sim.boot();
        const terminal = sim.getPlayerTerminal();
        expect(terminal).not.toBeNull();
    });

    it('tracks objective status', async () => {
        const sim = createSimulation({
            worldSpec: testWorldSpec(),
            backend,
            imageBaseUrl: '/images',
            biosUrl: '/bios.bin',
            vgaBiosUrl: '/vga.bin',
        });

        await sim.boot();
        const state = sim.getState();
        expect(state.objectiveStatus.get('obj-1')).toBe('available');
    });

    it('tracks hints and emits hint-used events', async () => {
        const sim = createSimulation({
            worldSpec: testWorldSpec(),
            backend,
            imageBaseUrl: '/images',
            biosUrl: '/bios.bin',
            vgaBiosUrl: '/vga.bin',
        });

        await sim.boot();

        // Track hint-used events
        const hintEvents: unknown[] = [];
        sim.events.onPrefix('custom:', (event) => {
            if (event.type === 'custom:hint-used') {
                hintEvents.push(event);
            }
        });

        const hint1 = sim.useHint();
        expect(hint1).toBe('Look in the root directory');
        expect(sim.getState().hintsUsed).toBe(1);
        expect(hintEvents).toHaveLength(1);

        const hint2 = sim.useHint();
        expect(hint2).toBe('The file is called flag.txt');
        expect(sim.getState().hintsUsed).toBe(2);
        expect(hintEvents).toHaveLength(2);

        // No more hints
        const hint3 = sim.useHint();
        expect(hint3).toBeNull();
        expect(hintEvents).toHaveLength(2); // No new event

        sim.destroy();
    });

    it('pauses and resumes', async () => {
        const sim = createSimulation({
            worldSpec: testWorldSpec(),
            backend,
            imageBaseUrl: '/images',
            biosUrl: '/bios.bin',
            vgaBiosUrl: '/vga.bin',
        });

        await sim.boot();
        expect(sim.getState().phase).toBe('running');

        sim.pause();
        expect(sim.getState().phase).toBe('paused');

        sim.resume();
        expect(sim.getState().phase).toBe('running');
    });

    it('increments tick counter', async () => {
        const sim = createSimulation({
            worldSpec: testWorldSpec(),
            backend,
            imageBaseUrl: '/images',
            biosUrl: '/bios.bin',
            vgaBiosUrl: '/vga.bin',
        });

        await sim.boot();
        expect(sim.getState().tick).toBe(0);

        vi.advanceTimersByTime(3000);
        expect(sim.getState().tick).toBe(3);

        sim.destroy();
    });

    it('stops tick counter on pause', async () => {
        const sim = createSimulation({
            worldSpec: testWorldSpec(),
            backend,
            imageBaseUrl: '/images',
            biosUrl: '/bios.bin',
            vgaBiosUrl: '/vga.bin',
        });

        await sim.boot();
        vi.advanceTimersByTime(2000);
        expect(sim.getState().tick).toBe(2);

        sim.pause();
        vi.advanceTimersByTime(5000);
        expect(sim.getState().tick).toBe(2); // Still 2

        sim.resume();
        vi.advanceTimersByTime(1000);
        expect(sim.getState().tick).toBe(3);

        sim.destroy();
    });

    it('prevents double boot', async () => {
        const sim = createSimulation({
            worldSpec: testWorldSpec(),
            backend,
            imageBaseUrl: '/images',
            biosUrl: '/bios.bin',
            vgaBiosUrl: '/vga.bin',
        });

        await sim.boot();
        await expect(sim.boot()).rejects.toThrow("Cannot boot simulation in phase 'running'");

        sim.destroy();
    });

    it('cleans up all resources on destroy', async () => {
        const destroySpy = vi.spyOn(backend, 'destroy');

        const sim = createSimulation({
            worldSpec: testWorldSpec(),
            backend,
            imageBaseUrl: '/images',
            biosUrl: '/bios.bin',
            vgaBiosUrl: '/vga.bin',
        });

        await sim.boot();
        sim.destroy();

        expect(sim.getState().phase).toBe('destroyed');
        expect(destroySpy).toHaveBeenCalled();
    });

    it('destroy is idempotent', async () => {
        const sim = createSimulation({
            worldSpec: testWorldSpec(),
            backend,
            imageBaseUrl: '/images',
            biosUrl: '/bios.bin',
            vgaBiosUrl: '/vga.bin',
        });

        await sim.boot();
        sim.destroy();
        sim.destroy(); // Should not throw

        expect(sim.getState().phase).toBe('destroyed');
    });

    it('freezes the WorldSpec after creation', () => {
        const spec = testWorldSpec();
        const sim = createSimulation({
            worldSpec: spec,
            backend,
            imageBaseUrl: '/images',
            biosUrl: '/bios.bin',
            vgaBiosUrl: '/vga.bin',
        });

        // Mutating the original spec should not affect the simulation
        (spec as Record<string, unknown>)['version'] = '99.0';
        expect(sim.world.version).toBe('2.0');

        // The simulation's world should be frozen
        expect(() => {
            (sim.world as Record<string, unknown>)['version'] = '99.0';
        }).toThrow();
    });

    it('completes objectives via objective:complete event', async () => {
        const spec = testWorldSpec({
            objectives: [
                {
                    id: 'cred-find',
                    title: 'Find the credential',
                    description: 'Find it',
                    type: 'credential-find',
                    required: true,
                    order: 1,
                    details: { kind: 'credential-find', credentialId: 'test-cred' },
                },
            ],
        });

        const sim = createSimulation({
            worldSpec: spec,
            backend,
            imageBaseUrl: '/images',
            biosUrl: '/bios.bin',
            vgaBiosUrl: '/vga.bin',
        });

        await sim.boot();

        // The engine now listens for objective:complete events
        // (which the objective-detector module would emit).
        // Simulate the module emitting the event:
        sim.events.emit({
            type: 'objective:complete',
            objectiveId: 'cred-find',
            timestamp: Date.now(),
        });

        expect(sim.getState().objectiveStatus.get('cred-find')).toBe('completed');
        expect(sim.getState().phase).toBe('completed');

        sim.destroy();
    });

    it('emits lifecycle events (boot, pause, resume)', async () => {
        const sim = createSimulation({
            worldSpec: testWorldSpec(),
            backend,
            imageBaseUrl: '/images',
            biosUrl: '/bios.bin',
            vgaBiosUrl: '/vga.bin',
        });

        const lifecycleEvents: string[] = [];
        sim.events.onPrefix('custom:', (event) => {
            if (event.type.startsWith('custom:sim-')) {
                lifecycleEvents.push(event.type);
            }
        });

        await sim.boot();
        expect(lifecycleEvents).toContain('custom:sim-booted');

        sim.pause();
        expect(lifecycleEvents).toContain('custom:sim-paused');

        sim.resume();
        expect(lifecycleEvents).toContain('custom:sim-resumed');

        sim.destroy();
    });

    it('initializes and destroys modules', async () => {
        const initSpy = vi.fn();
        const destroySpy = vi.fn();

        // Create a module registry with a test module
        const { createModuleRegistry } = await import('../../src/core/modules');
        const registry = createModuleRegistry();
        registry.register('test-module', () => ({
            id: 'test-module',
            type: 'engine',
            version: '1.0.0',
            description: 'Test module',
            provides: [],
            requires: [],
            init: initSpy,
            destroy: destroySpy,
        }));

        const spec = testWorldSpec({ modules: ['test-module'] });
        const sim = createSimulation({
            worldSpec: spec,
            backend,
            imageBaseUrl: '/images',
            biosUrl: '/bios.bin',
            vgaBiosUrl: '/vga.bin',
            moduleRegistry: registry,
        });

        await sim.boot();
        expect(initSpy).toHaveBeenCalledOnce();

        sim.destroy();
        expect(destroySpy).toHaveBeenCalledOnce();
    });
});
