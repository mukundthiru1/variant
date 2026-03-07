/**
 * VARIANT — Module Registry Tests
 *
 * Tests the module registry for loading, dependency resolution,
 * initialization order, and cleanup.
 */

import { describe, it, expect, vi } from 'vitest';
import { createModuleRegistry, ModuleLoadError } from '../../src/core/modules';
import type { Module, SimulationContext } from '../../src/core/modules';

// ── Helpers ────────────────────────────────────────────────────

function makeStubModule(overrides: Partial<Module> = {}): Module {
    return {
        id: 'stub',
        type: 'engine',
        version: '1.0.0',
        description: 'Stub module',
        provides: [],
        requires: [],
        init: vi.fn(),
        destroy: vi.fn(),
        ...overrides,
    };
}

const stubContext: SimulationContext = {
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
    events: null as unknown as SimulationContext['events'], // Not needed for these tests
    world: null as unknown as SimulationContext['world'],
    tick: 0,
    services: { register: () => {}, get: () => undefined, has: () => false, list: () => [] },
};

// ── Tests ──────────────────────────────────────────────────────

describe('ModuleRegistry', () => {
    it('registers and resolves a module', () => {
        const registry = createModuleRegistry();
        const mod = makeStubModule({ id: 'test-mod' });

        registry.register('test-mod', () => mod);
        const resolved = registry.resolve(['test-mod']);

        expect(resolved.length).toBe(1);
        expect(resolved[0]!.id).toBe('test-mod');
    });

    it('throws on duplicate registration', () => {
        const registry = createModuleRegistry();
        registry.register('dup', () => makeStubModule({ id: 'dup' }));

        expect(() => {
            registry.register('dup', () => makeStubModule({ id: 'dup' }));
        }).toThrow(ModuleLoadError);
    });

    it('throws on resolving unregistered module', () => {
        const registry = createModuleRegistry();

        expect(() => {
            registry.resolve(['nonexistent']);
        }).toThrow(ModuleLoadError);
    });

    it('resolves dependencies between modules', () => {
        const registry = createModuleRegistry();

        const provider = makeStubModule({
            id: 'provider',
            provides: [{ name: 'sql-engine' }],
        });
        const consumer = makeStubModule({
            id: 'consumer',
            requires: [{ name: 'sql-engine' }],
        });

        registry.register('provider', () => provider);
        registry.register('consumer', () => consumer);

        const resolved = registry.resolve(['provider', 'consumer']);
        expect(resolved.length).toBe(2);
    });

    it('throws on unmet dependency', () => {
        const registry = createModuleRegistry();

        const consumer = makeStubModule({
            id: 'consumer',
            requires: [{ name: 'something-missing' }],
        });

        registry.register('consumer', () => consumer);

        expect(() => {
            registry.resolve(['consumer']);
        }).toThrow(ModuleLoadError);
    });

    it('initializes modules in order', () => {
        const registry = createModuleRegistry();
        const initOrder: string[] = [];

        const mod1 = makeStubModule({
            id: 'first',
            init: () => { initOrder.push('first'); },
        });
        const mod2 = makeStubModule({
            id: 'second',
            init: () => { initOrder.push('second'); },
        });

        registry.register('first', () => mod1);
        registry.register('second', () => mod2);

        const resolved = registry.resolve(['first', 'second']);
        registry.initAll(resolved, stubContext);

        expect(initOrder).toEqual(['first', 'second']);
    });

    it('destroys modules in reverse order (LIFO)', () => {
        const registry = createModuleRegistry();
        const destroyOrder: string[] = [];

        const mod1 = makeStubModule({
            id: 'first',
            destroy: () => { destroyOrder.push('first'); },
        });
        const mod2 = makeStubModule({
            id: 'second',
            destroy: () => { destroyOrder.push('second'); },
        });

        registry.register('first', () => mod1);
        registry.register('second', () => mod2);

        const resolved = registry.resolve(['first', 'second']);
        registry.destroyAll(resolved);

        expect(destroyOrder).toEqual(['second', 'first']); // LIFO
    });

    it('wraps init errors in ModuleLoadError', () => {
        const registry = createModuleRegistry();

        const badMod = makeStubModule({
            id: 'bad',
            init: () => { throw new Error('init failed'); },
        });

        registry.register('bad', () => badMod);
        const resolved = registry.resolve(['bad']);

        expect(() => {
            registry.initAll(resolved, stubContext);
        }).toThrow(ModuleLoadError);
    });

    it('continues destroying other modules when one fails', () => {
        const registry = createModuleRegistry();
        const destroyOrder: string[] = [];
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => { });

        const mod1 = makeStubModule({
            id: 'first',
            destroy: () => { destroyOrder.push('first'); },
        });
        const badMod = makeStubModule({
            id: 'bad',
            destroy: () => { throw new Error('destroy failed'); },
        });
        const mod3 = makeStubModule({
            id: 'third',
            destroy: () => { destroyOrder.push('third'); },
        });

        registry.register('first', () => mod1);
        registry.register('bad', () => badMod);
        registry.register('third', () => mod3);

        const resolved = registry.resolve(['first', 'bad', 'third']);
        registry.destroyAll(resolved);

        // All modules attempted destruction, bad one logged error
        expect(destroyOrder).toContain('first');
        expect(consoleSpy).toHaveBeenCalled();

        consoleSpy.mockRestore();
    });

    it('lists registered module IDs', () => {
        const registry = createModuleRegistry();
        registry.register('alpha', () => makeStubModule({ id: 'alpha' }));
        registry.register('beta', () => makeStubModule({ id: 'beta' }));

        const ids = registry.listRegistered();
        expect(ids).toContain('alpha');
        expect(ids).toContain('beta');
        expect(ids.length).toBe(2);
    });
});
