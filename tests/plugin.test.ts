import { describe, it, expect, vi } from 'vitest';
import { createPluginRegistry, PluginLoadError } from '../src/core/plugin';
import type { Plugin, PluginContext } from '../src/core/plugin';

function createMockContext(config?: unknown): PluginContext {
    const extensions = new Map<string, unknown>();
    return {
        registerModule: vi.fn(),
        registerDetectionEngine: vi.fn(),
        registerNoiseRules: vi.fn(),
        registerMiddleware: vi.fn(),
        registerExtension(key: string, value: unknown): void { extensions.set(key, value); },
        getExtension<T = unknown>(key: string): T | undefined { return extensions.get(key) as T | undefined; },
        listExtensions(prefix: string): readonly string[] { return Array.from(extensions.keys()).filter(k => k.startsWith(prefix)); },
        getConfig: <T = unknown>() => config as T | undefined,
        log: vi.fn(),
    };
}

describe('PluginRegistry', () => {
    it('registers and retrieves plugins', () => {
        const registry = createPluginRegistry();

        const plugin: Plugin = {
            id: 'test/plugin',
            version: '1.0.0',
            description: 'Test plugin',
            activate: vi.fn(),
        };

        registry.register(plugin);
        expect(registry.has('test/plugin')).toBe(true);
        expect(registry.get('test/plugin')).toBe(plugin);
    });

    it('throws on duplicate registration', () => {
        const registry = createPluginRegistry();

        const plugin: Plugin = {
            id: 'test/dup',
            version: '1.0.0',
            description: 'Test',
            activate: vi.fn(),
        };

        registry.register(plugin);
        expect(() => registry.register(plugin)).toThrow(PluginLoadError);
    });

    it('activates plugins in dependency order', () => {
        const registry = createPluginRegistry();
        const order: string[] = [];

        const pluginA: Plugin = {
            id: 'test/a',
            version: '1.0.0',
            description: 'A',
            dependencies: ['test/b'],
            activate() { order.push('a'); },
        };

        const pluginB: Plugin = {
            id: 'test/b',
            version: '1.0.0',
            description: 'B',
            activate() { order.push('b'); },
        };

        registry.register(pluginA);
        registry.register(pluginB);

        registry.activateAll(() => createMockContext());

        expect(order).toEqual(['b', 'a']);
    });

    it('throws on missing dependency', () => {
        const registry = createPluginRegistry();

        const plugin: Plugin = {
            id: 'test/missing-dep',
            version: '1.0.0',
            description: 'Depends on missing',
            dependencies: ['test/nonexistent'],
            activate: vi.fn(),
        };

        registry.register(plugin);

        // activateAll should handle the error gracefully
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        expect(() => registry.activateAll(() => createMockContext())).toThrow();
        consoleSpy.mockRestore();
    });

    it('deactivates plugins in reverse order', () => {
        const registry = createPluginRegistry();
        const order: string[] = [];

        const pluginA: Plugin = {
            id: 'test/a',
            version: '1.0.0',
            description: 'A',
            activate() {},
            deactivate() { order.push('deactivate-a'); },
        };

        const pluginB: Plugin = {
            id: 'test/b',
            version: '1.0.0',
            description: 'B',
            activate() {},
            deactivate() { order.push('deactivate-b'); },
        };

        registry.register(pluginA);
        registry.register(pluginB);
        registry.activateAll(() => createMockContext());
        registry.deactivateAll();

        expect(order).toEqual(['deactivate-b', 'deactivate-a']);
    });

    it('passes context to plugins during activation', () => {
        const registry = createPluginRegistry();
        let receivedContext: PluginContext | null = null;

        const plugin: Plugin = {
            id: 'test/ctx',
            version: '1.0.0',
            description: 'Context test',
            activate(ctx) { receivedContext = ctx; },
        };

        registry.register(plugin);
        const mockCtx = createMockContext({ foo: 'bar' });
        registry.activateAll(() => mockCtx);

        expect(receivedContext).toBe(mockCtx);
    });

    it('handles plugin activation errors gracefully', () => {
        const registry = createPluginRegistry();
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

        const badPlugin: Plugin = {
            id: 'test/bad',
            version: '1.0.0',
            description: 'Throws on activate',
            activate() { throw new Error('activation failed'); },
        };

        const goodPlugin: Plugin = {
            id: 'test/good',
            version: '1.0.0',
            description: 'Works fine',
            activate: vi.fn(),
        };

        registry.register(badPlugin);
        registry.register(goodPlugin);
        registry.activateAll(() => createMockContext());

        // Good plugin should still be activated despite bad plugin failing
        expect(goodPlugin.activate).toHaveBeenCalled();

        consoleSpy.mockRestore();
    });

    it('prevents registration after activation', () => {
        const registry = createPluginRegistry();

        const plugin: Plugin = {
            id: 'test/early',
            version: '1.0.0',
            description: 'Registered early',
            activate: vi.fn(),
        };

        registry.register(plugin);
        registry.activateAll(() => createMockContext());

        const latePlugin: Plugin = {
            id: 'test/late',
            version: '1.0.0',
            description: 'Too late',
            activate: vi.fn(),
        };

        expect(() => registry.register(latePlugin)).toThrow(PluginLoadError);
    });

    it('lists all registered plugins', () => {
        const registry = createPluginRegistry();

        registry.register({ id: 'a', version: '1.0.0', description: 'A', activate: vi.fn() });
        registry.register({ id: 'b', version: '1.0.0', description: 'B', activate: vi.fn() });

        expect(registry.getAll().length).toBe(2);
    });
});
