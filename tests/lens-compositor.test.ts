/**
 * VARIANT — Lens Compositor Tests
 *
 * Tests for the lens compositor state management, registries,
 * and layout tree operations.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
    compositorReducer,
    createInitialState,
    generateLensId,
    collectLensIds,
    _resetLensIdCounter,
} from '../src/ui/lens/compositor-state';
import {
    createLensRegistry,
    createStartConfigPresetRegistry,
    registerDefaultPresets,
} from '../src/ui/lens/registry';
import type {
    LensInstance,
    LensDefinition,
    CompositorState,
} from '../src/ui/lens/types';

// ── Helpers ────────────────────────────────────────────────────

function makeLens(overrides: Partial<LensInstance> = {}): LensInstance {
    return {
        id: overrides.id ?? generateLensId(),
        type: overrides.type ?? 'terminal',
        title: overrides.title ?? 'Terminal',
        targetMachine: overrides.targetMachine ?? null,
        config: overrides.config ?? {},
    };
}

function makeDefinition(overrides: Partial<LensDefinition> = {}): LensDefinition {
    return {
        type: overrides.type ?? 'terminal',
        displayName: overrides.displayName ?? 'Terminal',
        description: overrides.description ?? 'A terminal emulator',
        icon: overrides.icon ?? '🖥',
        capabilities: overrides.capabilities ?? {
            targetMachine: 'required',
            compatibleBackends: null,
            writable: true,
            custom: {},
        },
        constraints: overrides.constraints ?? {
            minWidth: 200,
            minHeight: 150,
            preferredAspectRatio: null,
            preferredSize: 0.5,
        },
        shortcut: overrides.shortcut ?? null,
        allowMultiple: overrides.allowMultiple ?? true,
        ...(overrides.lifecycle !== undefined ? { lifecycle: overrides.lifecycle } : {}),
    };
}

// ── Lens Registry Tests ────────────────────────────────────────

describe('LensRegistry', () => {
    it('registers and retrieves a lens definition', () => {
        const registry = createLensRegistry();
        const def = makeDefinition({ type: 'terminal' });
        registry.register(def);

        expect(registry.has('terminal')).toBe(true);
        expect(registry.get('terminal')).toEqual(def);
    });

    it('rejects duplicate registrations', () => {
        const registry = createLensRegistry();
        registry.register(makeDefinition({ type: 'terminal' }));

        expect(() => {
            registry.register(makeDefinition({ type: 'terminal' }));
        }).toThrow(/already registered/);
    });

    it('rejects empty type strings', () => {
        const registry = createLensRegistry();

        expect(() => {
            registry.register(makeDefinition({ type: '' }));
        }).toThrow(/non-empty/);
    });

    it('rejects empty displayName', () => {
        const registry = createLensRegistry();

        expect(() => {
            registry.register(makeDefinition({ type: 'test', displayName: '' }));
        }).toThrow(/displayName/);
    });

    it('returns undefined for unregistered types', () => {
        const registry = createLensRegistry();

        expect(registry.get('nonexistent')).toBeUndefined();
        expect(registry.has('nonexistent')).toBe(false);
    });

    it('getAll returns all registered definitions', () => {
        const registry = createLensRegistry();
        registry.register(makeDefinition({ type: 'terminal', displayName: 'Terminal' }));
        registry.register(makeDefinition({ type: 'browser', displayName: 'Browser' }));

        const all = registry.getAll();
        expect(all).toHaveLength(2);
        expect(all.map(d => d.type)).toContain('terminal');
        expect(all.map(d => d.type)).toContain('browser');
    });

    it('getTypes returns all registered type IDs', () => {
        const registry = createLensRegistry();
        registry.register(makeDefinition({ type: 'terminal', displayName: 'Terminal' }));
        registry.register(makeDefinition({ type: 'browser', displayName: 'Browser' }));

        const types = registry.getTypes();
        expect(types).toContain('terminal');
        expect(types).toContain('browser');
    });

    it('freezes registered definitions', () => {
        const registry = createLensRegistry();
        const def = makeDefinition({ type: 'terminal' });
        registry.register(def);

        const retrieved = registry.get('terminal');
        expect(Object.isFrozen(retrieved)).toBe(true);
    });

    it('supports namespaced third-party types', () => {
        const registry = createLensRegistry();
        registry.register(makeDefinition({
            type: 'vendor/custom-lens',
            displayName: 'Custom Lens',
        }));

        expect(registry.has('vendor/custom-lens')).toBe(true);
    });
});

// ── Start Config Preset Registry Tests ─────────────────────────

describe('StartConfigPresetRegistry', () => {
    it('registers and resolves a preset', () => {
        const registry = createStartConfigPresetRegistry();
        const config = { lenses: [{ type: 'terminal' }] };
        registry.register('test', config);

        expect(registry.resolve('test')).toEqual(config);
    });

    it('rejects duplicate preset names', () => {
        const registry = createStartConfigPresetRegistry();
        registry.register('test', { lenses: [{ type: 'terminal' }] });

        expect(() => {
            registry.register('test', { lenses: [{ type: 'browser' }] });
        }).toThrow(/already registered/);
    });

    it('rejects empty preset names', () => {
        const registry = createStartConfigPresetRegistry();

        expect(() => {
            registry.register('', { lenses: [] });
        }).toThrow(/non-empty/);
    });

    it('returns undefined for unregistered presets', () => {
        const registry = createStartConfigPresetRegistry();

        expect(registry.resolve('nonexistent')).toBeUndefined();
    });

    it('getNames returns all registered preset names', () => {
        const registry = createStartConfigPresetRegistry();
        registry.register('a', { lenses: [] });
        registry.register('b', { lenses: [] });

        const names = registry.getNames();
        expect(names).toContain('a');
        expect(names).toContain('b');
    });
});

// ── Default Presets ────────────────────────────────────────────

describe('registerDefaultPresets', () => {
    it('registers terminal, desktop, and soc-workstation presets', () => {
        const registry = createStartConfigPresetRegistry();
        registerDefaultPresets(registry);

        expect(registry.resolve('terminal')).toBeDefined();
        expect(registry.resolve('desktop')).toBeDefined();
        expect(registry.resolve('soc-workstation')).toBeDefined();
    });

    it('terminal preset has one terminal lens', () => {
        const registry = createStartConfigPresetRegistry();
        registerDefaultPresets(registry);

        const preset = registry.resolve('terminal');
        expect(preset?.lenses).toHaveLength(1);
        expect(preset?.lenses[0]?.type).toBe('terminal');
    });

    it('desktop preset has terminal, browser, email', () => {
        const registry = createStartConfigPresetRegistry();
        registerDefaultPresets(registry);

        const preset = registry.resolve('desktop');
        expect(preset?.lenses).toHaveLength(3);
        expect(preset?.lenses.map(l => l.type)).toEqual(['terminal', 'browser', 'email']);
    });

    it('soc-workstation has 4 lenses with a split layout', () => {
        const registry = createStartConfigPresetRegistry();
        registerDefaultPresets(registry);

        const preset = registry.resolve('soc-workstation');
        expect(preset?.lenses).toHaveLength(4);
        expect(preset?.layout).toBeDefined();
        expect(preset?.layout?.type).toBe('split-v');
    });
});

// ── Compositor State Tests ─────────────────────────────────────

describe('compositorReducer', () => {
    let state: CompositorState;

    beforeEach(() => {
        _resetLensIdCounter();
        state = createInitialState();
    });

    describe('open-lens', () => {
        it('adds a lens to the state', () => {
            const lens = makeLens({ id: 'lens-a' });
            const next = compositorReducer(state, { type: 'open-lens', lens });

            expect(next.lenses.has('lens-a')).toBe(true);
            expect(next.taskbar).toContain('lens-a');
            expect(next.focusedLensId).toBe('lens-a');
        });

        it('first lens fills the layout', () => {
            const lens = makeLens({ id: 'lens-a' });
            const next = compositorReducer(state, { type: 'open-lens', lens });

            expect(next.layout).toEqual({ type: 'lens', lensId: 'lens-a' });
        });

        it('second lens splits horizontally by default', () => {
            const a = makeLens({ id: 'lens-a' });
            const b = makeLens({ id: 'lens-b' });

            let s = compositorReducer(state, { type: 'open-lens', lens: a });
            s = compositorReducer(s, { type: 'open-lens', lens: b });

            expect(s.layout.type).toBe('split-h');
        });

        it('second lens splits vertically when position=bottom', () => {
            const a = makeLens({ id: 'lens-a' });
            const b = makeLens({ id: 'lens-b' });

            let s = compositorReducer(state, { type: 'open-lens', lens: a });
            s = compositorReducer(s, { type: 'open-lens', lens: b, position: 'bottom' });

            expect(s.layout.type).toBe('split-v');
        });

        it('adds as tab when position=tab', () => {
            const a = makeLens({ id: 'lens-a' });
            const b = makeLens({ id: 'lens-b' });

            let s = compositorReducer(state, { type: 'open-lens', lens: a });
            s = compositorReducer(s, { type: 'open-lens', lens: b, position: 'tab' });

            expect(s.layout.type).toBe('tabs');
            if (s.layout.type === 'tabs') {
                expect(s.layout.children).toHaveLength(2);
                expect(s.layout.activeIndex).toBe(1);
            }
        });
    });

    describe('close-lens', () => {
        it('removes a lens from state', () => {
            const lens = makeLens({ id: 'lens-a' });
            let s = compositorReducer(state, { type: 'open-lens', lens });
            s = compositorReducer(s, { type: 'close-lens', lensId: 'lens-a' });

            expect(s.lenses.has('lens-a')).toBe(false);
            expect(s.taskbar).not.toContain('lens-a');
        });

        it('closing focused lens focuses next available', () => {
            const a = makeLens({ id: 'a' });
            const b = makeLens({ id: 'b' });

            let s = compositorReducer(state, { type: 'open-lens', lens: a });
            s = compositorReducer(s, { type: 'open-lens', lens: b });
            s = compositorReducer(s, { type: 'close-lens', lensId: 'b' });

            expect(s.focusedLensId).toBe('a');
        });

        it('closing last lens sets focus to null', () => {
            const a = makeLens({ id: 'a' });
            let s = compositorReducer(state, { type: 'open-lens', lens: a });
            s = compositorReducer(s, { type: 'close-lens', lensId: 'a' });

            expect(s.focusedLensId).toBeNull();
        });

        it('collapses layout when closing half of a split', () => {
            const a = makeLens({ id: 'a' });
            const b = makeLens({ id: 'b' });

            let s = compositorReducer(state, { type: 'open-lens', lens: a });
            s = compositorReducer(s, { type: 'open-lens', lens: b });
            s = compositorReducer(s, { type: 'close-lens', lensId: 'b' });

            expect(s.layout).toEqual({ type: 'lens', lensId: 'a' });
        });

        it('is a no-op for nonexistent lens IDs', () => {
            const a = makeLens({ id: 'a' });
            const s = compositorReducer(state, { type: 'open-lens', lens: a });
            const next = compositorReducer(s, { type: 'close-lens', lensId: 'nonexistent' });

            expect(next).toBe(s);
        });
    });

    describe('focus-lens', () => {
        it('changes the focused lens', () => {
            const a = makeLens({ id: 'a' });
            const b = makeLens({ id: 'b' });

            let s = compositorReducer(state, { type: 'open-lens', lens: a });
            s = compositorReducer(s, { type: 'open-lens', lens: b });
            s = compositorReducer(s, { type: 'focus-lens', lensId: 'a' });

            expect(s.focusedLensId).toBe('a');
        });

        it('is a no-op for the already-focused lens', () => {
            const a = makeLens({ id: 'a' });
            let s = compositorReducer(state, { type: 'open-lens', lens: a });
            const next = compositorReducer(s, { type: 'focus-lens', lensId: 'a' });

            expect(next).toBe(s);
        });

        it('is a no-op for nonexistent lens IDs', () => {
            const a = makeLens({ id: 'a' });
            const s = compositorReducer(state, { type: 'open-lens', lens: a });
            const next = compositorReducer(s, { type: 'focus-lens', lensId: 'nonexistent' });

            expect(next).toBe(s);
        });
    });

    describe('set-title', () => {
        it('updates a lens title', () => {
            const a = makeLens({ id: 'a', title: 'Terminal' });
            let s = compositorReducer(state, { type: 'open-lens', lens: a });
            s = compositorReducer(s, { type: 'set-title', lensId: 'a', title: 'root@web-01:~$' });

            expect(s.lenses.get('a')?.title).toBe('root@web-01:~$');
        });

        it('is a no-op for nonexistent lens IDs', () => {
            const s = createInitialState();
            const next = compositorReducer(s, { type: 'set-title', lensId: 'x', title: 'nope' });

            expect(next).toBe(s);
        });
    });

    describe('toggle-maximize', () => {
        it('maximizes a lens', () => {
            const a = makeLens({ id: 'a' });
            let s = compositorReducer(state, { type: 'open-lens', lens: a });
            s = compositorReducer(s, { type: 'toggle-maximize', lensId: 'a' });

            expect(s.maximizedLensId).toBe('a');
        });

        it('un-maximizes when toggled again', () => {
            const a = makeLens({ id: 'a' });
            let s = compositorReducer(state, { type: 'open-lens', lens: a });
            s = compositorReducer(s, { type: 'toggle-maximize', lensId: 'a' });
            s = compositorReducer(s, { type: 'toggle-maximize', lensId: 'a' });

            expect(s.maximizedLensId).toBeNull();
        });

        it('closing maximized lens clears maximize', () => {
            const a = makeLens({ id: 'a' });
            let s = compositorReducer(state, { type: 'open-lens', lens: a });
            s = compositorReducer(s, { type: 'toggle-maximize', lensId: 'a' });
            s = compositorReducer(s, { type: 'close-lens', lensId: 'a' });

            expect(s.maximizedLensId).toBeNull();
        });
    });

    describe('swap-lenses', () => {
        it('swaps two lens positions in the layout', () => {
            const a = makeLens({ id: 'a' });
            const b = makeLens({ id: 'b' });

            let s = compositorReducer(state, { type: 'open-lens', lens: a });
            s = compositorReducer(s, { type: 'open-lens', lens: b });

            // Layout should be split-h with a on left, b on right
            expect(collectLensIds(s.layout)).toEqual(['a', 'b']);

            s = compositorReducer(s, { type: 'swap-lenses', lensIdA: 'a', lensIdB: 'b' });

            expect(collectLensIds(s.layout)).toEqual(['b', 'a']);
        });
    });

    describe('set-split-ratio', () => {
        it('updates the split ratio at a path', () => {
            const a = makeLens({ id: 'a' });
            const b = makeLens({ id: 'b' });

            let s = compositorReducer(state, { type: 'open-lens', lens: a });
            s = compositorReducer(s, { type: 'open-lens', lens: b });

            s = compositorReducer(s, { type: 'set-split-ratio', path: [], ratio: 0.7 });

            if (s.layout.type === 'split-h') {
                expect(s.layout.ratio).toBe(0.7);
            }
        });

        it('clamps ratio between 0.1 and 0.9', () => {
            const a = makeLens({ id: 'a' });
            const b = makeLens({ id: 'b' });

            let s = compositorReducer(state, { type: 'open-lens', lens: a });
            s = compositorReducer(s, { type: 'open-lens', lens: b });

            s = compositorReducer(s, { type: 'set-split-ratio', path: [], ratio: 0.0 });
            if (s.layout.type === 'split-h') {
                expect(s.layout.ratio).toBe(0.1);
            }

            s = compositorReducer(s, { type: 'set-split-ratio', path: [], ratio: 1.0 });
            if (s.layout.type === 'split-h') {
                expect(s.layout.ratio).toBe(0.9);
            }
        });
    });

    describe('custom action', () => {
        it('is a no-op at the base reducer level', () => {
            const a = makeLens({ id: 'a' });
            let s = compositorReducer(state, { type: 'open-lens', lens: a });
            const next = compositorReducer(s, {
                type: 'custom',
                action: 'third-party:do-thing',
                payload: { value: 42 },
            });

            expect(next).toBe(s);
        });
    });
});

// ── collectLensIds Tests ───────────────────────────────────────

describe('collectLensIds', () => {
    it('collects from a single lens node', () => {
        expect(collectLensIds({ type: 'lens', lensId: 'a' })).toEqual(['a']);
    });

    it('ignores empty lens IDs', () => {
        expect(collectLensIds({ type: 'lens', lensId: '' })).toEqual([]);
    });

    it('collects from splits', () => {
        const layout = {
            type: 'split-h' as const,
            ratio: 0.5,
            children: [
                { type: 'lens' as const, lensId: 'a' },
                { type: 'lens' as const, lensId: 'b' },
            ] as const,
        };

        expect(collectLensIds(layout)).toEqual(['a', 'b']);
    });

    it('collects from nested splits', () => {
        const layout = {
            type: 'split-v' as const,
            ratio: 0.5,
            children: [
                {
                    type: 'split-h' as const,
                    ratio: 0.5,
                    children: [
                        { type: 'lens' as const, lensId: 'a' },
                        { type: 'lens' as const, lensId: 'b' },
                    ] as const,
                },
                { type: 'lens' as const, lensId: 'c' },
            ] as const,
        };

        expect(collectLensIds(layout)).toEqual(['a', 'b', 'c']);
    });

    it('collects from tabs', () => {
        const layout = {
            type: 'tabs' as const,
            children: [
                { type: 'lens' as const, lensId: 'a' },
                { type: 'lens' as const, lensId: 'b' },
                { type: 'lens' as const, lensId: 'c' },
            ],
            activeIndex: 0,
        };

        expect(collectLensIds(layout)).toEqual(['a', 'b', 'c']);
    });
});

// ── generateLensId Tests ───────────────────────────────────────

describe('generateLensId', () => {
    beforeEach(() => {
        _resetLensIdCounter();
    });

    it('generates unique IDs', () => {
        const ids = new Set<string>();
        for (let i = 0; i < 100; i++) {
            ids.add(generateLensId());
        }
        expect(ids.size).toBe(100);
    });

    it('generates prefixed IDs', () => {
        const id = generateLensId();
        expect(id.startsWith('lens-')).toBe(true);
    });
});
