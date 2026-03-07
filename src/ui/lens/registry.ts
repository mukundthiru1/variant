/**
 * VARIANT — Lens Registry Implementation
 *
 * Append-only registry for lens type definitions.
 * Third-party packages register their lens types here.
 * The compositor discovers available lenses by querying this registry.
 *
 * SECURITY: Once registered, a lens type cannot be overwritten.
 * This prevents definition poisoning where a malicious level
 * could redefine what 'terminal' means.
 */

import type {
    LensDefinition,
    LensRegistry,
    StartConfigPresetRegistry,
    StartLensConfig,
    LayoutNode,
} from './types';

// ── Lens Registry ──────────────────────────────────────────────

/**
 * Create a new lens registry.
 * Call this once at engine initialization. Pass it to the compositor.
 */
export function createLensRegistry(): LensRegistry {
    const definitions = new Map<string, LensDefinition>();

    return {
        register(definition: LensDefinition): void {
            if (definitions.has(definition.type)) {
                throw new Error(
                    `LensRegistry: lens type '${definition.type}' is already registered. ` +
                    `Lens definitions are append-only — they cannot be overwritten.`,
                );
            }

            // Validate definition completeness
            if (definition.type.length === 0) {
                throw new Error('LensRegistry: lens type must be a non-empty string.');
            }
            if (definition.displayName.length === 0) {
                throw new Error(`LensRegistry: lens '${definition.type}' must have a displayName.`);
            }

            definitions.set(definition.type, Object.freeze({ ...definition }));
        },

        get(type: string): LensDefinition | undefined {
            return definitions.get(type);
        },

        has(type: string): boolean {
            return definitions.has(type);
        },

        getAll(): readonly LensDefinition[] {
            return Object.freeze(Array.from(definitions.values()));
        },

        getTypes(): readonly string[] {
            return Object.freeze(Array.from(definitions.keys()));
        },
    };
}

// ── Start Config Preset Registry ───────────────────────────────

/**
 * Create a new start config preset registry.
 * Presets let level designers write `startConfig: 'terminal'`
 * instead of specifying the full lens configuration.
 */
export function createStartConfigPresetRegistry(): StartConfigPresetRegistry {
    const presets = new Map<string, { readonly lenses: readonly StartLensConfig[]; readonly layout?: LayoutNode }>();

    return {
        register(
            name: string,
            config: { readonly lenses: readonly StartLensConfig[]; readonly layout?: LayoutNode },
        ): void {
            if (presets.has(name)) {
                throw new Error(
                    `StartConfigPresetRegistry: preset '${name}' is already registered. ` +
                    `Presets are append-only — they cannot be overwritten.`,
                );
            }
            if (name.length === 0) {
                throw new Error('StartConfigPresetRegistry: preset name must be non-empty.');
            }

            presets.set(name, Object.freeze({ ...config }));
        },

        resolve(name: string): { readonly lenses: readonly StartLensConfig[]; readonly layout?: LayoutNode } | undefined {
            return presets.get(name);
        },

        getNames(): readonly string[] {
            return Object.freeze(Array.from(presets.keys()));
        },
    };
}

// ── Default Presets ────────────────────────────────────────────

/**
 * Register the built-in start config presets.
 * Called during engine initialization.
 */
export function registerDefaultPresets(registry: StartConfigPresetRegistry): void {
    registry.register('terminal', {
        lenses: [
            { type: 'terminal', title: 'Terminal' },
        ],
    });

    registry.register('desktop', {
        lenses: [
            { type: 'terminal', title: 'Terminal' },
            { type: 'browser', title: 'Browser' },
            { type: 'email', title: 'Email' },
        ],
        layout: {
            type: 'split-h',
            ratio: 0.5,
            children: [
                { type: 'lens', lensId: '__lens-0' },
                {
                    type: 'split-v',
                    ratio: 0.5,
                    children: [
                        { type: 'lens', lensId: '__lens-1' },
                        { type: 'lens', lensId: '__lens-2' },
                    ],
                },
            ],
        },
    });

    registry.register('soc-workstation', {
        lenses: [
            { type: 'terminal', title: 'Terminal' },
            { type: 'defense-dashboard', title: 'Defense Dashboard' },
            { type: 'network-map', title: 'Network Map' },
            { type: 'log-viewer', title: 'Logs' },
        ],
        layout: {
            type: 'split-v',
            ratio: 0.6,
            children: [
                {
                    type: 'split-h',
                    ratio: 0.5,
                    children: [
                        { type: 'lens', lensId: '__lens-0' },
                        { type: 'lens', lensId: '__lens-1' },
                    ],
                },
                {
                    type: 'split-h',
                    ratio: 0.5,
                    children: [
                        { type: 'lens', lensId: '__lens-2' },
                        { type: 'lens', lensId: '__lens-3' },
                    ],
                },
            ],
        },
    });
}
