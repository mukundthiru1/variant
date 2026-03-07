/**
 * VARIANT — Plugin System
 *
 * The primary extensibility mechanism. Plugins can:
 *   1. Register new modules
 *   2. Register new detection engines
 *   3. Register new noise rules
 *   4. Register new service handlers
 *   5. Register new lens definitions
 *   6. Add event bus middleware
 *   7. Add custom scoring rules
 *
 * DESIGN:
 *   A plugin is a plain object with lifecycle hooks.
 *   Plugins are loaded before the simulation starts.
 *   They receive a PluginContext with registration APIs.
 *
 * SECURITY:
 *   Plugins cannot access simulation internals directly.
 *   They can only use the registration APIs provided.
 *   Plugin errors are caught and logged — they cannot
 *   crash the engine.
 *
 * CONFIGURABILITY:
 *   Plugins can be enabled/disabled per-level via WorldSpec.
 *   Plugin configuration is passed through WorldSpec.extensions.
 *
 * SWAPPABILITY: Replace this file. Plugins implement the
 * Plugin interface, which is stable.
 */

import type { Module } from './modules';
import type { NamedMiddleware } from './middleware';
import type { DetectionEngine } from '../lib/detection/types';
import type { NoiseRule } from '../lib/stealth/types';

// ── Plugin Interface ────────────────────────────────────────

/**
 * A VARIANT plugin.
 *
 * Convention: namespace plugin IDs as 'vendor/name'.
 * Built-in plugins use 'variant/name'.
 */
export interface Plugin {
    /** Unique plugin ID. Convention: 'vendor/name'. */
    readonly id: string;

    /** Plugin version (semver). */
    readonly version: string;

    /** Human-readable description. */
    readonly description: string;

    /** Author information. */
    readonly author?: string;

    /** Plugin dependencies (other plugin IDs). */
    readonly dependencies?: readonly string[];

    /**
     * Called when the plugin is loaded.
     * Use the context to register modules, engines, rules, etc.
     */
    activate(context: PluginContext): void;

    /**
     * Called when the plugin is unloaded. Optional.
     * Clean up any resources.
     */
    deactivate?(): void;
}

// ── Plugin Context ──────────────────────────────────────────

/**
 * The API surface available to plugins during activation.
 *
 * SECURITY: This is a controlled API. Plugins cannot
 * access simulation internals or bypass security checks.
 */
export interface PluginContext {
    /** Register a module factory. */
    registerModule(id: string, factory: () => Module): void;

    /** Register a detection engine. */
    registerDetectionEngine(engine: DetectionEngine): void;

    /** Register noise rules. */
    registerNoiseRules(rules: readonly NoiseRule[]): void;

    /** Register event bus middleware. */
    registerMiddleware(middleware: NamedMiddleware): void;

    /**
     * Register a named extension handler.
     * This is the universal hook for plugin-provided extensions:
     *   - Objective evaluators: register('objective-evaluator:<name>', handler)
     *   - Game-over handlers:   register('gameover-handler:<name>', handler)
     *   - NPC templates:        register('npc-template:<name>', factory)
     *   - Vuln templates:       register('vuln-template:<name>', factory)
     *   - Scoring rules:        register('scoring-rule:<name>', evaluator)
     *   - Persistence sigs:     register('persistence-sig:<name>', signature)
     *   - Service handlers:     register('service-handler:<name>', handler)
     *   - Custom anything:      register('vendor/feature:<name>', value)
     *
     * The engine's service locator retrieves these at runtime.
     */
    registerExtension(key: string, value: unknown): void;

    /**
     * Get a previously registered extension by key.
     */
    getExtension<T = unknown>(key: string): T | undefined;

    /**
     * List all registered extension keys matching a prefix.
     */
    listExtensions(prefix: string): readonly string[];

    /**
     * Get plugin configuration from WorldSpec.extensions.
     * Returns undefined if no config is set for this plugin.
     */
    getConfig<T = unknown>(): T | undefined;

    /**
     * Log a message (plugin-namespaced).
     */
    log(level: 'info' | 'warn' | 'error', message: string): void;
}

// ── Plugin Registry ─────────────────────────────────────────

export interface PluginRegistry {
    /** Register a plugin. */
    register(plugin: Plugin): void;

    /** Get a plugin by ID. */
    get(id: string): Plugin | undefined;

    /** Get all registered plugins. */
    getAll(): readonly Plugin[];

    /**
     * Activate all registered plugins.
     * Resolves dependencies and calls activate() in order.
     */
    activateAll(contextFactory: (pluginId: string) => PluginContext): void;

    /**
     * Deactivate all plugins (reverse order).
     */
    deactivateAll(): void;

    /** Check if a plugin is registered. */
    has(id: string): boolean;
}

// ── Implementation ──────────────────────────────────────────

export function createPluginRegistry(): PluginRegistry {
    const plugins = new Map<string, Plugin>();
    const activationOrder: string[] = [];
    let activated = false;

    function topologicalSort(): Plugin[] {
        const visited = new Set<string>();
        const sorted: Plugin[] = [];

        function visit(id: string): void {
            if (visited.has(id)) return;
            visited.add(id);

            const plugin = plugins.get(id);
            if (plugin === undefined) {
                throw new PluginLoadError(
                    `Plugin '${id}' is required as a dependency but not registered`,
                    id,
                );
            }

            if (plugin.dependencies !== undefined) {
                for (const dep of plugin.dependencies) {
                    if (!plugins.has(dep)) {
                        throw new PluginLoadError(
                            `Plugin '${id}' depends on '${dep}' which is not registered`,
                            id,
                        );
                    }
                    visit(dep);
                }
            }

            sorted.push(plugin);
        }

        for (const id of plugins.keys()) {
            visit(id);
        }

        return sorted;
    }

    return {
        register(plugin: Plugin): void {
            if (activated) {
                throw new PluginLoadError(
                    `Cannot register plugin '${plugin.id}' after activation`,
                    plugin.id,
                );
            }
            if (plugins.has(plugin.id)) {
                throw new PluginLoadError(
                    `Plugin '${plugin.id}' is already registered`,
                    plugin.id,
                );
            }
            plugins.set(plugin.id, plugin);
        },

        get(id: string): Plugin | undefined {
            return plugins.get(id);
        },

        getAll(): readonly Plugin[] {
            return [...plugins.values()];
        },

        activateAll(contextFactory: (pluginId: string) => PluginContext): void {
            if (activated) return;

            const sorted = topologicalSort();

            for (const plugin of sorted) {
                try {
                    const context = contextFactory(plugin.id);
                    plugin.activate(context);
                    activationOrder.push(plugin.id);
                } catch (error: unknown) {
                    console.error(
                        `[PluginRegistry] Plugin '${plugin.id}' failed to activate:`,
                        error instanceof Error ? error.message : String(error),
                    );
                }
            }

            activated = true;
        },

        deactivateAll(): void {
            // Deactivate in reverse order
            for (let i = activationOrder.length - 1; i >= 0; i--) {
                const id = activationOrder[i]!;
                const plugin = plugins.get(id);
                if (plugin?.deactivate !== undefined) {
                    try {
                        plugin.deactivate();
                    } catch (error: unknown) {
                        console.error(
                            `[PluginRegistry] Plugin '${id}' failed to deactivate:`,
                            error instanceof Error ? error.message : String(error),
                        );
                    }
                }
            }
            activationOrder.length = 0;
            activated = false;
        },

        has(id: string): boolean {
            return plugins.has(id);
        },
    };
}

// ── Errors ──────────────────────────────────────────────────

export class PluginLoadError extends Error {
    override readonly name = 'PluginLoadError' as const;
    readonly pluginId: string;
    constructor(message: string, pluginId: string) {
        super(message);
        this.pluginId = pluginId;
    }
}
