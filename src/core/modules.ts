/**
 * VARIANT — Module System
 *
 * Everything that extends the engine is a module. Modules receive
 * a read-only simulation context and an event bus. They can listen
 * to events and emit events. They cannot directly mutate VMs,
 * network state, or other modules' state.
 *
 * SECURITY: Modules are loaded by ID. The engine maintains an
 * allowlist of registered modules. Community levels cannot load
 * modules that don't exist — the validator catches this.
 *
 * SECURITY: Modules receive SimulationContext which provides
 * read-only access to VMs and fabric. There is no path from
 * a module to mutable simulation internals.
 */

import type { EventBus } from './events';
import type { VMInstance } from './vm/types';
import type { NetworkFabric } from './fabric/types';
import type { WorldSpec } from './world/types';

// ── Service Locator ─────────────────────────────────────────────

/**
 * Inter-module service registry. Modules expose named services
 * during initialization. Other modules consume them by name.
 *
 * This decouples modules from each other — they depend on
 * service contracts, not concrete module implementations.
 *
 * Usage (producer):
 *   context.services.register('sql-engine', { query: ... });
 *
 * Usage (consumer):
 *   const sql = context.services.get<SQLEngine>('sql-engine');
 */
export interface ServiceLocator {
    /** Register a named service. Throws if already registered. */
    register(name: string, service: unknown): void;

    /** Get a service by name. Returns undefined if not registered. */
    get<T = unknown>(name: string): T | undefined;

    /** Check if a service is registered. */
    has(name: string): boolean;

    /** List all registered service names. */
    list(): readonly string[];
}

/**
 * Create a service locator instance.
 */
export function createServiceLocator(): ServiceLocator {
    const services = new Map<string, unknown>();

    return {
        register(name: string, service: unknown): void {
            if (services.has(name)) {
                throw new Error(
                    `ServiceLocator: service '${name}' is already registered. ` +
                    `Services are append-only — unregister is not supported.`,
                );
            }
            if (name.length === 0) {
                throw new Error('ServiceLocator: service name must be non-empty.');
            }
            services.set(name, service);
        },

        get<T = unknown>(name: string): T | undefined {
            return services.get(name) as T | undefined;
        },

        has(name: string): boolean {
            return services.has(name);
        },

        list(): readonly string[] {
            return Object.freeze(Array.from(services.keys()));
        },
    };
}

// ── Module types ───────────────────────────────────────────────

export type ModuleType =
    | 'lens'
    | 'engine'
    | 'service'
    | 'defense'
    | 'actor'
    | 'surface'
    | 'scoring'
    | 'protocol'
    | 'dynamics'
    | (string & {});  // open union — third-party types accepted

// ── Capability declarations ────────────────────────────────────

/**
 * Capabilities that modules provide or require.
 * Used for dependency resolution — a module that requires 'sql-engine'
 * will fail to load if no module provides 'sql-engine'.
 */
export interface Capability {
    readonly name: string;
    readonly version?: string;
}

// ── Simulation context (read-only view) ────────────────────────

/**
 * The context provided to modules during initialization.
 * This is the module's window into the simulation.
 *
 * SECURITY: Everything is readonly. Modules cannot:
 * - Add/remove VMs
 * - Modify network topology
 * - Change WorldSpec
 * - Access other modules' state
 */
export interface SimulationContext {
    readonly vms: ReadonlyMap<string, VMInstance>;
    readonly fabric: Readonly<Pick<NetworkFabric, 'getTrafficLog' | 'getStats' | 'tap' | 'addDNSRecord' | 'registerExternal' | 'getExternalHandler' | 'getExternalDomains'>>;
    readonly events: EventBus;
    readonly world: Readonly<WorldSpec>;
    readonly tick: number;

    /**
     * Inter-module service locator. Modules register services
     * during init() and consume them from other modules.
     * This replaces tight coupling between modules with
     * named service contracts.
     */
    readonly services: ServiceLocator;
}

// ── Module contract ────────────────────────────────────────────

/**
 * The universal module contract.
 *
 * Implementations must:
 * 1. Be stateless or manage their own state internally
 * 2. Not hold references to mutable simulation internals
 * 3. Clean up all resources in destroy()
 * 4. Not throw from init() or destroy()
 *
 * EXTENSIBILITY: The type field is any string, not a closed union.
 * Third-party packages define their own module types.
 */
export interface Module {
    readonly id: string;

    /** Module type. Any string. Well-known types use MODULE_* constants. */
    readonly type: string;

    readonly version: string;
    readonly description: string;

    /** What this module provides to the ecosystem. */
    readonly provides: readonly Capability[];

    /** What this module needs from the ecosystem. */
    readonly requires: readonly Capability[];

    /** Tags for querying/filtering modules. */
    readonly tags?: readonly string[];

    /**
     * Module-specific configuration schema.
     * Open record — each module defines its own config shape.
     */
    readonly config?: Readonly<Record<string, unknown>>;

    /** Initialize the module with simulation context. */
    init(context: SimulationContext): void;

    /**
     * Called after all modules have been initialized. Optional.
     * Use for cross-module coordination that requires all modules to be ready.
     */
    onAllInitialized?(context: SimulationContext): void;

    /**
     * Called before the first simulation tick. Optional.
     * Use for one-time setup that depends on the simulation being fully ready.
     */
    onSimulationStart?(context: SimulationContext): void;

    /**
     * Called every simulation tick. Optional.
     * Modules that need per-tick processing implement this.
     */
    onTick?(tick: number, context: SimulationContext): void;

    /**
     * Called before each tick is processed. Optional.
     * Use for pre-tick state preparation.
     */
    onPreTick?(tick: number, context: SimulationContext): void;

    /**
     * Called after each tick is fully processed. Optional.
     * Use for post-tick cleanup or aggregation.
     */
    onPostTick?(tick: number, context: SimulationContext): void;

    /**
     * Called when the simulation is paused. Optional.
     */
    onPause?(): void;

    /**
     * Called when the simulation is resumed. Optional.
     */
    onResume?(): void;

    /**
     * Called when the simulation is about to end (before destroy). Optional.
     * Use for final scoring, report generation, or data export.
     */
    onSimulationEnd?(context: SimulationContext): void;

    /** Tear down the module and release all resources. */
    destroy(): void;
}

// ── Module registry ────────────────────────────────────────────

/**
 * Error thrown when a module cannot be loaded.
 */
export class ModuleLoadError extends Error {
    override readonly name = 'ModuleLoadError' as const;
    readonly moduleId: string;
    constructor(message: string, moduleId: string, cause?: Error) {
        super(message, { cause });
        this.moduleId = moduleId;
    }
}

/**
 * Create a module registry.
 *
 * The registry manages module lifecycle:
 * 1. Registration (at build time)
 * 2. Resolution (check dependencies)
 * 3. Initialization (when simulation starts)
 * 4. Teardown (when simulation ends)
 */
export interface ModuleRegistry {
    /**
     * Register a module factory.
     * The factory is called when the module is needed.
     */
    register(id: string, factory: () => Module): void;

    /**
     * Resolve and load modules required by a WorldSpec.
     * Validates that all required capabilities are satisfied.
     * Throws ModuleLoadError if a module is missing or a dependency is unmet.
     */
    resolve(moduleIds: readonly string[]): Module[];

    /**
     * Initialize all resolved modules with the simulation context.
     */
    initAll(modules: Module[], context: SimulationContext): void;

    /**
     * Tear down all initialized modules.
     */
    destroyAll(modules: Module[]): void;

    /**
     * List all registered module IDs.
     */
    listRegistered(): readonly string[];

    /**
     * List modules by type.
     */
    listByType(type: string): readonly string[];

    /**
     * List modules that provide a specific capability.
     */
    listByCapability(capability: string): readonly string[];

    /**
     * Get module metadata without instantiating it.
     * Returns null if not registered.
     */
    getMetadata(id: string): ModuleMetadata | null;
}

/**
 * Lightweight metadata about a module, available without instantiation.
 * Used for UI (module picker), validation, and documentation.
 */
export interface ModuleMetadata {
    readonly id: string;
    readonly type: string;
    readonly version: string;
    readonly description: string;
    readonly provides: readonly Capability[];
    readonly requires: readonly Capability[];
    readonly tags: readonly string[];
}

/**
 * Create a module registry.
 */
export function createModuleRegistry(): ModuleRegistry {
    const factories = new Map<string, () => Module>();
    /** Cache of metadata from first instantiation, keyed by module ID. */
    const metadataCache = new Map<string, ModuleMetadata>();

    function ensureMetadata(id: string): ModuleMetadata | null {
        if (metadataCache.has(id)) return metadataCache.get(id) ?? null;
        const factory = factories.get(id);
        if (factory === undefined) return null;
        const mod = factory();
        const meta: ModuleMetadata = {
            id: mod.id,
            type: mod.type,
            version: mod.version,
            description: mod.description,
            provides: mod.provides,
            requires: mod.requires,
            tags: mod.tags ?? [],
        };
        metadataCache.set(id, meta);
        mod.destroy();
        return meta;
    }

    const registry: ModuleRegistry = {
        register(id: string, factory: () => Module): void {
            if (factories.has(id)) {
                throw new ModuleLoadError(
                    `Module '${id}' is already registered`,
                    id,
                );
            }
            factories.set(id, factory);
        },

        resolve(moduleIds: readonly string[]): Module[] {
            const modules: Module[] = [];
            const providedCapabilities = new Set<string>();

            for (const id of moduleIds) {
                const factory = factories.get(id);
                if (factory === undefined) {
                    throw new ModuleLoadError(
                        `Module '${id}' is not registered. Available: ${[...factories.keys()].join(', ')}`,
                        id,
                    );
                }

                const module = factory();
                modules.push(module);

                for (const cap of module.provides) {
                    providedCapabilities.add(cap.name);
                }
            }

            // Verify all required capabilities are provided
            for (const module of modules) {
                for (const req of module.requires) {
                    if (!providedCapabilities.has(req.name)) {
                        throw new ModuleLoadError(
                            `Module '${module.id}' requires capability '${req.name}' which is not provided by any loaded module`,
                            module.id,
                        );
                    }
                }
            }

            return modules;
        },

        initAll(modules: Module[], context: SimulationContext): void {
            for (const module of modules) {
                try {
                    module.init(context);
                } catch (error: unknown) {
                    throw new ModuleLoadError(
                        `Module '${module.id}' failed to initialize: ${error instanceof Error ? error.message : String(error)}`,
                        module.id,
                        error instanceof Error ? error : undefined,
                    );
                }
            }
        },

        destroyAll(modules: Module[]): void {
            // Destroy in reverse order (LIFO)
            for (let i = modules.length - 1; i >= 0; i--) {
                const module = modules[i];
                if (module === undefined) continue;
                try {
                    module.destroy();
                } catch (error: unknown) {
                    // Log but don't throw — we must try to destroy all modules
                    console.error(
                        `[ModuleRegistry] Module '${module.id}' failed to destroy:`,
                        error instanceof Error ? error.message : String(error),
                    );
                }
            }
        },

        listRegistered(): readonly string[] {
            return [...factories.keys()];
        },

        listByType(type: string): readonly string[] {
            const result: string[] = [];
            for (const id of factories.keys()) {
                const meta = ensureMetadata(id);
                if (meta !== null && meta.type === type) {
                    result.push(id);
                }
            }
            return result;
        },

        listByCapability(capability: string): readonly string[] {
            const result: string[] = [];
            for (const id of factories.keys()) {
                const meta = ensureMetadata(id);
                if (meta !== null && meta.provides.some(p => p.name === capability)) {
                    result.push(id);
                }
            }
            return result;
        },

        getMetadata(id: string): ModuleMetadata | null {
            return ensureMetadata(id);
        },
    };

    return registry;
}
