/**
 * VARIANT — Service Handler Factory
 *
 * Extensible factory for creating service handlers from WorldSpec
 * ServiceConfig entries. Third-party packages register their
 * service handler constructors here. The Simulacrum backend uses
 * this to instantiate services at boot time.
 *
 * EXTENSIBILITY: Any package can register a service handler factory.
 * The Simulacrum queries this factory by service name to create handlers.
 * Adding a new service type = register a factory function. Zero core changes.
 *
 * SECURITY: Factory functions receive a frozen ServiceContext.
 * They cannot modify the factory registry or other services.
 */

import type { ServiceHandler, ServiceContext } from './types';
import type { ServiceConfig } from '../../core/world/types';

// ── Factory Types ──────────────────────────────────────────────

/**
 * A function that creates a ServiceHandler from a WorldSpec ServiceConfig.
 * The factory receives the config and a context, and returns a handler.
 */
export type ServiceHandlerConstructor = (
    config: ServiceConfig,
    ctx: ServiceContext,
) => ServiceHandler;

/**
 * Metadata about a registered service handler type.
 */
export interface ServiceHandlerMeta {
    /** Service type name (e.g., 'http', 'ssh', 'mysql'). */
    readonly name: string;

    /** Human-readable display name. */
    readonly displayName: string;

    /** Short description. */
    readonly description: string;

    /** Default port for this service. */
    readonly defaultPort: number;

    /** Default protocol. */
    readonly defaultProtocol: 'tcp' | 'udp';

    /** Does this service require Simulacrum+ (lwIP TCP stack)? */
    readonly requiresTcpStack: boolean;

    /**
     * Compatible backends. null = all.
     * e.g., ['simulacrum', 'simulacrum+'] means this service only works
     * with Simulacrum backends, not v86.
     */
    readonly compatibleBackends: readonly string[] | null;
}

// ── Factory Interface ──────────────────────────────────────────

/**
 * The service handler factory. Registry + instantiation.
 *
 * EXTENSIBILITY: Third-party packages import this interface,
 * call register() to add their service types, and the Simulacrum
 * backend discovers them automatically.
 */
export interface ServiceHandlerFactory {
    /**
     * Register a service handler constructor.
     * Throws if a handler with the same name is already registered.
     */
    register(
        meta: ServiceHandlerMeta,
        constructor: ServiceHandlerConstructor,
    ): void;

    /**
     * Create a service handler from a WorldSpec ServiceConfig.
     * Returns null if no handler is registered for the service name.
     */
    create(config: ServiceConfig, ctx: ServiceContext): ServiceHandler | null;

    /**
     * Check if a handler is registered for a service name.
     */
    has(name: string): boolean;

    /**
     * Get metadata for a service handler type.
     */
    getMeta(name: string): ServiceHandlerMeta | undefined;

    /**
     * Get all registered service handler metadata.
     */
    getAllMeta(): readonly ServiceHandlerMeta[];

    /**
     * Get all registered service type names.
     */
    getNames(): readonly string[];
}

// ── Factory Implementation ─────────────────────────────────────

/**
 * Create a new service handler factory.
 * Call once at engine initialization.
 */
export function createServiceHandlerFactory(): ServiceHandlerFactory {
    const constructors = new Map<string, ServiceHandlerConstructor>();
    const metas = new Map<string, ServiceHandlerMeta>();

    return {
        register(
            meta: ServiceHandlerMeta,
            constructor: ServiceHandlerConstructor,
        ): void {
            if (constructors.has(meta.name)) {
                throw new Error(
                    `ServiceHandlerFactory: service type '${meta.name}' is already registered. ` +
                    `Service handler registrations are append-only.`,
                );
            }
            if (meta.name.length === 0) {
                throw new Error('ServiceHandlerFactory: service name must be non-empty.');
            }

            constructors.set(meta.name, constructor);
            metas.set(meta.name, Object.freeze({ ...meta }));
        },

        create(config: ServiceConfig, ctx: ServiceContext): ServiceHandler | null {
            const constructor = constructors.get(config.name);
            if (constructor === undefined) return null;
            return constructor(config, ctx);
        },

        has(name: string): boolean {
            return constructors.has(name);
        },

        getMeta(name: string): ServiceHandlerMeta | undefined {
            return metas.get(name);
        },

        getAllMeta(): readonly ServiceHandlerMeta[] {
            return Object.freeze(Array.from(metas.values()));
        },

        getNames(): readonly string[] {
            return Object.freeze(Array.from(constructors.keys()));
        },
    };
}
