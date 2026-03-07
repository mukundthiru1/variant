/**
 * VARIANT — Event Bus Middleware System
 *
 * Allows interception, transformation, and filtering of events
 * before they reach handlers. This is the primary extensibility
 * mechanism for the event bus.
 *
 * DESIGN:
 *   Middleware is a chain of functions. Each receives an event
 *   and a `next` callback. Calling `next(event)` passes the
 *   event to the next middleware (and ultimately to handlers).
 *   Not calling `next` suppresses the event.
 *
 * USE CASES:
 *   - Logging middleware (audit trail)
 *   - Rate limiting (prevent event storms)
 *   - Transformation (normalize events)
 *   - Filtering (suppress noise events)
 *   - Metrics (count events by type)
 *   - Replay (record and replay event sequences)
 *
 * CONFIGURABILITY:
 *   - Middleware can be added/removed at runtime
 *   - Middleware order is explicit (first added = first called)
 *   - Each middleware is a simple function — easy to test
 *
 * SWAPPABILITY: This is a standalone module. Replace it without
 * touching the event bus. The event bus wraps itself with
 * middleware via `createMiddlewareEventBus()`.
 */

import type { EngineEvent, EventBus, Unsubscribe } from './events';

// ── Types ──────────────────────────────────────────────────

/**
 * Middleware function. Receives the event and a `next` callback.
 * Call `next(event)` to pass the event along.
 * Call `next(modifiedEvent)` to transform the event.
 * Don't call `next` to suppress the event.
 */
export type EventMiddleware = (
    event: EngineEvent,
    next: (event: EngineEvent) => void,
) => void;

/**
 * Named middleware with metadata for debugging and management.
 */
export interface NamedMiddleware {
    /** Unique ID. */
    readonly id: string;

    /** Human-readable description. */
    readonly description: string;

    /** The middleware function. */
    readonly handler: EventMiddleware;

    /** Priority (lower = called first). Default: 100. */
    readonly priority?: number;

    /** Whether this middleware is currently active. */
    readonly active?: boolean;
}

/**
 * Middleware stack. Manages an ordered list of middleware
 * and provides the chain execution.
 */
export interface MiddlewareStack {
    /** Add middleware. Returns an unsubscribe function. */
    add(middleware: NamedMiddleware): Unsubscribe;

    /** Remove middleware by ID. */
    remove(id: string): boolean;

    /** Get all active middleware (sorted by priority). */
    getAll(): readonly NamedMiddleware[];

    /** Enable/disable middleware by ID. */
    setActive(id: string, active: boolean): boolean;

    /**
     * Execute the middleware chain for an event.
     * The `finalHandler` is called if no middleware suppresses the event.
     */
    execute(event: EngineEvent, finalHandler: (event: EngineEvent) => void): void;
}

// ── Implementation ──────────────────────────────────────────

export function createMiddlewareStack(): MiddlewareStack {
    const middlewares = new Map<string, NamedMiddleware & { active: boolean }>();
    let sorted: (NamedMiddleware & { active: boolean })[] = [];
    let dirty = true;

    function ensureSorted(): (NamedMiddleware & { active: boolean })[] {
        if (dirty) {
            sorted = [...middlewares.values()]
                .filter(m => m.active)
                .sort((a, b) => (a.priority ?? 100) - (b.priority ?? 100));
            dirty = false;
        }
        return sorted;
    }

    return {
        add(middleware: NamedMiddleware): Unsubscribe {
            if (middlewares.has(middleware.id)) {
                throw new Error(`Middleware '${middleware.id}' already registered`);
            }
            middlewares.set(middleware.id, {
                ...middleware,
                active: middleware.active ?? true,
            });
            dirty = true;

            let removed = false;
            return () => {
                if (removed) return;
                removed = true;
                middlewares.delete(middleware.id);
                dirty = true;
            };
        },

        remove(id: string): boolean {
            const existed = middlewares.delete(id);
            if (existed) dirty = true;
            return existed;
        },

        getAll(): readonly NamedMiddleware[] {
            return ensureSorted();
        },

        setActive(id: string, active: boolean): boolean {
            const mw = middlewares.get(id);
            if (mw === undefined) return false;
            mw.active = active;
            dirty = true;
            return true;
        },

        execute(event: EngineEvent, finalHandler: (event: EngineEvent) => void): void {
            const chain = ensureSorted();
            if (chain.length === 0) {
                finalHandler(event);
                return;
            }

            let idx = 0;
            function next(evt: EngineEvent): void {
                if (idx >= chain.length) {
                    finalHandler(evt);
                    return;
                }
                const mw = chain[idx++]!;
                try {
                    mw.handler(evt, next);
                } catch (error: unknown) {
                    console.error(
                        `[Middleware] '${mw.id}' threw:`,
                        error instanceof Error ? error.message : String(error),
                    );
                    // Continue chain on error — middleware should not break the bus
                    next(evt);
                }
            }

            next(event);
        },
    };
}

// ── Middleware-wrapped Event Bus ─────────────────────────────

/**
 * Wrap an existing EventBus with a middleware stack.
 * Events pass through middleware before reaching the inner bus.
 *
 * DESIGN: The wrapped bus implements the same EventBus interface.
 * Callers don't know middleware is involved. This is the adapter pattern.
 */
export function createMiddlewareEventBus(
    inner: EventBus,
    stack?: MiddlewareStack,
): EventBus & { readonly middleware: MiddlewareStack } {
    const middlewareStack = stack ?? createMiddlewareStack();

    const wrappedBus: EventBus & { readonly middleware: MiddlewareStack } = {
        middleware: middlewareStack,

        emit(event: EngineEvent): void {
            middlewareStack.execute(event, (finalEvent) => {
                inner.emit(finalEvent);
            });
        },

        on: inner.on.bind(inner),
        once: inner.once.bind(inner),
        waitFor: inner.waitFor.bind(inner),
        onPrefix: inner.onPrefix.bind(inner),
        getLog: inner.getLog.bind(inner),
        clearLog: inner.clearLog.bind(inner),
        removeAllListeners: inner.removeAllListeners.bind(inner),
    };

    return wrappedBus;
}

// ── Built-in Middleware Factories ────────────────────────────

/**
 * Rate-limiting middleware. Suppresses events that fire too
 * rapidly (more than `maxPerWindow` in `windowMs`).
 */
export function createRateLimitMiddleware(config: {
    readonly id?: string;
    readonly eventPattern: string;
    readonly maxPerWindow: number;
    readonly windowMs: number;
    readonly priority?: number;
}): NamedMiddleware {
    const window: number[] = [];

    return {
        id: config.id ?? `rate-limit-${config.eventPattern}`,
        description: `Rate limit '${config.eventPattern}' to ${config.maxPerWindow}/${config.windowMs}ms`,
        priority: config.priority ?? 50,
        handler(event, next) {
            if (!event.type.startsWith(config.eventPattern)) {
                next(event);
                return;
            }

            const now = Date.now();
            // Prune old entries
            while (window.length > 0 && window[0]! < now - config.windowMs) {
                window.shift();
            }

            if (window.length >= config.maxPerWindow) {
                // Suppressed — too many events in window
                return;
            }

            window.push(now);
            next(event);
        },
    };
}

/**
 * Logging middleware. Logs all events (or filtered by prefix)
 * to a callback function.
 */
export function createLoggingMiddleware(config: {
    readonly id?: string;
    readonly prefix?: string;
    readonly logger: (event: EngineEvent) => void;
    readonly priority?: number;
}): NamedMiddleware {
    return {
        id: config.id ?? `logger-${config.prefix ?? 'all'}`,
        description: `Log events matching '${config.prefix ?? '*'}'`,
        priority: config.priority ?? 10,
        handler(event, next) {
            if (config.prefix === undefined || event.type.startsWith(config.prefix)) {
                config.logger(event);
            }
            next(event);
        },
    };
}

/**
 * Metrics middleware. Counts events by type.
 */
export function createMetricsMiddleware(config?: {
    readonly id?: string;
    readonly priority?: number;
}): NamedMiddleware & { getMetrics(): Readonly<Record<string, number>> } {
    const counts = new Map<string, number>();

    const middleware: NamedMiddleware & { getMetrics(): Readonly<Record<string, number>> } = {
        id: config?.id ?? 'metrics',
        description: 'Count events by type',
        priority: config?.priority ?? 5,
        handler(event, next) {
            counts.set(event.type, (counts.get(event.type) ?? 0) + 1);
            next(event);
        },
        getMetrics(): Readonly<Record<string, number>> {
            return Object.fromEntries(counts);
        },
    };

    return middleware;
}

/**
 * Replay middleware. Records events for later replay.
 */
export function createReplayMiddleware(config?: {
    readonly id?: string;
    readonly maxEvents?: number;
    readonly priority?: number;
}): NamedMiddleware & {
    getRecording(): readonly EngineEvent[];
    replay(bus: EventBus): void;
    clear(): void;
} {
    const maxEvents = config?.maxEvents ?? 100_000;
    const recording: EngineEvent[] = [];

    const middleware: NamedMiddleware & {
        getRecording(): readonly EngineEvent[];
        replay(bus: EventBus): void;
        clear(): void;
    } = {
        id: config?.id ?? 'replay',
        description: 'Record events for replay',
        priority: config?.priority ?? 1,
        handler(event, next) {
            if (recording.length < maxEvents) {
                recording.push(event);
            }
            next(event);
        },
        getRecording() {
            return [...recording];
        },
        replay(bus: EventBus) {
            for (const event of recording) {
                bus.emit(event);
            }
        },
        clear() {
            recording.length = 0;
        },
    };

    return middleware;
}
