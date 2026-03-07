/**
 * VARIANT — Event Bus Implementation
 *
 * Bounded, typed, observable event system. The communication backbone.
 *
 * SECURITY: Log size is bounded to prevent memory exhaustion.
 * SECURITY: Custom events are namespaced — cannot forge core events.
 * SECURITY: Handler errors are caught and logged, never crash the bus.
 */

import type {
    EngineEvent,
    EventBus,
    EventByType,
    EventHandler,
    EventType,
    Unsubscribe,
} from './events';

/** Default maximum log entries before oldest are evicted. */
const DEFAULT_MAX_LOG_SIZE = 10_000;

/**
 * Create a new event bus instance.
 *
 * Each simulation gets its own bus. Buses are never shared
 * between simulations — this prevents cross-contamination.
 */
export function createEventBus(maxLogSize: number = DEFAULT_MAX_LOG_SIZE): EventBus {
    /**
     * Map from exact event type → set of handlers.
     * We use a Map of Sets for O(1) add/remove.
     */
    const exactHandlers = new Map<string, Set<EventHandler>>();

    /**
     * Map from prefix → set of handlers.
     * Prefix 'auth:' matches 'auth:login', 'auth:escalate', etc.
     */
    const prefixHandlers = new Map<string, Set<EventHandler>>();

    /**
     * Bounded event log. Oldest entries are evicted when full.
     * Implemented as a circular buffer for O(1) append.
     */
    const log: EngineEvent[] = [];
    let logHead = 0;
    let logCount = 0;

    function appendToLog(event: EngineEvent): void {
        if (logCount < maxLogSize) {
            log.push(event);
            logCount++;
        } else {
            // Circular overwrite
            log[logHead] = event;
            logHead = (logHead + 1) % maxLogSize;
        }
    }

    function invokeHandler(handler: EventHandler, event: EngineEvent): void {
        try {
            handler(event);
        } catch (error: unknown) {
            // Handler errors must never crash the bus.
            // Log to console in development. In production, this would
            // go to structured logging.
            console.error(
                `[EventBus] Handler threw for event '${event.type}':`,
                error instanceof Error ? error.message : String(error),
            );
        }
    }

    const bus: EventBus = {
        emit(event: EngineEvent): void {
            // Freeze the event to prevent mutation after emission.
            // This is a defense-in-depth measure — the type system
            // already marks everything readonly, but runtime freeze
            // catches bugs in untyped code paths.
            Object.freeze(event);
            appendToLog(event);

            // Exact match handlers
            const exact = exactHandlers.get(event.type);
            if (exact !== undefined) {
                for (const handler of exact) {
                    invokeHandler(handler, event);
                }
            }

            // Prefix match handlers
            for (const [prefix, handlers] of prefixHandlers) {
                if (event.type.startsWith(prefix)) {
                    for (const handler of handlers) {
                        invokeHandler(handler, event);
                    }
                }
            }
        },

        on<T extends EventType>(
            type: T,
            handler: EventHandler<EventByType<T>>,
        ): Unsubscribe {
            let handlers = exactHandlers.get(type);
            if (handlers === undefined) {
                handlers = new Set();
                exactHandlers.set(type, handlers);
            }

            // Cast is safe: the handler accepts EventByType<T> which is
            // a subtype of EngineEvent. We store it as EventHandler
            // because the discriminated union guarantees type safety.
            const wrapped = handler as EventHandler;
            handlers.add(wrapped);

            let unsubscribed = false;
            return () => {
                if (unsubscribed) return; // Idempotent
                unsubscribed = true;
                handlers.delete(wrapped);
                if (handlers.size === 0) {
                    exactHandlers.delete(type);
                }
            };
        },

        once<T extends EventType>(
            type: T,
            handler: EventHandler<EventByType<T>>,
        ): Unsubscribe {
            let unsub: Unsubscribe | null = null;
            unsub = bus.on(type, ((event: EventByType<T>) => {
                if (unsub !== null) unsub();
                handler(event);
            }) as EventHandler<EventByType<T>>);
            return unsub;
        },

        waitFor<T extends EventType>(
            type: T,
            predicate?: (event: EventByType<T>) => boolean,
        ): Promise<EventByType<T>> {
            return new Promise<EventByType<T>>((resolve) => {
                let unsub: Unsubscribe | null = null;
                unsub = bus.on(type, ((event: EventByType<T>) => {
                    if (predicate !== undefined && !predicate(event)) return;
                    if (unsub !== null) unsub();
                    resolve(event);
                }) as EventHandler<EventByType<T>>);
            });
        },

        onPrefix(prefix: string, handler: EventHandler): Unsubscribe {
            // Validate prefix format — must end with ':'
            // to prevent accidental matches (e.g., 'auth' matching 'authorization')
            if (!prefix.endsWith(':') && prefix !== '*') {
                throw new Error(
                    `[EventBus] Prefix '${prefix}' must end with ':' (e.g., 'auth:'). ` +
                    `Use '*' to subscribe to all events.`,
                );
            }

            const effectivePrefix = prefix === '*' ? '' : prefix;

            let handlers = prefixHandlers.get(effectivePrefix);
            if (handlers === undefined) {
                handlers = new Set();
                prefixHandlers.set(effectivePrefix, handlers);
            }

            handlers.add(handler);

            let unsubscribed = false;
            return () => {
                if (unsubscribed) return;
                unsubscribed = true;
                handlers.delete(handler);
                if (handlers.size === 0) {
                    prefixHandlers.delete(effectivePrefix);
                }
            };
        },

        getLog(filter?: string): readonly EngineEvent[] {
            // Reconstruct the log in chronological order from the circular buffer
            const result: EngineEvent[] = [];
            for (let i = 0; i < logCount; i++) {
                const idx = (logHead + i) % (logCount < maxLogSize ? logCount : maxLogSize);
                const entry = log[idx];
                if (entry === undefined) continue;
                if (filter === undefined || entry.type.startsWith(filter)) {
                    result.push(entry);
                }
            }
            return result;
        },

        clearLog(): void {
            log.length = 0;
            logHead = 0;
            logCount = 0;
        },

        removeAllListeners(): void {
            exactHandlers.clear();
            prefixHandlers.clear();
        },
    };

    return bus;
}
