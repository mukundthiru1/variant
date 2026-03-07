/**
 * VARIANT — Structured Event Query
 *
 * Query the event log with structured filters instead of
 * manual iteration. Essential for after-action reports,
 * module analytics, and debugging.
 *
 * DESIGN: Pure functions operating on readonly event arrays.
 * No mutation. No side effects. Composable via chaining.
 *
 * Usage:
 *   const query = createEventQuery(bus.getLog());
 *   const attacks = query
 *       .type('auth:login')
 *       .where(e => !e.success)
 *       .after(startTime)
 *       .before(endTime)
 *       .limit(100)
 *       .results();
 */

import type { EngineEvent, EventType, EventByType } from './events';

// ── Query Interface ──────────────────────────────────────────

/**
 * Fluent event query builder.
 * All methods return a new query (immutable chain).
 */
export interface EventQuery<T extends EngineEvent = EngineEvent> {
    /** Filter to events of a specific type. */
    type<E extends EventType>(eventType: E): EventQuery<EventByType<E>>;

    /** Filter to events matching a type prefix (e.g., 'auth:'). */
    prefix(typePrefix: string): EventQuery<T>;

    /** Filter with a custom predicate. */
    where(predicate: (event: T) => boolean): EventQuery<T>;

    /** Filter to events after a timestamp (inclusive). */
    after(timestamp: number): EventQuery<T>;

    /** Filter to events before a timestamp (inclusive). */
    before(timestamp: number): EventQuery<T>;

    /** Filter to events between two timestamps (inclusive). */
    between(startTimestamp: number, endTimestamp: number): EventQuery<T>;

    /** Filter to events with a specific field value. */
    field<K extends string>(key: K, value: unknown): EventQuery<T>;

    /** Limit the number of results. */
    limit(count: number): EventQuery<T>;

    /** Skip the first N results. */
    offset(count: number): EventQuery<T>;

    /** Sort results (default: chronological). */
    sort(order: 'asc' | 'desc'): EventQuery<T>;

    /** Execute the query and return results. */
    results(): readonly T[];

    /** Count matching events without materializing the full result. */
    count(): number;

    /** Get the first matching event, or undefined. */
    first(): T | undefined;

    /** Get the last matching event, or undefined. */
    last(): T | undefined;

    /** Group results by a field value. */
    groupBy<K extends string>(key: K): ReadonlyMap<unknown, readonly T[]>;
}

// ── Implementation ──────────────────────────────────────────

interface QueryState {
    readonly source: readonly EngineEvent[];
    readonly filters: readonly ((event: EngineEvent) => boolean)[];
    readonly limitN: number | null;
    readonly offsetN: number;
    readonly sortOrder: 'asc' | 'desc';
}

function executeFilters(state: QueryState): EngineEvent[] {
    let results: EngineEvent[] = [];

    for (const event of state.source) {
        let pass = true;
        for (const filter of state.filters) {
            if (!filter(event)) {
                pass = false;
                break;
            }
        }
        if (pass) results.push(event);
    }

    // Sort
    if (state.sortOrder === 'desc') {
        results.sort((a, b) => b.timestamp - a.timestamp);
    }
    // 'asc' is the natural order (event log is chronological)

    // Offset
    if (state.offsetN > 0) {
        results = results.slice(state.offsetN);
    }

    // Limit
    if (state.limitN !== null) {
        results = results.slice(0, state.limitN);
    }

    return results;
}

function createQueryFromState<T extends EngineEvent>(state: QueryState): EventQuery<T> {
    return {
        type<E extends EventType>(eventType: E): EventQuery<EventByType<E>> {
            return createQueryFromState<EventByType<E>>({
                ...state,
                filters: [...state.filters, (e) => e.type === eventType],
            } as QueryState);
        },

        prefix(typePrefix: string): EventQuery<T> {
            return createQueryFromState<T>({
                ...state,
                filters: [...state.filters, (e) => e.type.startsWith(typePrefix)],
            });
        },

        where(predicate: (event: T) => boolean): EventQuery<T> {
            return createQueryFromState<T>({
                ...state,
                filters: [...state.filters, predicate as (event: EngineEvent) => boolean],
            });
        },

        after(timestamp: number): EventQuery<T> {
            return createQueryFromState<T>({
                ...state,
                filters: [...state.filters, (e) => e.timestamp >= timestamp],
            });
        },

        before(timestamp: number): EventQuery<T> {
            return createQueryFromState<T>({
                ...state,
                filters: [...state.filters, (e) => e.timestamp <= timestamp],
            });
        },

        between(startTimestamp: number, endTimestamp: number): EventQuery<T> {
            return createQueryFromState<T>({
                ...state,
                filters: [
                    ...state.filters,
                    (e) => e.timestamp >= startTimestamp && e.timestamp <= endTimestamp,
                ],
            });
        },

        field<K extends string>(key: K, value: unknown): EventQuery<T> {
            return createQueryFromState<T>({
                ...state,
                filters: [
                    ...state.filters,
                    (e) => (e as unknown as Record<string, unknown>)[key] === value,
                ],
            });
        },

        limit(count: number): EventQuery<T> {
            return createQueryFromState<T>({
                ...state,
                limitN: count,
            });
        },

        offset(count: number): EventQuery<T> {
            return createQueryFromState<T>({
                ...state,
                offsetN: count,
            });
        },

        sort(order: 'asc' | 'desc'): EventQuery<T> {
            return createQueryFromState<T>({
                ...state,
                sortOrder: order,
            });
        },

        results(): readonly T[] {
            return executeFilters(state) as T[];
        },

        count(): number {
            // Optimized: don't sort or slice, just count filter matches
            let count = 0;
            for (const event of state.source) {
                let pass = true;
                for (const filter of state.filters) {
                    if (!filter(event)) {
                        pass = false;
                        break;
                    }
                }
                if (pass) count++;
            }
            return count;
        },

        first(): T | undefined {
            for (const event of state.source) {
                let pass = true;
                for (const filter of state.filters) {
                    if (!filter(event)) {
                        pass = false;
                        break;
                    }
                }
                if (pass) return event as T;
            }
            return undefined;
        },

        last(): T | undefined {
            let lastMatch: T | undefined;
            for (const event of state.source) {
                let pass = true;
                for (const filter of state.filters) {
                    if (!filter(event)) {
                        pass = false;
                        break;
                    }
                }
                if (pass) lastMatch = event as T;
            }
            return lastMatch;
        },

        groupBy<K extends string>(key: K): ReadonlyMap<unknown, readonly T[]> {
            const results = executeFilters(state) as T[];
            const groups = new Map<unknown, T[]>();

            for (const event of results) {
                const val = (event as unknown as Record<string, unknown>)[key];
                let group = groups.get(val);
                if (group === undefined) {
                    group = [];
                    groups.set(val, group);
                }
                group.push(event);
            }

            return groups;
        },
    };
}

/**
 * Create a new event query over a log of events.
 *
 * The log is not copied — it is read lazily when results()
 * or count() is called.
 */
export function createEventQuery(log: readonly EngineEvent[]): EventQuery {
    return createQueryFromState({
        source: log,
        filters: [],
        limitN: null,
        offsetN: 0,
        sortOrder: 'asc',
    });
}
