/**
 * VARIANT — Timer Clock Implementation
 *
 * Manages named timers: countdowns, stopwatches, intervals, oneshots.
 * Ticked by the simulation engine each tick.
 *
 * SWAPPABILITY: Implements TimerClock. Replace this file.
 */

import type {
    TimerClock,
    TimerDefinition,
    TimerInstance,
    TimerEvent,
    TimerExpiry,
    TimerState,
} from './types';

interface MutableTimer {
    id: string;
    label: string;
    type: 'countdown' | 'stopwatch' | 'interval' | 'oneshot';
    state: TimerState;
    visible: boolean;
    elapsedTicks: number;
    durationTicks: number;
    intervalTicks: number;
    fireCount: number;
    onExpiry: TimerExpiry | null;
    warnings: readonly number[];
}

export function createTimerClock(): TimerClock {
    const timers = new Map<string, MutableTimer>();
    const handlers = new Set<(event: TimerEvent) => void>();
    let currentTick = 0;

    function emitEvent(event: TimerEvent): void {
        for (const handler of handlers) {
            handler(event);
        }
    }

    function toInstance(t: MutableTimer): TimerInstance {
        const remainingTicks = t.type === 'countdown' || t.type === 'oneshot'
            ? Math.max(0, t.durationTicks - t.elapsedTicks)
            : 0;

        const progress = t.durationTicks > 0
            ? Math.min(1, t.elapsedTicks / t.durationTicks)
            : 0;

        const warning = t.type === 'countdown' && t.warnings.some(w => remainingTicks <= w && remainingTicks > 0);

        return {
            id: t.id,
            label: t.label,
            type: t.type,
            state: t.state,
            visible: t.visible,
            elapsedTicks: t.elapsedTicks,
            remainingTicks,
            durationTicks: t.durationTicks,
            progress,
            fireCount: t.fireCount,
            warning,
        };
    }

    return {
        create(definition: TimerDefinition): TimerInstance {
            const timer: MutableTimer = {
                id: definition.id,
                label: definition.label,
                type: definition.type,
                state: definition.autoStart ? 'running' : 'stopped',
                visible: definition.visible,
                elapsedTicks: 0,
                durationTicks: definition.durationTicks,
                intervalTicks: definition.intervalTicks,
                fireCount: 0,
                onExpiry: definition.onExpiry,
                warnings: definition.warnings,
            };

            timers.set(definition.id, timer);

            if (definition.autoStart) {
                emitEvent({ timerId: definition.id, kind: 'started', tick: currentTick, expiry: null });
            }

            return toInstance(timer);
        },

        start(timerId: string): boolean {
            const t = timers.get(timerId);
            if (t === undefined || t.state === 'running') return false;
            t.state = 'running';
            emitEvent({ timerId, kind: 'started', tick: currentTick, expiry: null });
            return true;
        },

        pause(timerId: string): boolean {
            const t = timers.get(timerId);
            if (t === undefined || t.state !== 'running') return false;
            t.state = 'paused';
            emitEvent({ timerId, kind: 'paused', tick: currentTick, expiry: null });
            return true;
        },

        resume(timerId: string): boolean {
            const t = timers.get(timerId);
            if (t === undefined || t.state !== 'paused') return false;
            t.state = 'running';
            emitEvent({ timerId, kind: 'resumed', tick: currentTick, expiry: null });
            return true;
        },

        stop(timerId: string): boolean {
            const t = timers.get(timerId);
            if (t === undefined) return false;
            t.state = 'stopped';
            t.elapsedTicks = 0;
            t.fireCount = 0;
            emitEvent({ timerId, kind: 'stopped', tick: currentTick, expiry: null });
            return true;
        },

        remove(timerId: string): boolean {
            return timers.delete(timerId);
        },

        get(timerId: string): TimerInstance | null {
            const t = timers.get(timerId);
            if (t === undefined) return null;
            return toInstance(t);
        },

        getAll(): readonly TimerInstance[] {
            return [...timers.values()].map(toInstance);
        },

        getVisible(): readonly TimerInstance[] {
            return [...timers.values()].filter(t => t.visible).map(toInstance);
        },

        tick(): readonly TimerEvent[] {
            currentTick++;
            const tickEvents: TimerEvent[] = [];

            for (const t of timers.values()) {
                if (t.state !== 'running') continue;

                t.elapsedTicks++;

                switch (t.type) {
                    case 'countdown': {
                        const remaining = t.durationTicks - t.elapsedTicks;

                        // Check warnings
                        if (t.warnings.includes(remaining)) {
                            tickEvents.push({ timerId: t.id, kind: 'warning', tick: currentTick, expiry: null });
                        }

                        // Check expiry
                        if (remaining <= 0) {
                            t.state = 'expired';
                            t.fireCount++;
                            tickEvents.push({ timerId: t.id, kind: 'expired', tick: currentTick, expiry: t.onExpiry });
                        }
                        break;
                    }

                    case 'oneshot': {
                        if (t.elapsedTicks >= t.durationTicks) {
                            t.state = 'expired';
                            t.fireCount++;
                            tickEvents.push({ timerId: t.id, kind: 'fired', tick: currentTick, expiry: t.onExpiry });
                        }
                        break;
                    }

                    case 'interval': {
                        if (t.intervalTicks > 0 && t.elapsedTicks % t.intervalTicks === 0) {
                            t.fireCount++;
                            tickEvents.push({ timerId: t.id, kind: 'fired', tick: currentTick, expiry: t.onExpiry });
                        }
                        break;
                    }

                    case 'stopwatch':
                        // Stopwatches just count up — no events
                        break;
                }
            }

            // Emit all tick events to handlers
            for (const evt of tickEvents) {
                emitEvent(evt);
            }

            return tickEvents;
        },

        onTimer(handler: (event: TimerEvent) => void): () => void {
            handlers.add(handler);
            return () => { handlers.delete(handler); };
        },

        clear(): void {
            timers.clear();
            handlers.clear();
            currentTick = 0;
        },
    };
}
