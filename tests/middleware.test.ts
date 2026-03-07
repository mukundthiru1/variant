import { describe, it, expect, vi } from 'vitest';
import { createEventBus } from '../src/core/event-bus';
import {
    createMiddlewareStack,
    createMiddlewareEventBus,
    createRateLimitMiddleware,
    createLoggingMiddleware,
    createMetricsMiddleware,
    createReplayMiddleware,
} from '../src/core/middleware';
import type { EngineEvent } from '../src/core/events';

// ── MiddlewareStack ──────────────────────────────────────────

describe('MiddlewareStack', () => {
    it('executes final handler when no middleware', () => {
        const stack = createMiddlewareStack();
        let called = false;
        const event: EngineEvent = { type: 'sim:tick', tick: 1, timestamp: Date.now() };

        stack.execute(event, () => { called = true; });
        expect(called).toBe(true);
    });

    it('passes events through middleware chain', () => {
        const stack = createMiddlewareStack();
        const order: string[] = [];

        stack.add({
            id: 'first',
            description: 'First',
            priority: 1,
            handler(event, next) {
                order.push('first');
                next(event);
            },
        });

        stack.add({
            id: 'second',
            description: 'Second',
            priority: 2,
            handler(event, next) {
                order.push('second');
                next(event);
            },
        });

        const event: EngineEvent = { type: 'sim:tick', tick: 1, timestamp: Date.now() };
        stack.execute(event, () => { order.push('final'); });

        expect(order).toEqual(['first', 'second', 'final']);
    });

    it('allows middleware to suppress events', () => {
        const stack = createMiddlewareStack();
        let finalCalled = false;

        stack.add({
            id: 'blocker',
            description: 'Blocks all',
            handler(_event, _next) {
                // Don't call next — suppress the event
            },
        });

        const event: EngineEvent = { type: 'sim:tick', tick: 1, timestamp: Date.now() };
        stack.execute(event, () => { finalCalled = true; });

        expect(finalCalled).toBe(false);
    });

    it('allows middleware to transform events', () => {
        const stack = createMiddlewareStack();

        stack.add({
            id: 'transformer',
            description: 'Changes tick',
            handler(event, next) {
                if (event.type === 'sim:tick') {
                    next({ ...event, tick: 999 } as EngineEvent);
                } else {
                    next(event);
                }
            },
        });

        let receivedTick = 0;
        const event: EngineEvent = { type: 'sim:tick', tick: 1, timestamp: Date.now() };
        stack.execute(event, (e) => {
            if (e.type === 'sim:tick') receivedTick = e.tick;
        });

        expect(receivedTick).toBe(999);
    });

    it('removes middleware by ID', () => {
        const stack = createMiddlewareStack();
        let called = false;

        stack.add({
            id: 'removable',
            description: 'Will be removed',
            handler(event, next) {
                called = true;
                next(event);
            },
        });

        stack.remove('removable');

        const event: EngineEvent = { type: 'sim:tick', tick: 1, timestamp: Date.now() };
        stack.execute(event, () => {});

        expect(called).toBe(false);
    });

    it('unsubscribe function removes middleware', () => {
        const stack = createMiddlewareStack();
        let called = false;

        const unsub = stack.add({
            id: 'unsub-test',
            description: 'Test',
            handler(event, next) {
                called = true;
                next(event);
            },
        });

        unsub();

        const event: EngineEvent = { type: 'sim:tick', tick: 1, timestamp: Date.now() };
        stack.execute(event, () => {});

        expect(called).toBe(false);
    });

    it('respects priority ordering', () => {
        const stack = createMiddlewareStack();
        const order: number[] = [];

        stack.add({
            id: 'high-priority',
            description: 'High',
            priority: 200,
            handler(event, next) { order.push(200); next(event); },
        });

        stack.add({
            id: 'low-priority',
            description: 'Low',
            priority: 10,
            handler(event, next) { order.push(10); next(event); },
        });

        const event: EngineEvent = { type: 'sim:tick', tick: 1, timestamp: Date.now() };
        stack.execute(event, () => {});

        expect(order).toEqual([10, 200]);
    });

    it('handles middleware errors gracefully', () => {
        const stack = createMiddlewareStack();
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        let finalCalled = false;

        stack.add({
            id: 'broken',
            description: 'Throws',
            handler() {
                throw new Error('middleware crash');
            },
        });

        const event: EngineEvent = { type: 'sim:tick', tick: 1, timestamp: Date.now() };
        stack.execute(event, () => { finalCalled = true; });

        // Should continue despite error
        expect(finalCalled).toBe(true);
        consoleSpy.mockRestore();
    });

    it('enables/disables middleware', () => {
        const stack = createMiddlewareStack();
        let count = 0;

        stack.add({
            id: 'toggle',
            description: 'Toggleable',
            handler(event, next) { count++; next(event); },
        });

        const event: EngineEvent = { type: 'sim:tick', tick: 1, timestamp: Date.now() };

        stack.execute(event, () => {});
        expect(count).toBe(1);

        stack.setActive('toggle', false);
        stack.execute(event, () => {});
        expect(count).toBe(1); // Should not have incremented

        stack.setActive('toggle', true);
        stack.execute(event, () => {});
        expect(count).toBe(2);
    });

    it('throws on duplicate middleware ID', () => {
        const stack = createMiddlewareStack();
        stack.add({ id: 'dup', description: 'First', handler(e, n) { n(e); } });
        expect(() => stack.add({ id: 'dup', description: 'Second', handler(e, n) { n(e); } }))
            .toThrow("Middleware 'dup' already registered");
    });
});

// ── Middleware-wrapped Event Bus ─────────────────────────────

describe('Middleware Event Bus', () => {
    it('wraps an event bus with middleware', () => {
        const inner = createEventBus();
        const bus = createMiddlewareEventBus(inner);

        let received = false;
        bus.on('sim:tick', () => { received = true; });
        bus.emit({ type: 'sim:tick', tick: 1, timestamp: Date.now() });

        expect(received).toBe(true);
    });

    it('middleware can filter events', () => {
        const inner = createEventBus();
        const bus = createMiddlewareEventBus(inner);

        bus.middleware.add({
            id: 'filter-ticks',
            description: 'Block tick events',
            handler(event, next) {
                if (event.type !== 'sim:tick') next(event);
            },
        });

        let tickReceived = false;
        let alertReceived = false;
        bus.on('sim:tick', () => { tickReceived = true; });
        bus.on('sim:alert', () => { alertReceived = true; });

        bus.emit({ type: 'sim:tick', tick: 1, timestamp: Date.now() });
        bus.emit({ type: 'sim:alert', source: 'test', message: 'hi', timestamp: Date.now() });

        expect(tickReceived).toBe(false);
        expect(alertReceived).toBe(true);
    });
});

// ── Built-in Middleware Factories ────────────────────────────

describe('Rate Limit Middleware', () => {
    it('suppresses events exceeding rate', () => {
        const inner = createEventBus();
        const bus = createMiddlewareEventBus(inner);

        bus.middleware.add(createRateLimitMiddleware({
            eventPattern: 'sim:tick',
            maxPerWindow: 2,
            windowMs: 1000,
        }));

        let count = 0;
        bus.on('sim:tick', () => { count++; });

        for (let i = 0; i < 5; i++) {
            bus.emit({ type: 'sim:tick', tick: i, timestamp: Date.now() });
        }

        expect(count).toBe(2);
    });

    it('does not affect non-matching events', () => {
        const inner = createEventBus();
        const bus = createMiddlewareEventBus(inner);

        bus.middleware.add(createRateLimitMiddleware({
            eventPattern: 'sim:tick',
            maxPerWindow: 1,
            windowMs: 1000,
        }));

        let count = 0;
        bus.on('sim:alert', () => { count++; });

        for (let i = 0; i < 5; i++) {
            bus.emit({ type: 'sim:alert', source: 'test', message: 'hi', timestamp: Date.now() });
        }

        expect(count).toBe(5);
    });
});

describe('Logging Middleware', () => {
    it('logs matching events', () => {
        const logged: EngineEvent[] = [];
        const mw = createLoggingMiddleware({
            prefix: 'auth:',
            logger: (event) => { logged.push(event); },
        });

        const stack = createMiddlewareStack();
        stack.add(mw);

        stack.execute(
            { type: 'auth:login', user: 'test', machine: 'm1', service: 'ssh', success: true, timestamp: Date.now() },
            () => {},
        );
        stack.execute(
            { type: 'sim:tick', tick: 1, timestamp: Date.now() },
            () => {},
        );

        expect(logged.length).toBe(1);
        expect(logged[0]!.type).toBe('auth:login');
    });
});

describe('Metrics Middleware', () => {
    it('counts events by type', () => {
        const metrics = createMetricsMiddleware();
        const stack = createMiddlewareStack();
        stack.add(metrics);

        stack.execute({ type: 'sim:tick', tick: 1, timestamp: Date.now() }, () => {});
        stack.execute({ type: 'sim:tick', tick: 2, timestamp: Date.now() }, () => {});
        stack.execute({ type: 'sim:alert', source: 'x', message: 'y', timestamp: Date.now() }, () => {});

        const counts = metrics.getMetrics();
        expect(counts['sim:tick']).toBe(2);
        expect(counts['sim:alert']).toBe(1);
    });
});

describe('Replay Middleware', () => {
    it('records and replays events', () => {
        const replay = createReplayMiddleware({ maxEvents: 100 });
        const stack = createMiddlewareStack();
        stack.add(replay);

        const events: EngineEvent[] = [
            { type: 'sim:tick', tick: 1, timestamp: 1000 },
            { type: 'sim:tick', tick: 2, timestamp: 2000 },
            { type: 'sim:alert', source: 'test', message: 'hi', timestamp: 3000 },
        ];

        for (const e of events) {
            stack.execute(e, () => {});
        }

        expect(replay.getRecording().length).toBe(3);

        // Replay into a new bus
        const replayBus = createEventBus();
        let replayCount = 0;
        replayBus.onPrefix('*', () => { replayCount++; });

        replay.replay(replayBus);
        expect(replayCount).toBe(3);
    });

    it('clears recording', () => {
        const replay = createReplayMiddleware();
        const stack = createMiddlewareStack();
        stack.add(replay);

        stack.execute({ type: 'sim:tick', tick: 1, timestamp: Date.now() }, () => {});
        expect(replay.getRecording().length).toBe(1);

        replay.clear();
        expect(replay.getRecording().length).toBe(0);
    });

    it('respects maxEvents limit', () => {
        const replay = createReplayMiddleware({ maxEvents: 3 });
        const stack = createMiddlewareStack();
        stack.add(replay);

        for (let i = 0; i < 10; i++) {
            stack.execute({ type: 'sim:tick', tick: i, timestamp: Date.now() }, () => {});
        }

        expect(replay.getRecording().length).toBe(3);
    });
});
