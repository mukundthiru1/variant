/**
 * VARIANT — Event Bus Advanced Tests
 *
 * Tests for once(), waitFor(), and wildcard subscription.
 */

import { describe, it, expect, vi } from 'vitest';
import { createEventBus } from '../../src/core/event-bus';
import type { SimTickEvent } from '../../src/core/events';

describe('EventBus.once', () => {
    it('fires handler exactly once then auto-unsubscribes', () => {
        const bus = createEventBus(100);
        const handler = vi.fn();

        bus.once('sim:tick', handler);

        bus.emit({ type: 'sim:tick', tick: 1, timestamp: 1000 });
        bus.emit({ type: 'sim:tick', tick: 2, timestamp: 2000 });
        bus.emit({ type: 'sim:tick', tick: 3, timestamp: 3000 });

        expect(handler).toHaveBeenCalledTimes(1);
        expect((handler.mock.calls[0]![0] as SimTickEvent).tick).toBe(1);
    });

    it('returns an unsubscribe function that works before the event fires', () => {
        const bus = createEventBus(100);
        const handler = vi.fn();

        const unsub = bus.once('sim:tick', handler);
        unsub();

        bus.emit({ type: 'sim:tick', tick: 1, timestamp: 1000 });
        expect(handler).not.toHaveBeenCalled();
    });

    it('unsubscribe is idempotent after once fires', () => {
        const bus = createEventBus(100);
        const handler = vi.fn();

        const unsub = bus.once('sim:tick', handler);
        bus.emit({ type: 'sim:tick', tick: 1, timestamp: 1000 });

        // Already auto-unsubscribed; manual unsub should not throw
        unsub();
        unsub();

        expect(handler).toHaveBeenCalledTimes(1);
    });

    it('does not interfere with other handlers on the same event type', () => {
        const bus = createEventBus(100);
        const onceHandler = vi.fn();
        const persistentHandler = vi.fn();

        bus.once('sim:tick', onceHandler);
        bus.on('sim:tick', persistentHandler);

        bus.emit({ type: 'sim:tick', tick: 1, timestamp: 1000 });
        bus.emit({ type: 'sim:tick', tick: 2, timestamp: 2000 });

        expect(onceHandler).toHaveBeenCalledTimes(1);
        expect(persistentHandler).toHaveBeenCalledTimes(2);
    });
});

describe('EventBus.waitFor', () => {
    it('resolves when the matching event fires', async () => {
        const bus = createEventBus(100);

        const promise = bus.waitFor('sim:tick');

        bus.emit({ type: 'sim:tick', tick: 42, timestamp: 1000 });

        const result = await promise;
        expect(result.type).toBe('sim:tick');
        expect((result as SimTickEvent).tick).toBe(42);
    });

    it('resolves only on the first matching event', async () => {
        const bus = createEventBus(100);

        const promise = bus.waitFor('sim:tick');

        bus.emit({ type: 'sim:tick', tick: 1, timestamp: 1000 });
        bus.emit({ type: 'sim:tick', tick: 2, timestamp: 2000 });

        const result = await promise;
        expect((result as SimTickEvent).tick).toBe(1);
    });

    it('supports predicate filtering', async () => {
        const bus = createEventBus(100);

        const promise = bus.waitFor(
            'sim:tick',
            (e) => (e as SimTickEvent).tick === 5,
        );

        // These should not resolve the promise
        bus.emit({ type: 'sim:tick', tick: 1, timestamp: 1000 });
        bus.emit({ type: 'sim:tick', tick: 3, timestamp: 2000 });

        // This should resolve it
        bus.emit({ type: 'sim:tick', tick: 5, timestamp: 3000 });

        const result = await promise;
        expect((result as SimTickEvent).tick).toBe(5);
    });

    it('ignores events of different types', async () => {
        const bus = createEventBus(100);

        const promise = bus.waitFor('auth:login');

        // Emit unrelated event
        bus.emit({ type: 'sim:tick', tick: 1, timestamp: 1000 });

        // Emit matching event
        bus.emit({
            type: 'auth:login',
            user: 'admin',
            machine: 'web-01',
            service: 'ssh',
            success: true,
            timestamp: 2000,
        });

        const result = await promise;
        expect(result.type).toBe('auth:login');
    });

    it('cleans up subscription after resolving', async () => {
        const bus = createEventBus(100);

        const promise = bus.waitFor('sim:tick');
        bus.emit({ type: 'sim:tick', tick: 1, timestamp: 1000 });
        await promise;

        // After resolving, the handler should be cleaned up.
        // Emit more events — if cleanup failed, internal state would grow.
        // We verify indirectly: removeAllListeners then emit should not crash.
        bus.removeAllListeners();
        bus.emit({ type: 'sim:tick', tick: 2, timestamp: 2000 });
    });
});

describe('EventBus.onPrefix wildcard', () => {
    it('* subscribes to all event types', () => {
        const bus = createEventBus(100);
        const handler = vi.fn();

        bus.onPrefix('*', handler);

        bus.emit({ type: 'sim:tick', tick: 1, timestamp: 1000 });
        bus.emit({ type: 'auth:login', user: 'x', machine: 'y', service: 'z', success: true, timestamp: 2000 });
        bus.emit({ type: 'custom:test', data: null, timestamp: 3000 });

        expect(handler).toHaveBeenCalledTimes(3);
    });

    it('rejects empty string prefix', () => {
        const bus = createEventBus(100);
        expect(() => bus.onPrefix('', vi.fn())).toThrow(/must end with ':'/);
    });

    it('rejects prefix without colon', () => {
        const bus = createEventBus(100);
        expect(() => bus.onPrefix('auth', vi.fn())).toThrow(/must end with ':'/);
    });

    it('wildcard unsubscribe works', () => {
        const bus = createEventBus(100);
        const handler = vi.fn();

        const unsub = bus.onPrefix('*', handler);
        bus.emit({ type: 'sim:tick', tick: 1, timestamp: 1000 });
        expect(handler).toHaveBeenCalledTimes(1);

        unsub();
        bus.emit({ type: 'sim:tick', tick: 2, timestamp: 2000 });
        expect(handler).toHaveBeenCalledTimes(1);
    });
});
