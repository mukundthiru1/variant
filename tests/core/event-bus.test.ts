/**
 * VARIANT — Event Bus Tests
 *
 * Tests the event bus for correctness, security, and edge cases.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createEventBus } from '../../src/core/event-bus';
import type { EngineEvent, AuthLoginEvent, SimTickEvent } from '../../src/core/events';

describe('EventBus', () => {
    let bus: ReturnType<typeof createEventBus>;

    beforeEach(() => {
        bus = createEventBus(100);
    });

    // ── Basic emission and subscription ──────────────────────────

    it('delivers events to exact-type subscribers', () => {
        const handler = vi.fn();
        bus.on('auth:login', handler);

        const event: AuthLoginEvent = {
            type: 'auth:login',
            user: 'admin',
            machine: 'web-01',
            service: 'ssh',
            success: true,
            timestamp: Date.now(),
        };

        bus.emit(event);

        expect(handler).toHaveBeenCalledTimes(1);
        expect(handler).toHaveBeenCalledWith(event);
    });

    it('does not deliver events to unrelated subscribers', () => {
        const handler = vi.fn();
        bus.on('auth:login', handler);

        bus.emit({
            type: 'sim:tick',
            tick: 1,
            timestamp: Date.now(),
        });

        expect(handler).not.toHaveBeenCalled();
    });

    it('delivers events to prefix subscribers', () => {
        const handler = vi.fn();
        bus.onPrefix('auth:', handler);

        bus.emit({
            type: 'auth:login',
            user: 'admin',
            machine: 'web-01',
            service: 'ssh',
            success: true,
            timestamp: Date.now(),
        });

        bus.emit({
            type: 'auth:escalate',
            machine: 'web-01',
            from: 'www-data',
            to: 'root',
            method: 'sudo',
            timestamp: Date.now(),
        });

        expect(handler).toHaveBeenCalledTimes(2);
    });

    it('delivers events to wildcard subscribers', () => {
        const handler = vi.fn();
        bus.onPrefix('*', handler);

        bus.emit({ type: 'sim:tick', tick: 1, timestamp: Date.now() });
        bus.emit({ type: 'auth:login', user: 'x', machine: 'y', service: 'z', success: true, timestamp: Date.now() });

        expect(handler).toHaveBeenCalledTimes(2);
    });

    // ── Unsubscribe ──────────────────────────────────────────────

    it('stops delivering after unsubscribe', () => {
        const handler = vi.fn();
        const unsub = bus.on('sim:tick', handler);

        bus.emit({ type: 'sim:tick', tick: 1, timestamp: Date.now() });
        expect(handler).toHaveBeenCalledTimes(1);

        unsub();

        bus.emit({ type: 'sim:tick', tick: 2, timestamp: Date.now() });
        expect(handler).toHaveBeenCalledTimes(1); // still 1
    });

    it('unsubscribe is idempotent', () => {
        const handler = vi.fn();
        const unsub = bus.on('sim:tick', handler);

        unsub();
        unsub(); // should not throw
        unsub();

        bus.emit({ type: 'sim:tick', tick: 1, timestamp: Date.now() });
        expect(handler).not.toHaveBeenCalled();
    });

    // ── Event log ────────────────────────────────────────────────

    it('logs emitted events', () => {
        bus.emit({ type: 'sim:tick', tick: 1, timestamp: 1000 });
        bus.emit({ type: 'sim:tick', tick: 2, timestamp: 2000 });

        const log = bus.getLog();
        expect(log).toHaveLength(2);
    });

    it('filters log by prefix', () => {
        bus.emit({ type: 'sim:tick', tick: 1, timestamp: 1000 });
        bus.emit({ type: 'auth:login', user: 'x', machine: 'y', service: 'z', success: true, timestamp: 2000 });
        bus.emit({ type: 'sim:tick', tick: 2, timestamp: 3000 });

        const simLog = bus.getLog('sim:');
        expect(simLog).toHaveLength(2);

        const authLog = bus.getLog('auth:');
        expect(authLog).toHaveLength(1);
    });

    it('evicts oldest entries when log is full', () => {
        const smallBus = createEventBus(3);

        smallBus.emit({ type: 'sim:tick', tick: 1, timestamp: 1000 });
        smallBus.emit({ type: 'sim:tick', tick: 2, timestamp: 2000 });
        smallBus.emit({ type: 'sim:tick', tick: 3, timestamp: 3000 });
        smallBus.emit({ type: 'sim:tick', tick: 4, timestamp: 4000 });

        const log = smallBus.getLog();
        expect(log).toHaveLength(3);
        // The oldest (tick=1) should have been evicted
        expect(log.some(e => e.type === 'sim:tick' && (e as SimTickEvent).tick === 1)).toBe(false);
    });

    it('clears the log', () => {
        bus.emit({ type: 'sim:tick', tick: 1, timestamp: 1000 });
        bus.emit({ type: 'sim:tick', tick: 2, timestamp: 2000 });

        bus.clearLog();
        expect(bus.getLog()).toHaveLength(0);
    });

    // ── Error handling ───────────────────────────────────────────

    it('does not crash if a handler throws', () => {
        const badHandler = vi.fn(() => { throw new Error('handler exploded'); });
        const goodHandler = vi.fn();

        bus.on('sim:tick', badHandler);
        bus.on('sim:tick', goodHandler);

        // Should not throw
        bus.emit({ type: 'sim:tick', tick: 1, timestamp: Date.now() });

        expect(badHandler).toHaveBeenCalledTimes(1);
        expect(goodHandler).toHaveBeenCalledTimes(1);
    });

    // ── Security ─────────────────────────────────────────────────

    it('freezes emitted events to prevent mutation', () => {
        let capturedEvent: EngineEvent | undefined;
        bus.on('sim:tick', (event) => { capturedEvent = event; });

        bus.emit({ type: 'sim:tick', tick: 1, timestamp: Date.now() });

        expect(capturedEvent).toBeDefined();
        expect(() => {
            // @ts-expect-error — testing runtime freeze
            capturedEvent.tick = 999;
        }).toThrow();
    });

    it('rejects prefix without colon suffix', () => {
        expect(() => {
            bus.onPrefix('auth', vi.fn());
        }).toThrow(/must end with ':'/);
    });

    // ── removeAllListeners ───────────────────────────────────────

    it('removes all listeners', () => {
        const handler1 = vi.fn();
        const handler2 = vi.fn();

        bus.on('sim:tick', handler1);
        bus.onPrefix('auth:', handler2);

        bus.removeAllListeners();

        bus.emit({ type: 'sim:tick', tick: 1, timestamp: Date.now() });
        bus.emit({ type: 'auth:login', user: 'x', machine: 'y', service: 'z', success: true, timestamp: Date.now() });

        expect(handler1).not.toHaveBeenCalled();
        expect(handler2).not.toHaveBeenCalled();
    });
});
