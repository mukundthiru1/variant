/**
 * VARIANT — Timer Clock tests
 */
import { describe, it, expect } from 'vitest';
import { createTimerClock } from '../../../src/lib/timer/timer-clock';
import type { TimerDefinition, TimerEvent } from '../../../src/lib/timer/types';

function makeTimer(overrides: Partial<TimerDefinition> & { id: string }): TimerDefinition {
    return {
        label: overrides.id,
        type: 'countdown',
        durationTicks: 100,
        intervalTicks: 0,
        autoStart: false,
        visible: true,
        onExpiry: null,
        warnings: [],
        ...overrides,
    };
}

describe('TimerClock', () => {
    it('creates a timer', () => {
        const clock = createTimerClock();
        const timer = clock.create(makeTimer({ id: 'timer-1' }));

        expect(timer.id).toBe('timer-1');
        expect(timer.state).toBe('stopped');
        expect(timer.elapsedTicks).toBe(0);
    });

    it('auto-starts when configured', () => {
        const clock = createTimerClock();
        const timer = clock.create(makeTimer({ id: 'timer-1', autoStart: true }));
        expect(timer.state).toBe('running');
    });

    it('starts and pauses a timer', () => {
        const clock = createTimerClock();
        clock.create(makeTimer({ id: 'timer-1' }));

        expect(clock.start('timer-1')).toBe(true);
        expect(clock.get('timer-1')!.state).toBe('running');

        expect(clock.pause('timer-1')).toBe(true);
        expect(clock.get('timer-1')!.state).toBe('paused');
    });

    it('resumes a paused timer', () => {
        const clock = createTimerClock();
        clock.create(makeTimer({ id: 'timer-1' }));
        clock.start('timer-1');
        clock.pause('timer-1');

        expect(clock.resume('timer-1')).toBe(true);
        expect(clock.get('timer-1')!.state).toBe('running');
    });

    it('stops and resets a timer', () => {
        const clock = createTimerClock();
        clock.create(makeTimer({ id: 'timer-1', autoStart: true }));
        clock.tick(); // 1 tick elapsed

        clock.stop('timer-1');
        expect(clock.get('timer-1')!.state).toBe('stopped');
        expect(clock.get('timer-1')!.elapsedTicks).toBe(0);
    });

    it('removes a timer', () => {
        const clock = createTimerClock();
        clock.create(makeTimer({ id: 'timer-1' }));
        expect(clock.remove('timer-1')).toBe(true);
        expect(clock.get('timer-1')).toBeNull();
    });

    it('countdown expires after duration', () => {
        const clock = createTimerClock();
        clock.create(makeTimer({ id: 'timer-1', type: 'countdown', durationTicks: 3, autoStart: true }));

        clock.tick(); // 1
        clock.tick(); // 2
        const events = clock.tick(); // 3 — should expire

        expect(events.length).toBe(1);
        expect(events[0]!.kind).toBe('expired');
        expect(events[0]!.timerId).toBe('timer-1');
        expect(clock.get('timer-1')!.state).toBe('expired');
    });

    it('countdown reports remaining ticks', () => {
        const clock = createTimerClock();
        clock.create(makeTimer({ id: 'timer-1', type: 'countdown', durationTicks: 10, autoStart: true }));

        clock.tick();
        clock.tick();
        clock.tick();

        const timer = clock.get('timer-1')!;
        expect(timer.remainingTicks).toBe(7);
        expect(timer.elapsedTicks).toBe(3);
    });

    it('countdown fires warning events', () => {
        const clock = createTimerClock();
        clock.create(makeTimer({ id: 'timer-1', type: 'countdown', durationTicks: 5, autoStart: true, warnings: [2] }));

        clock.tick(); // remaining: 4
        clock.tick(); // remaining: 3
        const events = clock.tick(); // remaining: 2 — warning

        expect(events.some(e => e.kind === 'warning')).toBe(true);
    });

    it('oneshot fires once after delay', () => {
        const clock = createTimerClock();
        clock.create(makeTimer({ id: 'timer-1', type: 'oneshot', durationTicks: 2, autoStart: true }));

        const e1 = clock.tick(); // 1
        expect(e1.length).toBe(0);

        const e2 = clock.tick(); // 2 — should fire
        expect(e2.length).toBe(1);
        expect(e2[0]!.kind).toBe('fired');
    });

    it('interval fires repeatedly', () => {
        const clock = createTimerClock();
        clock.create(makeTimer({ id: 'timer-1', type: 'interval', intervalTicks: 3, autoStart: true }));

        const results: TimerEvent[][] = [];
        for (let i = 0; i < 9; i++) {
            results.push([...clock.tick()]);
        }

        // Should fire at ticks 3, 6, 9
        const fireEvents = results.filter(r => r.some(e => e.kind === 'fired'));
        expect(fireEvents.length).toBe(3);
    });

    it('stopwatch just counts up', () => {
        const clock = createTimerClock();
        clock.create(makeTimer({ id: 'timer-1', type: 'stopwatch', autoStart: true }));

        for (let i = 0; i < 10; i++) {
            clock.tick();
        }

        expect(clock.get('timer-1')!.elapsedTicks).toBe(10);
    });

    it('paused timers do not advance', () => {
        const clock = createTimerClock();
        clock.create(makeTimer({ id: 'timer-1', type: 'stopwatch', autoStart: true }));

        clock.tick();
        clock.tick();
        clock.pause('timer-1');
        clock.tick();
        clock.tick();

        expect(clock.get('timer-1')!.elapsedTicks).toBe(2);
    });

    it('getAll returns all timers', () => {
        const clock = createTimerClock();
        clock.create(makeTimer({ id: 'timer-1' }));
        clock.create(makeTimer({ id: 'timer-2' }));
        clock.create(makeTimer({ id: 'timer-3' }));

        expect(clock.getAll().length).toBe(3);
    });

    it('getVisible filters non-visible timers', () => {
        const clock = createTimerClock();
        clock.create(makeTimer({ id: 'timer-1', visible: true }));
        clock.create(makeTimer({ id: 'timer-2', visible: false }));

        expect(clock.getVisible().length).toBe(1);
    });

    it('fires timer events to handlers', () => {
        const clock = createTimerClock();
        const events: TimerEvent[] = [];
        clock.onTimer(e => events.push(e));

        clock.create(makeTimer({ id: 'timer-1', type: 'countdown', durationTicks: 2, autoStart: true }));
        // autoStart emits 'started' event
        expect(events.some(e => e.kind === 'started')).toBe(true);

        clock.tick(); // 1 elapsed, 1 remaining
        clock.tick(); // 2 elapsed, 0 remaining — expired

        expect(events.some(e => e.kind === 'expired')).toBe(true);
    });

    it('expiry action is passed through', () => {
        const clock = createTimerClock();
        clock.create(makeTimer({
            id: 'timer-1',
            type: 'countdown',
            durationTicks: 1,
            autoStart: true,
            onExpiry: { kind: 'game-over', reason: 'Time ran out!' },
        }));

        const events = clock.tick();
        expect(events[0]!.expiry).toEqual({ kind: 'game-over', reason: 'Time ran out!' });
    });

    it('clears all timers', () => {
        const clock = createTimerClock();
        clock.create(makeTimer({ id: 'timer-1' }));
        clock.create(makeTimer({ id: 'timer-2' }));
        clock.clear();
        expect(clock.getAll().length).toBe(0);
    });

    it('progress is computed correctly', () => {
        const clock = createTimerClock();
        clock.create(makeTimer({ id: 'timer-1', type: 'countdown', durationTicks: 10, autoStart: true }));

        clock.tick(); // 1/10
        clock.tick(); // 2/10
        clock.tick(); // 3/10

        const timer = clock.get('timer-1')!;
        expect(timer.progress).toBeCloseTo(0.3);
    });
});
