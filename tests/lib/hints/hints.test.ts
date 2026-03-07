/**
 * VARIANT — Hint Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createHintEngine } from '../../../src/lib/hints/hint-engine';
import type { HintDefinition } from '../../../src/lib/hints/types';

function makeHint(overrides: Partial<HintDefinition> & { id: string }): HintDefinition {
    return {
        objectiveId: null,
        tier: 'nudge',
        penalty: 50,
        content: {
            title: `Hint ${overrides.id}`,
            text: `This is hint ${overrides.id}`,
            category: 'general',
        },
        trigger: null,
        cooldownTicks: 0,
        order: 0,
        ...overrides,
    };
}

describe('HintEngine', () => {
    it('loads hints and makes them available', () => {
        const engine = createHintEngine();
        engine.loadHints([
            makeHint({ id: 'hint-1' }),
            makeHint({ id: 'hint-2' }),
        ]);

        const available = engine.getAvailableHints();
        expect(available.length).toBe(2);
    });

    it('returns hints for specific objectives', () => {
        const engine = createHintEngine();
        engine.loadHints([
            makeHint({ id: 'hint-1', objectiveId: 'obj-1' }),
            makeHint({ id: 'hint-2', objectiveId: 'obj-2' }),
            makeHint({ id: 'hint-3', objectiveId: null }),
        ]);

        const obj1Hints = engine.getHintsForObjective('obj-1');
        expect(obj1Hints.length).toBe(1);
        expect(obj1Hints[0]!.id).toBe('hint-1');

        const generalHints = engine.getHintsForObjective(null);
        expect(generalHints.length).toBe(1);
    });

    it('uses a hint and applies penalty', () => {
        const engine = createHintEngine();
        engine.loadHints([makeHint({ id: 'hint-1', penalty: 75 })]);

        const content = engine.useHint('hint-1', 10);
        expect(content).not.toBeNull();
        expect(content!.title).toBe('Hint hint-1');
        expect(engine.getTotalPenalty()).toBe(75);
    });

    it('tracks hint state', () => {
        const engine = createHintEngine();
        engine.loadHints([makeHint({ id: 'hint-1' })]);

        let state = engine.getHintState('hint-1');
        expect(state!.available).toBe(true);
        expect(state!.used).toBe(false);
        expect(state!.useCount).toBe(0);

        engine.useHint('hint-1', 5);
        state = engine.getHintState('hint-1');
        expect(state!.used).toBe(true);
        expect(state!.useCount).toBe(1);
        expect(state!.lastUsedTick).toBe(5);
    });

    it('respects cooldown', () => {
        const engine = createHintEngine();
        engine.loadHints([makeHint({ id: 'hint-1', cooldownTicks: 10 })]);

        engine.useHint('hint-1', 5);
        // Too soon — should return null
        const blocked = engine.useHint('hint-1', 10);
        expect(blocked).toBeNull();

        // After cooldown — should work
        const allowed = engine.useHint('hint-1', 16);
        expect(allowed).not.toBeNull();
    });

    it('evaluates tick-based triggers', () => {
        const engine = createHintEngine();
        engine.loadHints([makeHint({
            id: 'hint-1',
            trigger: { kind: 'after-ticks', ticks: 30 },
        })]);

        expect(engine.getAvailableHints().length).toBe(0);

        engine.evaluateTriggers(20, 0, new Set());
        expect(engine.getAvailableHints().length).toBe(0);

        engine.evaluateTriggers(30, 0, new Set());
        expect(engine.getAvailableHints().length).toBe(1);
    });

    it('evaluates attempt-based triggers', () => {
        const engine = createHintEngine();
        engine.loadHints([makeHint({
            id: 'hint-1',
            trigger: { kind: 'after-attempts', attempts: 5 },
        })]);

        engine.evaluateTriggers(10, 3, new Set());
        expect(engine.getAvailableHints().length).toBe(0);

        engine.evaluateTriggers(10, 5, new Set());
        expect(engine.getAvailableHints().length).toBe(1);
    });

    it('evaluates objective-based triggers', () => {
        const engine = createHintEngine();
        engine.loadHints([makeHint({
            id: 'hint-2',
            trigger: { kind: 'after-objective', objectiveId: 'obj-1' },
        })]);

        engine.evaluateTriggers(10, 0, new Set());
        expect(engine.getAvailableHints().length).toBe(0);

        engine.evaluateTriggers(10, 0, new Set(['obj-1']));
        expect(engine.getAvailableHints().length).toBe(1);
    });

    it('evaluates event-based triggers', () => {
        const engine = createHintEngine();
        engine.loadHints([makeHint({
            id: 'hint-1',
            trigger: { kind: 'after-event', eventType: 'auth:login' },
        })]);

        engine.evaluateTriggers(10, 0, new Set());
        expect(engine.getAvailableHints().length).toBe(0);

        engine.notifyEvent('auth:login', { user: 'admin' });
        engine.evaluateTriggers(10, 0, new Set());
        expect(engine.getAvailableHints().length).toBe(1);
    });

    it('evaluates compound triggers', () => {
        const engine = createHintEngine();
        engine.loadHints([makeHint({
            id: 'hint-1',
            trigger: {
                kind: 'compound',
                conditions: [
                    { kind: 'after-ticks', ticks: 10 },
                    { kind: 'after-attempts', attempts: 3 },
                ],
            },
        })]);

        engine.evaluateTriggers(10, 2, new Set());
        expect(engine.getAvailableHints().length).toBe(0); // Only ticks met

        engine.evaluateTriggers(10, 3, new Set());
        expect(engine.getAvailableHints().length).toBe(1); // Both met
    });

    it('accumulates penalty across multiple hints', () => {
        const engine = createHintEngine();
        engine.loadHints([
            makeHint({ id: 'hint-1', penalty: 50 }),
            makeHint({ id: 'hint-2', penalty: 100 }),
        ]);

        engine.useHint('hint-1', 1);
        engine.useHint('hint-2', 2);
        expect(engine.getTotalPenalty()).toBe(150);
    });

    it('resets all state', () => {
        const engine = createHintEngine();
        engine.loadHints([makeHint({ id: 'hint-1', penalty: 50 })]);
        engine.useHint('hint-1', 1);

        engine.reset();
        expect(engine.getAvailableHints().length).toBe(0);
        expect(engine.getTotalPenalty()).toBe(0);
    });

    it('returns null for unknown hint', () => {
        const engine = createHintEngine();
        expect(engine.useHint('nonexistent', 1)).toBeNull();
        expect(engine.getHintState('nonexistent')).toBeNull();
    });

    it('orders hints by order field', () => {
        const engine = createHintEngine();
        engine.loadHints([
            makeHint({ id: 'hint-c', order: 3 }),
            makeHint({ id: 'hint-a', order: 1 }),
            makeHint({ id: 'hint-b', order: 2 }),
        ]);

        const available = engine.getAvailableHints();
        expect(available[0]!.id).toBe('hint-a');
        expect(available[1]!.id).toBe('hint-b');
        expect(available[2]!.id).toBe('hint-c');
    });
});
