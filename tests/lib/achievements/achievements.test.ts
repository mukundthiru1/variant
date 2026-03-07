/**
 * VARIANT — Achievement Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createAchievementEngine } from '../../../src/lib/achievements/achievement-engine';
import type { AchievementDefinition, SessionResult } from '../../../src/lib/achievements/types';

function makeDef(overrides: Partial<AchievementDefinition> & { id: string }): AchievementDefinition {
    return {
        name: overrides.id,
        description: `Achievement ${overrides.id}`,
        flavor: 'Well done.',
        icon: 'star',
        category: 'offense',
        tier: 'bronze',
        hidden: false,
        points: 100,
        condition: { kind: 'complete-level', levelId: null, minDifficulty: null },
        prerequisites: [],
        ...overrides,
    };
}

function makeSession(overrides?: Partial<SessionResult>): SessionResult {
    return {
        levelId: 'level-01',
        difficulty: 'medium',
        score: 800,
        maxScore: 1000,
        durationSeconds: 300,
        hintsUsed: 0,
        noiseLevel: 25,
        techniquesUsed: ['sqli'],
        objectivesCompleted: ['obj-1'],
        phase: 'completed',
        ...overrides,
    };
}

describe('AchievementEngine', () => {
    it('loads definitions', () => {
        const engine = createAchievementEngine();
        engine.loadDefinitions([makeDef({ id: 'ach-1' }), makeDef({ id: 'ach-2' })]);
        expect(engine.getDefinitions().length).toBe(2);
    });

    it('gets definitions by category', () => {
        const engine = createAchievementEngine();
        engine.loadDefinitions([
            makeDef({ id: 'ach-1', category: 'offense' }),
            makeDef({ id: 'ach-2', category: 'defense' }),
            makeDef({ id: 'ach-3', category: 'offense' }),
        ]);

        expect(engine.getByCategory('offense').length).toBe(2);
        expect(engine.getByCategory('defense').length).toBe(1);
    });

    it('evaluates complete-level condition', () => {
        const engine = createAchievementEngine();
        engine.loadDefinitions([makeDef({
            id: 'first-win',
            condition: { kind: 'complete-level', levelId: null, minDifficulty: null },
        })]);

        const unlocked = engine.evaluateSession(makeSession());
        expect(unlocked).toContain('first-win');
    });

    it('does not unlock on failure', () => {
        const engine = createAchievementEngine();
        engine.loadDefinitions([makeDef({
            id: 'first-win',
            condition: { kind: 'complete-level', levelId: null, minDifficulty: null },
        })]);

        const unlocked = engine.evaluateSession(makeSession({ phase: 'failed' }));
        expect(unlocked).not.toContain('first-win');
    });

    it('evaluates score condition', () => {
        const engine = createAchievementEngine();
        engine.loadDefinitions([makeDef({
            id: 'high-score',
            condition: { kind: 'score', minScore: 900, levelId: null },
        })]);

        const below = engine.evaluateSession(makeSession({ score: 800 }));
        expect(below).not.toContain('high-score');

        const above = engine.evaluateSession(makeSession({ score: 950 }));
        expect(above).toContain('high-score');
    });

    it('evaluates stealth condition', () => {
        const engine = createAchievementEngine();
        engine.loadDefinitions([makeDef({
            id: 'ghost',
            condition: { kind: 'stealth', maxNoise: 10, levelId: null },
        })]);

        const noisy = engine.evaluateSession(makeSession({ noiseLevel: 50 }));
        expect(noisy).not.toContain('ghost');

        const quiet = engine.evaluateSession(makeSession({ noiseLevel: 5 }));
        expect(quiet).toContain('ghost');
    });

    it('evaluates speed condition', () => {
        const engine = createAchievementEngine();
        engine.loadDefinitions([makeDef({
            id: 'speedrun',
            condition: { kind: 'speed', maxSeconds: 120, levelId: null },
        })]);

        const slow = engine.evaluateSession(makeSession({ durationSeconds: 300 }));
        expect(slow).not.toContain('speedrun');

        const fast = engine.evaluateSession(makeSession({ durationSeconds: 60 }));
        expect(fast).toContain('speedrun');
    });

    it('evaluates compound AND condition', () => {
        const engine = createAchievementEngine();
        engine.loadDefinitions([makeDef({
            id: 'perfect',
            condition: {
                kind: 'compound',
                op: 'and',
                conditions: [
                    { kind: 'complete-level', levelId: null, minDifficulty: null },
                    { kind: 'stealth', maxNoise: 15, levelId: null },
                ],
            },
        })]);

        const loud = engine.evaluateSession(makeSession({ noiseLevel: 50 }));
        expect(loud).not.toContain('perfect');

        const quiet = engine.evaluateSession(makeSession({ noiseLevel: 10 }));
        expect(quiet).toContain('perfect');
    });

    it('respects prerequisites', () => {
        const engine = createAchievementEngine();
        engine.loadDefinitions([
            makeDef({ id: 'basic' }),
            makeDef({
                id: 'advanced',
                prerequisites: ['basic'],
                condition: { kind: 'score', minScore: 900, levelId: null },
            }),
        ]);

        // First session (score 800) — unlocks basic but not advanced (score too low)
        const firstUnlocked = engine.evaluateSession(makeSession({ score: 800 }));
        expect(firstUnlocked).toContain('basic');
        expect(firstUnlocked).not.toContain('advanced');
        expect(engine.getProgress('basic')!.unlocked).toBe(true);

        // Second session (score 950) — now advanced should unlock (prereq met + score met)
        const secondUnlocked = engine.evaluateSession(makeSession({ score: 950 }));
        expect(secondUnlocked).toContain('advanced');
    });

    it('tracks total points', () => {
        const engine = createAchievementEngine();
        engine.loadDefinitions([
            makeDef({ id: 'ach-1', points: 100 }),
            makeDef({ id: 'ach-2', points: 250 }),
        ]);

        engine.evaluateSession(makeSession());
        expect(engine.getTotalPoints()).toBe(350);
    });

    it('manual unlock works', () => {
        const engine = createAchievementEngine();
        engine.loadDefinitions([makeDef({ id: 'special', points: 500 })]);

        expect(engine.unlock('special')).toBe(true);
        expect(engine.getProgress('special')!.unlocked).toBe(true);
        expect(engine.getTotalPoints()).toBe(500);
    });

    it('does not unlock same achievement twice', () => {
        const engine = createAchievementEngine();
        engine.loadDefinitions([makeDef({ id: 'ach-1', points: 100 })]);

        engine.evaluateSession(makeSession());
        engine.evaluateSession(makeSession());
        expect(engine.getTotalPoints()).toBe(100);
    });

    it('reports all progress', () => {
        const engine = createAchievementEngine();
        engine.loadDefinitions([makeDef({ id: 'ach-1' }), makeDef({ id: 'ach-2' })]);

        const all = engine.getAllProgress();
        expect(all.length).toBe(2);
    });

    it('reports unlocked achievements', () => {
        const engine = createAchievementEngine();
        engine.loadDefinitions([makeDef({ id: 'ach-1' }), makeDef({ id: 'ach-2' })]);
        engine.evaluateSession(makeSession());

        const unlocked = engine.getUnlocked();
        expect(unlocked.length).toBe(2);
    });

    it('resets progress', () => {
        const engine = createAchievementEngine();
        engine.loadDefinitions([makeDef({ id: 'ach-1', points: 100 })]);
        engine.evaluateSession(makeSession());

        engine.reset();
        expect(engine.getTotalPoints()).toBe(0);
        expect(engine.getUnlocked().length).toBe(0);
    });

    it('evaluates difficulty minimum', () => {
        const engine = createAchievementEngine();
        engine.loadDefinitions([makeDef({
            id: 'hard-win',
            condition: { kind: 'complete-level', levelId: null, minDifficulty: 'hard' },
        })]);

        const easy = engine.evaluateSession(makeSession({ difficulty: 'easy' }));
        expect(easy).not.toContain('hard-win');

        const hard = engine.evaluateSession(makeSession({ difficulty: 'hard' }));
        expect(hard).toContain('hard-win');
    });
});
