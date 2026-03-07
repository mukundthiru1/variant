/**
 * VARIANT — Leaderboard Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createLeaderboardEngine } from '../../../src/lib/leaderboard/leaderboard-engine';
import type { ScoreEntry, LeaderboardConfig } from '../../../src/lib/leaderboard/types';

function makeEntry(overrides: Partial<ScoreEntry> & { id: string; playerId: string }): ScoreEntry {
    return {
        displayName: overrides.playerId,
        scopeId: 'scenario-1',
        score: 100,
        timeSecs: 300,
        completion: 1.0,
        grade: 'A',
        achievedAt: new Date().toISOString(),
        tags: [],
        ...overrides,
    };
}

function makeBoard(overrides?: Partial<LeaderboardConfig>): LeaderboardConfig {
    return {
        id: 'board-1',
        name: 'Test Board',
        scope: { kind: 'global' },
        rankingMethod: 'highest-score',
        ...overrides,
    };
}

describe('LeaderboardEngine', () => {
    it('creates and retrieves boards', () => {
        const engine = createLeaderboardEngine();
        engine.createBoard(makeBoard());

        expect(engine.getBoard('board-1')).not.toBeNull();
        expect(engine.getBoard('nonexistent')).toBeNull();
        expect(engine.listBoards().length).toBe(1);
    });

    it('throws on duplicate board', () => {
        const engine = createLeaderboardEngine();
        engine.createBoard(makeBoard());
        expect(() => engine.createBoard(makeBoard())).toThrow();
    });

    it('submits scores and returns rank', () => {
        const engine = createLeaderboardEngine();
        engine.createBoard(makeBoard());

        const rank = engine.submit('board-1', makeEntry({ id: 'e1', playerId: 'p1', score: 100 }));
        expect(rank).toBe(1);
    });

    it('returns null for unknown board', () => {
        const engine = createLeaderboardEngine();
        expect(engine.submit('nonexistent', makeEntry({ id: 'e1', playerId: 'p1' }))).toBeNull();
    });

    it('ranks by highest score', () => {
        const engine = createLeaderboardEngine();
        engine.createBoard(makeBoard({ rankingMethod: 'highest-score' }));

        engine.submit('board-1', makeEntry({ id: 'e1', playerId: 'p1', score: 50 }));
        engine.submit('board-1', makeEntry({ id: 'e2', playerId: 'p2', score: 150 }));
        engine.submit('board-1', makeEntry({ id: 'e3', playerId: 'p3', score: 100 }));

        const top = engine.getTop('board-1', 10);
        expect(top.length).toBe(3);
        expect(top[0]!.entry.playerId).toBe('p2');
        expect(top[1]!.entry.playerId).toBe('p3');
        expect(top[2]!.entry.playerId).toBe('p1');
        expect(top[0]!.rank).toBe(1);
        expect(top[2]!.rank).toBe(3);
    });

    it('ranks by lowest time', () => {
        const engine = createLeaderboardEngine();
        engine.createBoard(makeBoard({ rankingMethod: 'lowest-time' }));

        engine.submit('board-1', makeEntry({ id: 'e1', playerId: 'p1', timeSecs: 600 }));
        engine.submit('board-1', makeEntry({ id: 'e2', playerId: 'p2', timeSecs: 120 }));
        engine.submit('board-1', makeEntry({ id: 'e3', playerId: 'p3', timeSecs: 300 }));

        const top = engine.getTop('board-1', 10);
        expect(top[0]!.entry.playerId).toBe('p2');
        expect(top[2]!.entry.playerId).toBe('p1');
    });

    it('ranks by highest completion', () => {
        const engine = createLeaderboardEngine();
        engine.createBoard(makeBoard({ rankingMethod: 'highest-completion' }));

        engine.submit('board-1', makeEntry({ id: 'e1', playerId: 'p1', completion: 0.5 }));
        engine.submit('board-1', makeEntry({ id: 'e2', playerId: 'p2', completion: 1.0 }));

        const top = engine.getTop('board-1', 10);
        expect(top[0]!.entry.playerId).toBe('p2');
    });

    it('getTop limits results', () => {
        const engine = createLeaderboardEngine();
        engine.createBoard(makeBoard());

        for (let i = 0; i < 10; i++) {
            engine.submit('board-1', makeEntry({ id: `e${i}`, playerId: `p${i}`, score: i * 10 }));
        }

        expect(engine.getTop('board-1', 3).length).toBe(3);
    });

    it('getPlayerRank returns player best rank', () => {
        const engine = createLeaderboardEngine();
        engine.createBoard(makeBoard());

        engine.submit('board-1', makeEntry({ id: 'e1', playerId: 'p1', score: 50 }));
        engine.submit('board-1', makeEntry({ id: 'e2', playerId: 'p2', score: 100 }));

        const rank = engine.getPlayerRank('board-1', 'p1');
        expect(rank).not.toBeNull();
        expect(rank!.rank).toBe(2);
    });

    it('getPlayerRank returns null for unknown player', () => {
        const engine = createLeaderboardEngine();
        engine.createBoard(makeBoard());
        expect(engine.getPlayerRank('board-1', 'nobody')).toBeNull();
    });

    it('getPlayerEntries returns all entries for a player', () => {
        const engine = createLeaderboardEngine();
        engine.createBoard(makeBoard());

        engine.submit('board-1', makeEntry({ id: 'e1', playerId: 'p1', score: 50 }));
        engine.submit('board-1', makeEntry({ id: 'e2', playerId: 'p1', score: 80 }));
        engine.submit('board-1', makeEntry({ id: 'e3', playerId: 'p2', score: 100 }));

        const entries = engine.getPlayerEntries('board-1', 'p1');
        expect(entries.length).toBe(2);
    });

    it('enforces minCompletion', () => {
        const engine = createLeaderboardEngine();
        engine.createBoard(makeBoard({ minCompletion: 0.8 }));

        const rank = engine.submit('board-1', makeEntry({ id: 'e1', playerId: 'p1', completion: 0.5 }));
        expect(rank).toBeNull();

        const rank2 = engine.submit('board-1', makeEntry({ id: 'e2', playerId: 'p2', completion: 0.9 }));
        expect(rank2).toBe(1);
    });

    it('validates max-score rule', () => {
        const engine = createLeaderboardEngine();
        engine.createBoard(makeBoard({
            validation: [{ type: 'max-score', value: 1000 }],
        }));

        const ok = engine.submit('board-1', makeEntry({ id: 'e1', playerId: 'p1', score: 500 }));
        expect(ok).toBe(1);

        const bad = engine.submit('board-1', makeEntry({ id: 'e2', playerId: 'p2', score: 1500 }));
        expect(bad).toBeNull();
    });

    it('validates min-time rule', () => {
        const engine = createLeaderboardEngine();
        engine.createBoard(makeBoard({
            validation: [{ type: 'min-time', value: 60 }],
        }));

        const bad = engine.submit('board-1', makeEntry({ id: 'e1', playerId: 'p1', timeSecs: 30 }));
        expect(bad).toBeNull();

        const ok = engine.submit('board-1', makeEntry({ id: 'e2', playerId: 'p2', timeSecs: 120 }));
        expect(ok).toBe(1);
    });

    it('validates with custom validator', () => {
        const engine = createLeaderboardEngine();
        engine.registerValidator('no-f-grade', (entry) => entry.grade !== 'F');

        engine.createBoard(makeBoard({
            validation: [{ type: 'custom', value: 0, validatorName: 'no-f-grade' }],
        }));

        const bad = engine.submit('board-1', makeEntry({ id: 'e1', playerId: 'p1', grade: 'F' }));
        expect(bad).toBeNull();

        const ok = engine.submit('board-1', makeEntry({ id: 'e2', playerId: 'p2', grade: 'A' }));
        expect(ok).toBe(1);
    });

    it('throws on duplicate validator', () => {
        const engine = createLeaderboardEngine();
        engine.registerValidator('test', () => true);
        expect(() => engine.registerValidator('test', () => true)).toThrow();
    });

    it('computes player stats', () => {
        const engine = createLeaderboardEngine();
        engine.createBoard(makeBoard());

        engine.submit('board-1', makeEntry({
            id: 'e1', playerId: 'p1', score: 80, completion: 0.8, grade: 'B',
            scopeId: 's1', achievedAt: '2026-03-01T10:00:00Z',
        }));
        engine.submit('board-1', makeEntry({
            id: 'e2', playerId: 'p1', score: 100, completion: 1.0, grade: 'A',
            scopeId: 's2', achievedAt: '2026-03-02T10:00:00Z',
        }));

        const stats = engine.getPlayerStats('p1');
        expect(stats.totalSubmissions).toBe(2);
        expect(stats.averageScore).toBe(90);
        expect(stats.averageCompletion).toBe(0.9);
        expect(stats.gradeDistribution['A']).toBe(1);
        expect(stats.gradeDistribution['B']).toBe(1);
        expect(stats.bestScores['s1']).toBe(80);
        expect(stats.bestScores['s2']).toBe(100);
    });

    it('computes streak for consecutive days', () => {
        const engine = createLeaderboardEngine();
        engine.createBoard(makeBoard());

        engine.submit('board-1', makeEntry({
            id: 'e1', playerId: 'p1', achievedAt: '2026-03-01T10:00:00Z',
        }));
        engine.submit('board-1', makeEntry({
            id: 'e2', playerId: 'p1', achievedAt: '2026-03-02T10:00:00Z',
        }));
        engine.submit('board-1', makeEntry({
            id: 'e3', playerId: 'p1', achievedAt: '2026-03-03T10:00:00Z',
        }));

        const stats = engine.getPlayerStats('p1');
        expect(stats.bestStreak).toBe(3);
    });

    it('empty stats for unknown player', () => {
        const engine = createLeaderboardEngine();
        const stats = engine.getPlayerStats('nobody');
        expect(stats.totalSubmissions).toBe(0);
        expect(stats.averageScore).toBe(0);
        expect(stats.currentStreak).toBe(0);
    });

    it('getAroundRank returns context', () => {
        const engine = createLeaderboardEngine();
        engine.createBoard(makeBoard());

        for (let i = 0; i < 10; i++) {
            engine.submit('board-1', makeEntry({ id: `e${i}`, playerId: `p${i}`, score: (i + 1) * 10 }));
        }

        const around = engine.getAroundRank('board-1', 5, 2);
        expect(around.length).toBe(5); // ranks 3-7
        expect(around[0]!.rank).toBe(3);
        expect(around[4]!.rank).toBe(7);
    });

    it('percentile calculation', () => {
        const engine = createLeaderboardEngine();
        engine.createBoard(makeBoard());

        engine.submit('board-1', makeEntry({ id: 'e1', playerId: 'p1', score: 100 }));
        engine.submit('board-1', makeEntry({ id: 'e2', playerId: 'p2', score: 50 }));

        const top = engine.getTop('board-1', 10);
        expect(top[0]!.percentile).toBe(100); // rank 1 = top
        expect(top[1]!.percentile).toBe(0);   // rank 2 = bottom
    });

    it('removeBoard', () => {
        const engine = createLeaderboardEngine();
        engine.createBoard(makeBoard());

        expect(engine.removeBoard('board-1')).toBe(true);
        expect(engine.removeBoard('board-1')).toBe(false);
        expect(engine.getBoard('board-1')).toBeNull();
    });

    it('clear removes everything', () => {
        const engine = createLeaderboardEngine();
        engine.createBoard(makeBoard());
        engine.submit('board-1', makeEntry({ id: 'e1', playerId: 'p1' }));

        engine.clear();
        expect(engine.listBoards().length).toBe(0);
    });

    it('trims to maxEntries', () => {
        const engine = createLeaderboardEngine();
        engine.createBoard(makeBoard({ maxEntries: 3 }));

        for (let i = 0; i < 5; i++) {
            engine.submit('board-1', makeEntry({ id: `e${i}`, playerId: `p${i}`, score: (i + 1) * 10 }));
        }

        const top = engine.getTop('board-1', 100);
        expect(top.length).toBe(3);
        // Should keep the 3 highest scores
        expect(top[0]!.entry.score).toBe(50);
        expect(top[2]!.entry.score).toBe(30);
    });

    it('composite ranking considers score, completion, and time', () => {
        const engine = createLeaderboardEngine();
        engine.createBoard(makeBoard({ rankingMethod: 'composite' }));

        // High score, slow
        engine.submit('board-1', makeEntry({ id: 'e1', playerId: 'p1', score: 200, completion: 1.0, timeSecs: 600 }));
        // Medium score, fast
        engine.submit('board-1', makeEntry({ id: 'e2', playerId: 'p2', score: 150, completion: 1.0, timeSecs: 100 }));

        const top = engine.getTop('board-1', 10);
        // p2 should rank higher because of speed advantage in composite
        expect(top[0]!.entry.playerId).toBe('p2');
    });
});
