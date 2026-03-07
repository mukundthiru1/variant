/**
 * VARIANT — Scoring Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createScoringEngine } from '../../../src/lib/scoring/scoring-engine';
import type { ScoringDimension, ScoreModifier, GradeThreshold } from '../../../src/lib/scoring/types';

function dim(id: string, weight: number, maxPoints: number): ScoringDimension {
    return { id, name: `Dimension ${id}`, weight, maxPoints, description: `Dim ${id}` };
}

function bonus(id: string, points: number, category: string = 'bonus'): ScoreModifier {
    return { id, name: `Bonus ${id}`, points, category, description: `Mod ${id}` };
}

function penalty(id: string, points: number, category: string = 'penalty'): ScoreModifier {
    return { id, name: `Penalty ${id}`, points: -Math.abs(points), category, description: `Mod ${id}` };
}

describe('ScoringEngine', () => {
    // ── Dimensions ─────────────────────────────────────────────

    it('registers and retrieves dimensions', () => {
        const engine = createScoringEngine();
        engine.addDimension(dim('time', 0.3, 100));
        engine.addDimension(dim('stealth', 0.7, 100));

        expect(engine.getDimension('time')).not.toBeNull();
        expect(engine.getDimension('nonexistent')).toBeNull();
        expect(engine.listDimensions().length).toBe(2);
    });

    it('throws on duplicate dimension', () => {
        const engine = createScoringEngine();
        engine.addDimension(dim('time', 0.5, 100));
        expect(() => engine.addDimension(dim('time', 0.5, 100))).toThrow();
    });

    // ── Modifiers ──────────────────────────────────────────────

    it('registers and retrieves modifiers', () => {
        const engine = createScoringEngine();
        engine.addModifier(bonus('speed-bonus', 5));

        expect(engine.getModifier('speed-bonus')).not.toBeNull();
        expect(engine.getModifier('nonexistent')).toBeNull();
        expect(engine.listModifiers().length).toBe(1);
    });

    it('throws on duplicate modifier', () => {
        const engine = createScoringEngine();
        engine.addModifier(bonus('a', 5));
        expect(() => engine.addModifier(bonus('a', 10))).toThrow();
    });

    // ── Setting Scores ─────────────────────────────────────────

    it('setDimensionScore returns true for valid dimension', () => {
        const engine = createScoringEngine();
        engine.addDimension(dim('time', 0.5, 100));
        expect(engine.setDimensionScore('time', 80)).toBe(true);
    });

    it('setDimensionScore returns false for unknown dimension', () => {
        const engine = createScoringEngine();
        expect(engine.setDimensionScore('nonexistent', 50)).toBe(false);
    });

    it('clamps score to maxPoints', () => {
        const engine = createScoringEngine();
        engine.addDimension(dim('time', 1.0, 100));
        engine.setDimensionScore('time', 999);

        const result = engine.compute();
        expect(result.dimensions[0]!.rawPoints).toBe(100);
    });

    it('clamps score to minimum 0', () => {
        const engine = createScoringEngine();
        engine.addDimension(dim('time', 1.0, 100));
        engine.setDimensionScore('time', -50);

        const result = engine.compute();
        expect(result.dimensions[0]!.rawPoints).toBe(0);
    });

    // ── Computing Scores ───────────────────────────────────────

    it('computes score with single dimension at 100%', () => {
        const engine = createScoringEngine();
        engine.addDimension(dim('time', 1.0, 100));
        engine.setDimensionScore('time', 100);

        const result = engine.compute();
        expect(result.percentage).toBe(100);
        expect(result.grade).toBe('S');
    });

    it('computes score with single dimension at 50%', () => {
        const engine = createScoringEngine();
        engine.addDimension(dim('time', 1.0, 200));
        engine.setDimensionScore('time', 100);

        const result = engine.compute();
        expect(result.percentage).toBe(50);
    });

    it('computes weighted score across multiple dimensions', () => {
        const engine = createScoringEngine();
        engine.addDimension(dim('time', 0.5, 100));
        engine.addDimension(dim('stealth', 0.5, 100));

        engine.setDimensionScore('time', 100);   // 100% × 0.5 = 50
        engine.setDimensionScore('stealth', 50);  // 50% × 0.5 = 25
        // Total: 75/100 = 75%

        const result = engine.compute();
        expect(result.percentage).toBe(75);
        expect(result.grade).toBe('B');
    });

    it('unset dimensions count as 0', () => {
        const engine = createScoringEngine();
        engine.addDimension(dim('time', 0.5, 100));
        engine.addDimension(dim('stealth', 0.5, 100));

        engine.setDimensionScore('time', 100);
        // stealth not set → 0

        const result = engine.compute();
        expect(result.percentage).toBe(50);
    });

    // ── Modifiers in Scoring ───────────────────────────────────

    it('applies bonus to score', () => {
        const engine = createScoringEngine();
        engine.addDimension(dim('time', 1.0, 100));
        engine.addModifier(bonus('speed', 5));

        engine.setDimensionScore('time', 90);
        engine.applyModifier('speed', 'Completed under par time');

        const result = engine.compute();
        expect(result.totalScore).toBe(95);
        expect(result.totalBonus).toBe(5);
    });

    it('applies penalty to score', () => {
        const engine = createScoringEngine();
        engine.addDimension(dim('time', 1.0, 100));
        engine.addModifier(penalty('detected', 10));

        engine.setDimensionScore('time', 90);
        engine.applyModifier('detected', 'Triggered alarm');

        const result = engine.compute();
        expect(result.totalScore).toBe(80);
        expect(result.totalPenalty).toBe(-10);
    });

    it('applyModifier returns false for unknown modifier', () => {
        const engine = createScoringEngine();
        expect(engine.applyModifier('nonexistent', 'reason')).toBe(false);
    });

    it('same modifier can be applied multiple times', () => {
        const engine = createScoringEngine();
        engine.addDimension(dim('time', 1.0, 100));
        engine.addModifier(penalty('mistake', 5));

        engine.setDimensionScore('time', 100);
        engine.applyModifier('mistake', 'First mistake');
        engine.applyModifier('mistake', 'Second mistake');

        const result = engine.compute();
        expect(result.modifiers.length).toBe(2);
        expect(result.totalPenalty).toBe(-10);
        expect(result.totalScore).toBe(90);
    });

    // ── Grade Thresholds ───────────────────────────────────────

    it('default grades work correctly', () => {
        const engine = createScoringEngine();
        expect(engine.gradeForPercentage(100)).toBe('S');
        expect(engine.gradeForPercentage(97)).toBe('S');
        expect(engine.gradeForPercentage(96)).toBe('A+');
        expect(engine.gradeForPercentage(93)).toBe('A+');
        expect(engine.gradeForPercentage(85)).toBe('A');
        expect(engine.gradeForPercentage(70)).toBe('B');
        expect(engine.gradeForPercentage(55)).toBe('C');
        expect(engine.gradeForPercentage(40)).toBe('D');
        expect(engine.gradeForPercentage(20)).toBe('F');
        expect(engine.gradeForPercentage(0)).toBe('F');
    });

    it('custom grade thresholds', () => {
        const engine = createScoringEngine();
        const custom: GradeThreshold[] = [
            { grade: 'Pass', minPercentage: 50 },
            { grade: 'Fail', minPercentage: 0 },
        ];
        engine.setGradeThresholds(custom);

        expect(engine.gradeForPercentage(75)).toBe('Pass');
        expect(engine.gradeForPercentage(50)).toBe('Pass');
        expect(engine.gradeForPercentage(49)).toBe('Fail');
    });

    it('throws for unsorted grade thresholds', () => {
        const engine = createScoringEngine();
        expect(() => engine.setGradeThresholds([
            { grade: 'F', minPercentage: 0 },
            { grade: 'A', minPercentage: 90 },
        ])).toThrow();
    });

    // ── Dimension Breakdown ────────────────────────────────────

    it('compute returns dimension breakdown', () => {
        const engine = createScoringEngine();
        engine.addDimension(dim('time', 0.4, 100));
        engine.addDimension(dim('stealth', 0.6, 50));

        engine.setDimensionScore('time', 80);
        engine.setDimensionScore('stealth', 40);

        const result = engine.compute();
        expect(result.dimensions.length).toBe(2);

        const timeDim = result.dimensions.find(d => d.dimensionId === 'time')!;
        expect(timeDim.rawPoints).toBe(80);
        expect(timeDim.maxPoints).toBe(100);
        expect(timeDim.percentage).toBe(80);

        const stealthDim = result.dimensions.find(d => d.dimensionId === 'stealth')!;
        expect(stealthDim.rawPoints).toBe(40);
        expect(stealthDim.maxPoints).toBe(50);
        expect(stealthDim.percentage).toBe(80);
    });

    // ── Reset ──────────────────────────────────────────────────

    it('resetScores keeps dimensions but clears scores', () => {
        const engine = createScoringEngine();
        engine.addDimension(dim('time', 1.0, 100));
        engine.addModifier(bonus('a', 5));

        engine.setDimensionScore('time', 80);
        engine.applyModifier('a', 'reason');

        engine.resetScores();

        expect(engine.listDimensions().length).toBe(1);
        expect(engine.listModifiers().length).toBe(1);

        const result = engine.compute();
        expect(result.percentage).toBe(0);
        expect(result.modifiers.length).toBe(0);
    });

    it('clear removes everything', () => {
        const engine = createScoringEngine();
        engine.addDimension(dim('time', 1.0, 100));
        engine.addModifier(bonus('a', 5));
        engine.setDimensionScore('time', 80);

        engine.clear();

        expect(engine.listDimensions().length).toBe(0);
        expect(engine.listModifiers().length).toBe(0);
        expect(engine.compute().percentage).toBe(0);
    });

    // ── Edge Cases ─────────────────────────────────────────────

    it('compute with no dimensions returns zero', () => {
        const engine = createScoringEngine();
        const result = engine.compute();
        expect(result.percentage).toBe(0);
        expect(result.grade).toBe('F');
    });

    it('score does not go below 0', () => {
        const engine = createScoringEngine();
        engine.addDimension(dim('time', 1.0, 100));
        engine.addModifier(penalty('huge', 200));

        engine.setDimensionScore('time', 10);
        engine.applyModifier('huge', 'disaster');

        const result = engine.compute();
        expect(result.totalScore).toBeGreaterThanOrEqual(0);
    });
});
