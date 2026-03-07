/**
 * VARIANT — Scoring Engine Implementation
 *
 * Multi-dimensional weighted scoring with bonuses, penalties,
 * and configurable grade thresholds.
 *
 * SWAPPABILITY: Implements ScoringEngine. Replace this file.
 */

import type {
    ScoringEngine,
    ScoringDimension,
    ScoreModifier,
    GradeThreshold,
    DimensionScore,
    AppliedModifier,
    ScoreResult,
} from './types';

const DEFAULT_GRADES: readonly GradeThreshold[] = [
    { grade: 'S', minPercentage: 97 },
    { grade: 'A+', minPercentage: 93 },
    { grade: 'A', minPercentage: 85 },
    { grade: 'B+', minPercentage: 80 },
    { grade: 'B', minPercentage: 70 },
    { grade: 'C+', minPercentage: 65 },
    { grade: 'C', minPercentage: 55 },
    { grade: 'D', minPercentage: 40 },
    { grade: 'F', minPercentage: 0 },
];

export function createScoringEngine(): ScoringEngine {
    const dimensions = new Map<string, ScoringDimension>();
    const modifiers = new Map<string, ScoreModifier>();
    let gradeThresholds: readonly GradeThreshold[] = DEFAULT_GRADES;

    // Current session state
    const dimensionScores = new Map<string, number>(); // dimensionId → rawPoints
    const appliedModifiers: AppliedModifier[] = [];

    function computeGrade(percentage: number): string {
        for (const threshold of gradeThresholds) {
            if (percentage >= threshold.minPercentage) {
                return threshold.grade;
            }
        }
        return 'F';
    }

    return {
        // ── Configuration ───────────────────────────────────────

        addDimension(dimension: ScoringDimension): void {
            if (dimensions.has(dimension.id)) {
                throw new Error(`Dimension '${dimension.id}' already registered`);
            }
            dimensions.set(dimension.id, dimension);
        },

        getDimension(id: string): ScoringDimension | null {
            return dimensions.get(id) ?? null;
        },

        listDimensions(): readonly ScoringDimension[] {
            return [...dimensions.values()];
        },

        addModifier(modifier: ScoreModifier): void {
            if (modifiers.has(modifier.id)) {
                throw new Error(`Modifier '${modifier.id}' already registered`);
            }
            modifiers.set(modifier.id, modifier);
        },

        getModifier(id: string): ScoreModifier | null {
            return modifiers.get(id) ?? null;
        },

        listModifiers(): readonly ScoreModifier[] {
            return [...modifiers.values()];
        },

        setGradeThresholds(thresholds: readonly GradeThreshold[]): void {
            // Validate: must be sorted descending by minPercentage
            for (let i = 1; i < thresholds.length; i++) {
                if (thresholds[i]!.minPercentage >= thresholds[i - 1]!.minPercentage) {
                    throw new Error('Grade thresholds must be sorted descending by minPercentage');
                }
            }
            gradeThresholds = [...thresholds];
        },

        getGradeThresholds(): readonly GradeThreshold[] {
            return [...gradeThresholds];
        },

        // ── Scoring ─────────────────────────────────────────────

        setDimensionScore(dimensionId: string, rawPoints: number): boolean {
            if (!dimensions.has(dimensionId)) return false;
            const dim = dimensions.get(dimensionId)!;
            // Clamp to [0, maxPoints]
            const clamped = Math.max(0, Math.min(rawPoints, dim.maxPoints));
            dimensionScores.set(dimensionId, clamped);
            return true;
        },

        applyModifier(modifierId: string, reason: string): boolean {
            const modifier = modifiers.get(modifierId);
            if (modifier === undefined) return false;
            appliedModifiers.push({
                modifierId,
                points: modifier.points,
                category: modifier.category,
                reason,
            });
            return true;
        },

        compute(): ScoreResult {
            const dimScores: DimensionScore[] = [];
            let weightedTotal = 0;
            let maxPossible = 0;

            for (const dim of dimensions.values()) {
                const rawPoints = dimensionScores.get(dim.id) ?? 0;
                const percentage = dim.maxPoints > 0 ? (rawPoints / dim.maxPoints) * 100 : 0;
                const weightedScore = percentage * dim.weight;

                dimScores.push({
                    dimensionId: dim.id,
                    rawPoints,
                    maxPoints: dim.maxPoints,
                    percentage,
                    weightedScore,
                });

                weightedTotal += weightedScore;
                maxPossible += 100 * dim.weight;
            }

            // Apply modifiers
            let totalBonus = 0;
            let totalPenalty = 0;
            for (const mod of appliedModifiers) {
                if (mod.points > 0) {
                    totalBonus += mod.points;
                } else {
                    totalPenalty += mod.points;
                }
            }

            // Total score: weighted percentage + modifier points
            // maxPossible should normalize to 100 if weights sum to 1.0
            const basePercentage = maxPossible > 0 ? (weightedTotal / maxPossible) * 100 : 0;
            const totalScore = basePercentage + totalBonus + totalPenalty;
            const clampedScore = Math.max(0, Math.min(totalScore, 100 + totalBonus));
            const percentage = Math.max(0, Math.min(clampedScore, 100));
            const grade = computeGrade(percentage);

            return {
                totalScore: clampedScore,
                maxPossibleScore: 100,
                percentage,
                grade,
                dimensions: dimScores,
                modifiers: [...appliedModifiers],
                totalBonus,
                totalPenalty,
            };
        },

        gradeForPercentage(percentage: number): string {
            return computeGrade(percentage);
        },

        // ── Reset ───────────────────────────────────────────────

        resetScores(): void {
            dimensionScores.clear();
            appliedModifiers.length = 0;
        },

        clear(): void {
            dimensions.clear();
            modifiers.clear();
            gradeThresholds = DEFAULT_GRADES;
            dimensionScores.clear();
            appliedModifiers.length = 0;
        },
    };
}
