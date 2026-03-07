/**
 * VARIANT — Scoring Engine Types
 *
 * Computes player scores from multiple weighted dimensions.
 * Configurable per-level: which dimensions matter, their weights,
 * bonus/penalty rules, and grade thresholds.
 *
 * DIMENSIONS (built-in):
 * - time: faster completion = higher score
 * - stealth: fewer detections = higher score
 * - completeness: objectives completed / total
 * - technique: quality of approach (tool usage, efficiency)
 * - accuracy: correct actions vs mistakes
 *
 * EXTENSIBILITY:
 * - Register custom dimensions for level-specific scoring
 * - Bonus rules: extra points for specific achievements
 * - Penalty rules: deductions for specific mistakes
 * - Grade thresholds are fully configurable
 *
 * SWAPPABILITY: Implements ScoringEngine. Replace this file.
 */

// ── Dimensions ──────────────────────────────────────────────────

/** A scoring dimension with a weight. */
export interface ScoringDimension {
    /** Unique dimension ID. */
    readonly id: string;
    /** Display name. */
    readonly name: string;
    /** Weight (0.0 to 1.0). All weights should sum to 1.0. */
    readonly weight: number;
    /** Maximum raw points for this dimension. */
    readonly maxPoints: number;
    /** Description. */
    readonly description: string;
}

// ── Bonus / Penalty Rules ───────────────────────────────────────

/** A bonus or penalty rule. */
export interface ScoreModifier {
    /** Unique modifier ID. */
    readonly id: string;
    /** Display name. */
    readonly name: string;
    /** Points to add (positive) or subtract (negative). */
    readonly points: number;
    /** Category for grouping in reports. */
    readonly category: string;
    /** Description of what triggers this modifier. */
    readonly description: string;
}

// ── Grade Thresholds ────────────────────────────────────────────

/** A grade definition with minimum percentage threshold. */
export interface GradeThreshold {
    /** Grade label (e.g., 'S', 'A+', 'A', 'B'). */
    readonly grade: string;
    /** Minimum percentage (0-100) to achieve this grade. */
    readonly minPercentage: number;
}

// ── Score Result ────────────────────────────────────────────────

/** Score for a single dimension. */
export interface DimensionScore {
    /** Dimension ID. */
    readonly dimensionId: string;
    /** Raw points earned. */
    readonly rawPoints: number;
    /** Maximum points possible. */
    readonly maxPoints: number;
    /** Percentage (0-100). */
    readonly percentage: number;
    /** Weighted contribution to total score. */
    readonly weightedScore: number;
}

/** A modifier that was applied. */
export interface AppliedModifier {
    /** Modifier ID. */
    readonly modifierId: string;
    /** Points applied. */
    readonly points: number;
    /** Category. */
    readonly category: string;
    /** Reason / trigger description. */
    readonly reason: string;
}

/** The final computed score. */
export interface ScoreResult {
    /** Total score (weighted sum + modifiers). */
    readonly totalScore: number;
    /** Maximum possible score (all dimensions maxed, no penalties). */
    readonly maxPossibleScore: number;
    /** Overall percentage (0-100). */
    readonly percentage: number;
    /** Letter grade. */
    readonly grade: string;
    /** Breakdown by dimension. */
    readonly dimensions: readonly DimensionScore[];
    /** Applied bonuses and penalties. */
    readonly modifiers: readonly AppliedModifier[];
    /** Total bonus points. */
    readonly totalBonus: number;
    /** Total penalty points. */
    readonly totalPenalty: number;
}

// ── Engine ──────────────────────────────────────────────────────

/** The scoring engine. */
export interface ScoringEngine {
    // ── Configuration ───────────────────────────────────────────

    /** Register a scoring dimension. */
    addDimension(dimension: ScoringDimension): void;

    /** Get a dimension by ID. */
    getDimension(id: string): ScoringDimension | null;

    /** List all dimensions. */
    listDimensions(): readonly ScoringDimension[];

    /** Register a score modifier (bonus or penalty rule). */
    addModifier(modifier: ScoreModifier): void;

    /** Get a modifier by ID. */
    getModifier(id: string): ScoreModifier | null;

    /** List all modifiers. */
    listModifiers(): readonly ScoreModifier[];

    /** Set grade thresholds. Must be sorted descending by minPercentage. */
    setGradeThresholds(thresholds: readonly GradeThreshold[]): void;

    /** Get the current grade thresholds. */
    getGradeThresholds(): readonly GradeThreshold[];

    // ── Scoring ─────────────────────────────────────────────────

    /** Set raw points for a dimension. */
    setDimensionScore(dimensionId: string, rawPoints: number): boolean;

    /** Apply a modifier (bonus or penalty). */
    applyModifier(modifierId: string, reason: string): boolean;

    /** Compute the final score result. */
    compute(): ScoreResult;

    /** Get the grade for a given percentage. */
    gradeForPercentage(percentage: number): string;

    // ── Reset ───────────────────────────────────────────────────

    /** Reset scores and applied modifiers (keeps configuration). */
    resetScores(): void;

    /** Clear all state including configuration. */
    clear(): void;
}
