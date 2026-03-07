/**
 * VARIANT — Level Designer Toolkit Types
 *
 * Tools for level designers to validate, analyze, and compose levels.
 * Integrates with MITRE catalog, vuln catalog, and misconfig catalog
 * to provide comprehensive level analysis.
 */

import type { MitreTactic } from '../mitre/types';

// ── Level Validation ────────────────────────────────────────────

export interface LevelValidationResult {
    readonly valid: boolean;
    readonly errors: readonly ValidationIssue[];
    readonly warnings: readonly ValidationIssue[];
    readonly info: readonly ValidationIssue[];
}

export interface ValidationIssue {
    readonly code: string;
    readonly message: string;
    readonly path?: string;
    readonly severity: 'error' | 'warning' | 'info';
}

// ── MITRE Coverage Analysis ─────────────────────────────────────

export interface MitreCoverageAnalysis {
    /** Tactics covered by this level. */
    readonly tacticsPresent: readonly MitreTactic[];

    /** Tactics not covered. */
    readonly tacticsMissing: readonly MitreTactic[];

    /** All MITRE techniques referenced. */
    readonly techniquesReferenced: readonly string[];

    /** Percentage of kill chain covered (14 tactics). */
    readonly killChainCoveragePercent: number;

    /** Suggestions to improve coverage. */
    readonly suggestions: readonly string[];
}

// ── Difficulty Analysis ─────────────────────────────────────────

export interface DifficultyAnalysis {
    /** Computed difficulty based on level structure. */
    readonly computedDifficulty: 'beginner' | 'easy' | 'medium' | 'hard' | 'expert';

    /** Does the computed difficulty match the declared difficulty? */
    readonly matchesDeclared: boolean;

    /** Factors that contribute to difficulty. */
    readonly factors: readonly DifficultyFactor[];

    /** Overall difficulty score (0-100). */
    readonly score: number;
}

export interface DifficultyFactor {
    readonly name: string;
    readonly contribution: number;
    readonly description: string;
}

// ── Level Completeness ──────────────────────────────────────────

export interface CompletenessAnalysis {
    /** Overall completeness score (0-100). */
    readonly score: number;

    /** What's present. */
    readonly present: readonly string[];

    /** What's missing but recommended. */
    readonly missing: readonly string[];

    /** What could be improved. */
    readonly improvements: readonly string[];
}

// ── Level Toolkit Interface ─────────────────────────────────────

export interface LevelToolkit {
    /** Validate a WorldSpec for correctness and best practices. */
    validate(world: unknown): LevelValidationResult;

    /** Analyze MITRE ATT&CK coverage of a level. */
    analyzeMitreCoverage(world: unknown): MitreCoverageAnalysis;

    /** Analyze difficulty and compare with declared difficulty. */
    analyzeDifficulty(world: unknown): DifficultyAnalysis;

    /** Analyze completeness — what's missing from the level. */
    analyzeCompleteness(world: unknown): CompletenessAnalysis;

    /** Generate a full analysis report combining all analyses. */
    fullAnalysis(world: unknown): LevelAnalysisReport;
}

export interface LevelAnalysisReport {
    readonly validation: LevelValidationResult;
    readonly mitreCoverage: MitreCoverageAnalysis;
    readonly difficulty: DifficultyAnalysis;
    readonly completeness: CompletenessAnalysis;
    readonly overallScore: number;
    readonly summary: string;
}
