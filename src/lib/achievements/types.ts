/**
 * VARIANT — Achievement/Badge System Types
 *
 * Persistent player progression. Achievements are unlocked by
 * meeting conditions across sessions. They represent skills
 * mastered, milestones reached, and feats accomplished.
 *
 * This is what makes players come back. Meta-progression
 * outside individual levels. Skill trees, badges, titles.
 *
 * DESIGN:
 *   - Achievements are defined in a catalog (global, not per-level)
 *   - Conditions are evaluated against session telemetry
 *   - Unlocked achievements persist across sessions
 *   - Rarity is computed from community-wide unlock rates
 *
 * EXTENSIBILITY:
 *   - Custom condition types
 *   - Custom badge visuals
 *   - Achievement packs (third-party)
 *   - Tiered achievements (bronze → silver → gold → diamond)
 *   - Hidden/secret achievements
 *
 * SWAPPABILITY: Pure types. No implementation here.
 */

// ── Achievement Definition ──────────────────────────────────

export interface AchievementDefinition {
    /** Unique achievement ID. Format: 'category/name'. */
    readonly id: string;

    /** Human-readable name. */
    readonly name: string;

    /** Short description. */
    readonly description: string;

    /** Longer flavor text shown after unlock. */
    readonly flavor: string;

    /** Icon identifier. */
    readonly icon: string;

    /** Achievement category for grouping. */
    readonly category: AchievementCategory;

    /** Tier level (for tiered achievements). */
    readonly tier: AchievementTier;

    /** Is this achievement hidden until unlocked? */
    readonly hidden: boolean;

    /** Points awarded for unlocking. */
    readonly points: number;

    /** Condition(s) that must be met to unlock. */
    readonly condition: AchievementCondition;

    /** Prerequisites — other achievements that must be unlocked first. */
    readonly prerequisites: readonly string[];
}

export type AchievementCategory =
    | 'offense'         // Attack skills
    | 'defense'         // Blue team skills
    | 'stealth'         // Low-noise operations
    | 'speed'           // Fast completions
    | 'exploration'     // Finding secrets
    | 'mastery'         // Expert-level feats
    | 'social'          // Community contributions
    | 'meta'            // Cross-category milestones
    | (string & {});    // Open for extensions

export type AchievementTier =
    | 'bronze'
    | 'silver'
    | 'gold'
    | 'diamond'
    | 'legendary';

// ── Achievement Conditions ──────────────────────────────────

export type AchievementCondition =
    | CompleteLevelCondition
    | ScoreCondition
    | StealthCondition
    | SpeedCondition
    | TechniqueCondition
    | CountCondition
    | StreakCondition
    | CompoundCondition
    | CustomCondition;

export interface CompleteLevelCondition {
    readonly kind: 'complete-level';
    /** Complete any level, or a specific one. null = any. */
    readonly levelId: string | null;
    /** Minimum difficulty to count. null = any. */
    readonly minDifficulty: string | null;
}

export interface ScoreCondition {
    readonly kind: 'score';
    /** Achieve at least this score. */
    readonly minScore: number;
    /** On this specific level, or any. null = any. */
    readonly levelId: string | null;
}

export interface StealthCondition {
    readonly kind: 'stealth';
    /** Complete with noise level at or below this threshold. */
    readonly maxNoise: number;
    readonly levelId: string | null;
}

export interface SpeedCondition {
    readonly kind: 'speed';
    /** Complete within this many seconds. */
    readonly maxSeconds: number;
    readonly levelId: string | null;
}

export interface TechniqueCondition {
    readonly kind: 'technique';
    /** Use this specific technique/vuln category. */
    readonly technique: string;
    /** Number of times it must be used. */
    readonly count: number;
}

export interface CountCondition {
    readonly kind: 'count';
    /** Count of a specific metric. */
    readonly metric: string;
    /** Must reach this count. */
    readonly target: number;
}

export interface StreakCondition {
    readonly kind: 'streak';
    /** Consecutive completions matching a condition. */
    readonly condition: AchievementCondition;
    readonly count: number;
}

export interface CompoundCondition {
    readonly kind: 'compound';
    readonly op: 'and' | 'or';
    readonly conditions: readonly AchievementCondition[];
}

export interface CustomCondition {
    readonly kind: 'custom';
    readonly type: string;
    readonly config: Readonly<Record<string, unknown>>;
}

// ── Player Achievement State ────────────────────────────────

export interface AchievementProgress {
    readonly achievementId: string;
    readonly unlocked: boolean;
    readonly unlockedAt: string | null;
    readonly progress: number;      // 0.0 to 1.0
    readonly progressDetail: string; // "3/10 levels completed"
}

// ── Achievement Engine ──────────────────────────────────────

/**
 * Session telemetry fed to the achievement engine after each game.
 */
export interface SessionResult {
    readonly levelId: string;
    readonly difficulty: string;
    readonly score: number;
    readonly maxScore: number;
    readonly durationSeconds: number;
    readonly hintsUsed: number;
    readonly noiseLevel: number;
    readonly techniquesUsed: readonly string[];
    readonly objectivesCompleted: readonly string[];
    readonly phase: string;
}

export interface AchievementEngine {
    /** Load achievement definitions into the catalog. */
    loadDefinitions(defs: readonly AchievementDefinition[]): void;

    /** Get all achievement definitions. */
    getDefinitions(): readonly AchievementDefinition[];

    /** Get definitions by category. */
    getByCategory(category: string): readonly AchievementDefinition[];

    /** Get a single definition. */
    getDefinition(id: string): AchievementDefinition | null;

    /** Get progress for a specific achievement. */
    getProgress(id: string): AchievementProgress | null;

    /** Get all progress entries. */
    getAllProgress(): readonly AchievementProgress[];

    /** Get all unlocked achievements. */
    getUnlocked(): readonly AchievementProgress[];

    /** Get total points earned. */
    getTotalPoints(): number;

    /**
     * Evaluate a session result against all achievement conditions.
     * Returns newly unlocked achievement IDs.
     */
    evaluateSession(result: SessionResult): readonly string[];

    /**
     * Manually mark an achievement as unlocked.
     * Used for achievements triggered by events outside session results.
     */
    unlock(id: string): boolean;

    /** Reset all progress. */
    reset(): void;
}
