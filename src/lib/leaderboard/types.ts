/**
 * VARIANT — Leaderboard & Ranking System
 *
 * Competitive scoring, ranking, and progression tracking.
 * Supports per-scenario, per-campaign, and global leaderboards.
 *
 * FEATURES:
 * - Multiple ranking algorithms (ELO, percentile, raw score)
 * - Time-decay for freshness
 * - Category filtering (by difficulty, tag, campaign)
 * - Anti-cheat: score validation rules
 * - Streak tracking and personal bests
 *
 * SWAPPABILITY: Implements LeaderboardEngine. Replace this file.
 */

// ── Score Entry ─────────────────────────────────────────────────

/** A single score submission. */
export interface ScoreEntry {
    /** Unique entry ID. */
    readonly id: string;
    /** Player identifier. */
    readonly playerId: string;
    /** Player display name. */
    readonly displayName: string;
    /** Scenario or campaign ID this score belongs to. */
    readonly scopeId: string;
    /** Raw score value. */
    readonly score: number;
    /** Time taken in seconds. */
    readonly timeSecs: number;
    /** Completion percentage (0-1). */
    readonly completion: number;
    /** Grade (A+, A, B, etc.). */
    readonly grade: ScoreGrade;
    /** When this score was achieved (ISO 8601). */
    readonly achievedAt: string;
    /** Tags for categorization. */
    readonly tags: readonly string[];
    /** Custom metadata. */
    readonly metadata?: Readonly<Record<string, unknown>>;
}

export type ScoreGrade = 'S' | 'A+' | 'A' | 'B+' | 'B' | 'C+' | 'C' | 'D' | 'F';

// ── Leaderboard Definition ──────────────────────────────────────

/** Configuration for a leaderboard. */
export interface LeaderboardConfig {
    /** Unique leaderboard ID. */
    readonly id: string;
    /** Display name. */
    readonly name: string;
    /** What this leaderboard tracks. */
    readonly scope: LeaderboardScope;
    /** Ranking method. */
    readonly rankingMethod: RankingMethod;
    /** Maximum entries to keep. Default: 1000. */
    readonly maxEntries?: number;
    /** Time decay half-life in days. 0 = no decay. */
    readonly decayHalfLifeDays?: number;
    /** Minimum completion to qualify. Default: 0. */
    readonly minCompletion?: number;
    /** Score validation rules. */
    readonly validation?: readonly ScoreValidationRule[];
}

export type LeaderboardScope =
    | { readonly kind: 'scenario'; readonly scenarioId: string }
    | { readonly kind: 'campaign'; readonly campaignId: string }
    | { readonly kind: 'global' }
    | { readonly kind: 'tag'; readonly tag: string };

export type RankingMethod =
    | 'highest-score'
    | 'lowest-time'
    | 'highest-completion'
    | 'composite';

/** A rule for validating submitted scores. */
export interface ScoreValidationRule {
    /** Rule type. */
    readonly type: 'max-score' | 'min-time' | 'max-time' | 'custom';
    /** Threshold value. */
    readonly value: number;
    /** Custom validator name (for 'custom' type). */
    readonly validatorName?: string;
}

// ── Ranked Entry ────────────────────────────────────────────────

/** A score entry with its rank computed. */
export interface RankedEntry {
    /** Rank (1-based). */
    readonly rank: number;
    /** The underlying score entry. */
    readonly entry: ScoreEntry;
    /** Effective score after decay. */
    readonly effectiveScore: number;
    /** Percentile (0-100). */
    readonly percentile: number;
}

// ── Player Stats ────────────────────────────────────────────────

/** Aggregated stats for a player. */
export interface PlayerStats {
    readonly playerId: string;
    readonly totalSubmissions: number;
    readonly bestScores: Readonly<Record<string, number>>;
    readonly averageScore: number;
    readonly averageCompletion: number;
    readonly gradeDistribution: Readonly<Record<ScoreGrade, number>>;
    readonly currentStreak: number;
    readonly bestStreak: number;
    readonly lastPlayedAt: string;
}

// ── Leaderboard Engine ──────────────────────────────────────────

export interface LeaderboardEngine {
    /** Create a new leaderboard. */
    createBoard(config: LeaderboardConfig): void;

    /** Get leaderboard config. */
    getBoard(id: string): LeaderboardConfig | null;

    /** List all leaderboards. */
    listBoards(): readonly LeaderboardConfig[];

    /** Submit a score. Returns the rank, or null if validation failed. */
    submit(boardId: string, entry: ScoreEntry): number | null;

    /** Get the top N entries. */
    getTop(boardId: string, limit: number): readonly RankedEntry[];

    /** Get a specific player's rank on a board. */
    getPlayerRank(boardId: string, playerId: string): RankedEntry | null;

    /** Get a player's entries on a board. */
    getPlayerEntries(boardId: string, playerId: string): readonly RankedEntry[];

    /** Get aggregated player stats across all boards. */
    getPlayerStats(playerId: string): PlayerStats;

    /** Get entries around a specific rank (for context). */
    getAroundRank(boardId: string, rank: number, radius: number): readonly RankedEntry[];

    /** Register a custom score validator. */
    registerValidator(name: string, fn: (entry: ScoreEntry) => boolean): void;

    /** Remove a leaderboard. */
    removeBoard(id: string): boolean;

    /** Clear all boards and entries. */
    clear(): void;
}
