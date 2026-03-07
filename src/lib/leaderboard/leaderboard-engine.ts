/**
 * VARIANT — Leaderboard Engine Implementation
 *
 * Competitive scoring with ranking, decay, validation, and stats.
 *
 * SWAPPABILITY: Implements LeaderboardEngine. Replace this file.
 */

import type {
    LeaderboardEngine,
    LeaderboardConfig,
    ScoreEntry,
    RankedEntry,
    PlayerStats,
    ScoreGrade,
    ScoreValidationRule,
} from './types';

interface BoardState {
    config: LeaderboardConfig;
    entries: ScoreEntry[];
}

export function createLeaderboardEngine(): LeaderboardEngine {
    const boards = new Map<string, BoardState>();
    const validators = new Map<string, (entry: ScoreEntry) => boolean>();

    function validateEntry(rules: readonly ScoreValidationRule[], entry: ScoreEntry): boolean {
        for (const rule of rules) {
            switch (rule.type) {
                case 'max-score':
                    if (entry.score > rule.value) return false;
                    break;
                case 'min-time':
                    if (entry.timeSecs < rule.value) return false;
                    break;
                case 'max-time':
                    if (entry.timeSecs > rule.value) return false;
                    break;
                case 'custom': {
                    if (rule.validatorName === undefined) return false;
                    const fn = validators.get(rule.validatorName);
                    if (fn !== undefined && !fn(entry)) return false;
                    break;
                }
            }
        }
        return true;
    }

    function computeEffectiveScore(entry: ScoreEntry, config: LeaderboardConfig): number {
        const halfLife = config.decayHalfLifeDays ?? 0;
        if (halfLife <= 0) return entry.score;

        const ageMs = Date.now() - new Date(entry.achievedAt).getTime();
        const ageDays = ageMs / (1000 * 60 * 60 * 24);
        const decay = Math.pow(0.5, ageDays / halfLife);
        return entry.score * decay;
    }

    function rankEntries(board: BoardState): RankedEntry[] {
        const config = board.config;
        const minCompletion = config.minCompletion ?? 0;

        const qualifying = board.entries.filter(e => e.completion >= minCompletion);

        const scored = qualifying.map(entry => ({
            entry,
            effectiveScore: computeEffectiveScore(entry, config),
        }));

        // Sort based on ranking method
        switch (config.rankingMethod) {
            case 'highest-score':
                scored.sort((a, b) => b.effectiveScore - a.effectiveScore);
                break;
            case 'lowest-time':
                scored.sort((a, b) => a.entry.timeSecs - b.entry.timeSecs);
                break;
            case 'highest-completion':
                scored.sort((a, b) => b.entry.completion - a.entry.completion);
                break;
            case 'composite':
                scored.sort((a, b) => {
                    const aComposite = a.effectiveScore * a.entry.completion * (1000 / Math.max(1, a.entry.timeSecs));
                    const bComposite = b.effectiveScore * b.entry.completion * (1000 / Math.max(1, b.entry.timeSecs));
                    return bComposite - aComposite;
                });
                break;
        }

        const total = scored.length;
        return scored.map((s, i) => ({
            rank: i + 1,
            entry: s.entry,
            effectiveScore: s.effectiveScore,
            percentile: total > 1 ? ((total - i - 1) / (total - 1)) * 100 : 100,
        }));
    }

    return {
        createBoard(config: LeaderboardConfig): void {
            if (boards.has(config.id)) {
                throw new Error(`Leaderboard '${config.id}' already exists`);
            }
            boards.set(config.id, { config, entries: [] });
        },

        getBoard(id: string): LeaderboardConfig | null {
            return boards.get(id)?.config ?? null;
        },

        listBoards(): readonly LeaderboardConfig[] {
            return [...boards.values()].map(b => b.config);
        },

        submit(boardId: string, entry: ScoreEntry): number | null {
            const board = boards.get(boardId);
            if (board === undefined) return null;

            // Validate
            if (board.config.validation !== undefined) {
                if (!validateEntry(board.config.validation, entry)) return null;
            }

            // Check min completion
            const minCompletion = board.config.minCompletion ?? 0;
            if (entry.completion < minCompletion) return null;

            board.entries.push(entry);

            // Trim to max entries (keep best)
            const maxEntries = board.config.maxEntries ?? 1000;
            if (board.entries.length > maxEntries) {
                const ranked = rankEntries(board);
                board.entries = ranked.slice(0, maxEntries).map(r => r.entry);
            }

            // Return rank
            const ranked = rankEntries(board);
            const playerRank = ranked.find(r => r.entry.id === entry.id);
            return playerRank?.rank ?? null;
        },

        getTop(boardId: string, limit: number): readonly RankedEntry[] {
            const board = boards.get(boardId);
            if (board === undefined) return [];
            return rankEntries(board).slice(0, limit);
        },

        getPlayerRank(boardId: string, playerId: string): RankedEntry | null {
            const board = boards.get(boardId);
            if (board === undefined) return null;

            const ranked = rankEntries(board);
            // Return the player's best rank
            return ranked.find(r => r.entry.playerId === playerId) ?? null;
        },

        getPlayerEntries(boardId: string, playerId: string): readonly RankedEntry[] {
            const board = boards.get(boardId);
            if (board === undefined) return [];

            const ranked = rankEntries(board);
            return ranked.filter(r => r.entry.playerId === playerId);
        },

        getPlayerStats(playerId: string): PlayerStats {
            const allEntries: ScoreEntry[] = [];
            for (const board of boards.values()) {
                for (const entry of board.entries) {
                    if (entry.playerId === playerId) {
                        allEntries.push(entry);
                    }
                }
            }

            const bestScores: Record<string, number> = {};
            const gradeDistribution: Record<ScoreGrade, number> = {
                'S': 0, 'A+': 0, 'A': 0, 'B+': 0, 'B': 0,
                'C+': 0, 'C': 0, 'D': 0, 'F': 0,
            };

            let totalScore = 0;
            let totalCompletion = 0;

            for (const entry of allEntries) {
                totalScore += entry.score;
                totalCompletion += entry.completion;
                gradeDistribution[entry.grade]++;

                const current = bestScores[entry.scopeId];
                if (current === undefined || entry.score > current) {
                    bestScores[entry.scopeId] = entry.score;
                }
            }

            // Compute streak (consecutive days with submissions)
            const sortedByDate = [...allEntries].sort(
                (a, b) => new Date(b.achievedAt).getTime() - new Date(a.achievedAt).getTime()
            );

            let currentStreak = 0;
            let bestStreak = 0;

            if (sortedByDate.length > 0) {
                currentStreak = 1;
                let prevDay = toDateString(sortedByDate[0]!.achievedAt);

                for (let i = 1; i < sortedByDate.length; i++) {
                    const day = toDateString(sortedByDate[i]!.achievedAt);
                    if (day === prevDay) continue;

                    const prevDate = new Date(prevDay);
                    const currDate = new Date(day);
                    const diffDays = (prevDate.getTime() - currDate.getTime()) / (1000 * 60 * 60 * 24);

                    if (Math.abs(diffDays - 1) < 0.5) {
                        currentStreak++;
                    } else {
                        if (currentStreak > bestStreak) bestStreak = currentStreak;
                        currentStreak = 1;
                    }
                    prevDay = day;
                }
                if (currentStreak > bestStreak) bestStreak = currentStreak;
            }

            return {
                playerId,
                totalSubmissions: allEntries.length,
                bestScores,
                averageScore: allEntries.length > 0 ? totalScore / allEntries.length : 0,
                averageCompletion: allEntries.length > 0 ? totalCompletion / allEntries.length : 0,
                gradeDistribution,
                currentStreak,
                bestStreak,
                lastPlayedAt: sortedByDate.length > 0 ? sortedByDate[0]!.achievedAt : '',
            };
        },

        getAroundRank(boardId: string, rank: number, radius: number): readonly RankedEntry[] {
            const board = boards.get(boardId);
            if (board === undefined) return [];

            const ranked = rankEntries(board);
            const start = Math.max(0, rank - 1 - radius);
            const end = Math.min(ranked.length, rank + radius);
            return ranked.slice(start, end);
        },

        registerValidator(name: string, fn: (entry: ScoreEntry) => boolean): void {
            if (validators.has(name)) {
                throw new Error(`Validator '${name}' already registered`);
            }
            validators.set(name, fn);
        },

        removeBoard(id: string): boolean {
            return boards.delete(id);
        },

        clear(): void {
            boards.clear();
            validators.clear();
        },
    };
}

function toDateString(iso: string): string {
    return iso.slice(0, 10);
}
