/**
 * VARIANT — Achievement Engine Implementation
 *
 * Evaluates session results against achievement conditions,
 * tracks progress, and manages unlocks.
 *
 * SWAPPABILITY: Implements AchievementEngine. Replace this file.
 */

import type {
    AchievementEngine,
    AchievementDefinition,
    AchievementProgress,
    AchievementCondition,
    SessionResult,
} from './types';

interface MutableProgress {
    unlocked: boolean;
    unlockedAt: string | null;
    progress: number;
    progressDetail: string;
    // Internal tracking
    levelCompletions: number;
    techniqueUses: Map<string, number>;
    metricCounts: Map<string, number>;
    streakCount: number;
}

export function createAchievementEngine(): AchievementEngine {
    const definitions = new Map<string, AchievementDefinition>();
    const progress = new Map<string, MutableProgress>();

    function getOrCreateProgress(id: string): MutableProgress {
        let p = progress.get(id);
        if (p === undefined) {
            p = {
                unlocked: false,
                unlockedAt: null,
                progress: 0,
                progressDetail: '',
                levelCompletions: 0,
                techniqueUses: new Map(),
                metricCounts: new Map(),
                streakCount: 0,
            };
            progress.set(id, p);
        }
        return p;
    }

    function evaluateCondition(condition: AchievementCondition, result: SessionResult, prog: MutableProgress): boolean {
        switch (condition.kind) {
            case 'complete-level': {
                if (result.phase !== 'completed') return false;
                if (condition.levelId !== null && condition.levelId !== result.levelId) return false;
                if (condition.minDifficulty !== null) {
                    const levels = ['beginner', 'easy', 'medium', 'hard', 'expert'];
                    const required = levels.indexOf(condition.minDifficulty);
                    const actual = levels.indexOf(result.difficulty);
                    if (actual < required) return false;
                }
                return true;
            }

            case 'score':
                if (condition.levelId !== null && condition.levelId !== result.levelId) return false;
                return result.score >= condition.minScore;

            case 'stealth':
                if (condition.levelId !== null && condition.levelId !== result.levelId) return false;
                return result.phase === 'completed' && result.noiseLevel <= condition.maxNoise;

            case 'speed':
                if (condition.levelId !== null && condition.levelId !== result.levelId) return false;
                return result.phase === 'completed' && result.durationSeconds <= condition.maxSeconds;

            case 'technique': {
                const count = prog.techniqueUses.get(condition.technique) ?? 0;
                return count >= condition.count;
            }

            case 'count': {
                const count = prog.metricCounts.get(condition.metric) ?? 0;
                return count >= condition.target;
            }

            case 'streak':
                return prog.streakCount >= condition.count;

            case 'compound':
                if (condition.op === 'and') {
                    return condition.conditions.every(c => evaluateCondition(c, result, prog));
                }
                return condition.conditions.some(c => evaluateCondition(c, result, prog));

            case 'custom':
                return false; // Custom conditions need external evaluation
        }
    }

    function computeProgress(condition: AchievementCondition, result: SessionResult, prog: MutableProgress): { progress: number; detail: string } {
        switch (condition.kind) {
            case 'complete-level':
                return {
                    progress: result.phase === 'completed' ? 1 : 0,
                    detail: result.phase === 'completed' ? 'Complete' : 'Not completed',
                };

            case 'score':
                return {
                    progress: Math.min(1, result.score / condition.minScore),
                    detail: `${result.score}/${condition.minScore} points`,
                };

            case 'stealth':
                return {
                    progress: result.noiseLevel <= condition.maxNoise ? 1 : Math.max(0, 1 - (result.noiseLevel - condition.maxNoise) / 100),
                    detail: `Noise: ${result.noiseLevel} (max: ${condition.maxNoise})`,
                };

            case 'speed':
                return {
                    progress: result.durationSeconds <= condition.maxSeconds ? 1 : Math.max(0, 1 - (result.durationSeconds - condition.maxSeconds) / condition.maxSeconds),
                    detail: `${result.durationSeconds}s (max: ${condition.maxSeconds}s)`,
                };

            case 'technique': {
                const count = prog.techniqueUses.get(condition.technique) ?? 0;
                return {
                    progress: Math.min(1, count / condition.count),
                    detail: `${count}/${condition.count} uses`,
                };
            }

            case 'count': {
                const count = prog.metricCounts.get(condition.metric) ?? 0;
                return {
                    progress: Math.min(1, count / condition.target),
                    detail: `${count}/${condition.target}`,
                };
            }

            case 'streak':
                return {
                    progress: Math.min(1, prog.streakCount / condition.count),
                    detail: `${prog.streakCount}/${condition.count} streak`,
                };

            default:
                return { progress: 0, detail: '' };
        }
    }

    function prerequisitesMet(def: AchievementDefinition): boolean {
        for (const prereq of def.prerequisites) {
            const p = progress.get(prereq);
            if (p === undefined || !p.unlocked) return false;
        }
        return true;
    }

    return {
        loadDefinitions(defs: readonly AchievementDefinition[]): void {
            for (const d of defs) {
                definitions.set(d.id, d);
                getOrCreateProgress(d.id); // Ensure state exists
            }
        },

        getDefinitions(): readonly AchievementDefinition[] {
            return [...definitions.values()];
        },

        getByCategory(category: string): readonly AchievementDefinition[] {
            return [...definitions.values()].filter(d => d.category === category);
        },

        getDefinition(id: string): AchievementDefinition | null {
            return definitions.get(id) ?? null;
        },

        getProgress(id: string): AchievementProgress | null {
            const p = progress.get(id);
            if (p === undefined) return null;
            return {
                achievementId: id,
                unlocked: p.unlocked,
                unlockedAt: p.unlockedAt,
                progress: p.progress,
                progressDetail: p.progressDetail,
            };
        },

        getAllProgress(): readonly AchievementProgress[] {
            const result: AchievementProgress[] = [];
            for (const [id, p] of progress) {
                result.push({
                    achievementId: id,
                    unlocked: p.unlocked,
                    unlockedAt: p.unlockedAt,
                    progress: p.progress,
                    progressDetail: p.progressDetail,
                });
            }
            return result;
        },

        getUnlocked(): readonly AchievementProgress[] {
            return this.getAllProgress().filter(p => p.unlocked);
        },

        getTotalPoints(): number {
            let total = 0;
            for (const [id, p] of progress) {
                if (p.unlocked) {
                    const def = definitions.get(id);
                    if (def !== undefined) total += def.points;
                }
            }
            return total;
        },

        evaluateSession(result: SessionResult): readonly string[] {
            const newlyUnlocked: string[] = [];

            // Update technique tracking
            for (const technique of result.techniquesUsed) {
                for (const p of progress.values()) {
                    const count = p.techniqueUses.get(technique) ?? 0;
                    p.techniqueUses.set(technique, count + 1);
                }
            }

            // Update level completion count
            if (result.phase === 'completed') {
                for (const p of progress.values()) {
                    p.levelCompletions++;
                    p.metricCounts.set('levels-completed', p.levelCompletions);
                }
            }

            // Evaluate each achievement
            for (const [id, def] of definitions) {
                const p = getOrCreateProgress(id);
                if (p.unlocked) continue;

                // Check prerequisites
                if (!prerequisitesMet(def)) continue;

                // Compute progress
                const { progress: prog, detail } = computeProgress(def.condition, result, p);
                p.progress = prog;
                p.progressDetail = detail;

                // Check if condition is met
                if (evaluateCondition(def.condition, result, p)) {
                    p.unlocked = true;
                    p.unlockedAt = new Date().toISOString();
                    p.progress = 1;
                    newlyUnlocked.push(id);
                }
            }

            return newlyUnlocked;
        },

        unlock(id: string): boolean {
            const def = definitions.get(id);
            if (def === undefined) return false;

            const p = getOrCreateProgress(id);
            if (p.unlocked) return false;

            p.unlocked = true;
            p.unlockedAt = new Date().toISOString();
            p.progress = 1;
            return true;
        },

        reset(): void {
            progress.clear();
            // Re-create progress entries for all definitions
            for (const id of definitions.keys()) {
                getOrCreateProgress(id);
            }
        },
    };
}
