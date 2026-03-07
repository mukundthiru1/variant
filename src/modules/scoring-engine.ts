/**
 * VARIANT — Scoring Engine Module
 *
 * Calculates and maintains the player's score based on:
 *   - Objective completion rewards
 *   - Time bonus (configurable curve)
 *   - Stealth bonus (based on noise from stealth engine)
 *   - Hint penalties
 *   - Custom scoring rules (via module evaluators)
 *
 * CONFIGURABILITY:
 *   - Time bonus: curve type, par time, bonus amount
 *   - Stealth bonus: noise thresholds, bonus scaling
 *   - Custom scoring rules: third-party evaluators
 *   - All parameters from WorldSpec.scoring
 *
 * SWAPPABILITY: Implements Module interface. Replace this file.
 *
 * SECURITY: Read-only event bus access. Cannot mutate state.
 */

import type { Module, SimulationContext, Capability } from '../core/modules';
import type { Unsubscribe, EventBus } from '../core/events';
import type { ScoringConfig, ObjectiveSpec } from '../core/world/types';

// ── Module ID ──────────────────────────────────────────────────

const MODULE_ID = 'scoring-engine';
const MODULE_VERSION = '2.0.0';

// ── Score Breakdown ─────────────────────────────────────────

/**
 * Detailed score breakdown. Emitted with every score update
 * so the UI can show where points came from.
 */
export interface ScoreBreakdown {
    /** Base score (starts at maxScore). */
    readonly baseScore: number;

    /** Points from objective rewards. */
    readonly objectivePoints: number;

    /** Time bonus points (positive if fast, 0 if slow). */
    readonly timeBonus: number;

    /** Stealth bonus points (based on noise level). */
    readonly stealthBonus: number;

    /** Points deducted from hints. */
    readonly hintPenalty: number;

    /** Points from custom scoring rules. */
    readonly customPoints: number;

    /** Final computed score. */
    readonly totalScore: number;

    /** Current tier based on score. */
    readonly tier: string;

    /** Tier color. */
    readonly tierColor: string;
}

// ── Scoring Engine Config ───────────────────────────────────

export interface ScoringEngineConfig {
    /**
     * Time bonus configuration.
     * parTimeTicks: expected completion time in ticks
     * maxBonus: maximum time bonus points
     * curve: how bonus decays after par time
     */
    readonly timeBonus?: {
        readonly parTimeTicks: number;
        readonly maxBonus: number;
        readonly curve: 'linear' | 'exponential' | 'step' | (string & {});
    };

    /**
     * Stealth bonus configuration.
     * maxBonus: maximum stealth bonus
     * noiseThreshold: noise below this gets full bonus
     * noiseCeiling: noise above this gets zero bonus
     */
    readonly stealthBonus?: {
        readonly maxBonus: number;
        readonly noiseThreshold: number;
        readonly noiseCeiling: number;
    };
}

// ── Factory ────────────────────────────────────────────────────

export function createScoringEngine(engineConfig?: ScoringEngineConfig): Module {
    const eConfig = engineConfig ?? {};
    const unsubscribers: Unsubscribe[] = [];
    let config: ScoringConfig | null = null;
    let objectiveMap = new Map<string, ObjectiveSpec>();
    let startTick = 0;
    let currentTick = 0;
    let totalNoise = 0;
    let objectivePoints = 0;
    let hintsUsedCount = 0;
    let customPoints = 0;

    function computeTimeBonus(): number {
        if (config === null || !config.timeBonus) return 0;

        const timeBonusCfg = eConfig.timeBonus;
        if (timeBonusCfg === undefined) {
            // Default: linear decay, par = 300 ticks (5 min), max 200 points
            return computeTimeBonusWithParams(300, 200, 'linear');
        }

        return computeTimeBonusWithParams(
            timeBonusCfg.parTimeTicks,
            timeBonusCfg.maxBonus,
            timeBonusCfg.curve,
        );
    }

    function computeTimeBonusWithParams(
        parTimeTicks: number,
        maxBonus: number,
        curve: 'linear' | 'exponential' | 'step' | (string & {}),
    ): number {
        const elapsed = currentTick - startTick;
        if (elapsed <= 0) return maxBonus;

        const ratio = elapsed / parTimeTicks;

        switch (curve) {
            case 'linear':
                // Full bonus at par, linearly decrease to 0 at 2x par
                return Math.max(0, Math.round(maxBonus * (2 - ratio)));

            case 'exponential':
                // Exponential decay after par
                return Math.round(maxBonus * Math.exp(-Math.max(0, ratio - 1)));

            case 'step':
                // Step function: full bonus up to par, half at 1.5x, zero at 2x
                if (ratio <= 1) return maxBonus;
                if (ratio <= 1.5) return Math.round(maxBonus * 0.5);
                return 0;

            default:
                // Unknown curve type — fall back to linear
                return Math.max(0, Math.round(maxBonus * (2 - ratio)));
        }
    }

    function computeStealthBonus(): number {
        if (config === null || !config.stealthBonus) return 0;

        const stealthCfg = eConfig.stealthBonus ?? {
            maxBonus: 200,
            noiseThreshold: 50,
            noiseCeiling: 500,
        };

        if (totalNoise <= stealthCfg.noiseThreshold) {
            return stealthCfg.maxBonus;
        }

        if (totalNoise >= stealthCfg.noiseCeiling) {
            return 0;
        }

        const range = stealthCfg.noiseCeiling - stealthCfg.noiseThreshold;
        const excess = totalNoise - stealthCfg.noiseThreshold;
        const ratio = 1 - (excess / range);

        return Math.round(stealthCfg.maxBonus * ratio);
    }

    function computeTotalScore(): number {
        if (config === null) return 0;

        const timeB = computeTimeBonus();
        const stealthB = computeStealthBonus();
        const hintPen = hintsUsedCount * config.hintPenalty;

        return Math.max(0, config.maxScore + objectivePoints + timeB + stealthB + customPoints - hintPen);
    }

    function getTier(score: number): { name: string; color: string } {
        if (config === null || config.tiers.length === 0) {
            return { name: 'UNRANKED', color: '#888888' };
        }

        // Tiers are sorted by minScore descending
        const sorted = [...config.tiers].sort((a, b) => b.minScore - a.minScore);
        for (const tier of sorted) {
            if (score >= tier.minScore) {
                return { name: tier.name, color: tier.color };
            }
        }

        return { name: sorted[sorted.length - 1]?.name ?? 'UNRANKED', color: sorted[sorted.length - 1]?.color ?? '#888888' };
    }

    function buildBreakdown(): ScoreBreakdown {
        const total = computeTotalScore();
        const tier = getTier(total);

        return {
            baseScore: config?.maxScore ?? 0,
            objectivePoints,
            timeBonus: computeTimeBonus(),
            stealthBonus: computeStealthBonus(),
            hintPenalty: hintsUsedCount * (config?.hintPenalty ?? 0),
            customPoints,
            totalScore: total,
            tier: tier.name,
            tierColor: tier.color,
        };
    }

    function emitScoreUpdate(events: EventBus): void {
        events.emit({
            type: 'custom:score-update',
            data: buildBreakdown(),
            timestamp: Date.now(),
        });
    }

    // ── Module interface ──────────────────────────────────────

    const module: Module = {
        id: MODULE_ID,
        type: 'scoring',
        version: MODULE_VERSION,
        description: 'Calculates player score with time bonus, stealth bonus, and custom scoring rules',

        provides: [{ name: 'scoring' }] as readonly Capability[],
        requires: [] as readonly Capability[],

        init(context: SimulationContext): void {
            config = context.world.scoring;
            // Score starts at maxScore, computed dynamically via computeTotalScore()
            startTick = context.tick;
            currentTick = context.tick;
            totalNoise = 0;
            objectivePoints = 0;
            hintsUsedCount = 0;
            customPoints = 0;

            // Build objective lookup
            objectiveMap = new Map();
            for (const obj of context.world.objectives) {
                objectiveMap.set(obj.id, obj);
            }

            // Listen for objective completions
            const objUnsub = context.events.on('objective:complete', (event) => {
                const obj = objectiveMap.get(event.objectiveId);
                if (obj !== undefined && obj.reward !== undefined) {
                    objectivePoints += obj.reward;
                    emitScoreUpdate(context.events);
                }
            });
            unsubscribers.push(objUnsub);

            // Listen for noise events
            if (config.stealthBonus) {
                const noiseUnsub = context.events.on('sim:noise', (event) => {
                    totalNoise += event.amount;
                });
                unsubscribers.push(noiseUnsub);
            }

            // Listen for tick events (for time bonus computation)
            if (config.timeBonus) {
                const tickUnsub = context.events.on('sim:tick', (event) => {
                    currentTick = event.tick;
                });
                unsubscribers.push(tickUnsub);
            }

            // Listen for hint usage
            const hintUnsub = context.events.onPrefix('custom:', (event) => {
                if (event.type === 'custom:hint-used' && config !== null) {
                    hintsUsedCount++;
                    emitScoreUpdate(context.events);
                }

                // Handle score query
                if (event.type === 'custom:score-query') {
                    emitScoreUpdate(context.events);
                }

                // Handle custom scoring events
                if (event.type === 'custom:score-custom-points') {
                    const data = event.data as { points: number } | null;
                    if (data !== null && typeof data === 'object' && typeof data.points === 'number') {
                        customPoints += data.points;
                        emitScoreUpdate(context.events);
                    }
                }
            });
            unsubscribers.push(hintUnsub);

            emitScoreUpdate(context.events);
        },

        onTick(_tick: number, context: SimulationContext): void {
            // Periodically recompute score (time bonus changes every tick)
            if (config?.timeBonus) {
                currentTick = _tick;
                emitScoreUpdate(context.events);
            }
        },

        destroy(): void {
            for (const unsub of unsubscribers) {
                unsub();
            }
            unsubscribers.length = 0;
            // Reset all scoring state
            config = null;
            objectiveMap.clear();
            totalNoise = 0;
            objectivePoints = 0;
            hintsUsedCount = 0;
            customPoints = 0;
        },
    };

    return module;
}
