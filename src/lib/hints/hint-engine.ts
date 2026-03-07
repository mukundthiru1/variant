/**
 * VARIANT — Hint Engine Implementation
 *
 * Manages hint availability, triggers, cooldowns, and penalties.
 *
 * SWAPPABILITY: Implements HintEngine. Replace this file.
 */

import type {
    HintEngine,
    HintDefinition,
    HintContent,
    HintState,
    HintTrigger,
} from './types';

interface MutableHintState {
    available: boolean;
    used: boolean;
    lastUsedTick: number | null;
    useCount: number;
}

export function createHintEngine(): HintEngine {
    const hints = new Map<string, HintDefinition>();
    const states = new Map<string, MutableHintState>();
    let totalPenalty = 0;

    // Track events seen for EventTrigger evaluation
    const seenEvents = new Map<string, unknown[]>();

    function getOrCreateState(hintId: string): MutableHintState {
        let s = states.get(hintId);
        if (s === undefined) {
            s = { available: false, used: false, lastUsedTick: null, useCount: 0 };
            states.set(hintId, s);
        }
        return s;
    }

    function evaluateSingleTrigger(
        trigger: HintTrigger,
        currentTick: number,
        commandCount: number,
        completedObjectives: ReadonlySet<string>,
    ): boolean {
        switch (trigger.kind) {
            case 'after-ticks':
                return currentTick >= trigger.ticks;

            case 'after-attempts':
                return commandCount >= trigger.attempts;

            case 'after-event': {
                const events = seenEvents.get(trigger.eventType);
                return events !== undefined && events.length > 0;
            }

            case 'after-objective':
                return completedObjectives.has(trigger.objectiveId);

            case 'compound':
                return trigger.conditions.every(c =>
                    evaluateSingleTrigger(c, currentTick, commandCount, completedObjectives),
                );

            case 'custom':
                // Custom triggers are always available unless overridden
                return true;
        }
    }

    return {
        loadHints(hintDefs: readonly HintDefinition[]): void {
            for (const h of hintDefs) {
                hints.set(h.id, h);
                const s = getOrCreateState(h.id);
                // Hints with no trigger are immediately available
                if (h.trigger === null) {
                    s.available = true;
                }
            }
        },

        getHintsForObjective(objectiveId: string | null): readonly HintDefinition[] {
            const result: HintDefinition[] = [];
            for (const h of hints.values()) {
                if (h.objectiveId === objectiveId) {
                    result.push(h);
                }
            }
            return result.sort((a, b) => a.order - b.order);
        },

        getHintState(hintId: string): HintState | null {
            const s = states.get(hintId);
            if (s === undefined) return null;
            return { ...s };
        },

        getAvailableHints(): readonly HintDefinition[] {
            const result: HintDefinition[] = [];
            for (const [id, h] of hints) {
                const s = states.get(id);
                if (s !== undefined && s.available) {
                    result.push(h);
                }
            }
            return result.sort((a, b) => a.order - b.order);
        },

        useHint(hintId: string, currentTick: number): HintContent | null {
            const hint = hints.get(hintId);
            if (hint === undefined) return null;

            const s = getOrCreateState(hintId);
            if (!s.available) return null;

            // Check cooldown
            if (s.lastUsedTick !== null && (currentTick - s.lastUsedTick) < hint.cooldownTicks) {
                return null;
            }

            s.used = true;
            s.lastUsedTick = currentTick;
            s.useCount++;
            totalPenalty += hint.penalty;

            return hint.content;
        },

        evaluateTriggers(
            currentTick: number,
            commandCount: number,
            completedObjectives: ReadonlySet<string>,
        ): void {
            for (const [id, hint] of hints) {
                const s = getOrCreateState(id);
                if (s.available) continue; // Already available

                if (hint.trigger === null) {
                    s.available = true;
                    continue;
                }

                if (evaluateSingleTrigger(hint.trigger, currentTick, commandCount, completedObjectives)) {
                    s.available = true;
                }
            }
        },

        notifyEvent(eventType: string, eventData: unknown): void {
            const events = seenEvents.get(eventType) ?? [];
            events.push(eventData);
            seenEvents.set(eventType, events);
        },

        getTotalPenalty(): number {
            return totalPenalty;
        },

        reset(): void {
            hints.clear();
            states.clear();
            seenEvents.clear();
            totalPenalty = 0;
        },
    };
}
