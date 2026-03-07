/**
 * VARIANT — Event Correlation Engine Implementation
 *
 * SWAPPABILITY: Replace this file. The CorrelationEngine interface is stable.
 */

import type {
    CorrelationEngine,
    CorrelationRule,
    CorrelationEvent,
    CorrelationMatch,
    SequenceStrategy,
    ThresholdStrategy,
    UniqueStrategy,
    StepCondition,
} from './types';

export function createCorrelationEngine(): CorrelationEngine {
    const rules = new Map<string, CorrelationRule>();
    const eventWindows = new Map<string, CorrelationEvent[]>();
    const matchHistory: CorrelationMatch[] = [];
    const firedRules = new Set<string>();
    const lastFired = new Map<string, number>();
    const actionHandlers = new Map<string, (params: Readonly<Record<string, unknown>>, match: CorrelationMatch) => void>();

    // Sequence progress: ruleId → current step index
    const sequenceProgress = new Map<string, number>();

    function pruneWindow(windowKey: string, nowMs: number, windowMs: number): CorrelationEvent[] {
        let events = eventWindows.get(windowKey);
        if (events === undefined) {
            events = [];
            eventWindows.set(windowKey, events);
        }

        const cutoff = nowMs - windowMs;
        while (events.length > 0 && events[0]!.timestamp < cutoff) {
            events.shift();
        }

        return events;
    }

    function checkConditions(
        event: CorrelationEvent,
        conditions: readonly StepCondition[] | undefined,
    ): boolean {
        if (conditions === undefined || conditions.length === 0) return true;

        for (const cond of conditions) {
            const val = event.fields[cond.field];
            switch (cond.operator) {
                case '==':
                    if (val !== cond.value) return false;
                    break;
                case '!=':
                    if (val === cond.value) return false;
                    break;
                case 'contains':
                    if (typeof val !== 'string' || !val.includes(String(cond.value))) return false;
                    break;
                case 'matches':
                    if (typeof val !== 'string' || !new RegExp(String(cond.value)).test(val)) return false;
                    break;
            }
        }
        return true;
    }

    function matchesEventType(eventType: string, pattern: string): boolean {
        if (pattern.endsWith('*')) {
            return eventType.startsWith(pattern.slice(0, -1));
        }
        return eventType === pattern;
    }

    function evaluateSequence(
        rule: CorrelationRule,
        strategy: SequenceStrategy,
        event: CorrelationEvent,
        events: CorrelationEvent[],
    ): CorrelationMatch | null {
        const currentStep = sequenceProgress.get(rule.id) ?? 0;
        const step = strategy.steps[currentStep];
        if (step === undefined) return null;

        if (!matchesEventType(event.type, step.eventType)) return null;
        if (!checkConditions(event, step.conditions)) return null;

        const nextStep = currentStep + 1;
        if (nextStep >= strategy.steps.length) {
            // All steps matched — fire!
            sequenceProgress.set(rule.id, 0);
            return createMatch(rule, events);
        }

        sequenceProgress.set(rule.id, nextStep);
        return null;
    }

    function evaluateThreshold(
        rule: CorrelationRule,
        strategy: ThresholdStrategy,
        event: CorrelationEvent,
        events: CorrelationEvent[],
    ): CorrelationMatch | null {
        if (!matchesEventType(event.type, strategy.eventType)) return null;
        if (!checkConditions(event, strategy.conditions)) return null;

        if (strategy.groupBy !== undefined) {
            const groupValue = event.fields[strategy.groupBy];
            const groupKey = String(groupValue);
            const matching = events.filter(e =>
                matchesEventType(e.type, strategy.eventType) &&
                String(e.fields[strategy.groupBy!]) === groupKey &&
                checkConditions(e, strategy.conditions),
            );
            if (matching.length >= strategy.threshold) {
                return createMatch(rule, matching);
            }
        } else {
            const matching = events.filter(e =>
                matchesEventType(e.type, strategy.eventType) &&
                checkConditions(e, strategy.conditions),
            );
            if (matching.length >= strategy.threshold) {
                return createMatch(rule, matching);
            }
        }

        return null;
    }

    function evaluateUnique(
        rule: CorrelationRule,
        strategy: UniqueStrategy,
        event: CorrelationEvent,
        events: CorrelationEvent[],
    ): CorrelationMatch | null {
        if (!matchesEventType(event.type, strategy.eventType)) return null;

        const matching = events.filter(e => matchesEventType(e.type, strategy.eventType));

        if (strategy.groupBy !== undefined) {
            const groupValue = event.fields[strategy.groupBy];
            const groupKey = String(groupValue);
            const grouped = matching.filter(e =>
                String(e.fields[strategy.groupBy!]) === groupKey,
            );
            const unique = new Set(grouped.map(e => String(e.fields[strategy.uniqueField])));
            if (unique.size >= strategy.threshold) {
                return createMatch(rule, grouped);
            }
        } else {
            const unique = new Set(matching.map(e => String(e.fields[strategy.uniqueField])));
            if (unique.size >= strategy.threshold) {
                return createMatch(rule, matching);
            }
        }

        return null;
    }

    function createMatch(
        rule: CorrelationRule,
        events: readonly CorrelationEvent[],
    ): CorrelationMatch {
        return {
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity ?? 'medium',
            matchedEvents: events,
            timestamp: Date.now(),
            actions: rule.actions,
        };
    }

    function canFire(rule: CorrelationRule, nowMs: number): boolean {
        if (rule.enabled === false) return false;
        if (rule.repeatable === false && firedRules.has(rule.id)) return false;

        if (rule.cooldownMs !== undefined && rule.cooldownMs > 0) {
            const last = lastFired.get(rule.id);
            if (last !== undefined && nowMs - last < rule.cooldownMs) return false;
        }

        return true;
    }

    const engine: CorrelationEngine = {
        addRule(rule: CorrelationRule): void {
            if (rules.has(rule.id)) {
                throw new Error(`CorrelationEngine: rule '${rule.id}' already exists`);
            }
            rules.set(rule.id, rule);
        },

        removeRule(id: string): boolean {
            sequenceProgress.delete(id);
            return rules.delete(id);
        },

        getRules(): readonly CorrelationRule[] {
            return [...rules.values()];
        },

        setRuleEnabled(id: string, enabled: boolean): boolean {
            const rule = rules.get(id);
            if (rule === undefined) return false;
            rules.set(id, { ...rule, enabled });
            return true;
        },

        processEvent(event: CorrelationEvent): readonly CorrelationMatch[] {
            const matches: CorrelationMatch[] = [];
            const nowMs = event.timestamp;

            for (const rule of rules.values()) {
                if (!canFire(rule, nowMs)) continue;

                // Add event to this rule's window
                const windowKey = rule.id;
                const events = pruneWindow(windowKey, nowMs, rule.windowMs);
                events.push(event);

                let match: CorrelationMatch | null = null;

                switch (rule.strategy.type) {
                    case 'sequence':
                        match = evaluateSequence(rule, rule.strategy, event, events);
                        break;
                    case 'threshold':
                        match = evaluateThreshold(rule, rule.strategy, event, events);
                        break;
                    case 'unique':
                        match = evaluateUnique(rule, rule.strategy, event, events);
                        break;
                }

                if (match !== null) {
                    firedRules.add(rule.id);
                    lastFired.set(rule.id, nowMs);
                    matchHistory.push(match);
                    matches.push(match);

                    // Execute action handlers
                    for (const action of match.actions) {
                        const handler = actionHandlers.get(action.type);
                        if (handler !== undefined) {
                            handler(action.params, match);
                        }
                    }
                }
            }

            return matches;
        },

        getRecentMatches(limit?: number): readonly CorrelationMatch[] {
            if (limit === undefined) return [...matchHistory];
            return matchHistory.slice(-limit);
        },

        reset(): void {
            eventWindows.clear();
            matchHistory.length = 0;
            firedRules.clear();
            lastFired.clear();
            sequenceProgress.clear();
        },

        registerActionHandler(type, handler): void {
            if (actionHandlers.has(type)) {
                throw new Error(`CorrelationEngine: action handler '${type}' already registered`);
            }
            actionHandlers.set(type, handler);
        },
    };

    return engine;
}
