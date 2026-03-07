/**
 * VARIANT — Rule Engine Implementation
 *
 * Evaluates declarative rules against fact sets.
 * All conditions are pure data — no code execution.
 *
 * SWAPPABILITY: Replace this file. The RuleEngine interface is stable.
 */

import type {
    RuleEngine,
    RuleDefinition,
    RuleCondition,
    RuleFiring,
    FactSet,
    CustomConditionEvaluator,
    ActionHandler,
} from './types';

export function createRuleEngine(): RuleEngine {
    const rules = new Map<string, RuleDefinition>();
    const firedRules = new Set<string>();
    const customConditions = new Map<string, CustomConditionEvaluator>();
    const actionHandlers = new Map<string, ActionHandler>();

    function evaluateCondition(condition: RuleCondition, facts: FactSet): boolean {
        switch (condition.type) {
            case 'compare': {
                const factValue = facts[condition.fact];
                if (factValue === undefined) return false;

                switch (condition.operator) {
                    case '==': return factValue === condition.value;
                    case '!=': return factValue !== condition.value;
                    case '>': return (factValue as number) > (condition.value as number);
                    case '<': return (factValue as number) < (condition.value as number);
                    case '>=': return (factValue as number) >= (condition.value as number);
                    case '<=': return (factValue as number) <= (condition.value as number);
                }
                return false;
            }

            case 'and':
                return condition.conditions.every(c => evaluateCondition(c, facts));

            case 'or':
                return condition.conditions.some(c => evaluateCondition(c, facts));

            case 'not':
                return condition.conditions.length > 0
                    ? !evaluateCondition(condition.conditions[0]!, facts)
                    : false;

            case 'exists':
                return condition.fact in facts && facts[condition.fact] !== undefined;

            case 'contains': {
                const val = facts[condition.fact];
                if (typeof val === 'string') {
                    return val.includes(String(condition.value));
                }
                if (Array.isArray(val)) {
                    return val.includes(condition.value);
                }
                return false;
            }

            case 'match': {
                const val = facts[condition.fact];
                if (typeof val !== 'string') return false;
                const regex = new RegExp(condition.pattern, condition.flags ?? '');
                return regex.test(val);
            }

            case 'custom': {
                const evaluator = customConditions.get(condition.name);
                if (evaluator === undefined) return false;
                return evaluator(condition.params, facts);
            }
        }
    }

    function evaluateRule(
        rule: RuleDefinition,
        facts: FactSet,
    ): RuleFiring | null {
        if (rule.enabled === false) return null;
        if (!rule.repeatable && firedRules.has(rule.id)) return null;

        if (!evaluateCondition(rule.condition, facts)) return null;

        firedRules.add(rule.id);

        // Execute action handlers
        for (const action of rule.actions) {
            const handler = actionHandlers.get(action.type);
            if (handler !== undefined) {
                handler(action.params, facts);
            }
        }

        return {
            ruleId: rule.id,
            actions: rule.actions,
            timestamp: Date.now(),
        };
    }

    function getRulesSorted(): RuleDefinition[] {
        return [...rules.values()].sort(
            (a, b) => (b.priority ?? 0) - (a.priority ?? 0),
        );
    }

    const engine: RuleEngine = {
        addRule(rule: RuleDefinition): void {
            if (rules.has(rule.id)) {
                throw new Error(`RuleEngine: rule '${rule.id}' already exists`);
            }
            rules.set(rule.id, rule);
        },

        removeRule(id: string): boolean {
            return rules.delete(id);
        },

        getRule(id: string): RuleDefinition | undefined {
            return rules.get(id);
        },

        getAllRules(): readonly RuleDefinition[] {
            return [...rules.values()];
        },

        setRuleEnabled(id: string, enabled: boolean): boolean {
            const rule = rules.get(id);
            if (rule === undefined) return false;
            // Replace with updated rule (immutable pattern)
            rules.set(id, { ...rule, enabled });
            return true;
        },

        evaluate(facts: FactSet): readonly RuleFiring[] {
            const firings: RuleFiring[] = [];
            for (const rule of getRulesSorted()) {
                if (rule.evaluationMode !== 'continuous') continue;
                const firing = evaluateRule(rule, facts);
                if (firing !== null) firings.push(firing);
            }
            return firings;
        },

        evaluateForEvent(eventType: string, facts: FactSet): readonly RuleFiring[] {
            const firings: RuleFiring[] = [];
            for (const rule of getRulesSorted()) {
                if (rule.evaluationMode !== 'event') continue;
                if (rule.triggerEvents !== undefined &&
                    !rule.triggerEvents.includes(eventType)) continue;
                const firing = evaluateRule(rule, facts);
                if (firing !== null) firings.push(firing);
            }
            return firings;
        },

        evaluateCondition(condition: RuleCondition, facts: FactSet): boolean {
            return evaluateCondition(condition, facts);
        },

        reset(): void {
            firedRules.clear();
        },

        registerConditionType(
            name: string,
            evaluator: CustomConditionEvaluator,
        ): void {
            if (customConditions.has(name)) {
                throw new Error(`RuleEngine: custom condition '${name}' already registered`);
            }
            customConditions.set(name, evaluator);
        },

        registerActionHandler(
            type: string,
            handler: ActionHandler,
        ): void {
            if (actionHandlers.has(type)) {
                throw new Error(`RuleEngine: action handler '${type}' already registered`);
            }
            actionHandlers.set(type, handler);
        },
    };

    return engine;
}
