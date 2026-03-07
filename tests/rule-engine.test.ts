import { describe, it, expect, vi } from 'vitest';
import { createRuleEngine } from '../src/lib/rules/rule-engine';
import type { RuleDefinition, RuleCondition, FactSet } from '../src/lib/rules/types';

// ── Helpers ─────────────────────────────────────────────────

function makeRule(overrides: Partial<RuleDefinition> & { id: string; condition: RuleCondition }): RuleDefinition {
    return {
        name: overrides.id,
        evaluationMode: 'continuous',
        actions: [{ type: 'test-action', params: {} }],
        ...overrides,
    };
}

// ── Condition Evaluation ────────────────────────────────────

describe('Rule Engine', () => {
    describe('Comparison Conditions', () => {
        it('evaluates == correctly', () => {
            const engine = createRuleEngine();
            const facts: FactSet = { status: 'active', count: 5 };

            expect(engine.evaluateCondition(
                { type: 'compare', fact: 'status', operator: '==', value: 'active' }, facts,
            )).toBe(true);
            expect(engine.evaluateCondition(
                { type: 'compare', fact: 'status', operator: '==', value: 'inactive' }, facts,
            )).toBe(false);
        });

        it('evaluates != correctly', () => {
            const engine = createRuleEngine();
            expect(engine.evaluateCondition(
                { type: 'compare', fact: 'x', operator: '!=', value: 10 },
                { x: 5 },
            )).toBe(true);
        });

        it('evaluates numeric comparisons', () => {
            const engine = createRuleEngine();
            const facts: FactSet = { score: 75 };

            expect(engine.evaluateCondition(
                { type: 'compare', fact: 'score', operator: '>', value: 50 }, facts,
            )).toBe(true);
            expect(engine.evaluateCondition(
                { type: 'compare', fact: 'score', operator: '<', value: 50 }, facts,
            )).toBe(false);
            expect(engine.evaluateCondition(
                { type: 'compare', fact: 'score', operator: '>=', value: 75 }, facts,
            )).toBe(true);
            expect(engine.evaluateCondition(
                { type: 'compare', fact: 'score', operator: '<=', value: 75 }, facts,
            )).toBe(true);
        });

        it('returns false for missing facts', () => {
            const engine = createRuleEngine();
            expect(engine.evaluateCondition(
                { type: 'compare', fact: 'missing', operator: '==', value: 'x' }, {},
            )).toBe(false);
        });
    });

    describe('Logical Conditions', () => {
        it('evaluates AND (all must be true)', () => {
            const engine = createRuleEngine();
            const facts: FactSet = { a: true, b: true };

            expect(engine.evaluateCondition({
                type: 'and',
                conditions: [
                    { type: 'compare', fact: 'a', operator: '==', value: true },
                    { type: 'compare', fact: 'b', operator: '==', value: true },
                ],
            }, facts)).toBe(true);

            expect(engine.evaluateCondition({
                type: 'and',
                conditions: [
                    { type: 'compare', fact: 'a', operator: '==', value: true },
                    { type: 'compare', fact: 'b', operator: '==', value: false },
                ],
            }, facts)).toBe(false);
        });

        it('evaluates OR (any must be true)', () => {
            const engine = createRuleEngine();
            expect(engine.evaluateCondition({
                type: 'or',
                conditions: [
                    { type: 'compare', fact: 'x', operator: '==', value: 1 },
                    { type: 'compare', fact: 'x', operator: '==', value: 2 },
                ],
            }, { x: 2 })).toBe(true);
        });

        it('evaluates NOT (negates first condition)', () => {
            const engine = createRuleEngine();
            expect(engine.evaluateCondition({
                type: 'not',
                conditions: [
                    { type: 'compare', fact: 'x', operator: '==', value: 5 },
                ],
            }, { x: 3 })).toBe(true);

            expect(engine.evaluateCondition({
                type: 'not',
                conditions: [
                    { type: 'compare', fact: 'x', operator: '==', value: 5 },
                ],
            }, { x: 5 })).toBe(false);
        });

        it('supports deeply nested conditions', () => {
            const engine = createRuleEngine();
            const condition: RuleCondition = {
                type: 'and',
                conditions: [
                    {
                        type: 'or',
                        conditions: [
                            { type: 'compare', fact: 'role', operator: '==', value: 'admin' },
                            { type: 'compare', fact: 'role', operator: '==', value: 'root' },
                        ],
                    },
                    { type: 'compare', fact: 'score', operator: '>=', value: 100 },
                ],
            };

            expect(engine.evaluateCondition(condition, { role: 'admin', score: 150 })).toBe(true);
            expect(engine.evaluateCondition(condition, { role: 'user', score: 150 })).toBe(false);
            expect(engine.evaluateCondition(condition, { role: 'root', score: 50 })).toBe(false);
        });
    });

    describe('Exists Condition', () => {
        it('returns true when fact exists', () => {
            const engine = createRuleEngine();
            expect(engine.evaluateCondition(
                { type: 'exists', fact: 'key' }, { key: 'value' },
            )).toBe(true);
        });

        it('returns false when fact is missing', () => {
            const engine = createRuleEngine();
            expect(engine.evaluateCondition(
                { type: 'exists', fact: 'key' }, {},
            )).toBe(false);
        });

        it('returns false when fact is undefined', () => {
            const engine = createRuleEngine();
            expect(engine.evaluateCondition(
                { type: 'exists', fact: 'key' }, { key: undefined },
            )).toBe(false);
        });
    });

    describe('Contains Condition', () => {
        it('checks string contains', () => {
            const engine = createRuleEngine();
            expect(engine.evaluateCondition(
                { type: 'contains', fact: 'path', value: '/admin' },
                { path: '/api/admin/users' },
            )).toBe(true);
        });

        it('checks array contains', () => {
            const engine = createRuleEngine();
            expect(engine.evaluateCondition(
                { type: 'contains', fact: 'tags', value: 'critical' },
                { tags: ['warning', 'critical', 'security'] },
            )).toBe(true);
        });

        it('returns false for non-containing', () => {
            const engine = createRuleEngine();
            expect(engine.evaluateCondition(
                { type: 'contains', fact: 'text', value: 'missing' },
                { text: 'hello world' },
            )).toBe(false);
        });
    });

    describe('Match Condition', () => {
        it('matches regex patterns', () => {
            const engine = createRuleEngine();
            expect(engine.evaluateCondition(
                { type: 'match', fact: 'input', pattern: '\\d{3}-\\d{4}' },
                { input: 'Call 555-1234' },
            )).toBe(true);
        });

        it('supports case-insensitive flag', () => {
            const engine = createRuleEngine();
            expect(engine.evaluateCondition(
                { type: 'match', fact: 'cmd', pattern: 'select.*from', flags: 'i' },
                { cmd: 'SELECT * FROM users' },
            )).toBe(true);
        });

        it('returns false for non-matching', () => {
            const engine = createRuleEngine();
            expect(engine.evaluateCondition(
                { type: 'match', fact: 'text', pattern: '^\\d+$' },
                { text: 'abc' },
            )).toBe(false);
        });
    });

    describe('Custom Conditions', () => {
        it('delegates to registered evaluator', () => {
            const engine = createRuleEngine();
            engine.registerConditionType('is-even', (params, facts) => {
                const val = facts[params['fact'] as string] as number;
                return val % 2 === 0;
            });

            expect(engine.evaluateCondition(
                { type: 'custom', name: 'is-even', params: { fact: 'count' } },
                { count: 4 },
            )).toBe(true);

            expect(engine.evaluateCondition(
                { type: 'custom', name: 'is-even', params: { fact: 'count' } },
                { count: 3 },
            )).toBe(false);
        });

        it('returns false for unregistered custom conditions', () => {
            const engine = createRuleEngine();
            expect(engine.evaluateCondition(
                { type: 'custom', name: 'unknown', params: {} }, {},
            )).toBe(false);
        });
    });

    // ── Rule Evaluation ─────────────────────────────────────

    describe('Rule Evaluation', () => {
        it('fires matching continuous rules', () => {
            const engine = createRuleEngine();
            engine.addRule(makeRule({
                id: 'high-score',
                condition: { type: 'compare', fact: 'score', operator: '>=', value: 100 },
            }));

            const firings = engine.evaluate({ score: 150 });
            expect(firings.length).toBe(1);
            expect(firings[0]!.ruleId).toBe('high-score');
        });

        it('does not fire non-matching rules', () => {
            const engine = createRuleEngine();
            engine.addRule(makeRule({
                id: 'high-score',
                condition: { type: 'compare', fact: 'score', operator: '>=', value: 100 },
            }));

            const firings = engine.evaluate({ score: 50 });
            expect(firings.length).toBe(0);
        });

        it('fires rules only once by default', () => {
            const engine = createRuleEngine();
            engine.addRule(makeRule({
                id: 'once-rule',
                condition: { type: 'compare', fact: 'x', operator: '==', value: true },
            }));

            expect(engine.evaluate({ x: true }).length).toBe(1);
            expect(engine.evaluate({ x: true }).length).toBe(0);
        });

        it('fires repeatable rules multiple times', () => {
            const engine = createRuleEngine();
            engine.addRule(makeRule({
                id: 'repeat-rule',
                condition: { type: 'compare', fact: 'x', operator: '==', value: true },
                repeatable: true,
            }));

            expect(engine.evaluate({ x: true }).length).toBe(1);
            expect(engine.evaluate({ x: true }).length).toBe(1);
        });

        it('respects rule priority', () => {
            const engine = createRuleEngine();
            engine.addRule(makeRule({
                id: 'low-priority',
                condition: { type: 'compare', fact: 'x', operator: '==', value: true },
                priority: 1,
                repeatable: true,
            }));
            engine.addRule(makeRule({
                id: 'high-priority',
                condition: { type: 'compare', fact: 'x', operator: '==', value: true },
                priority: 10,
                repeatable: true,
            }));

            const firings = engine.evaluate({ x: true });
            expect(firings[0]!.ruleId).toBe('high-priority');
            expect(firings[1]!.ruleId).toBe('low-priority');
        });

        it('skips disabled rules', () => {
            const engine = createRuleEngine();
            engine.addRule(makeRule({
                id: 'disabled',
                condition: { type: 'compare', fact: 'x', operator: '==', value: true },
                enabled: false,
            }));

            expect(engine.evaluate({ x: true }).length).toBe(0);
        });
    });

    describe('Event-Triggered Rules', () => {
        it('fires rules matching the event type', () => {
            const engine = createRuleEngine();
            engine.addRule(makeRule({
                id: 'on-login',
                evaluationMode: 'event',
                triggerEvents: ['auth:login'],
                condition: { type: 'compare', fact: 'success', operator: '==', value: false },
            }));

            const firings = engine.evaluateForEvent('auth:login', { success: false });
            expect(firings.length).toBe(1);
        });

        it('ignores rules for different event types', () => {
            const engine = createRuleEngine();
            engine.addRule(makeRule({
                id: 'on-login',
                evaluationMode: 'event',
                triggerEvents: ['auth:login'],
                condition: { type: 'compare', fact: 'x', operator: '==', value: true },
            }));

            const firings = engine.evaluateForEvent('fs:write', { x: true });
            expect(firings.length).toBe(0);
        });

        it('does not fire continuous rules on event evaluation', () => {
            const engine = createRuleEngine();
            engine.addRule(makeRule({
                id: 'continuous',
                evaluationMode: 'continuous',
                condition: { type: 'compare', fact: 'x', operator: '==', value: true },
            }));

            const firings = engine.evaluateForEvent('any', { x: true });
            expect(firings.length).toBe(0);
        });
    });

    // ── Rule Management ─────────────────────────────────────

    describe('Rule Management', () => {
        it('adds and retrieves rules', () => {
            const engine = createRuleEngine();
            const rule = makeRule({
                id: 'test',
                condition: { type: 'exists', fact: 'x' },
            });
            engine.addRule(rule);
            expect(engine.getRule('test')).toEqual(rule);
        });

        it('rejects duplicate IDs', () => {
            const engine = createRuleEngine();
            engine.addRule(makeRule({ id: 'dup', condition: { type: 'exists', fact: 'x' } }));
            expect(() => engine.addRule(
                makeRule({ id: 'dup', condition: { type: 'exists', fact: 'y' } }),
            )).toThrow();
        });

        it('removes rules', () => {
            const engine = createRuleEngine();
            engine.addRule(makeRule({ id: 'rem', condition: { type: 'exists', fact: 'x' } }));
            expect(engine.removeRule('rem')).toBe(true);
            expect(engine.getRule('rem')).toBeUndefined();
        });

        it('lists all rules', () => {
            const engine = createRuleEngine();
            engine.addRule(makeRule({ id: 'a', condition: { type: 'exists', fact: 'x' } }));
            engine.addRule(makeRule({ id: 'b', condition: { type: 'exists', fact: 'y' } }));
            expect(engine.getAllRules().length).toBe(2);
        });

        it('enables/disables rules at runtime', () => {
            const engine = createRuleEngine();
            engine.addRule(makeRule({
                id: 'toggle',
                condition: { type: 'compare', fact: 'x', operator: '==', value: true },
                repeatable: true,
            }));

            expect(engine.evaluate({ x: true }).length).toBe(1);
            engine.setRuleEnabled('toggle', false);
            expect(engine.evaluate({ x: true }).length).toBe(0);
            engine.setRuleEnabled('toggle', true);
            expect(engine.evaluate({ x: true }).length).toBe(1);
        });

        it('resets fired rules', () => {
            const engine = createRuleEngine();
            engine.addRule(makeRule({
                id: 'once',
                condition: { type: 'compare', fact: 'x', operator: '==', value: true },
            }));

            engine.evaluate({ x: true });
            expect(engine.evaluate({ x: true }).length).toBe(0);

            engine.reset();
            expect(engine.evaluate({ x: true }).length).toBe(1);
        });
    });

    // ── Action Handlers ─────────────────────────────────────

    describe('Action Handlers', () => {
        it('calls registered action handler on rule firing', () => {
            const engine = createRuleEngine();
            const handler = vi.fn();
            engine.registerActionHandler('score-points', handler);

            engine.addRule(makeRule({
                id: 'score',
                condition: { type: 'compare', fact: 'x', operator: '==', value: true },
                actions: [{ type: 'score-points', params: { points: 100 } }],
            }));

            engine.evaluate({ x: true });
            expect(handler).toHaveBeenCalledWith({ points: 100 }, { x: true });
        });

        it('rejects duplicate action handler registration', () => {
            const engine = createRuleEngine();
            engine.registerActionHandler('test', vi.fn());
            expect(() => engine.registerActionHandler('test', vi.fn())).toThrow();
        });
    });
});
