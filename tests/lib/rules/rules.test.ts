/**
 * VARIANT — Rule Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createRuleEngine } from '../../../src/lib/rules/rule-engine';
import type { RuleDefinition, RuleCondition, FactSet } from '../../../src/lib/rules/types';

function makeRule(overrides: Partial<RuleDefinition> & { id: string }): RuleDefinition {
    return {
        name: overrides.id,
        evaluationMode: 'continuous',
        condition: { type: 'compare', fact: 'score', operator: '>=', value: 100 },
        actions: [{ type: 'emit-event', params: { event: 'test' } }],
        ...overrides,
    };
}

describe('RuleEngine', () => {
    it('adds and retrieves rules', () => {
        const engine = createRuleEngine();
        engine.addRule(makeRule({ id: 'rule-1' }));

        expect(engine.getRule('rule-1')).toBeTruthy();
        expect(engine.getRule('nonexistent')).toBeUndefined();
        expect(engine.getAllRules().length).toBe(1);
    });

    it('throws on duplicate rule ID', () => {
        const engine = createRuleEngine();
        engine.addRule(makeRule({ id: 'rule-1' }));
        expect(() => engine.addRule(makeRule({ id: 'rule-1' }))).toThrow();
    });

    it('removes rules', () => {
        const engine = createRuleEngine();
        engine.addRule(makeRule({ id: 'rule-1' }));

        expect(engine.removeRule('rule-1')).toBe(true);
        expect(engine.removeRule('nonexistent')).toBe(false);
        expect(engine.getAllRules().length).toBe(0);
    });

    it('evaluates compare == condition', () => {
        const engine = createRuleEngine();
        const cond: RuleCondition = { type: 'compare', fact: 'status', operator: '==', value: 'active' };

        expect(engine.evaluateCondition(cond, { status: 'active' })).toBe(true);
        expect(engine.evaluateCondition(cond, { status: 'inactive' })).toBe(false);
    });

    it('evaluates compare != condition', () => {
        const engine = createRuleEngine();
        const cond: RuleCondition = { type: 'compare', fact: 'status', operator: '!=', value: 'blocked' };

        expect(engine.evaluateCondition(cond, { status: 'active' })).toBe(true);
        expect(engine.evaluateCondition(cond, { status: 'blocked' })).toBe(false);
    });

    it('evaluates numeric comparisons', () => {
        const engine = createRuleEngine();
        const facts: FactSet = { score: 75 };

        expect(engine.evaluateCondition({ type: 'compare', fact: 'score', operator: '>', value: 50 }, facts)).toBe(true);
        expect(engine.evaluateCondition({ type: 'compare', fact: 'score', operator: '<', value: 50 }, facts)).toBe(false);
        expect(engine.evaluateCondition({ type: 'compare', fact: 'score', operator: '>=', value: 75 }, facts)).toBe(true);
        expect(engine.evaluateCondition({ type: 'compare', fact: 'score', operator: '<=', value: 75 }, facts)).toBe(true);
    });

    it('evaluates AND condition', () => {
        const engine = createRuleEngine();
        const cond: RuleCondition = {
            type: 'and',
            conditions: [
                { type: 'compare', fact: 'a', operator: '==', value: 1 },
                { type: 'compare', fact: 'b', operator: '==', value: 2 },
            ],
        };

        expect(engine.evaluateCondition(cond, { a: 1, b: 2 })).toBe(true);
        expect(engine.evaluateCondition(cond, { a: 1, b: 3 })).toBe(false);
    });

    it('evaluates OR condition', () => {
        const engine = createRuleEngine();
        const cond: RuleCondition = {
            type: 'or',
            conditions: [
                { type: 'compare', fact: 'a', operator: '==', value: 1 },
                { type: 'compare', fact: 'b', operator: '==', value: 2 },
            ],
        };

        expect(engine.evaluateCondition(cond, { a: 1, b: 0 })).toBe(true);
        expect(engine.evaluateCondition(cond, { a: 0, b: 2 })).toBe(true);
        expect(engine.evaluateCondition(cond, { a: 0, b: 0 })).toBe(false);
    });

    it('evaluates NOT condition', () => {
        const engine = createRuleEngine();
        const cond: RuleCondition = {
            type: 'not',
            conditions: [
                { type: 'compare', fact: 'blocked', operator: '==', value: true },
            ],
        };

        expect(engine.evaluateCondition(cond, { blocked: false })).toBe(true);
        expect(engine.evaluateCondition(cond, { blocked: true })).toBe(false);
    });

    it('evaluates exists condition', () => {
        const engine = createRuleEngine();
        const cond: RuleCondition = { type: 'exists', fact: 'token' };

        expect(engine.evaluateCondition(cond, { token: 'abc' })).toBe(true);
        expect(engine.evaluateCondition(cond, {})).toBe(false);
    });

    it('evaluates contains condition on string', () => {
        const engine = createRuleEngine();
        const cond: RuleCondition = { type: 'contains', fact: 'command', value: 'passwd' };

        expect(engine.evaluateCondition(cond, { command: 'cat /etc/passwd' })).toBe(true);
        expect(engine.evaluateCondition(cond, { command: 'ls -la' })).toBe(false);
    });

    it('evaluates contains condition on array', () => {
        const engine = createRuleEngine();
        const cond: RuleCondition = { type: 'contains', fact: 'tags', value: 'admin' };

        expect(engine.evaluateCondition(cond, { tags: ['user', 'admin'] })).toBe(true);
        expect(engine.evaluateCondition(cond, { tags: ['user', 'guest'] })).toBe(false);
    });

    it('evaluates match (regex) condition', () => {
        const engine = createRuleEngine();
        const cond: RuleCondition = { type: 'match', fact: 'input', pattern: '^SELECT.*FROM', flags: 'i' };

        expect(engine.evaluateCondition(cond, { input: 'select * from users' })).toBe(true);
        expect(engine.evaluateCondition(cond, { input: 'INSERT INTO users' })).toBe(false);
    });

    it('evaluates continuous rules', () => {
        const engine = createRuleEngine();
        engine.addRule(makeRule({
            id: 'high-score',
            evaluationMode: 'continuous',
            condition: { type: 'compare', fact: 'score', operator: '>=', value: 100 },
        }));

        const low = engine.evaluate({ score: 50 });
        expect(low.length).toBe(0);

        const high = engine.evaluate({ score: 150 });
        expect(high.length).toBe(1);
        expect(high[0]!.ruleId).toBe('high-score');
    });

    it('non-repeatable rules fire only once', () => {
        const engine = createRuleEngine();
        engine.addRule(makeRule({
            id: 'once',
            repeatable: false,
            condition: { type: 'compare', fact: 'x', operator: '==', value: 1 },
        }));

        const first = engine.evaluate({ x: 1 });
        expect(first.length).toBe(1);

        const second = engine.evaluate({ x: 1 });
        expect(second.length).toBe(0);
    });

    it('repeatable rules fire every time', () => {
        const engine = createRuleEngine();
        engine.addRule(makeRule({
            id: 'always',
            repeatable: true,
            condition: { type: 'compare', fact: 'x', operator: '==', value: 1 },
        }));

        expect(engine.evaluate({ x: 1 }).length).toBe(1);
        expect(engine.evaluate({ x: 1 }).length).toBe(1);
        expect(engine.evaluate({ x: 1 }).length).toBe(1);
    });

    it('disabled rules do not fire', () => {
        const engine = createRuleEngine();
        engine.addRule(makeRule({
            id: 'disabled',
            enabled: false,
            condition: { type: 'compare', fact: 'x', operator: '==', value: 1 },
        }));

        expect(engine.evaluate({ x: 1 }).length).toBe(0);
    });

    it('enables/disables rules at runtime', () => {
        const engine = createRuleEngine();
        engine.addRule(makeRule({
            id: 'togglable',
            enabled: false,
            repeatable: true,
            condition: { type: 'compare', fact: 'x', operator: '==', value: 1 },
        }));

        expect(engine.evaluate({ x: 1 }).length).toBe(0);

        engine.setRuleEnabled('togglable', true);
        expect(engine.evaluate({ x: 1 }).length).toBe(1);

        engine.setRuleEnabled('togglable', false);
        expect(engine.evaluate({ x: 1 }).length).toBe(0);
    });

    it('setRuleEnabled returns false for unknown rule', () => {
        const engine = createRuleEngine();
        expect(engine.setRuleEnabled('nonexistent', true)).toBe(false);
    });

    it('evaluates event-triggered rules', () => {
        const engine = createRuleEngine();
        engine.addRule(makeRule({
            id: 'on-login',
            evaluationMode: 'event',
            triggerEvents: ['auth:login'],
            condition: { type: 'compare', fact: 'success', operator: '==', value: false },
        }));

        // Should not fire on continuous evaluate
        expect(engine.evaluate({ success: false }).length).toBe(0);

        // Should fire on matching event
        expect(engine.evaluateForEvent('auth:login', { success: false }).length).toBe(1);

        // Should not fire on non-matching event
        expect(engine.evaluateForEvent('fs:read', { success: false }).length).toBe(0);
    });

    it('respects priority ordering', () => {
        const engine = createRuleEngine();
        const fired: string[] = [];

        engine.registerActionHandler('track', (params) => {
            fired.push(params['id'] as string);
        });

        engine.addRule(makeRule({
            id: 'low',
            priority: 1,
            repeatable: true,
            condition: { type: 'compare', fact: 'x', operator: '==', value: 1 },
            actions: [{ type: 'track', params: { id: 'low' } }],
        }));

        engine.addRule(makeRule({
            id: 'high',
            priority: 10,
            repeatable: true,
            condition: { type: 'compare', fact: 'x', operator: '==', value: 1 },
            actions: [{ type: 'track', params: { id: 'high' } }],
        }));

        engine.evaluate({ x: 1 });
        expect(fired[0]).toBe('high');
        expect(fired[1]).toBe('low');
    });

    it('registers and uses custom condition', () => {
        const engine = createRuleEngine();
        engine.registerConditionType('is-even', (params, facts) => {
            const value = facts[params['fact'] as string];
            return typeof value === 'number' && value % 2 === 0;
        });

        const cond: RuleCondition = { type: 'custom', name: 'is-even', params: { fact: 'count' } };
        expect(engine.evaluateCondition(cond, { count: 4 })).toBe(true);
        expect(engine.evaluateCondition(cond, { count: 3 })).toBe(false);
    });

    it('throws on duplicate custom condition', () => {
        const engine = createRuleEngine();
        engine.registerConditionType('test', () => true);
        expect(() => engine.registerConditionType('test', () => true)).toThrow();
    });

    it('registers and uses action handler', () => {
        const engine = createRuleEngine();
        const executed: string[] = [];

        engine.registerActionHandler('log', (params) => {
            executed.push(params['message'] as string);
        });

        engine.addRule(makeRule({
            id: 'logger',
            condition: { type: 'compare', fact: 'x', operator: '==', value: 1 },
            actions: [{ type: 'log', params: { message: 'Rule fired!' } }],
        }));

        engine.evaluate({ x: 1 });
        expect(executed).toEqual(['Rule fired!']);
    });

    it('throws on duplicate action handler', () => {
        const engine = createRuleEngine();
        engine.registerActionHandler('test', () => {});
        expect(() => engine.registerActionHandler('test', () => {})).toThrow();
    });

    it('resets fired state', () => {
        const engine = createRuleEngine();
        engine.addRule(makeRule({
            id: 'once',
            repeatable: false,
            condition: { type: 'compare', fact: 'x', operator: '==', value: 1 },
        }));

        engine.evaluate({ x: 1 });
        expect(engine.evaluate({ x: 1 }).length).toBe(0);

        engine.reset();
        expect(engine.evaluate({ x: 1 }).length).toBe(1);
    });

    it('returns false for missing fact in comparison', () => {
        const engine = createRuleEngine();
        const cond: RuleCondition = { type: 'compare', fact: 'missing', operator: '==', value: 1 };
        expect(engine.evaluateCondition(cond, {})).toBe(false);
    });

    it('unknown custom condition returns false', () => {
        const engine = createRuleEngine();
        const cond: RuleCondition = { type: 'custom', name: 'nonexistent', params: {} };
        expect(engine.evaluateCondition(cond, {})).toBe(false);
    });

    it('deeply nested conditions', () => {
        const engine = createRuleEngine();
        const cond: RuleCondition = {
            type: 'and',
            conditions: [
                {
                    type: 'or',
                    conditions: [
                        { type: 'compare', fact: 'a', operator: '==', value: 1 },
                        { type: 'compare', fact: 'b', operator: '==', value: 2 },
                    ],
                },
                { type: 'not', conditions: [{ type: 'compare', fact: 'blocked', operator: '==', value: true }] },
            ],
        };

        expect(engine.evaluateCondition(cond, { a: 1, blocked: false })).toBe(true);
        expect(engine.evaluateCondition(cond, { a: 0, b: 2, blocked: false })).toBe(true);
        expect(engine.evaluateCondition(cond, { a: 1, blocked: true })).toBe(false);
        expect(engine.evaluateCondition(cond, { a: 0, b: 0, blocked: false })).toBe(false);
    });
});
