/**
 * VARIANT — Stealth System tests (NoiseRuleRegistry)
 */
import { describe, it, expect } from 'vitest';
import { createNoiseRuleRegistry, createBuiltinRules } from '../../../src/lib/stealth/stealth-engine';
import type { NoiseRule } from '../../../src/lib/stealth/types';

function rule(id: string, eventPattern: string, category: string = 'reconnaissance', baseNoise: number = 10): NoiseRule {
    return {
        id,
        description: `Rule ${id}`,
        category,
        eventPattern,
        baseNoise,
    };
}

describe('NoiseRuleRegistry', () => {
    it('registers and retrieves rules', () => {
        const reg = createNoiseRuleRegistry();
        reg.register(rule('r1', 'net:connect'));

        expect(reg.get('r1')).not.toBeUndefined();
        expect(reg.get('nonexistent')).toBeUndefined();
        expect(reg.getAll().length).toBe(1);
    });

    it('throws on duplicate rule', () => {
        const reg = createNoiseRuleRegistry();
        reg.register(rule('r1', 'net:connect'));
        expect(() => reg.register(rule('r1', 'other'))).toThrow();
    });

    it('registerAll adds multiple rules', () => {
        const reg = createNoiseRuleRegistry();
        reg.registerAll([
            rule('r1', 'net:connect'),
            rule('r2', 'fs:read'),
            rule('r3', 'auth:login'),
        ]);
        expect(reg.getAll().length).toBe(3);
    });

    it('registerAll throws on duplicate', () => {
        const reg = createNoiseRuleRegistry();
        reg.register(rule('r1', 'net:connect'));
        expect(() => reg.registerAll([rule('r1', 'other')])).toThrow();
    });

    it('getMatchingRules finds exact matches', () => {
        const reg = createNoiseRuleRegistry();
        reg.register(rule('r1', 'net:connect'));
        reg.register(rule('r2', 'fs:read'));

        const matches = reg.getMatchingRules('net:connect');
        expect(matches.length).toBe(1);
        expect(matches[0]!.id).toBe('r1');
    });

    it('getMatchingRules finds prefix wildcard matches', () => {
        const reg = createNoiseRuleRegistry();
        reg.register(rule('r1', 'net:*'));
        reg.register(rule('r2', 'fs:read'));

        const matches = reg.getMatchingRules('net:connect');
        expect(matches.length).toBe(1);
        expect(matches[0]!.id).toBe('r1');
    });

    it('getMatchingRules returns both exact and prefix', () => {
        const reg = createNoiseRuleRegistry();
        reg.register(rule('r1', 'net:connect'));
        reg.register(rule('r2', 'net:*'));

        const matches = reg.getMatchingRules('net:connect');
        expect(matches.length).toBe(2);
    });

    it('getMatchingRules returns empty for no matches', () => {
        const reg = createNoiseRuleRegistry();
        reg.register(rule('r1', 'net:connect'));

        expect(reg.getMatchingRules('auth:login').length).toBe(0);
    });

    it('getByCategory filters correctly', () => {
        const reg = createNoiseRuleRegistry();
        reg.register(rule('r1', 'net:connect', 'reconnaissance'));
        reg.register(rule('r2', 'auth:login', 'credential-access'));
        reg.register(rule('r3', 'net:dns', 'reconnaissance'));

        expect(reg.getByCategory('reconnaissance').length).toBe(2);
        expect(reg.getByCategory('credential-access').length).toBe(1);
        expect(reg.getByCategory('exploitation').length).toBe(0);
    });
});

describe('Built-in Noise Rules', () => {
    it('creates a comprehensive set of built-in rules', () => {
        const rules = createBuiltinRules();
        expect(rules.length).toBeGreaterThan(10);
    });

    it('all built-in rules have unique IDs', () => {
        const rules = createBuiltinRules();
        const ids = new Set(rules.map(r => r.id));
        expect(ids.size).toBe(rules.length);
    });

    it('all built-in rules have valid categories', () => {
        const rules = createBuiltinRules();
        for (const r of rules) {
            expect(r.category.length).toBeGreaterThan(0);
            expect(r.baseNoise).toBeGreaterThan(0);
        }
    });

    it('built-in rules cover major attack categories', () => {
        const rules = createBuiltinRules();
        const categories = new Set(rules.map(r => r.category));
        expect(categories.has('reconnaissance')).toBe(true);
        expect(categories.has('credential-access')).toBe(true);
        expect(categories.has('exploitation')).toBe(true);
        expect(categories.has('lateral-movement')).toBe(true);
        expect(categories.has('exfiltration')).toBe(true);
        expect(categories.has('persistence')).toBe(true);
        expect(categories.has('privilege-escalation')).toBe(true);
        expect(categories.has('defense-evasion')).toBe(true);
    });

    it('built-in rules can be loaded into registry', () => {
        const reg = createNoiseRuleRegistry();
        reg.registerAll(createBuiltinRules());
        expect(reg.getAll().length).toBe(createBuiltinRules().length);
    });
});
