/**
 * VARIANT — Correlation Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createCorrelationEngine } from '../../../src/lib/correlation/correlation-engine';
import type { CorrelationRule, CorrelationEvent } from '../../../src/lib/correlation/types';

function evt(type: string, timestamp: number, fields: Record<string, unknown> = {}): CorrelationEvent {
    return { type, timestamp, fields };
}

function thresholdRule(id: string, eventType: string, threshold: number, windowMs: number): CorrelationRule {
    return {
        id,
        name: `Threshold ${id}`,
        strategy: { type: 'threshold', eventType, threshold },
        windowMs,
        actions: [],
    };
}

function sequenceRule(id: string, steps: string[], windowMs: number): CorrelationRule {
    return {
        id,
        name: `Sequence ${id}`,
        strategy: { type: 'sequence', steps: steps.map(s => ({ eventType: s })) },
        windowMs,
        actions: [],
    };
}

function uniqueRule(id: string, eventType: string, uniqueField: string, threshold: number, windowMs: number): CorrelationRule {
    return {
        id,
        name: `Unique ${id}`,
        strategy: { type: 'unique', eventType, uniqueField, threshold },
        windowMs,
        actions: [],
    };
}

describe('CorrelationEngine', () => {
    // ── Rules ──────────────────────────────────────────────────

    it('adds and lists rules', () => {
        const engine = createCorrelationEngine();
        engine.addRule(thresholdRule('r1', 'login:fail', 3, 60000));

        expect(engine.getRules().length).toBe(1);
    });

    it('throws on duplicate rule', () => {
        const engine = createCorrelationEngine();
        engine.addRule(thresholdRule('r1', 'login:fail', 3, 60000));
        expect(() => engine.addRule(thresholdRule('r1', 'other', 5, 1000))).toThrow();
    });

    it('removes a rule', () => {
        const engine = createCorrelationEngine();
        engine.addRule(thresholdRule('r1', 'login:fail', 3, 60000));
        expect(engine.removeRule('r1')).toBe(true);
        expect(engine.removeRule('nonexistent')).toBe(false);
        expect(engine.getRules().length).toBe(0);
    });

    it('enables/disables a rule', () => {
        const engine = createCorrelationEngine();
        engine.addRule(thresholdRule('r1', 'login:fail', 3, 60000));
        expect(engine.setRuleEnabled('r1', false)).toBe(true);
        expect(engine.setRuleEnabled('nonexistent', true)).toBe(false);
    });

    // ── Threshold Strategy ─────────────────────────────────────

    it('threshold fires when count reached', () => {
        const engine = createCorrelationEngine();
        engine.addRule(thresholdRule('brute', 'login:fail', 3, 60000));

        expect(engine.processEvent(evt('login:fail', 1000)).length).toBe(0);
        expect(engine.processEvent(evt('login:fail', 2000)).length).toBe(0);
        const matches = engine.processEvent(evt('login:fail', 3000));
        expect(matches.length).toBe(1);
        expect(matches[0]!.ruleId).toBe('brute');
    });

    it('threshold does not fire for wrong event type', () => {
        const engine = createCorrelationEngine();
        engine.addRule(thresholdRule('brute', 'login:fail', 3, 60000));

        engine.processEvent(evt('login:success', 1000));
        engine.processEvent(evt('login:success', 2000));
        expect(engine.processEvent(evt('login:success', 3000)).length).toBe(0);
    });

    it('threshold respects time window', () => {
        const engine = createCorrelationEngine();
        engine.addRule(thresholdRule('brute', 'login:fail', 3, 5000));

        engine.processEvent(evt('login:fail', 1000));
        engine.processEvent(evt('login:fail', 2000));
        // Third event is outside the window relative to first
        expect(engine.processEvent(evt('login:fail', 7000)).length).toBe(0);
    });

    // ── Sequence Strategy ──────────────────────────────────────

    it('sequence fires when all steps match in order', () => {
        const engine = createCorrelationEngine();
        engine.addRule(sequenceRule('attack', ['recon', 'exploit', 'escalate'], 60000));

        expect(engine.processEvent(evt('recon', 1000)).length).toBe(0);
        expect(engine.processEvent(evt('exploit', 2000)).length).toBe(0);
        const matches = engine.processEvent(evt('escalate', 3000));
        expect(matches.length).toBe(1);
        expect(matches[0]!.ruleId).toBe('attack');
    });

    it('sequence does not fire out of order', () => {
        const engine = createCorrelationEngine();
        engine.addRule(sequenceRule('attack', ['recon', 'exploit', 'escalate'], 60000));

        engine.processEvent(evt('exploit', 1000)); // wrong order
        engine.processEvent(evt('recon', 2000));
        expect(engine.processEvent(evt('escalate', 3000)).length).toBe(0);
    });

    // ── Unique Strategy ────────────────────────────────────────

    it('unique fires when threshold of distinct values reached', () => {
        const engine = createCorrelationEngine();
        engine.addRule(uniqueRule('portscan', 'net:connect', 'port', 3, 60000));

        expect(engine.processEvent(evt('net:connect', 1000, { port: 22 })).length).toBe(0);
        expect(engine.processEvent(evt('net:connect', 2000, { port: 80 })).length).toBe(0);
        const matches = engine.processEvent(evt('net:connect', 3000, { port: 443 }));
        expect(matches.length).toBe(1);
    });

    it('unique does not count duplicates', () => {
        const engine = createCorrelationEngine();
        engine.addRule(uniqueRule('portscan', 'net:connect', 'port', 3, 60000));

        engine.processEvent(evt('net:connect', 1000, { port: 22 }));
        engine.processEvent(evt('net:connect', 2000, { port: 22 }));
        expect(engine.processEvent(evt('net:connect', 3000, { port: 22 })).length).toBe(0);
    });

    // ── Disabled Rules ─────────────────────────────────────────

    it('disabled rule does not fire', () => {
        const engine = createCorrelationEngine();
        engine.addRule(thresholdRule('r1', 'login:fail', 1, 60000));
        engine.setRuleEnabled('r1', false);

        expect(engine.processEvent(evt('login:fail', 1000)).length).toBe(0);
    });

    // ── Non-repeatable Rules ───────────────────────────────────

    it('non-repeatable rule fires only once', () => {
        const engine = createCorrelationEngine();
        engine.addRule({ ...thresholdRule('once', 'test', 1, 60000), repeatable: false });

        expect(engine.processEvent(evt('test', 1000)).length).toBe(1);
        expect(engine.processEvent(evt('test', 2000)).length).toBe(0);
    });

    // ── Match History ──────────────────────────────────────────

    it('records match history', () => {
        const engine = createCorrelationEngine();
        engine.addRule(thresholdRule('r1', 'test', 1, 60000));

        engine.processEvent(evt('test', 1000));
        engine.processEvent(evt('test', 2000));

        const history = engine.getRecentMatches();
        expect(history.length).toBe(2);
    });

    it('getRecentMatches respects limit', () => {
        const engine = createCorrelationEngine();
        engine.addRule(thresholdRule('r1', 'test', 1, 60000));

        engine.processEvent(evt('test', 1000));
        engine.processEvent(evt('test', 2000));
        engine.processEvent(evt('test', 3000));

        expect(engine.getRecentMatches(2).length).toBe(2);
    });

    // ── Action Handlers ────────────────────────────────────────

    it('executes registered action handlers', () => {
        const engine = createCorrelationEngine();
        const rule: CorrelationRule = {
            ...thresholdRule('r1', 'test', 1, 60000),
            actions: [{ type: 'alert', params: { level: 'high' } }],
        };
        engine.addRule(rule);

        let called = false;
        engine.registerActionHandler('alert', (params) => {
            called = true;
            expect(params['level']).toBe('high');
        });

        engine.processEvent(evt('test', 1000));
        expect(called).toBe(true);
    });

    it('throws on duplicate action handler', () => {
        const engine = createCorrelationEngine();
        engine.registerActionHandler('alert', () => {});
        expect(() => engine.registerActionHandler('alert', () => {})).toThrow();
    });

    // ── Reset ──────────────────────────────────────────────────

    it('reset clears windows and history', () => {
        const engine = createCorrelationEngine();
        engine.addRule(thresholdRule('r1', 'test', 1, 60000));
        engine.processEvent(evt('test', 1000));

        engine.reset();

        expect(engine.getRecentMatches().length).toBe(0);
    });
});
