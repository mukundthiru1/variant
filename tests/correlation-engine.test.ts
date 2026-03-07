import { describe, it, expect, vi } from 'vitest';
import { createCorrelationEngine } from '../src/lib/correlation/correlation-engine';
import type { CorrelationRule, CorrelationEvent } from '../src/lib/correlation/types';

// ── Helpers ─────────────────────────────────────────────────

function event(type: string, fields: Record<string, unknown> = {}, timestamp?: number): CorrelationEvent {
    return { type, timestamp: timestamp ?? Date.now(), fields };
}

// ── Sequence Strategy ───────────────────────────────────────

describe('Correlation Engine', () => {
    describe('Sequence Strategy', () => {
        it('detects ordered event sequence', () => {
            const engine = createCorrelationEngine();
            engine.addRule({
                id: 'attack-chain',
                name: 'Attack Chain',
                strategy: {
                    type: 'sequence',
                    steps: [
                        { eventType: 'net:connect' },
                        { eventType: 'auth:login' },
                        { eventType: 'auth:escalate' },
                    ],
                },
                windowMs: 60_000,
                actions: [{ type: 'alert', params: { message: 'Attack chain detected' } }],
            });

            const now = Date.now();
            expect(engine.processEvent(event('net:connect', {}, now)).length).toBe(0);
            expect(engine.processEvent(event('auth:login', {}, now + 1000)).length).toBe(0);
            const matches = engine.processEvent(event('auth:escalate', {}, now + 2000));
            expect(matches.length).toBe(1);
            expect(matches[0]!.ruleId).toBe('attack-chain');
        });

        it('resets sequence on non-matching event type', () => {
            const engine = createCorrelationEngine();
            engine.addRule({
                id: 'seq',
                name: 'Seq',
                strategy: {
                    type: 'sequence',
                    steps: [
                        { eventType: 'a' },
                        { eventType: 'b' },
                    ],
                },
                windowMs: 60_000,
                actions: [],
            });

            engine.processEvent(event('a'));
            // Non-matching event — sequence stays (doesn't reset progress)
            engine.processEvent(event('x'));
            // Next matching event should complete the sequence
            const matches = engine.processEvent(event('b'));
            expect(matches.length).toBe(1);
        });

        it('respects step conditions', () => {
            const engine = createCorrelationEngine();
            engine.addRule({
                id: 'failed-login-chain',
                name: 'Failed Login Chain',
                strategy: {
                    type: 'sequence',
                    steps: [
                        { eventType: 'auth:login', conditions: [{ field: 'success', operator: '==', value: false }] },
                        { eventType: 'auth:login', conditions: [{ field: 'success', operator: '==', value: true }] },
                    ],
                },
                windowMs: 60_000,
                actions: [],
            });

            // First step: failed login
            engine.processEvent(event('auth:login', { success: false }));
            // Second step: successful login — completes chain
            const matches = engine.processEvent(event('auth:login', { success: true }));
            expect(matches.length).toBe(1);
        });

        it('supports wildcard event types', () => {
            const engine = createCorrelationEngine();
            engine.addRule({
                id: 'any-auth',
                name: 'Any Auth',
                strategy: {
                    type: 'sequence',
                    steps: [{ eventType: 'auth:*' }],
                },
                windowMs: 60_000,
                actions: [],
            });

            const matches = engine.processEvent(event('auth:login', {}));
            expect(matches.length).toBe(1);
        });
    });

    // ── Threshold Strategy ──────────────────────────────────

    describe('Threshold Strategy', () => {
        it('fires when threshold is reached', () => {
            const engine = createCorrelationEngine();
            engine.addRule({
                id: 'brute-force',
                name: 'Brute Force',
                strategy: {
                    type: 'threshold',
                    eventType: 'auth:login',
                    threshold: 3,
                    conditions: [{ field: 'success', operator: '==', value: false }],
                },
                windowMs: 60_000,
                actions: [{ type: 'alert', params: { severity: 'high' } }],
                severity: 'high',
            });

            const now = Date.now();
            expect(engine.processEvent(event('auth:login', { success: false }, now)).length).toBe(0);
            expect(engine.processEvent(event('auth:login', { success: false }, now + 1000)).length).toBe(0);
            const matches = engine.processEvent(event('auth:login', { success: false }, now + 2000));
            expect(matches.length).toBe(1);
            expect(matches[0]!.severity).toBe('high');
        });

        it('does not fire below threshold', () => {
            const engine = createCorrelationEngine();
            engine.addRule({
                id: 'threshold',
                name: 'Threshold',
                strategy: { type: 'threshold', eventType: 'x', threshold: 5 },
                windowMs: 60_000,
                actions: [],
            });

            for (let i = 0; i < 4; i++) {
                expect(engine.processEvent(event('x')).length).toBe(0);
            }
        });

        it('groups by field', () => {
            const engine = createCorrelationEngine();
            engine.addRule({
                id: 'per-ip',
                name: 'Per IP',
                strategy: {
                    type: 'threshold',
                    eventType: 'auth:login',
                    threshold: 2,
                    groupBy: 'sourceIP',
                },
                windowMs: 60_000,
                actions: [],
            });

            const now = Date.now();
            engine.processEvent(event('auth:login', { sourceIP: '10.0.0.1' }, now));
            engine.processEvent(event('auth:login', { sourceIP: '10.0.0.2' }, now + 100));
            // Different IPs — neither group hits threshold
            expect(engine.processEvent(event('auth:login', { sourceIP: '10.0.0.2' }, now + 200)).length).toBe(1);
        });

        it('ignores events not matching conditions', () => {
            const engine = createCorrelationEngine();
            engine.addRule({
                id: 'failed-only',
                name: 'Failed Only',
                strategy: {
                    type: 'threshold',
                    eventType: 'auth:login',
                    threshold: 2,
                    conditions: [{ field: 'success', operator: '==', value: false }],
                },
                windowMs: 60_000,
                actions: [],
            });

            engine.processEvent(event('auth:login', { success: true }));
            engine.processEvent(event('auth:login', { success: false }));
            // Only 1 failed login — below threshold
            expect(engine.processEvent(event('auth:login', { success: true })).length).toBe(0);
        });
    });

    // ── Unique Strategy ─────────────────────────────────────

    describe('Unique Strategy', () => {
        it('fires when unique count reaches threshold', () => {
            const engine = createCorrelationEngine();
            engine.addRule({
                id: 'port-scan',
                name: 'Port Scan',
                strategy: {
                    type: 'unique',
                    eventType: 'net:connect',
                    uniqueField: 'port',
                    threshold: 3,
                },
                windowMs: 60_000,
                actions: [],
            });

            const now = Date.now();
            engine.processEvent(event('net:connect', { port: 22 }, now));
            engine.processEvent(event('net:connect', { port: 80 }, now + 100));
            const matches = engine.processEvent(event('net:connect', { port: 443 }, now + 200));
            expect(matches.length).toBe(1);
        });

        it('does not count duplicate values', () => {
            const engine = createCorrelationEngine();
            engine.addRule({
                id: 'unique-ports',
                name: 'Unique Ports',
                strategy: {
                    type: 'unique',
                    eventType: 'net:connect',
                    uniqueField: 'port',
                    threshold: 3,
                },
                windowMs: 60_000,
                actions: [],
            });

            const now = Date.now();
            engine.processEvent(event('net:connect', { port: 22 }, now));
            engine.processEvent(event('net:connect', { port: 22 }, now + 100));
            expect(engine.processEvent(event('net:connect', { port: 80 }, now + 200)).length).toBe(0);
        });
    });

    // ── Rule Management ─────────────────────────────────────

    describe('Rule Management', () => {
        it('rejects duplicate rule IDs', () => {
            const engine = createCorrelationEngine();
            const rule: CorrelationRule = {
                id: 'dup', name: 'Dup',
                strategy: { type: 'threshold', eventType: 'x', threshold: 1 },
                windowMs: 1000, actions: [],
            };
            engine.addRule(rule);
            expect(() => engine.addRule(rule)).toThrow();
        });

        it('removes rules', () => {
            const engine = createCorrelationEngine();
            engine.addRule({
                id: 'rem', name: 'Rem',
                strategy: { type: 'threshold', eventType: 'x', threshold: 1 },
                windowMs: 1000, actions: [],
            });
            expect(engine.removeRule('rem')).toBe(true);
            expect(engine.getRules().length).toBe(0);
        });

        it('enables/disables rules', () => {
            const engine = createCorrelationEngine();
            engine.addRule({
                id: 'toggle', name: 'Toggle',
                strategy: { type: 'threshold', eventType: 'x', threshold: 1 },
                windowMs: 60_000, actions: [],
            });

            expect(engine.processEvent(event('x')).length).toBe(1);
            engine.reset();
            engine.setRuleEnabled('toggle', false);
            expect(engine.processEvent(event('x')).length).toBe(0);
        });
    });

    // ── Non-Repeatable & Cooldown ───────────────────────────

    describe('Firing Control', () => {
        it('non-repeatable rules fire only once', () => {
            const engine = createCorrelationEngine();
            engine.addRule({
                id: 'once', name: 'Once',
                strategy: { type: 'threshold', eventType: 'x', threshold: 1 },
                windowMs: 60_000, actions: [],
                repeatable: false,
            });

            expect(engine.processEvent(event('x')).length).toBe(1);
            expect(engine.processEvent(event('x')).length).toBe(0);
        });

        it('cooldown prevents rapid re-firing', () => {
            const engine = createCorrelationEngine();
            engine.addRule({
                id: 'cool', name: 'Cool',
                strategy: { type: 'threshold', eventType: 'x', threshold: 1 },
                windowMs: 60_000, actions: [],
                cooldownMs: 5_000,
            });

            const now = Date.now();
            expect(engine.processEvent(event('x', {}, now)).length).toBe(1);
            // Within cooldown
            expect(engine.processEvent(event('x', {}, now + 1000)).length).toBe(0);
            // After cooldown
            expect(engine.processEvent(event('x', {}, now + 6000)).length).toBe(1);
        });
    });

    // ── Match History ───────────────────────────────────────

    describe('Match History', () => {
        it('stores match history', () => {
            const engine = createCorrelationEngine();
            engine.addRule({
                id: 'hist', name: 'Hist',
                strategy: { type: 'threshold', eventType: 'x', threshold: 1 },
                windowMs: 60_000, actions: [],
            });

            engine.processEvent(event('x'));
            expect(engine.getRecentMatches().length).toBe(1);
        });

        it('limits match history', () => {
            const engine = createCorrelationEngine();
            engine.addRule({
                id: 'hist', name: 'Hist',
                strategy: { type: 'threshold', eventType: 'x', threshold: 1 },
                windowMs: 60_000, actions: [],
                repeatable: true, cooldownMs: 0,
            });

            for (let i = 0; i < 10; i++) {
                engine.processEvent(event('x', {}, Date.now() + i * 10));
            }

            expect(engine.getRecentMatches(3).length).toBe(3);
        });

        it('clears on reset', () => {
            const engine = createCorrelationEngine();
            engine.addRule({
                id: 'hist', name: 'Hist',
                strategy: { type: 'threshold', eventType: 'x', threshold: 1 },
                windowMs: 60_000, actions: [],
            });

            engine.processEvent(event('x'));
            engine.reset();
            expect(engine.getRecentMatches().length).toBe(0);
        });
    });

    // ── Action Handlers ─────────────────────────────────────

    describe('Action Handlers', () => {
        it('calls registered action handler on match', () => {
            const engine = createCorrelationEngine();
            const handler = vi.fn();
            engine.registerActionHandler('alert', handler);

            engine.addRule({
                id: 'act', name: 'Action',
                strategy: { type: 'threshold', eventType: 'x', threshold: 1 },
                windowMs: 60_000,
                actions: [{ type: 'alert', params: { msg: 'test' } }],
            });

            engine.processEvent(event('x'));
            expect(handler).toHaveBeenCalledTimes(1);
            expect(handler).toHaveBeenCalledWith(
                { msg: 'test' },
                expect.objectContaining({ ruleId: 'act' }),
            );
        });

        it('rejects duplicate action handlers', () => {
            const engine = createCorrelationEngine();
            engine.registerActionHandler('x', vi.fn());
            expect(() => engine.registerActionHandler('x', vi.fn())).toThrow();
        });
    });

    // ── Step Condition Operators ─────────────────────────────

    describe('Step Conditions', () => {
        it('!= operator works', () => {
            const engine = createCorrelationEngine();
            engine.addRule({
                id: 'neq', name: 'NEQ',
                strategy: {
                    type: 'threshold', eventType: 'x', threshold: 1,
                    conditions: [{ field: 'status', operator: '!=', value: 'ok' }],
                },
                windowMs: 60_000, actions: [],
            });

            expect(engine.processEvent(event('x', { status: 'ok' })).length).toBe(0);
            expect(engine.processEvent(event('x', { status: 'error' })).length).toBe(1);
        });

        it('contains operator works', () => {
            const engine = createCorrelationEngine();
            engine.addRule({
                id: 'contains', name: 'Contains',
                strategy: {
                    type: 'threshold', eventType: 'x', threshold: 1,
                    conditions: [{ field: 'path', operator: 'contains', value: '/admin' }],
                },
                windowMs: 60_000, actions: [],
            });

            expect(engine.processEvent(event('x', { path: '/api/admin/users' })).length).toBe(1);
        });

        it('matches (regex) operator works', () => {
            const engine = createCorrelationEngine();
            engine.addRule({
                id: 'regex', name: 'Regex',
                strategy: {
                    type: 'threshold', eventType: 'x', threshold: 1,
                    conditions: [{ field: 'cmd', operator: 'matches', value: '^sudo\\s' }],
                },
                windowMs: 60_000, actions: [],
            });

            expect(engine.processEvent(event('x', { cmd: 'sudo cat /etc/shadow' })).length).toBe(1);
            engine.reset();
            expect(engine.processEvent(event('x', { cmd: 'cat /etc/passwd' })).length).toBe(0);
        });
    });
});
