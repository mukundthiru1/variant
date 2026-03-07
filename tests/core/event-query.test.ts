/**
 * VARIANT — Event Query Tests
 */

import { describe, it, expect } from 'vitest';
import { createEventQuery } from '../../src/core/event-query';
import type { EngineEvent, AuthLoginEvent } from '../../src/core/events';

function makeLog(): EngineEvent[] {
    return [
        { type: 'sim:tick', tick: 1, timestamp: 1000 },
        { type: 'auth:login', user: 'admin', machine: 'web-01', service: 'ssh', success: false, timestamp: 1100 },
        { type: 'auth:login', user: 'admin', machine: 'web-01', service: 'ssh', success: false, timestamp: 1200 },
        { type: 'auth:login', user: 'admin', machine: 'web-01', service: 'ssh', success: true, timestamp: 1300 },
        { type: 'sim:tick', tick: 2, timestamp: 2000 },
        { type: 'fs:read', machine: 'web-01', path: '/etc/passwd', user: 'admin', timestamp: 2100 },
        { type: 'auth:escalate', machine: 'web-01', from: 'admin', to: 'root', method: 'sudo', timestamp: 2200 },
        { type: 'fs:read', machine: 'db-01', path: '/etc/shadow', user: 'root', timestamp: 2300 },
        { type: 'sim:tick', tick: 3, timestamp: 3000 },
        { type: 'defense:alert', machine: 'web-01', ruleId: 'brute-force', severity: 'high', detail: 'Multiple failed logins', timestamp: 3100 },
    ] as unknown as EngineEvent[];
}

describe('EventQuery', () => {
    it('returns all events with no filters', () => {
        const log = makeLog();
        const results = createEventQuery(log).results();
        expect(results.length).toBe(10);
    });

    it('filters by exact type', () => {
        const results = createEventQuery(makeLog())
            .type('auth:login')
            .results();
        expect(results.length).toBe(3);
        expect(results.every(e => e.type === 'auth:login')).toBe(true);
    });

    it('filters by prefix', () => {
        const results = createEventQuery(makeLog())
            .prefix('auth:')
            .results();
        expect(results.length).toBe(4); // 3 login + 1 escalate
    });

    it('filters with custom predicate', () => {
        const results = createEventQuery(makeLog())
            .type('auth:login')
            .where((e) => !(e as AuthLoginEvent).success)
            .results();
        expect(results.length).toBe(2);
    });

    it('filters by timestamp range with after/before', () => {
        const results = createEventQuery(makeLog())
            .after(2000)
            .before(2300)
            .results();
        expect(results.length).toBe(4); // tick:2, fs:read, auth:escalate, fs:read(db-01)
    });

    it('filters by timestamp range with between', () => {
        const results = createEventQuery(makeLog())
            .between(1100, 1300)
            .results();
        expect(results.length).toBe(3); // 3 auth:login events
    });

    it('filters by field value', () => {
        const results = createEventQuery(makeLog())
            .field('machine', 'db-01')
            .results();
        expect(results.length).toBe(1);
    });

    it('limits results', () => {
        const results = createEventQuery(makeLog())
            .limit(3)
            .results();
        expect(results.length).toBe(3);
    });

    it('offsets results', () => {
        const results = createEventQuery(makeLog())
            .offset(8)
            .results();
        expect(results.length).toBe(2);
    });

    it('combines limit and offset', () => {
        const results = createEventQuery(makeLog())
            .offset(2)
            .limit(3)
            .results();
        expect(results.length).toBe(3);
        expect(results[0]!.type).toBe('auth:login');
    });

    it('sorts descending by timestamp', () => {
        const results = createEventQuery(makeLog())
            .sort('desc')
            .results();
        expect(results[0]!.timestamp).toBe(3100);
        expect(results[results.length - 1]!.timestamp).toBe(1000);
    });

    it('counts without materializing', () => {
        const count = createEventQuery(makeLog())
            .type('sim:tick')
            .count();
        expect(count).toBe(3);
    });

    it('gets first matching event', () => {
        const first = createEventQuery(makeLog())
            .type('auth:login')
            .first();
        expect(first).toBeDefined();
        expect(first!.timestamp).toBe(1100);
    });

    it('gets last matching event', () => {
        const last = createEventQuery(makeLog())
            .type('auth:login')
            .last();
        expect(last).toBeDefined();
        expect(last!.timestamp).toBe(1300);
    });

    it('returns undefined for first/last with no matches', () => {
        const first = createEventQuery(makeLog())
            .type('objective:complete')
            .first();
        expect(first).toBeUndefined();

        const last = createEventQuery(makeLog())
            .type('objective:complete')
            .last();
        expect(last).toBeUndefined();
    });

    it('groups by field', () => {
        const groups = createEventQuery(makeLog())
            .prefix('auth:')
            .groupBy('machine');

        expect(groups.size).toBe(1);
        expect(groups.get('web-01')!.length).toBe(4);
    });

    it('chains multiple filters', () => {
        const results = createEventQuery(makeLog())
            .prefix('auth:')
            .field('machine', 'web-01')
            .after(1200)
            .results();
        // auth:login@1200, auth:login@1300, auth:escalate@2200
        expect(results.length).toBe(3);
    });

    it('handles empty log', () => {
        const query = createEventQuery([]);
        expect(query.results().length).toBe(0);
        expect(query.count()).toBe(0);
        expect(query.first()).toBeUndefined();
        expect(query.last()).toBeUndefined();
    });
});
