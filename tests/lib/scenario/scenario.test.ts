/**
 * VARIANT — Scenario Store tests
 */
import { describe, it, expect } from 'vitest';
import { createScenarioStore } from '../../../src/lib/scenario/scenario-store';
import type { WorldSpec } from '../../../src/core/world/types';

function makeSpec(title: string): WorldSpec {
    return {
        version: '2.0',
        trust: 'community',
        meta: {
            title,
            scenario: 'Test scenario',
            briefing: ['Do the thing.'],
            difficulty: 'medium',
            mode: 'attack',
            vulnClasses: ['sqli'],
            tags: ['test'],
            estimatedMinutes: 30,
            author: { name: 'Tester', id: 'tester-1', type: 'community' },
        },
        machines: {
            'web-01': {
                hostname: 'web-01',
                image: 'ubuntu',
                memoryMB: 64,
                role: 'target',
                interfaces: [{ ip: '10.0.0.1', segment: 'dmz' }],
            },
        },
        startMachine: 'web-01',
        network: {
            segments: [{ id: 'dmz', subnet: '10.0.0.0/24' }],
            edges: [],
        },
        credentials: [],
        objectives: [],
        modules: [],
        scoring: { maxScore: 1000, timeBonus: true, stealthBonus: true, hintPenalty: 50, tiers: [] },
        hints: [],
    };
}

describe('ScenarioStore', () => {
    it('starts empty', () => {
        const store = createScenarioStore();
        expect(store.count()).toBe(0);
        expect(store.list().length).toBe(0);
    });

    it('serializes and deserializes', () => {
        const store = createScenarioStore();
        const spec = makeSpec('Test Level');

        const json = store.serialize(spec);
        expect(typeof json).toBe('string');

        const parsed = store.deserialize(json);
        expect(parsed).not.toBeNull();
        expect(parsed!.meta.title).toBe('Test Level');
    });

    it('returns null for invalid JSON', () => {
        const store = createScenarioStore();
        expect(store.deserialize('not json {')).toBeNull();
    });

    it('computes deterministic hash', () => {
        const store = createScenarioStore();
        const spec = makeSpec('Test Level');

        const h1 = store.hash(spec);
        const h2 = store.hash(spec);
        expect(h1).toBe(h2);
    });

    it('different specs produce different hashes', () => {
        const store = createScenarioStore();
        const h1 = store.hash(makeSpec('Level A'));
        const h2 = store.hash(makeSpec('Level B'));
        expect(h1).not.toBe(h2);
    });

    it('saves and loads', () => {
        const store = createScenarioStore();
        const spec = makeSpec('Test Level');

        const meta = store.save(spec, '1.0.0', ['tutorial']);
        expect(meta.hash).toBeTruthy();
        expect(meta.versionTag).toBe('1.0.0');
        expect(meta.tags).toContain('tutorial');
        expect(meta.parentHash).toBeNull();
        expect(meta.forkDepth).toBe(0);

        const loaded = store.load(meta.hash);
        expect(loaded).not.toBeNull();
        expect(loaded!.meta.title).toBe('Test Level');
    });

    it('returns null for unknown hash', () => {
        const store = createScenarioStore();
        expect(store.load('nonexistent')).toBeNull();
    });

    it('lists all saved scenarios', () => {
        const store = createScenarioStore();
        store.save(makeSpec('Level 1'), '1.0');
        store.save(makeSpec('Level 2'), '1.0');

        expect(store.list().length).toBe(2);
        expect(store.count()).toBe(2);
    });

    it('searches by tag', () => {
        const store = createScenarioStore();
        store.save(makeSpec('Level 1'), '1.0', ['beginner', 'tutorial']);
        store.save(makeSpec('Level 2'), '1.0', ['advanced']);
        store.save(makeSpec('Level 3'), '1.0', ['beginner']);

        expect(store.searchByTag('beginner').length).toBe(2);
        expect(store.searchByTag('advanced').length).toBe(1);
        expect(store.searchByTag('nonexistent').length).toBe(0);
    });

    it('searches by title', () => {
        const store = createScenarioStore();
        store.save(makeSpec('SQL Injection Lab'), '1.0');
        store.save(makeSpec('XSS Challenge'), '1.0');
        store.save(makeSpec('Advanced SQL Attack'), '1.0');

        expect(store.searchByTitle('SQL').length).toBe(2);
        expect(store.searchByTitle('xss').length).toBe(1); // case-insensitive
        expect(store.searchByTitle('nothing').length).toBe(0);
    });

    it('forks a scenario', () => {
        const store = createScenarioStore();
        const original = store.save(makeSpec('Original Level'), '1.0');

        const result = store.fork(original.hash, {
            author: 'Forker',
            authorId: 'forker-1',
            versionTag: '1.1',
            title: 'Forked Level',
            addTags: ['forked'],
        });

        expect(result).not.toBeNull();
        expect(result!.spec.meta.title).toBe('Forked Level');
        expect(result!.meta.parentHash).toBe(original.hash);
        expect(result!.meta.forkDepth).toBe(1);
        expect(result!.meta.tags).toContain('forked');
        expect(store.count()).toBe(2);
    });

    it('fork returns null for unknown hash', () => {
        const store = createScenarioStore();
        expect(store.fork('nonexistent', {
            author: 'A', authorId: 'a', versionTag: '1.0',
        })).toBeNull();
    });

    it('diffs two different specs', () => {
        const store = createScenarioStore();
        const m1 = store.save(makeSpec('Level A'), '1.0');
        const m2 = store.save(makeSpec('Level B'), '1.0');

        const diff = store.diff(m1.hash, m2.hash);
        expect(diff).not.toBeNull();
        expect(diff!.baseHash).toBe(m1.hash);
        expect(diff!.targetHash).toBe(m2.hash);
        expect(diff!.stats.total).toBeGreaterThan(0);
        expect(diff!.stats.modified).toBeGreaterThan(0);
    });

    it('diff returns null for unknown hashes', () => {
        const store = createScenarioStore();
        expect(store.diff('a', 'b')).toBeNull();
    });

    it('diff detects additions', () => {
        const store = createScenarioStore();
        const spec1 = makeSpec('Base');
        const spec2 = makeSpec('Extended');
        // Add a machine to spec2
        (spec2 as unknown as Record<string, unknown>)['machines'] = {
            ...(spec2.machines as Record<string, unknown>),
            'db-01': {
                hostname: 'db-01',
                image: 'ubuntu',
                memoryMB: 128,
                role: 'infrastructure',
                interfaces: [{ ip: '10.0.1.1', segment: 'internal' }],
            },
        };

        const m1 = store.save(spec1, '1.0');
        const m2 = store.save(spec2, '1.0');
        const diff = store.diff(m1.hash, m2.hash);

        expect(diff).not.toBeNull();
        const additions = diff!.changes.filter(c => c.kind === 'added');
        expect(additions.length).toBeGreaterThan(0);
    });

    it('removes a scenario', () => {
        const store = createScenarioStore();
        const meta = store.save(makeSpec('To Delete'), '1.0');

        expect(store.remove(meta.hash)).toBe(true);
        expect(store.load(meta.hash)).toBeNull();
        expect(store.count()).toBe(0);
    });

    it('remove returns false for unknown hash', () => {
        const store = createScenarioStore();
        expect(store.remove('nonexistent')).toBe(false);
    });

    it('clears all scenarios', () => {
        const store = createScenarioStore();
        store.save(makeSpec('L1'), '1.0');
        store.save(makeSpec('L2'), '1.0');
        store.save(makeSpec('L3'), '1.0');

        store.clear();
        expect(store.count()).toBe(0);
    });

    it('loaded spec is a deep copy (mutation-safe)', () => {
        const store = createScenarioStore();
        const meta = store.save(makeSpec('Original'), '1.0');

        const loaded = store.load(meta.hash)!;
        (loaded as unknown as Record<string, unknown>)['startMachine'] = 'hacked';

        const reloaded = store.load(meta.hash)!;
        expect(reloaded.startMachine).toBe('web-01');
    });

    it('meta includes size in bytes', () => {
        const store = createScenarioStore();
        const meta = store.save(makeSpec('Test'), '1.0');
        expect(meta.sizeBytes).toBeGreaterThan(0);
    });

    it('nested fork tracks depth', () => {
        const store = createScenarioStore();
        const m0 = store.save(makeSpec('Original'), '1.0');
        const f1 = store.fork(m0.hash, { author: 'A', authorId: 'a', versionTag: '2.0', title: 'Fork 1' })!;
        const f2 = store.fork(f1.meta.hash, { author: 'B', authorId: 'b', versionTag: '3.0', title: 'Fork 2' })!;

        expect(f1.meta.forkDepth).toBe(1);
        expect(f2.meta.forkDepth).toBe(2);
    });
});
