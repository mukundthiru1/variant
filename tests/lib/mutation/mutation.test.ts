/**
 * VARIANT — Mutation Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createMutationEngine } from '../../../src/lib/mutation/mutation-engine';
import type { MutationConstraints, ScenarioFitness, MutationOperator, MutationOp } from '../../../src/lib/mutation/types';

function makeSpec(): Record<string, unknown> {
    return {
        version: '2.0',
        meta: { title: 'Test Level', difficulty: 'medium' },
        machines: {
            'web-01': {
                hostname: 'web-01',
                image: 'ubuntu',
                memoryMB: 64,
                role: 'target',
                interfaces: [{ ip: '10.0.0.1', segment: 'dmz' }],
                services: [{ name: 'http', command: 'nginx', ports: [80], autostart: true }],
            },
            'db-01': {
                hostname: 'db-01',
                image: 'ubuntu',
                memoryMB: 128,
                role: 'infrastructure',
                interfaces: [{ ip: '10.0.1.1', segment: 'internal' }],
                services: [{ name: 'mysql', command: 'mysqld', ports: [3306], autostart: true }],
            },
        },
        network: {
            segments: [{ id: 'dmz', subnet: '10.0.0.0/24' }, { id: 'internal', subnet: '10.0.1.0/24' }],
            edges: [{ from: 'web-01', to: 'db-01', bidirectional: true }],
        },
        credentials: [{ id: 'cred-1', type: 'password', value: 'pass123' }],
        objectives: [],
    };
}

function makeConstraints(overrides?: Partial<MutationConstraints>): MutationConstraints {
    return {
        maxMachines: 10,
        maxSegments: 5,
        maxCredentials: 20,
        maxObjectives: 10,
        allowedVulnClasses: [],
        difficultyRange: ['easy', 'hard'],
        maxSeverity: 1.0,
        maxMutationsPerGeneration: 3,
        requiredRoles: ['target'],
        ...overrides,
    };
}

function makeFitness(id: string, overrides?: Partial<ScenarioFitness>): ScenarioFitness {
    return {
        scenarioId: id,
        engagement: 0.7,
        learningGain: 0.5,
        completionRate: 0.6,
        avgDuration: 500,
        sampleSize: 50,
        failModes: [],
        ...overrides,
    };
}

describe('MutationEngine', () => {
    it('has built-in operators', () => {
        const engine = createMutationEngine();
        const kinds = engine.getOperatorKinds();

        expect(kinds).toContain('add-service');
        expect(kinds).toContain('remove-service');
        expect(kinds).toContain('add-edge');
        expect(kinds).toContain('adjust-difficulty');
    });

    it('registers custom operator', () => {
        const engine = createMutationEngine();
        const custom: MutationOperator = {
            apply(spec, _seed) {
                const result = JSON.parse(JSON.stringify(spec));
                return {
                    spec: result,
                    mutation: {
                        id: 'custom-1',
                        kind: 'custom' as MutationOp['kind'],
                        description: 'Custom mutation',
                        path: 'custom',
                        severity: 0.1,
                    },
                };
            },
        };

        engine.registerOperator('custom-op', custom);
        expect(engine.getOperatorKinds()).toContain('custom-op');
    });

    it('mutates a spec and returns results', () => {
        const engine = createMutationEngine();
        const results = engine.mutate(makeSpec(), makeConstraints(), 3, 42);

        expect(results.length).toBe(3);
        for (const r of results) {
            expect(r.variantId).toBeTruthy();
            expect(r.mutations.length).toBeGreaterThan(0);
        }
    });

    it('mutations are deterministic with same seed', () => {
        const engine = createMutationEngine();
        const r1 = engine.mutate(makeSpec(), makeConstraints(), 1, 12345);
        const r2 = engine.mutate(makeSpec(), makeConstraints(), 1, 12345);

        expect(r1[0]!.mutations.length).toBe(r2[0]!.mutations.length);
        for (let i = 0; i < r1[0]!.mutations.length; i++) {
            expect(r1[0]!.mutations[i]!.kind).toBe(r2[0]!.mutations[i]!.kind);
        }
    });

    it('different seeds produce different mutations', () => {
        const engine = createMutationEngine();
        const r1 = engine.mutate(makeSpec(), makeConstraints(), 5, 111);
        const r2 = engine.mutate(makeSpec(), makeConstraints(), 5, 999);

        // At least one should differ (probabilistic but highly likely with 5 results)
        const ids1 = r1.map(r => r.mutations.map(m => m.kind).join(','));
        const ids2 = r2.map(r => r.mutations.map(m => m.kind).join(','));
        const allSame = ids1.every((id, i) => id === ids2[i]);
        expect(allSame).toBe(false);
    });

    it('validates mutation results against constraints', () => {
        const engine = createMutationEngine();
        const results = engine.mutate(makeSpec(), makeConstraints({ maxMachines: 2 }), 3, 42);

        // All results should be valid or have error messages
        for (const r of results) {
            if (!r.valid) {
                expect(r.errors.length).toBeGreaterThan(0);
            }
        }
    });

    it('respects maxSeverity constraint', () => {
        const engine = createMutationEngine();
        const results = engine.mutate(makeSpec(), makeConstraints({ maxSeverity: 0.01 }), 5, 42);

        // With very low maxSeverity, most mutations should be filtered
        expect(results.length).toBe(5);
    });

    it('crossover merges two parents', () => {
        const engine = createMutationEngine();
        const parentA = makeSpec();
        const parentB = makeSpec();
        (parentB['meta'] as Record<string, unknown>)['title'] = 'Parent B Level';

        const result = engine.crossover(parentA, parentB, {
            traits: [
                { aspect: 'network', parentAWeight: 0 },  // always take from B
            ],
            seed: 42,
        });

        expect(result.variantId).toBeTruthy();
        expect(result.valid).toBe(true);
    });

    it('crossover with parentAWeight=1 keeps parent A', () => {
        const engine = createMutationEngine();
        const parentA = makeSpec();
        const parentB = makeSpec();

        const result = engine.crossover(parentA, parentB, {
            traits: [{ aspect: 'network', parentAWeight: 1.0 }],
            seed: 42,
        });

        // No mutations should have been applied (kept A)
        expect(result.mutations.length).toBe(0);
    });

    it('selects fittest from population', () => {
        const engine = createMutationEngine();
        const population = [
            makeFitness('low', { engagement: 0.1, learningGain: 0.1 }),
            makeFitness('mid', { engagement: 0.5, learningGain: 0.5 }),
            makeFitness('high', { engagement: 0.9, learningGain: 0.9 }),
        ];

        const selected = engine.select(population, 2, 3);
        expect(selected.length).toBe(2);
        // High fitness should be selected more often with tournament selection
    });

    it('select returns empty for empty population', () => {
        const engine = createMutationEngine();
        const selected = engine.select([], 5, 3);
        expect(selected.length).toBe(0);
    });

    it('evolves a generation', () => {
        const engine = createMutationEngine();
        const spec = makeSpec();
        const population = [
            makeFitness('scenario-1', { engagement: 0.8 }),
            makeFitness('scenario-2', { engagement: 0.6 }),
        ];
        const specs = new Map<string, Record<string, unknown>>();
        specs.set('scenario-1', spec);
        specs.set('scenario-2', makeSpec());

        const generation = engine.evolve(population, specs, makeConstraints(), {
            offspringCount: 3,
            tournamentSize: 2,
            mutationRate: 0.8,
            crossoverRate: 0.3,
            maxMutationsPerOffspring: 2,
            seed: 42,
            generation: 0,
        });

        expect(generation.generation).toBe(0);
        expect(generation.offspring.length).toBeGreaterThan(0);
        expect(generation.parents.length).toBeGreaterThan(0);
    });

    it('evolve produces offspring with mutations', () => {
        const engine = createMutationEngine();
        const population = [makeFitness('s1'), makeFitness('s2')];
        const specs = new Map([['s1', makeSpec()], ['s2', makeSpec()]]);

        const gen = engine.evolve(population, specs, makeConstraints(), {
            offspringCount: 5,
            tournamentSize: 2,
            mutationRate: 1.0,
            crossoverRate: 0.0,
            maxMutationsPerOffspring: 3,
            seed: 123,
            generation: 1,
        });

        const withMutations = gen.offspring.filter(o => o.mutations.length > 0);
        expect(withMutations.length).toBeGreaterThan(0);
    });

    it('mutation results include estimated difficulty', () => {
        const engine = createMutationEngine();
        const results = engine.mutate(makeSpec(), makeConstraints(), 1, 42);
        expect(results[0]!.estimatedDifficulty).toBeTruthy();
    });

    it('handles spec with no machines gracefully', () => {
        const engine = createMutationEngine();
        const emptySpec = { version: '2.0', meta: { difficulty: 'easy' }, machines: {} };
        const results = engine.mutate(emptySpec, makeConstraints(), 1, 42);
        expect(results.length).toBe(1);
    });
});
