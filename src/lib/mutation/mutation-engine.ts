/**
 * VARIANT — Scenario Mutation Engine Implementation
 *
 * Genetic operators on WorldSpec for self-breeding levels.
 * Deterministic given a seed — reproducible evolution.
 *
 * SWAPPABILITY: Implements MutationEngine. Replace this file.
 */

import type {
    MutationEngine,
    MutationConstraints,
    MutationResult,
    MutationOp,
    MutationOperator,
    CrossoverConfig,
    ScenarioFitness,
    ScenarioGeneration,
    EvolutionConfig,
} from './types';

/** Simple seeded PRNG (mulberry32). Deterministic given a seed. */
function createRng(seed: number): () => number {
    let t = seed | 0;
    return () => {
        t = (t + 0x6D2B79F5) | 0;
        let x = Math.imul(t ^ (t >>> 15), 1 | t);
        x = (x + Math.imul(x ^ (x >>> 7), 61 | x)) ^ x;
        return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
    };
}

function generateId(rng: () => number): string {
    return 'var-' + Math.floor(rng() * 0xFFFFFFFF).toString(16).padStart(8, '0');
}

function deepClone<T>(obj: T): T {
    return JSON.parse(JSON.stringify(obj));
}

// ── Built-in Mutation Operators ─────────────────────────────────

function addServiceOperator(): MutationOperator {
    const servicePool = ['http', 'ssh', 'ftp', 'mysql', 'dns', 'smtp'];
    const portMap: Record<string, number> = { http: 80, ssh: 22, ftp: 21, mysql: 3306, dns: 53, smtp: 25 };

    return {
        apply(spec: Record<string, unknown>, seed: number) {
            const rng = createRng(seed);
            const result = deepClone(spec);
            const machines = result['machines'] as Record<string, Record<string, unknown>> | undefined;
            if (machines === undefined) return { spec: result, mutation: makeMutation('add-service', 'No machines', 0.3) };

            const machineIds = Object.keys(machines);
            if (machineIds.length === 0) return { spec: result, mutation: makeMutation('add-service', 'No machines', 0.3) };

            const targetId = machineIds[Math.floor(rng() * machineIds.length)]!;
            const target = machines[targetId]!;
            const serviceName = servicePool[Math.floor(rng() * servicePool.length)]!;

            const services = (target['services'] as Record<string, unknown>[] | undefined) ?? [];
            const existing = services.some((s: Record<string, unknown>) => s['name'] === serviceName);
            if (existing) return { spec: result, mutation: makeMutation('add-service', `${serviceName} already exists on ${targetId}`, 0.1) };

            services.push({
                name: serviceName,
                command: serviceName,
                ports: [portMap[serviceName] ?? 8080],
                autostart: true,
            });
            target['services'] = services;

            return {
                spec: result,
                mutation: makeMutation('add-service', `Added ${serviceName} to ${targetId}`, 0.4),
            };
        },
    };
}

function removeServiceOperator(): MutationOperator {
    return {
        apply(spec: Record<string, unknown>, seed: number) {
            const rng = createRng(seed);
            const result = deepClone(spec);
            const machines = result['machines'] as Record<string, Record<string, unknown>> | undefined;
            if (machines === undefined) return { spec: result, mutation: makeMutation('remove-service', 'No machines', 0.1) };

            const machineIds = Object.keys(machines);
            if (machineIds.length === 0) return { spec: result, mutation: makeMutation('remove-service', 'No machines', 0.1) };

            const targetId = machineIds[Math.floor(rng() * machineIds.length)]!;
            const target = machines[targetId]!;
            const services = target['services'] as Record<string, unknown>[] | undefined;
            if (services === undefined || services.length === 0) {
                return { spec: result, mutation: makeMutation('remove-service', `No services on ${targetId}`, 0.1) };
            }

            const idx = Math.floor(rng() * services.length);
            const removed = services[idx]!;
            services.splice(idx, 1);

            return {
                spec: result,
                mutation: makeMutation('remove-service', `Removed ${removed['name']} from ${targetId}`, 0.5),
            };
        },
    };
}

function addEdgeOperator(): MutationOperator {
    return {
        apply(spec: Record<string, unknown>, seed: number) {
            const rng = createRng(seed);
            const result = deepClone(spec);
            const machines = result['machines'] as Record<string, unknown> | undefined;
            if (machines === undefined) return { spec: result, mutation: makeMutation('add-edge', 'No machines', 0.1) };

            const machineIds = Object.keys(machines);
            if (machineIds.length < 2) return { spec: result, mutation: makeMutation('add-edge', 'Need 2+ machines', 0.1) };

            const fromIdx = Math.floor(rng() * machineIds.length);
            let toIdx = Math.floor(rng() * (machineIds.length - 1));
            if (toIdx >= fromIdx) toIdx++;

            const network = (result['network'] as Record<string, unknown>) ?? { segments: [], edges: [] };
            const edges = (network['edges'] as Record<string, unknown>[]) ?? [];

            edges.push({
                from: machineIds[fromIdx],
                to: machineIds[toIdx],
                bidirectional: true,
            });
            network['edges'] = edges;
            result['network'] = network;

            return {
                spec: result,
                mutation: makeMutation('add-edge', `Added edge ${machineIds[fromIdx]} → ${machineIds[toIdx]}`, 0.3),
            };
        },
    };
}

function adjustDifficultyOperator(): MutationOperator {
    const difficulties = ['beginner', 'easy', 'medium', 'hard', 'expert'];

    return {
        apply(spec: Record<string, unknown>, seed: number) {
            const rng = createRng(seed);
            const result = deepClone(spec);
            const meta = result['meta'] as Record<string, unknown> | undefined;
            if (meta === undefined) return { spec: result, mutation: makeMutation('adjust-difficulty', 'No meta', 0.1) };

            const currentDiff = meta['difficulty'] as string;
            const currentIdx = difficulties.indexOf(currentDiff);
            const direction = rng() > 0.5 ? 1 : -1;
            const newIdx = Math.max(0, Math.min(difficulties.length - 1, currentIdx + direction));
            meta['difficulty'] = difficulties[newIdx];

            return {
                spec: result,
                mutation: makeMutation('adjust-difficulty', `Difficulty: ${currentDiff} → ${difficulties[newIdx]}`, 0.2),
            };
        },
    };
}

function makeMutation(kind: string, description: string, severity: number): MutationOp {
    return {
        id: kind + '-' + Date.now().toString(36),
        kind: kind as MutationOp['kind'],
        description,
        path: kind,
        severity,
    };
}

// ── Engine ──────────────────────────────────────────────────────

export function createMutationEngine(): MutationEngine {
    const operators = new Map<string, MutationOperator>();

    // Register built-in operators
    operators.set('add-service', addServiceOperator());
    operators.set('remove-service', removeServiceOperator());
    operators.set('add-edge', addEdgeOperator());
    operators.set('adjust-difficulty', adjustDifficultyOperator());

    function validateResult(spec: Record<string, unknown>, mutations: readonly MutationOp[], constraints: MutationConstraints): MutationResult {
        const errors: string[] = [];
        const machines = spec['machines'] as Record<string, unknown> | undefined;
        const machineCount = machines !== undefined ? Object.keys(machines).length : 0;

        if (machineCount > constraints.maxMachines) {
            errors.push(`Too many machines: ${machineCount} > ${constraints.maxMachines}`);
        }

        const network = spec['network'] as Record<string, unknown> | undefined;
        const segments = (network?.['segments'] as unknown[]) ?? [];
        if (segments.length > constraints.maxSegments) {
            errors.push(`Too many segments: ${segments.length} > ${constraints.maxSegments}`);
        }

        const credentials = (spec['credentials'] as unknown[]) ?? [];
        if (credentials.length > constraints.maxCredentials) {
            errors.push(`Too many credentials: ${credentials.length} > ${constraints.maxCredentials}`);
        }

        const meta = spec['meta'] as Record<string, unknown> | undefined;
        const difficulty = (meta?.['difficulty'] as string) ?? 'medium';

        return {
            variantId: generateId(createRng(Date.now())),
            mutations,
            valid: errors.length === 0,
            errors,
            estimatedDifficulty: difficulty,
        };
    }

    return {
        mutate(
            spec: Record<string, unknown>,
            constraints: MutationConstraints,
            count: number,
            seed: number,
        ): readonly MutationResult[] {
            const rng = createRng(seed);
            const results: MutationResult[] = [];
            const operatorKinds = [...operators.keys()];

            for (let i = 0; i < count; i++) {
                let current = deepClone(spec);
                const mutations: MutationOp[] = [];
                const numMutations = Math.min(
                    Math.floor(rng() * constraints.maxMutationsPerGeneration) + 1,
                    constraints.maxMutationsPerGeneration,
                );

                for (let j = 0; j < numMutations; j++) {
                    const kind = operatorKinds[Math.floor(rng() * operatorKinds.length)]!;
                    const operator = operators.get(kind)!;
                    const opSeed = Math.floor(rng() * 0xFFFFFFFF);
                    const { spec: mutated, mutation } = operator.apply(current, opSeed);

                    if (mutation.severity <= constraints.maxSeverity) {
                        current = mutated;
                        mutations.push(mutation);
                    }
                }

                results.push(validateResult(current, mutations, constraints));
            }

            return results;
        },

        crossover(
            parentA: Record<string, unknown>,
            parentB: Record<string, unknown>,
            config: CrossoverConfig,
        ): MutationResult {
            const rng = createRng(config.seed);
            const result = deepClone(parentA);
            const mutations: MutationOp[] = [];

            for (const trait of config.traits) {
                const useA = rng() < trait.parentAWeight;
                if (!useA) {
                    const source = deepClone(parentB);
                    const key = traitToKey(trait.aspect);
                    if (key !== null && source[key] !== undefined) {
                        result[key] = source[key];
                        mutations.push(makeMutation(
                            'crossover-' + trait.aspect,
                            `Took ${trait.aspect} from parent B`,
                            0.5,
                        ));
                    }
                }
            }

            return {
                variantId: generateId(rng),
                mutations,
                valid: true,
                errors: [],
                estimatedDifficulty: ((result['meta'] as Record<string, unknown>)?.['difficulty'] as string) ?? 'medium',
            };
        },

        select(
            population: readonly ScenarioFitness[],
            count: number,
            tournamentSize: number,
        ): readonly ScenarioFitness[] {
            if (population.length === 0) return [];

            const rng = createRng(42);
            const selected: ScenarioFitness[] = [];

            for (let i = 0; i < count; i++) {
                let best: ScenarioFitness | null = null;
                let bestScore = -Infinity;

                for (let j = 0; j < tournamentSize; j++) {
                    const candidate = population[Math.floor(rng() * population.length)]!;
                    const score = fitnessScore(candidate);
                    if (score > bestScore) {
                        bestScore = score;
                        best = candidate;
                    }
                }

                if (best !== null) {
                    selected.push(best);
                }
            }

            return selected;
        },

        evolve(
            population: readonly ScenarioFitness[],
            specs: ReadonlyMap<string, Record<string, unknown>>,
            constraints: MutationConstraints,
            config: EvolutionConfig,
        ): ScenarioGeneration {
            const rng = createRng(config.seed);
            const parents = this.select(population, config.offspringCount * 2, config.tournamentSize);
            const offspring: MutationResult[] = [];

            for (let i = 0; i < config.offspringCount; i++) {
                const parentIdx = Math.floor(rng() * parents.length);
                const parentFitness = parents[parentIdx]!;
                const parentSpec = specs.get(parentFitness.scenarioId);

                if (parentSpec === undefined) continue;

                const shouldCrossover = rng() < config.crossoverRate && parents.length >= 2;

                let childSpec: Record<string, unknown>;

                if (shouldCrossover) {
                    let otherIdx = Math.floor(rng() * (parents.length - 1));
                    if (otherIdx >= parentIdx) otherIdx++;
                    const otherFitness = parents[otherIdx]!;
                    const otherSpec = specs.get(otherFitness.scenarioId);

                    if (otherSpec !== undefined) {
                        const crossResult = this.crossover(parentSpec, otherSpec, {
                            traits: [
                                { aspect: 'network', parentAWeight: 0.5 },
                                { aspect: 'services', parentAWeight: 0.5 },
                                { aspect: 'credentials', parentAWeight: 0.5 },
                            ],
                            seed: Math.floor(rng() * 0xFFFFFFFF),
                        });
                        childSpec = deepClone(parentSpec);
                        offspring.push(crossResult);
                        continue;
                    } else {
                        childSpec = deepClone(parentSpec);
                    }
                } else {
                    childSpec = deepClone(parentSpec);
                }

                // Apply mutations
                if (rng() < config.mutationRate) {
                    const mutated = this.mutate(
                        childSpec,
                        constraints,
                        1,
                        Math.floor(rng() * 0xFFFFFFFF),
                    );
                    if (mutated.length > 0) {
                        offspring.push(mutated[0]!);
                        continue;
                    }
                }

                offspring.push({
                    variantId: generateId(rng),
                    mutations: [],
                    valid: true,
                    errors: [],
                    estimatedDifficulty: 'medium',
                });
            }

            return {
                generation: config.generation,
                parents: parents.map(p => p.scenarioId),
                offspring,
                createdAt: Date.now(),
            };
        },

        registerOperator(kind: string, operator: MutationOperator): void {
            operators.set(kind, operator);
        },

        getOperatorKinds(): readonly string[] {
            return [...operators.keys()];
        },
    };
}

function traitToKey(aspect: string): string | null {
    switch (aspect) {
        case 'network': return 'network';
        case 'vulns': return 'machines';
        case 'services': return 'machines';
        case 'credentials': return 'credentials';
        case 'objectives': return 'objectives';
        case 'dynamics': return 'dynamics';
        case 'scoring': return 'scoring';
        default: return null;
    }
}

function fitnessScore(f: ScenarioFitness): number {
    // Weighted composite: engagement matters most, completion rate penalized if too high or low
    const completionPenalty = Math.abs(f.completionRate - 0.6); // ideal ~60%
    return (f.engagement * 0.4) + (f.learningGain * 0.3) - (completionPenalty * 0.2) + (Math.min(f.sampleSize, 100) / 100 * 0.1);
}
