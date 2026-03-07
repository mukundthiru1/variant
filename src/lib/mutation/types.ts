/**
 * VARIANT — Scenario Mutation Engine Type Definitions
 *
 * Genetic operators on WorldSpec that enable self-breeding levels.
 * Scenarios evolve via fitness functions derived from telemetry:
 * engagement, learning gain, completion rate, fail modes.
 *
 * OPERATORS:
 * - mutateNetwork: add/remove/rewire network segments and edges
 * - mutateVulns: toggle/swap vulnerability configurations
 * - mutateServices: add/remove/reconfigure services on machines
 * - mutateCredentials: shuffle credential locations and targets
 * - mutateDifficulty: adjust timing, noise thresholds, resource limits
 * - crossover: merge traits from two parent WorldSpecs
 *
 * SAFETY: The validator gates every mutation output. Broken/unsafe
 * offspring are rejected before they enter the population.
 *
 * SWAPPABILITY: Implements MutationEngine interface. Replace this file.
 */

// ── Mutation Operators ──────────────────────────────────────────

/** A single mutation operation applied to a WorldSpec. */
export interface MutationOp {
    /** Unique ID for this mutation. */
    readonly id: string;

    /** What kind of mutation this is. */
    readonly kind: MutationKind;

    /** Human-readable description of what changed. */
    readonly description: string;

    /** The path in the WorldSpec that was modified (dot notation). */
    readonly path: string;

    /** Severity: how much this changes the scenario. 0-1. */
    readonly severity: number;
}

export type MutationKind =
    | 'add-machine'
    | 'remove-machine'
    | 'add-service'
    | 'remove-service'
    | 'modify-service'
    | 'add-vuln'
    | 'remove-vuln'
    | 'swap-vuln'
    | 'add-credential'
    | 'remove-credential'
    | 'move-credential'
    | 'add-segment'
    | 'remove-segment'
    | 'rewire-edge'
    | 'add-edge'
    | 'remove-edge'
    | 'adjust-difficulty'
    | 'add-objective'
    | 'modify-objective'
    | 'add-dynamic'
    | 'modify-firewall'
    | (string & {});     // open for extensions

// ── Mutation Constraints ────────────────────────────────────────

/** Constraints that limit what mutations are allowed. */
export interface MutationConstraints {
    /** Maximum number of machines in the result. */
    readonly maxMachines: number;

    /** Maximum number of network segments. */
    readonly maxSegments: number;

    /** Maximum number of credentials. */
    readonly maxCredentials: number;

    /** Maximum number of objectives. */
    readonly maxObjectives: number;

    /** Allowed vulnerability classes (empty = all allowed). */
    readonly allowedVulnClasses: readonly string[];

    /** Difficulty range for the output. */
    readonly difficultyRange: readonly [string, string];

    /** Maximum mutation severity per operation. */
    readonly maxSeverity: number;

    /** Maximum total mutations per generation. */
    readonly maxMutationsPerGeneration: number;

    /** Required machine roles that must be preserved. */
    readonly requiredRoles: readonly string[];
}

// ── Fitness ─────────────────────────────────────────────────────

/** Fitness metrics for a scenario, derived from telemetry. */
export interface ScenarioFitness {
    /** Scenario ID. */
    readonly scenarioId: string;

    /** Average engagement score (0-1). Higher = more engaging. */
    readonly engagement: number;

    /** Average learning gain (0-1). Higher = players learned more. */
    readonly learningGain: number;

    /** Completion rate (0-1). Too high = too easy, too low = too hard. */
    readonly completionRate: number;

    /** Average session duration in ticks. */
    readonly avgDuration: number;

    /** Number of sessions contributing to this fitness. */
    readonly sampleSize: number;

    /** Common failure modes observed. */
    readonly failModes: readonly FailMode[];
}

export interface FailMode {
    /** What went wrong. */
    readonly description: string;

    /** How often this failure occurs (0-1). */
    readonly frequency: number;

    /** At what tick players typically fail. */
    readonly avgFailTick: number;
}

// ── Generation ──────────────────────────────────────────────────

/** A generation of scenario variants. */
export interface ScenarioGeneration {
    /** Generation number (0-based). */
    readonly generation: number;

    /** Parent scenario IDs. */
    readonly parents: readonly string[];

    /** The offspring WorldSpec variants. */
    readonly offspring: readonly MutationResult[];

    /** Timestamp when this generation was created. */
    readonly createdAt: number;
}

/** Result of mutating a WorldSpec. */
export interface MutationResult {
    /** Unique ID for this variant. */
    readonly variantId: string;

    /** The mutations applied. */
    readonly mutations: readonly MutationOp[];

    /** Whether the validator accepted this offspring. */
    readonly valid: boolean;

    /** Validation errors (if invalid). */
    readonly errors: readonly string[];

    /** Estimated difficulty of the result. */
    readonly estimatedDifficulty: string;
}

// ── Crossover ───────────────────────────────────────────────────

/** Configuration for crossover between two parent WorldSpecs. */
export interface CrossoverConfig {
    /** Which aspects to take from parent A vs parent B. */
    readonly traits: readonly CrossoverTrait[];

    /** Random seed for reproducibility. */
    readonly seed: number;
}

export interface CrossoverTrait {
    /** Which part of WorldSpec this trait covers. */
    readonly aspect: 'network' | 'vulns' | 'services' | 'credentials' | 'objectives' | 'dynamics' | 'scoring';

    /** Probability of taking from parent A (vs parent B). 0-1. */
    readonly parentAWeight: number;
}

// ── Mutation Engine Interface ───────────────────────────────────

/**
 * The scenario mutation engine.
 *
 * SAFETY: Every mutation output is validated. Invalid offspring are
 * marked but not discarded — they carry useful information about
 * what doesn't work.
 *
 * EXTENSIBILITY: Custom mutation operators can be registered.
 * The fitness function is pluggable.
 */
export interface MutationEngine {
    /**
     * Apply random mutations to a WorldSpec within constraints.
     * Returns the mutated spec and a record of what changed.
     */
    mutate(
        spec: Record<string, unknown>,
        constraints: MutationConstraints,
        count: number,
        seed: number,
    ): readonly MutationResult[];

    /**
     * Crossover two parent WorldSpecs to produce offspring.
     */
    crossover(
        parentA: Record<string, unknown>,
        parentB: Record<string, unknown>,
        config: CrossoverConfig,
    ): MutationResult;

    /**
     * Select the fittest scenarios from a population.
     * Uses tournament selection with configurable pressure.
     */
    select(
        population: readonly ScenarioFitness[],
        count: number,
        tournamentSize: number,
    ): readonly ScenarioFitness[];

    /**
     * Run a full evolution cycle: select parents → crossover → mutate → validate.
     */
    evolve(
        population: readonly ScenarioFitness[],
        specs: ReadonlyMap<string, Record<string, unknown>>,
        constraints: MutationConstraints,
        config: EvolutionConfig,
    ): ScenarioGeneration;

    /** Register a custom mutation operator. */
    registerOperator(kind: string, operator: MutationOperator): void;

    /** Get registered operator kinds. */
    getOperatorKinds(): readonly string[];
}

/** Configuration for a full evolution cycle. */
export interface EvolutionConfig {
    /** Number of offspring to produce. */
    readonly offspringCount: number;

    /** Tournament size for selection. */
    readonly tournamentSize: number;

    /** Probability of mutation per offspring (0-1). */
    readonly mutationRate: number;

    /** Probability of crossover vs pure mutation (0-1). */
    readonly crossoverRate: number;

    /** Maximum mutations per offspring. */
    readonly maxMutationsPerOffspring: number;

    /** Random seed. */
    readonly seed: number;

    /** Generation number. */
    readonly generation: number;
}

/** A pluggable mutation operator. */
export interface MutationOperator {
    /** Apply this mutation to a spec. Returns the modified spec and mutation record. */
    apply(
        spec: Record<string, unknown>,
        seed: number,
    ): { readonly spec: Record<string, unknown>; readonly mutation: MutationOp };
}
