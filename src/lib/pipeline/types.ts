/**
 * VARIANT — CI/CD Pipeline Simulator Type Definitions
 *
 * Simulates build pipelines, artifact registries, git hooks,
 * and deployment workflows. Supply chain security as a native
 * engine primitive.
 *
 * COMPONENTS:
 * - PipelineDefinition: YAML-like pipeline config (stages, jobs, steps)
 * - ArtifactRegistry: simulated package manager (npm, docker, pip)
 * - RunnerPool: simulated build runners with resource constraints
 * - PipelineEngine: orchestrates execution, tracks state
 *
 * ATTACK SCENARIOS:
 * - Dependency confusion: malicious package in public registry
 * - Build poisoning: compromised CI runner
 * - Secret exfiltration: leaked env vars in build logs
 * - Artifact tampering: modified packages post-build
 *
 * SWAPPABILITY: Implements PipelineEngine interface. Replace this file.
 */

// ── Pipeline Definition ─────────────────────────────────────────

/** A complete CI/CD pipeline definition. */
export interface PipelineDefinition {
    /** Unique pipeline ID. */
    readonly id: string;

    /** Human-readable name. */
    readonly name: string;

    /** Git repository this pipeline belongs to. */
    readonly repository: string;

    /** Branch trigger patterns. */
    readonly triggers: readonly PipelineTrigger[];

    /** Ordered stages. */
    readonly stages: readonly PipelineStage[];

    /** Environment variables available to all jobs. */
    readonly env: Readonly<Record<string, string>>;

    /** Secrets (masked in logs). */
    readonly secrets: Readonly<Record<string, string>>;
}

export interface PipelineTrigger {
    readonly kind: 'push' | 'pull-request' | 'schedule' | 'manual' | 'tag';
    readonly branches?: readonly string[];
    readonly schedule?: string;
}

/** A pipeline stage containing parallel jobs. */
export interface PipelineStage {
    readonly name: string;
    readonly jobs: readonly PipelineJob[];
}

/** A single job within a stage. */
export interface PipelineJob {
    readonly id: string;
    readonly name: string;

    /** Runner label requirement. */
    readonly runsOn: string;

    /** Steps to execute in order. */
    readonly steps: readonly PipelineStep[];

    /** Jobs that must complete before this one. */
    readonly needs: readonly string[];

    /** Condition for running this job. */
    readonly condition?: string;

    /** Job-level environment variables. */
    readonly env?: Readonly<Record<string, string>>;

    /** Artifacts produced by this job. */
    readonly artifacts?: readonly ArtifactOutput[];

    /** Timeout in ticks. */
    readonly timeoutTicks: number;
}

/** A single step within a job. */
export interface PipelineStep {
    readonly name: string;
    readonly command: string;

    /** Whether to continue on failure. */
    readonly continueOnError: boolean;

    /** Step-level environment variables. */
    readonly env?: Readonly<Record<string, string>>;
}

/** An artifact produced by a job. */
export interface ArtifactOutput {
    readonly name: string;
    readonly path: string;
    readonly retention: number; // ticks to retain
}

// ── Pipeline Run State ──────────────────────────────────────────

/** State of a pipeline run. */
export interface PipelineRun {
    readonly runId: string;
    readonly pipelineId: string;
    readonly trigger: PipelineTrigger;
    readonly status: PipelineStatus;
    readonly startTick: number;
    readonly endTick: number | null;
    readonly stages: readonly StageRun[];
}

export type PipelineStatus = 'queued' | 'running' | 'success' | 'failure' | 'cancelled';

export interface StageRun {
    readonly name: string;
    readonly status: PipelineStatus;
    readonly jobs: readonly JobRun[];
}

export interface JobRun {
    readonly jobId: string;
    readonly status: PipelineStatus;
    readonly runnerId: string | null;
    readonly logs: readonly LogLine[];
    readonly startTick: number | null;
    readonly endTick: number | null;
}

export interface LogLine {
    readonly tick: number;
    readonly level: 'info' | 'warn' | 'error' | 'debug';
    readonly message: string;
    /** Whether this line contains a masked secret. */
    readonly masked: boolean;
}

// ── Artifact Registry ───────────────────────────────────────────

/** A package in the artifact registry. */
export interface ArtifactPackage {
    readonly name: string;
    readonly version: string;
    readonly registry: string; // 'npm', 'docker', 'pip', 'maven', custom
    readonly hash: string;
    readonly publishedAt: number; // tick
    readonly publisher: string;
    readonly dependencies: readonly PackageDependency[];
    readonly malicious: boolean;
    readonly compromised: boolean;
    readonly metadata: Readonly<Record<string, unknown>>;
}

export interface PackageDependency {
    readonly name: string;
    readonly versionRange: string;
    readonly registry: string;
}

// ── Runner Pool ─────────────────────────────────────────────────

/** A build runner in the pool. */
export interface BuildRunner {
    readonly id: string;
    readonly label: string;
    readonly status: 'idle' | 'busy' | 'offline' | 'compromised';
    readonly machine: string; // machine ID in the simulation
    readonly maxConcurrent: number;
    readonly currentJobs: number;
}

// ── Pipeline Engine Interface ───────────────────────────────────

/**
 * The pipeline engine simulates CI/CD workflows within the
 * simulation. Pipelines run on simulated build runners and
 * interact with artifact registries.
 *
 * SECURITY: Secret masking in logs. Compromised runners are
 * detectable via process tree and network monitoring.
 *
 * EXTENSIBILITY: Custom step executors, registry types, and
 * trigger conditions can be added.
 */
export interface PipelineEngine {
    /** Register a pipeline definition. */
    registerPipeline(definition: PipelineDefinition): void;

    /** Get a registered pipeline. */
    getPipeline(id: string): PipelineDefinition | null;

    /** List all registered pipelines. */
    listPipelines(): readonly PipelineDefinition[];

    /** Register a build runner. */
    registerRunner(runner: BuildRunner): void;

    /** Get runner status. */
    getRunner(id: string): BuildRunner | null;

    /** List all runners. */
    listRunners(): readonly BuildRunner[];

    /** Trigger a pipeline run. Returns the run ID. */
    trigger(pipelineId: string, triggerKind: PipelineTrigger, tick: number): string | null;

    /** Advance all running pipelines by one tick. */
    tick(currentTick: number): readonly PipelineEvent[];

    /** Get a pipeline run by ID. */
    getRun(runId: string): PipelineRun | null;

    /** List all runs for a pipeline. */
    listRuns(pipelineId: string): readonly PipelineRun[];

    /** Cancel a running pipeline. */
    cancel(runId: string): boolean;

    /** Publish a package to the artifact registry. */
    publishArtifact(pkg: ArtifactPackage): void;

    /** Resolve a package from the artifact registry. */
    resolveArtifact(name: string, versionRange: string, registry: string): ArtifactPackage | null;

    /** List all artifacts in a registry. */
    listArtifacts(registry: string): readonly ArtifactPackage[];

    /** Compromise a runner (for attack scenarios). */
    compromiseRunner(runnerId: string): boolean;

    /** Subscribe to pipeline events. */
    onEvent(handler: (event: PipelineEvent) => void): () => void;

    /** Clear all state. */
    clear(): void;
}

/** Events emitted by the pipeline engine. */
export interface PipelineEvent {
    readonly kind: PipelineEventKind;
    readonly tick: number;
    readonly pipelineId: string;
    readonly runId: string;
    readonly detail: string;
    readonly data: Readonly<Record<string, unknown>>;
}

export type PipelineEventKind =
    | 'run-started'
    | 'run-completed'
    | 'run-failed'
    | 'stage-started'
    | 'stage-completed'
    | 'job-started'
    | 'job-completed'
    | 'job-failed'
    | 'step-executed'
    | 'artifact-published'
    | 'artifact-resolved'
    | 'secret-leaked'
    | 'runner-compromised'
    | (string & {});
