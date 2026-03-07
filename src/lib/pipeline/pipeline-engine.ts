/**
 * VARIANT — CI/CD Pipeline Engine Implementation
 *
 * Simulates build pipelines, artifact registries, runners.
 * Supply chain security as a native engine primitive.
 *
 * SWAPPABILITY: Implements PipelineEngine. Replace this file.
 */

import type {
    PipelineEngine,
    PipelineDefinition,
    PipelineRun,
    PipelineEvent,
    PipelineEventKind,
    PipelineTrigger,
    PipelineStatus,
    LogLine,
    BuildRunner,
    ArtifactPackage,
} from './types';

interface MutableRunner {
    id: string;
    label: string;
    status: 'idle' | 'busy' | 'offline' | 'compromised';
    machine: string;
    maxConcurrent: number;
    currentJobs: number;
}

interface MutableRun {
    runId: string;
    pipelineId: string;
    trigger: PipelineTrigger;
    status: PipelineStatus;
    startTick: number;
    endTick: number | null;
    stages: MutableStageRun[];
    currentStageIdx: number;
}

interface MutableStageRun {
    name: string;
    status: PipelineStatus;
    jobs: MutableJobRun[];
}

interface MutableJobRun {
    jobId: string;
    status: PipelineStatus;
    runnerId: string | null;
    logs: LogLine[];
    startTick: number | null;
    endTick: number | null;
    stepIdx: number;
    timeoutTick: number | null;
}

let runCounter = 0;

function generateRunId(): string {
    return 'run-' + (++runCounter).toString(36).padStart(6, '0');
}

function maskSecrets(message: string, secrets: Readonly<Record<string, string>>): { text: string; masked: boolean } {
    let result = message;
    let masked = false;
    for (const value of Object.values(secrets)) {
        if (value.length > 0 && result.includes(value)) {
            result = result.split(value).join('***');
            masked = true;
        }
    }
    return { text: result, masked };
}

export function createPipelineEngine(): PipelineEngine {
    const pipelines = new Map<string, PipelineDefinition>();
    const runners = new Map<string, MutableRunner>();
    const runs = new Map<string, MutableRun>();
    const artifacts = new Map<string, ArtifactPackage[]>(); // registry → packages
    const handlers = new Set<(event: PipelineEvent) => void>();

    function emitEvent(kind: PipelineEventKind, tick: number, pipelineId: string, runId: string, detail: string, data?: Record<string, unknown>): PipelineEvent {
        const event: PipelineEvent = { kind, tick, pipelineId, runId, detail, data: data ?? {} };
        for (const handler of handlers) {
            handler(event);
        }
        return event;
    }

    function findAvailableRunner(label: string): MutableRunner | null {
        for (const runner of runners.values()) {
            if (runner.label === label && runner.status !== 'offline' && runner.currentJobs < runner.maxConcurrent) {
                return runner;
            }
        }
        return null;
    }

    function toImmutableRun(run: MutableRun): PipelineRun {
        return {
            runId: run.runId,
            pipelineId: run.pipelineId,
            trigger: run.trigger,
            status: run.status,
            startTick: run.startTick,
            endTick: run.endTick,
            stages: run.stages.map(s => ({
                name: s.name,
                status: s.status,
                jobs: s.jobs.map(j => ({
                    jobId: j.jobId,
                    status: j.status,
                    runnerId: j.runnerId,
                    logs: [...j.logs],
                    startTick: j.startTick,
                    endTick: j.endTick,
                })),
            })),
        };
    }

    return {
        registerPipeline(definition: PipelineDefinition): void {
            pipelines.set(definition.id, definition);
        },

        getPipeline(id: string): PipelineDefinition | null {
            return pipelines.get(id) ?? null;
        },

        listPipelines(): readonly PipelineDefinition[] {
            return [...pipelines.values()];
        },

        registerRunner(runner: BuildRunner): void {
            runners.set(runner.id, {
                id: runner.id,
                label: runner.label,
                status: runner.status,
                machine: runner.machine,
                maxConcurrent: runner.maxConcurrent,
                currentJobs: runner.currentJobs,
            });
        },

        getRunner(id: string): BuildRunner | null {
            const r = runners.get(id);
            if (r === undefined) return null;
            return { ...r };
        },

        listRunners(): readonly BuildRunner[] {
            return [...runners.values()].map(r => ({ ...r }));
        },

        trigger(pipelineId: string, triggerKind: PipelineTrigger, tick: number): string | null {
            const pipeline = pipelines.get(pipelineId);
            if (pipeline === undefined) return null;

            const runId = generateRunId();
            const stages: MutableStageRun[] = pipeline.stages.map(stage => ({
                name: stage.name,
                status: 'queued' as PipelineStatus,
                jobs: stage.jobs.map(job => ({
                    jobId: job.id,
                    status: 'queued' as PipelineStatus,
                    runnerId: null,
                    logs: [],
                    startTick: null,
                    endTick: null,
                    stepIdx: 0,
                    timeoutTick: null,
                })),
            }));

            const run: MutableRun = {
                runId,
                pipelineId,
                trigger: triggerKind,
                status: 'running',
                startTick: tick,
                endTick: null,
                stages,
                currentStageIdx: 0,
            };

            runs.set(runId, run);
            emitEvent('run-started', tick, pipelineId, runId, `Pipeline ${pipeline.name} started`);
            return runId;
        },

        tick(currentTick: number): readonly PipelineEvent[] {
            const events: PipelineEvent[] = [];

            for (const run of runs.values()) {
                if (run.status !== 'running') continue;

                const pipeline = pipelines.get(run.pipelineId);
                if (pipeline === undefined) continue;

                if (run.currentStageIdx >= run.stages.length) {
                    run.status = 'success';
                    run.endTick = currentTick;
                    events.push(emitEvent('run-completed', currentTick, run.pipelineId, run.runId, 'Pipeline completed successfully'));
                    continue;
                }

                const stage = run.stages[run.currentStageIdx]!;
                const pipelineStage = pipeline.stages[run.currentStageIdx]!;

                if (stage.status === 'queued') {
                    stage.status = 'running';
                    events.push(emitEvent('stage-started', currentTick, run.pipelineId, run.runId, `Stage ${stage.name} started`));
                }

                let allJobsDone = true;
                let anyFailed = false;

                for (let ji = 0; ji < stage.jobs.length; ji++) {
                    const job = stage.jobs[ji]!;
                    const jobDef = pipelineStage.jobs[ji]!;

                    if (job.status === 'success' || job.status === 'failure') continue;

                    allJobsDone = false;

                    // Try to start queued jobs
                    if (job.status === 'queued') {
                        const runner = findAvailableRunner(jobDef.runsOn);
                        if (runner !== null) {
                            job.status = 'running';
                            job.runnerId = runner.id;
                            job.startTick = currentTick;
                            job.timeoutTick = currentTick + jobDef.timeoutTicks;
                            runner.currentJobs++;
                            if (runner.currentJobs >= runner.maxConcurrent) {
                                runner.status = 'busy';
                            }
                            events.push(emitEvent('job-started', currentTick, run.pipelineId, run.runId,
                                `Job ${jobDef.name} started on ${runner.id}`, { jobId: job.jobId }));
                        }
                        continue;
                    }

                    // Process running jobs — execute one step per tick
                    if (job.status === 'running') {
                        // Check timeout
                        if (job.timeoutTick !== null && currentTick >= job.timeoutTick) {
                            job.status = 'failure';
                            job.endTick = currentTick;
                            job.logs.push({ tick: currentTick, level: 'error', message: 'Job timed out', masked: false });
                            releaseRunner(job.runnerId);
                            anyFailed = true;
                            events.push(emitEvent('job-failed', currentTick, run.pipelineId, run.runId,
                                `Job ${jobDef.name} timed out`, { jobId: job.jobId }));
                            continue;
                        }

                        // Check if runner is compromised
                        if (job.runnerId !== null) {
                            const runner = runners.get(job.runnerId);
                            if (runner !== undefined && runner.status === 'compromised') {
                                // Compromised runner leaks secrets
                                for (const [key, value] of Object.entries(pipeline.secrets)) {
                                    job.logs.push({
                                        tick: currentTick,
                                        level: 'error',
                                        message: `LEAKED SECRET: ${key}=${value}`,
                                        masked: false,
                                    });
                                    events.push(emitEvent('secret-leaked', currentTick, run.pipelineId, run.runId,
                                        `Secret ${key} leaked on compromised runner`, { key, runnerId: job.runnerId }));
                                }
                            }
                        }

                        if (job.stepIdx < jobDef.steps.length) {
                            const step = jobDef.steps[job.stepIdx]!;
                            const { text, masked } = maskSecrets(step.command, pipeline.secrets);
                            job.logs.push({ tick: currentTick, level: 'info', message: `$ ${text}`, masked });
                            job.stepIdx++;

                            events.push(emitEvent('step-executed', currentTick, run.pipelineId, run.runId,
                                `Step: ${step.name}`, { jobId: job.jobId, command: text }));
                        } else {
                            // All steps done
                            job.status = 'success';
                            job.endTick = currentTick;
                            releaseRunner(job.runnerId);
                            events.push(emitEvent('job-completed', currentTick, run.pipelineId, run.runId,
                                `Job ${jobDef.name} completed`, { jobId: job.jobId }));
                        }
                    }
                }

                if (anyFailed) {
                    stage.status = 'failure';
                    run.status = 'failure';
                    run.endTick = currentTick;
                    events.push(emitEvent('run-failed', currentTick, run.pipelineId, run.runId,
                        `Pipeline failed at stage ${stage.name}`));
                } else if (allJobsDone) {
                    stage.status = 'success';
                    events.push(emitEvent('stage-completed', currentTick, run.pipelineId, run.runId,
                        `Stage ${stage.name} completed`));
                    run.currentStageIdx++;
                }
            }

            return events;

            function releaseRunner(runnerId: string | null): void {
                if (runnerId === null) return;
                const runner = runners.get(runnerId);
                if (runner !== undefined && runner.status !== 'compromised') {
                    runner.currentJobs = Math.max(0, runner.currentJobs - 1);
                    if (runner.currentJobs === 0) runner.status = 'idle';
                }
            }
        },

        getRun(runId: string): PipelineRun | null {
            const run = runs.get(runId);
            if (run === undefined) return null;
            return toImmutableRun(run);
        },

        listRuns(pipelineId: string): readonly PipelineRun[] {
            return [...runs.values()]
                .filter(r => r.pipelineId === pipelineId)
                .map(toImmutableRun);
        },

        cancel(runId: string): boolean {
            const run = runs.get(runId);
            if (run === undefined || run.status !== 'running') return false;
            run.status = 'cancelled';
            run.endTick = 0;
            return true;
        },

        publishArtifact(pkg: ArtifactPackage): void {
            const list = artifacts.get(pkg.registry) ?? [];
            list.push(pkg);
            artifacts.set(pkg.registry, list);
        },

        resolveArtifact(name: string, _versionRange: string, registry: string): ArtifactPackage | null {
            const list = artifacts.get(registry);
            if (list === undefined) return null;

            // Simple: find latest matching name
            const matching = list.filter(p => p.name === name);
            if (matching.length === 0) return null;
            return matching[matching.length - 1]!;
        },

        listArtifacts(registry: string): readonly ArtifactPackage[] {
            return artifacts.get(registry) ?? [];
        },

        compromiseRunner(runnerId: string): boolean {
            const runner = runners.get(runnerId);
            if (runner === undefined) return false;
            runner.status = 'compromised';
            return true;
        },

        onEvent(handler: (event: PipelineEvent) => void): () => void {
            handlers.add(handler);
            return () => { handlers.delete(handler); };
        },

        clear(): void {
            pipelines.clear();
            runners.clear();
            runs.clear();
            artifacts.clear();
            handlers.clear();
            runCounter = 0;
        },
    };
}
