/**
 * VARIANT — CI/CD Pipeline Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createPipelineEngine } from '../../../src/lib/pipeline/pipeline-engine';
import type { PipelineDefinition, PipelineTrigger, BuildRunner, ArtifactPackage, PipelineEvent } from '../../../src/lib/pipeline/types';

function makePipeline(overrides?: Partial<PipelineDefinition>): PipelineDefinition {
    return {
        id: 'pipeline-1',
        name: 'Build & Test',
        repository: 'org/app',
        triggers: [{ kind: 'push', branches: ['main'] }],
        stages: [
            {
                name: 'build',
                jobs: [{
                    id: 'build-job',
                    name: 'Build',
                    runsOn: 'linux',
                    steps: [
                        { name: 'Checkout', command: 'git checkout main', continueOnError: false },
                        { name: 'Install', command: 'npm install', continueOnError: false },
                        { name: 'Build', command: 'npm run build', continueOnError: false },
                    ],
                    needs: [],
                    timeoutTicks: 100,
                }],
            },
            {
                name: 'test',
                jobs: [{
                    id: 'test-job',
                    name: 'Test',
                    runsOn: 'linux',
                    steps: [
                        { name: 'Run tests', command: 'npm test', continueOnError: false },
                    ],
                    needs: ['build-job'],
                    timeoutTicks: 50,
                }],
            },
        ],
        env: { NODE_ENV: 'ci' },
        secrets: { NPM_TOKEN: 'secret-token-123' },
        ...overrides,
    };
}

function makeRunner(overrides?: Partial<BuildRunner>): BuildRunner {
    return {
        id: 'runner-1',
        label: 'linux',
        status: 'idle',
        machine: 'ci-01',
        maxConcurrent: 2,
        currentJobs: 0,
        ...overrides,
    };
}

function makeTrigger(): PipelineTrigger {
    return { kind: 'push', branches: ['main'] };
}

describe('PipelineEngine', () => {
    it('registers and retrieves pipeline', () => {
        const engine = createPipelineEngine();
        engine.registerPipeline(makePipeline());

        expect(engine.getPipeline('pipeline-1')).not.toBeNull();
        expect(engine.getPipeline('nonexistent')).toBeNull();
        expect(engine.listPipelines().length).toBe(1);
    });

    it('registers and retrieves runner', () => {
        const engine = createPipelineEngine();
        engine.registerRunner(makeRunner());

        expect(engine.getRunner('runner-1')).not.toBeNull();
        expect(engine.getRunner('nonexistent')).toBeNull();
        expect(engine.listRunners().length).toBe(1);
    });

    it('triggers a pipeline run', () => {
        const engine = createPipelineEngine();
        engine.registerPipeline(makePipeline());
        engine.registerRunner(makeRunner());

        const runId = engine.trigger('pipeline-1', makeTrigger(), 1);
        expect(runId).not.toBeNull();

        const run = engine.getRun(runId!);
        expect(run).not.toBeNull();
        expect(run!.status).toBe('running');
        expect(run!.pipelineId).toBe('pipeline-1');
    });

    it('returns null when triggering unknown pipeline', () => {
        const engine = createPipelineEngine();
        expect(engine.trigger('nonexistent', makeTrigger(), 1)).toBeNull();
    });

    it('executes pipeline steps on tick', () => {
        const engine = createPipelineEngine();
        engine.registerPipeline(makePipeline());
        engine.registerRunner(makeRunner());

        const runId = engine.trigger('pipeline-1', makeTrigger(), 0)!;

        // Tick 1: stage starts, job assigned to runner
        engine.tick(1);
        const run1 = engine.getRun(runId)!;
        expect(run1.stages[0]!.status).toBe('running');
        expect(run1.stages[0]!.jobs[0]!.status).toBe('running');

        // Tick 2: first step executes
        engine.tick(2);
        const run2 = engine.getRun(runId)!;
        expect(run2.stages[0]!.jobs[0]!.logs.length).toBe(1);
    });

    it('completes pipeline after all stages', () => {
        const engine = createPipelineEngine();
        engine.registerPipeline(makePipeline());
        engine.registerRunner(makeRunner());

        const runId = engine.trigger('pipeline-1', makeTrigger(), 0)!;

        // Build stage: 3 steps + 1 completion tick
        for (let i = 1; i <= 5; i++) engine.tick(i);

        // Test stage: 1 step + 1 completion tick + stage advance + run complete
        for (let i = 6; i <= 12; i++) engine.tick(i);

        const run = engine.getRun(runId)!;
        expect(run.status).toBe('success');
    });

    it('masks secrets in logs', () => {
        const engine = createPipelineEngine();
        engine.registerPipeline(makePipeline({
            stages: [{
                name: 'deploy',
                jobs: [{
                    id: 'deploy-job',
                    name: 'Deploy',
                    runsOn: 'linux',
                    steps: [{ name: 'Push', command: 'npm publish --token secret-token-123', continueOnError: false }],
                    needs: [],
                    timeoutTicks: 50,
                }],
            }],
        }));
        engine.registerRunner(makeRunner());

        const runId = engine.trigger('pipeline-1', makeTrigger(), 0)!;
        engine.tick(1); // start stage + job
        engine.tick(2); // execute step

        const run = engine.getRun(runId)!;
        const logs = run.stages[0]!.jobs[0]!.logs;
        const stepLog = logs.find(l => l.message.includes('npm publish'));
        expect(stepLog).toBeTruthy();
        expect(stepLog!.message).toContain('***');
        expect(stepLog!.message).not.toContain('secret-token-123');
        expect(stepLog!.masked).toBe(true);
    });

    it('handles job timeout', () => {
        const engine = createPipelineEngine();
        engine.registerPipeline(makePipeline({
            stages: [{
                name: 'slow',
                jobs: [{
                    id: 'slow-job',
                    name: 'Slow Job',
                    runsOn: 'linux',
                    steps: Array.from({ length: 200 }, (_, i) => ({
                        name: `Step ${i}`,
                        command: `echo ${i}`,
                        continueOnError: false,
                    })),
                    needs: [],
                    timeoutTicks: 5,
                }],
            }],
        }));
        engine.registerRunner(makeRunner());

        const runId = engine.trigger('pipeline-1', makeTrigger(), 0)!;

        // Tick past timeout
        for (let i = 1; i <= 10; i++) engine.tick(i);

        const run = engine.getRun(runId)!;
        expect(run.status).toBe('failure');
    });

    it('publishes and resolves artifacts', () => {
        const engine = createPipelineEngine();

        const pkg: ArtifactPackage = {
            name: 'my-lib',
            version: '1.0.0',
            registry: 'npm',
            hash: 'abc123',
            publishedAt: 1,
            publisher: 'ci',
            dependencies: [],
            malicious: false,
            compromised: false,
            metadata: {},
        };

        engine.publishArtifact(pkg);

        const resolved = engine.resolveArtifact('my-lib', '1.0.0', 'npm');
        expect(resolved).not.toBeNull();
        expect(resolved!.name).toBe('my-lib');
    });

    it('returns null for unknown artifact', () => {
        const engine = createPipelineEngine();
        expect(engine.resolveArtifact('nonexistent', '*', 'npm')).toBeNull();
    });

    it('lists artifacts by registry', () => {
        const engine = createPipelineEngine();
        engine.publishArtifact({ name: 'a', version: '1.0', registry: 'npm', hash: 'h1', publishedAt: 1, publisher: 'ci', dependencies: [], malicious: false, compromised: false, metadata: {} });
        engine.publishArtifact({ name: 'b', version: '1.0', registry: 'docker', hash: 'h2', publishedAt: 1, publisher: 'ci', dependencies: [], malicious: false, compromised: false, metadata: {} });

        expect(engine.listArtifacts('npm').length).toBe(1);
        expect(engine.listArtifacts('docker').length).toBe(1);
        expect(engine.listArtifacts('pip').length).toBe(0);
    });

    it('compromises a runner', () => {
        const engine = createPipelineEngine();
        engine.registerRunner(makeRunner());

        expect(engine.compromiseRunner('runner-1')).toBe(true);
        expect(engine.getRunner('runner-1')!.status).toBe('compromised');
        expect(engine.compromiseRunner('nonexistent')).toBe(false);
    });

    it('compromised runner leaks secrets', () => {
        const engine = createPipelineEngine();
        engine.registerPipeline(makePipeline());
        engine.registerRunner(makeRunner());

        engine.trigger('pipeline-1', makeTrigger(), 0);
        engine.tick(1); // start job on runner

        // Compromise the runner
        engine.compromiseRunner('runner-1');

        const events: PipelineEvent[] = [];
        engine.onEvent(e => events.push(e));

        engine.tick(2); // should detect compromised runner and leak secrets

        const leaked = events.filter(e => e.kind === 'secret-leaked');
        expect(leaked.length).toBeGreaterThan(0);
    });

    it('cancels a running pipeline', () => {
        const engine = createPipelineEngine();
        engine.registerPipeline(makePipeline());
        engine.registerRunner(makeRunner());

        const runId = engine.trigger('pipeline-1', makeTrigger(), 0)!;
        expect(engine.cancel(runId)).toBe(true);

        const run = engine.getRun(runId)!;
        expect(run.status).toBe('cancelled');
    });

    it('cancel returns false for non-running pipeline', () => {
        const engine = createPipelineEngine();
        expect(engine.cancel('nonexistent')).toBe(false);
    });

    it('fires events to handlers', () => {
        const engine = createPipelineEngine();
        engine.registerPipeline(makePipeline());
        engine.registerRunner(makeRunner());

        const events: PipelineEvent[] = [];
        engine.onEvent(e => events.push(e));

        engine.trigger('pipeline-1', makeTrigger(), 0);
        expect(events.some(e => e.kind === 'run-started')).toBe(true);
    });

    it('unsubscribes event handler', () => {
        const engine = createPipelineEngine();
        engine.registerPipeline(makePipeline());
        engine.registerRunner(makeRunner());

        const events: PipelineEvent[] = [];
        const unsub = engine.onEvent(e => events.push(e));

        engine.trigger('pipeline-1', makeTrigger(), 0);
        const countAfterFirst = events.length;

        unsub();
        engine.trigger('pipeline-1', makeTrigger(), 1);
        expect(events.length).toBe(countAfterFirst);
    });

    it('lists runs by pipeline', () => {
        const engine = createPipelineEngine();
        engine.registerPipeline(makePipeline());
        engine.registerRunner(makeRunner());

        engine.trigger('pipeline-1', makeTrigger(), 0);
        engine.trigger('pipeline-1', makeTrigger(), 1);

        expect(engine.listRuns('pipeline-1').length).toBe(2);
        expect(engine.listRuns('nonexistent').length).toBe(0);
    });

    it('runner becomes busy when at capacity', () => {
        const engine = createPipelineEngine();
        engine.registerPipeline(makePipeline({
            stages: [{
                name: 'parallel',
                jobs: [
                    { id: 'j1', name: 'J1', runsOn: 'linux', steps: [{ name: 's', command: 'echo 1', continueOnError: false }], needs: [], timeoutTicks: 50 },
                    { id: 'j2', name: 'J2', runsOn: 'linux', steps: [{ name: 's', command: 'echo 2', continueOnError: false }], needs: [], timeoutTicks: 50 },
                ],
            }],
        }));
        engine.registerRunner(makeRunner({ maxConcurrent: 2 }));

        engine.trigger('pipeline-1', makeTrigger(), 0);
        engine.tick(1); // both jobs start

        const runner = engine.getRunner('runner-1')!;
        expect(runner.status).toBe('busy');
    });

    it('clears all state', () => {
        const engine = createPipelineEngine();
        engine.registerPipeline(makePipeline());
        engine.registerRunner(makeRunner());
        engine.trigger('pipeline-1', makeTrigger(), 0);

        engine.clear();
        expect(engine.listPipelines().length).toBe(0);
        expect(engine.listRunners().length).toBe(0);
    });

    it('handles malicious artifact in registry', () => {
        const engine = createPipelineEngine();
        engine.publishArtifact({
            name: 'legit-lib',
            version: '1.0.0',
            registry: 'npm',
            hash: 'clean',
            publishedAt: 1,
            publisher: 'trusted',
            dependencies: [],
            malicious: false,
            compromised: false,
            metadata: {},
        });
        engine.publishArtifact({
            name: 'legit-lib',
            version: '1.0.1',
            registry: 'npm',
            hash: 'evil',
            publishedAt: 2,
            publisher: 'attacker',
            dependencies: [],
            malicious: true,
            compromised: false,
            metadata: { payload: 'reverse-shell' },
        });

        // resolveArtifact returns latest — which is the malicious one
        const resolved = engine.resolveArtifact('legit-lib', '*', 'npm');
        expect(resolved).not.toBeNull();
        expect(resolved!.malicious).toBe(true);
    });
});
