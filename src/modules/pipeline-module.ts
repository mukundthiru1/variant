/**
 * VARIANT — CI/CD Pipeline Simulation Module
 *
 * Simulates CI/CD platforms (Jenkins, GitLab CI, GitHub Actions) within
 * the air-gapped simulation. Provides endpoints for pipeline discovery,
 * triggering runs, accessing environment variables (secrets), and
 * executing commands on runners (RCE simulation).
 *
 * API Endpoints:
 *   - GET  /api/v1/pipelines              → List all pipeline definitions
 *   - GET  /api/v1/pipelines/{id}         → Get pipeline definition
 *   - POST /api/v1/pipelines/{id}/trigger → Trigger a pipeline run
 *   - GET  /api/v1/pipelines/{id}/env     → Get pipeline env vars (secrets!)
 *   - GET  /api/v1/runs/{runId}           → Get run status and stage results
 *   - GET  /api/v1/runners                → List all pipeline runners
 *   - GET  /api/v1/runners/{id}           → Get runner details with secrets
 *   - POST /api/v1/runners/{id}/exec      → Execute command on runner (RCE)
 *
 * SECURITY: Pure simulation. No real CI/CD systems are accessed.
 * MODULARITY: Swappable module. Reads PipelineSpec from WorldSpec.
 */

import type { Module, SimulationContext, Capability } from '../core/modules';
import type { ExternalRequest, ExternalResponse, ExternalServiceHandler } from '../core/fabric/types';
import type { PipelineSpec, PipelineDefinitionSpec, PipelineStageSpec, PipelineRunnerSpec } from '../core/world/types';

// ── Module ID ──────────────────────────────────────────────────

const MODULE_ID = 'pipeline-sim';
const MODULE_VERSION = '1.0.0';

// ── Response helpers ───────────────────────────────────────────

const encoder = new TextEncoder();

function jsonResponse(status: number, data: unknown): ExternalResponse {
    const headers = new Map<string, string>();
    headers.set('content-type', 'application/json');
    headers.set('server', 'VARIANT-Pipeline/1.0');
    return { status, headers, body: encoder.encode(JSON.stringify(data, null, 2)) };
}

function make404(message = 'Not Found'): ExternalResponse {
    return jsonResponse(404, { error: message });
}

function make400(message = 'Bad Request'): ExternalResponse {
    return jsonResponse(400, { error: message });
}

// ── Pipeline Run State ─────────────────────────────────────────

type PipelineRunStatus = 'pending' | 'running' | 'success' | 'failed';

interface PipelineRun {
    readonly runId: string;
    readonly pipelineName: string;
    readonly status: PipelineRunStatus;
    readonly startedAt: number;
    readonly completedAt?: number;
    readonly stages: PipelineStageResult[];
    readonly triggeredBy: string;
}

interface PipelineStageResult {
    readonly name: string;
    readonly status: 'pending' | 'running' | 'success' | 'failed';
    readonly startedAt?: number;
    readonly completedAt?: number;
    readonly output?: string;
    readonly error?: string;
}

// ── In-memory state (per module instance) ──────────────────────

interface PipelineState {
    runs: Map<string, PipelineRun>;
    triggerCount: Map<string, number>; // pipeline name → count (for deterministic IDs)
}

// ── Factory ────────────────────────────────────────────────────

export function createPipelineModule(): Module {
    const state: PipelineState = {
        runs: new Map(),
        triggerCount: new Map(),
    };

    return {
        id: MODULE_ID,
        type: 'engine',
        version: MODULE_VERSION,
        description: 'Simulates CI/CD pipelines (Jenkins, GitLab CI, GitHub Actions) with secret extraction and runner RCE attack surface',

        provides: [{ name: 'pipeline' }, { name: 'ci-cd' }] as readonly Capability[],
        requires: [{ name: 'variant-internet' }] as readonly Capability[],

        init(context: SimulationContext): void {
            const pipeline = context.world.pipeline;
            if (pipeline === undefined) return;

            // Register the pipeline API service
            const handler: ExternalServiceHandler = {
                domain: `pipeline.${pipeline.tool}.variant.local`,
                description: `VARIANT Pipeline: ${pipeline.tool} CI/CD API`,
                handleRequest(request: ExternalRequest): ExternalResponse {
                    return handlePipelineRequest(request, pipeline, state, context);
                },
            };

            context.fabric.addDNSRecord({
                domain: handler.domain,
                ip: '172.16.2.10',
                type: 'A',
                ttl: 3600,
            });

            context.fabric.registerExternal(handler);

            context.events.emit({
                type: 'sim:alert',
                source: MODULE_ID,
                message: `Pipeline API activated: ${pipeline.tool} (${pipeline.pipelines.length} pipelines, ${pipeline.runners.length} runners)`,
                timestamp: Date.now(),
            });
        },

        destroy(): void {
            // Clear in-memory state
            state.runs.clear();
            state.triggerCount.clear();
        },
    };
}

// ── Request Handler ────────────────────────────────────────────

function handlePipelineRequest(
    request: ExternalRequest,
    pipeline: PipelineSpec,
    state: PipelineState,
    context: SimulationContext,
): ExternalResponse {
    const path = request.path;
    const method = request.method;

    // GET /api/v1/pipelines - List all pipelines
    if (path === '/api/v1/pipelines' && method === 'GET') {
        return listPipelines(pipeline);
    }

    // GET /api/v1/pipelines/{id} - Get specific pipeline
    const pipelineMatch = path.match(/^\/api\/v1\/pipelines\/([^/]+)$/);
    if (pipelineMatch !== null && method === 'GET') {
        const pipelineId = decodeURIComponent(pipelineMatch[1]!);
        return getPipeline(pipelineId, pipeline);
    }

    // GET /api/v1/pipelines/{id}/env - Get pipeline env vars (secrets!)
    const envMatch = path.match(/^\/api\/v1\/pipelines\/([^/]+)\/env$/);
    if (envMatch !== null && method === 'GET') {
        const pipelineId = decodeURIComponent(envMatch[1]!);
        return getPipelineEnv(pipelineId, pipeline, context);
    }

    // POST /api/v1/pipelines/{id}/trigger - Trigger pipeline run
    const triggerMatch = path.match(/^\/api\/v1\/pipelines\/([^/]+)\/trigger$/);
    if (triggerMatch !== null && method === 'POST') {
        const pipelineId = decodeURIComponent(triggerMatch[1]!);
        return triggerPipeline(pipelineId, pipeline, state, context);
    }

    // GET /api/v1/runs/{runId} - Get run status
    const runMatch = path.match(/^\/api\/v1\/runs\/([^/]+)$/);
    if (runMatch !== null && method === 'GET') {
        const runId = decodeURIComponent(runMatch[1]!);
        return getRunStatus(runId, state);
    }

    // GET /api/v1/runners - List runners
    if (path === '/api/v1/runners' && method === 'GET') {
        return listRunners(pipeline);
    }

    // GET /api/v1/runners/{id} - Get runner details
    const runnerMatch = path.match(/^\/api\/v1\/runners\/([^/]+)$/);
    if (runnerMatch !== null && method === 'GET') {
        const runnerId = decodeURIComponent(runnerMatch[1]!);
        return getRunnerDetails(runnerId, pipeline);
    }

    // POST /api/v1/runners/{id}/exec - Execute command on runner (RCE)
    const execMatch = path.match(/^\/api\/v1\/runners\/([^/]+)\/exec$/);
    if (execMatch !== null && method === 'POST') {
        const runnerId = decodeURIComponent(execMatch[1]!);
        return execOnRunner(runnerId, request, pipeline, context);
    }

    return make404();
}

// ── API Endpoints ──────────────────────────────────────────────

function listPipelines(pipeline: PipelineSpec): ExternalResponse {
    const pipelines = pipeline.pipelines.map(p => ({
        name: p.name,
        trigger: p.trigger,
        stageCount: p.stages.length,
        stages: p.stages.map(s => s.name),
        vulnerabilities: p.vulnerabilities ?? [],
    }));

    return jsonResponse(200, { pipelines });
}

function getPipeline(pipelineId: string, pipeline: PipelineSpec): ExternalResponse {
    const def = findPipeline(pipelineId, pipeline);
    if (def === undefined) {
        return make404(`Pipeline '${pipelineId}' not found`);
    }

    return jsonResponse(200, {
        name: def.name,
        trigger: def.trigger,
        stages: def.stages.map(s => ({
            name: s.name,
            commands: s.commands,
            env: s.env ?? {},
            artifacts: s.artifacts ?? [],
        })),
        vulnerabilities: def.vulnerabilities ?? [],
    });
}

function getPipelineEnv(pipelineId: string, pipeline: PipelineSpec, context: SimulationContext): ExternalResponse {
    const def = findPipeline(pipelineId, pipeline);
    if (def === undefined) {
        return make404(`Pipeline '${pipelineId}' not found`);
    }

    // Collect all environment variables from pipeline and stages
    const envVars: Record<string, string> = {};

    // Pipeline-level secrets
    for (const [key, value] of Object.entries(pipeline.secrets)) {
        envVars[key] = value;
        emitCredentialFound(context, key, 'pipeline-secrets');
    }

    // Stage-level env vars
    for (const stage of def.stages) {
        if (stage.env !== undefined) {
            for (const [key, value] of Object.entries(stage.env)) {
                envVars[`${stage.name}.${key}`] = value;
                if (looksLikeSecret(key, value)) {
                    emitCredentialFound(context, key, `stage-${stage.name}`);
                }
            }
        }
    }

    return jsonResponse(200, {
        pipeline: pipelineId,
        environment: envVars,
    });
}

function triggerPipeline(
    pipelineId: string,
    pipeline: PipelineSpec,
    state: PipelineState,
    context: SimulationContext,
): ExternalResponse {
    const def = findPipeline(pipelineId, pipeline);
    if (def === undefined) {
        return make404(`Pipeline '${pipelineId}' not found`);
    }

    // Generate deterministic run ID
    const triggerCount = state.triggerCount.get(pipelineId) ?? 0;
    state.triggerCount.set(pipelineId, triggerCount + 1);
    const runId = `${pipelineId}-run-${triggerCount + 1}`;

    // Create stage results
    const stageResults: PipelineStageResult[] = def.stages.map(stage => ({
        name: stage.name,
        status: 'pending',
    }));

    // Create run
    const run: PipelineRun = {
        runId,
        pipelineName: pipelineId,
        status: 'running',
        startedAt: Date.now(),
        stages: stageResults,
        triggeredBy: 'api',
    };

    state.runs.set(runId, run);

    // Simulate execution
    simulatePipelineExecution(run, def, context, pipeline);

    // Update final state after simulation
    const finalRun = state.runs.get(runId);
    if (finalRun !== undefined) {
        const failedStage = finalRun.stages.find(s => s.status === 'failed');
        if (failedStage !== undefined) {
            state.runs.set(runId, {
                ...finalRun,
                status: 'failed',
                completedAt: Date.now(),
            });
        } else {
            state.runs.set(runId, {
                ...finalRun,
                status: 'success',
                completedAt: Date.now(),
            });
        }
    }

    return jsonResponse(200, {
        runId,
        status: 'running',
        pipeline: pipelineId,
        message: 'Pipeline triggered successfully',
    });
}

function getRunStatus(runId: string, state: PipelineState): ExternalResponse {
    const run = state.runs.get(runId);
    if (run === undefined) {
        return make404(`Run '${runId}' not found`);
    }

    return jsonResponse(200, {
        runId: run.runId,
        pipeline: run.pipelineName,
        status: run.status,
        startedAt: run.startedAt,
        completedAt: run.completedAt,
        stages: run.stages.map(s => ({
            name: s.name,
            status: s.status,
            startedAt: s.startedAt,
            completedAt: s.completedAt,
            output: s.output,
            error: s.error,
        })),
    });
}

function listRunners(pipeline: PipelineSpec): ExternalResponse {
    const runners = pipeline.runners.map(r => ({
        name: r.name,
        machineId: r.machineId,
        // Include labels/tags from the spec if available
        labels: ['docker', 'linux', 'x64'],
        status: 'online',
    }));

    return jsonResponse(200, { runners });
}

function getRunnerDetails(runnerId: string, pipeline: PipelineSpec): ExternalResponse {
    const runner = findRunner(runnerId, pipeline);
    if (runner === undefined) {
        return make404(`Runner '${runnerId}' not found`);
    }

    // Collect mounted secrets for this runner
    const mountedSecrets: Record<string, string> = {};

    // Pipeline secrets are mounted on all runners
    for (const [key, value] of Object.entries(pipeline.secrets)) {
        mountedSecrets[key] = value;
    }

    // Find pipelines that can run on this runner and collect their env vars
    for (const pipelineDef of pipeline.pipelines) {
        for (const stage of pipelineDef.stages) {
            if (stage.env !== undefined) {
                for (const [key, value] of Object.entries(stage.env)) {
                    mountedSecrets[`${pipelineDef.name}.${stage.name}.${key}`] = value;
                }
            }
        }
    }

    return jsonResponse(200, {
        name: runner.name,
        machineId: runner.machineId,
        labels: ['docker', 'linux', 'x64'],
        status: 'online',
        environment: mountedSecrets,
        privileged: isPrivilegedRunner(runner),
    });
}

function execOnRunner(
    runnerId: string,
    request: ExternalRequest,
    pipeline: PipelineSpec,
    context: SimulationContext,
): ExternalResponse {
    const runner = findRunner(runnerId, pipeline);
    if (runner === undefined) {
        return make404(`Runner '${runnerId}' not found`);
    }

    // Parse command from request body
    let command = '';
    if (request.body !== null) {
        try {
            const bodyText = new TextDecoder().decode(request.body);
            const parsed = JSON.parse(bodyText);
            command = parsed.command ?? '';
        } catch {
            // ignore parse errors
        }
    }

    if (command === '') {
        return make400('Missing command in request body');
    }

    // Emit defense alert for RCE on runner
    context.events.emit({
        type: 'defense:alert',
        machine: runner.machineId,
        ruleId: 'pipeline:rce-detected',
        severity: 'critical',
        detail: `RCE detected on CI runner '${runnerId}': ${command.slice(0, 100)}`,
        timestamp: Date.now(),
    });

    const privileged = isPrivilegedRunner(runner);

    if (!privileged) {
        return jsonResponse(200, {
            stdout: '',
            stderr: 'Permission denied: runner is not privileged',
            exitCode: 1,
            privileged: false,
        });
    }

    // Simulate command execution with access to secrets
    const availableSecrets: Record<string, string> = {};
    for (const [key, value] of Object.entries(pipeline.secrets)) {
        availableSecrets[key] = value;
    }

    // Simulate command output
    let stdout = '';
    let stderr = '';
    let exitCode = 0;

    if (command.includes('env') || command.includes('printenv')) {
        stdout = Object.entries(availableSecrets)
            .map(([k, v]) => `${k}=${v}`)
            .join('\n');
    } else if (command.includes('cat') && command.includes('secret')) {
        const secretKey = Object.keys(availableSecrets)[0];
        if (secretKey !== undefined) {
            const secretValue = availableSecrets[secretKey]!;
            stdout = secretValue;
            emitCredentialFound(context, secretKey, 'runner-exec');
        }
    } else if (command.includes('curl') || command.includes('wget')) {
        stdout = 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"status":"ok"}';
    } else {
        stdout = `Executed: ${command}`;
    }

    return jsonResponse(200, {
        stdout,
        stderr,
        exitCode,
        privileged: true,
    });
}

// ── Pipeline Execution Simulation ──────────────────────────────

function simulatePipelineExecution(
    run: PipelineRun,
    def: PipelineDefinitionSpec,
    context: SimulationContext,
    pipeline: PipelineSpec,
): void {
    for (let i = 0; i < def.stages.length; i++) {
        const stage = def.stages[i]!;
        const stageResult = run.stages[i]!;

        // Update stage to running
        run.stages[i] = {
            ...stageResult,
            status: 'running',
            startedAt: Date.now(),
        };

        // Simulate command execution
        for (const command of stage.commands) {
            simulateCommandExecution(command, stage, context, pipeline);
        }

        // Check for failure condition
        if (stageResultShouldFail(stage)) {
            run.stages[i] = {
                ...run.stages[i]!,
                status: 'failed',
                completedAt: Date.now(),
                error: 'Stage failed: simulated failure condition',
            };
            // Stop pipeline on first failure
            return;
        }

        // Mark stage as success
        run.stages[i] = {
            ...run.stages[i]!,
            status: 'success',
            completedAt: Date.now(),
            output: `Stage '${stage.name}' completed successfully`,
        };
    }
}

function simulateCommandExecution(
    command: string,
    stage: PipelineStageSpec,
    context: SimulationContext,
    pipeline: PipelineSpec,
): void {
    // Emit network events for commands that make network requests
    if (command.includes('curl') || command.includes('wget')) {
        // Extract URL if possible
        const urlMatch = command.match(/(?:curl|wget)[^|&;]*\s+(?:-[^\s]+\s+)*([^\s-][^\s]*)/);
        const url = urlMatch?.[1] ?? 'http://example.com';

        // Find runner machine ID for event
        const runner = pipeline.runners[0];
        const machineId = runner?.machineId ?? 'pipeline-runner';

        context.events.emit({
            type: 'net:request',
            method: 'GET',
            url,
            source: machineId,
            destination: url,
            timestamp: Date.now(),
        });
    }

    // Emit exec events for ssh, scp, etc.
    if (command.includes('ssh') || command.includes('scp')) {
        const runner = pipeline.runners[0];
        const machineId = runner?.machineId ?? 'pipeline-runner';
        const commandParts = command.split(' ');
        const baseCmd = commandParts[0] ?? 'ssh';
        const args = commandParts.slice(1);

        context.events.emit({
            type: 'fs:exec',
            machine: machineId,
            path: `/usr/bin/${baseCmd}`,
            args,
            user: 'pipeline',
            timestamp: Date.now(),
        });
    }

    // Check for secret access in commands
    for (const [key, value] of Object.entries(stage.env ?? {})) {
        if (command.includes(`$${key}`) || command.includes(`\${${key}}`) || command.includes(value)) {
            if (looksLikeSecret(key, value)) {
                emitCredentialFound(context, key, 'pipeline-execution');
            }
        }
    }
}

function stageResultShouldFail(_stage: PipelineStageSpec): boolean {
    // Simulate failure based on stage configuration
    // In a real implementation, this might check a failCondition field
    // For now, we use heuristics or could extend PipelineStageSpec with failCondition
    return false; // Stages succeed by default
}

// ── Utilities ──────────────────────────────────────────────────

function findPipeline(name: string, pipeline: PipelineSpec): PipelineDefinitionSpec | undefined {
    return pipeline.pipelines.find(p => p.name === name);
}

function findRunner(name: string, pipeline: PipelineSpec): PipelineRunnerSpec | undefined {
    return pipeline.runners.find(r => r.name === name);
}

function isPrivilegedRunner(runner: PipelineRunnerSpec): boolean {
    // Check if runner has privileged flag (could be extended in spec)
    // For now, runners with 'privileged' in name are privileged
    return runner.name.toLowerCase().includes('privileged') ||
           runner.name.toLowerCase().includes('admin') ||
           runner.name.toLowerCase().includes('build');
}

function looksLikeSecret(key: string, value: string): boolean {
    const secretPatterns = [
        /password/i,
        /secret/i,
        /token/i,
        /key/i,
        /credential/i,
        /api[_-]?key/i,
        /auth/i,
        /private/i,
    ];

    const keyLower = key.toLowerCase();
    return secretPatterns.some(pattern => pattern.test(keyLower)) ||
           value.length > 20; // Long values might be tokens/keys
}

function emitCredentialFound(
    context: SimulationContext,
    credentialId: string,
    location: string,
): void {
    // Find the server machine for the event
    const machineId = context.world.pipeline?.serverMachine ?? 'pipeline-server';

    context.events.emit({
        type: 'auth:credential-found',
        credentialId,
        machine: machineId,
        location,
        timestamp: Date.now(),
    });
}
