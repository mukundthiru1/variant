/**
 * VARIANT — Pipeline Module Tests
 *
 * Tests for CI/CD pipeline simulation including:
 * - Pipeline discovery and details
 * - Pipeline triggering and run status
 * - Environment variable/secret access
 * - Runner enumeration and details
 * - Runner RCE simulation (privileged and non-privileged)
 * - Event emission for credentials and defense alerts
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { createPipelineModule } from '../../src/modules/pipeline-module';
import type { ExternalRequest, ExternalServiceHandler } from '../../src/core/fabric/types';
import type { PipelineSpec } from '../../src/core/world/types';

// ── Helpers ────────────────────────────────────────────────────

const decoder = new TextDecoder();

function makeRequest(method: string, path: string, headers?: Record<string, string>, body?: string): ExternalRequest {
    const headerMap = new Map<string, string>();
    if (headers) {
        for (const [k, v] of Object.entries(headers)) {
            headerMap.set(k, v);
        }
    }
    return {
        method,
        path,
        headers: headerMap,
        body: body !== undefined ? new TextEncoder().encode(body) : null,
    };
}

function responseText(handler: ExternalServiceHandler, req: ExternalRequest): string {
    return decoder.decode(handler.handleRequest(req).body);
}

function responseJson(handler: ExternalServiceHandler, req: ExternalRequest): any {
    return JSON.parse(responseText(handler, req));
}

function responseStatus(handler: ExternalServiceHandler, req: ExternalRequest): number {
    return handler.handleRequest(req).status;
}

function createMockContext(pipeline: PipelineSpec | undefined) {
    const registeredHandlers: ExternalServiceHandler[] = [];
    const registeredDNS: Array<{ domain: string; ip: string; type: string; ttl: number }> = [];
    const emittedEvents: any[] = [];

    const context = {
        world: { pipeline } as any,
        fabric: {
            addDNSRecord(record: any) { registeredDNS.push(record); },
            registerExternal(handler: ExternalServiceHandler) { registeredHandlers.push(handler); },
        } as any,
        events: { emit(event: any) { emittedEvents.push(event); } } as any,
        vms: new Map(),
        tick: 0,
        services: {} as any,
    };

    return { context, registeredHandlers, registeredDNS, emittedEvents };
}

// ── Fixtures ───────────────────────────────────────────────────

function makePipelineSpec(): PipelineSpec {
    return {
        tool: 'jenkins',
        serverMachine: 'jenkins-server',
        pipelines: [
            {
                name: 'build-and-test',
                trigger: 'push',
                stages: [
                    {
                        name: 'build',
                        commands: ['npm install', 'npm run build'],
                        env: { NODE_ENV: 'production', BUILD_TOKEN: 'sk-build-12345' },
                    },
                    {
                        name: 'test',
                        commands: ['npm test', 'curl https://api.example.com/health'],
                        env: { TEST_API_KEY: 'test-key-abc123' },
                    },
                    {
                        name: 'deploy',
                        commands: ['ssh deploy@server "./deploy.sh"', 'wget https://cdn.example.com/assets.zip'],
                        env: { DEPLOY_PASSWORD: 'd3pl0y_s3cr3t!', AWS_ACCESS_KEY: 'AKIAIOSFODNN7EXAMPLE' },
                    },
                ],
                vulnerabilities: ['exposed-env-vars', 'weak-secrets'],
            },
            {
                name: 'security-scan',
                trigger: 'schedule',
                stages: [
                    {
                        name: 'scan',
                        commands: ['trivy scan .'],
                    },
                ],
            },
        ],
        secrets: {
            DOCKER_REGISTRY_TOKEN: 'dckr_pat_abcdef123456',
            SLACK_WEBHOOK_URL: 'https://hooks.slack.com/services/T000/B000/XXXX',
            GITHUB_TOKEN: 'ghp_xxxxxxxxxxxxxxxxxxxx',
        },
        runners: [
            {
                name: 'docker-runner-1',
                machineId: 'runner-vm-1',
            },
            {
                name: 'privileged-builder',
                machineId: 'runner-vm-2',
            },
            {
                name: 'restricted-runner',
                machineId: 'runner-vm-3',
            },
        ],
    };
}

// ── Tests ──────────────────────────────────────────────────────

describe('createPipelineModule', () => {
    it('creates module with correct metadata', () => {
        const mod = createPipelineModule();
        expect(mod.id).toBe('pipeline-sim');
        expect(mod.version).toBe('1.0.0');
        expect(mod.provides).toContainEqual({ name: 'pipeline' });
        expect(mod.provides).toContainEqual({ name: 'ci-cd' });
    });

    it('does nothing when pipeline is undefined', () => {
        const mod = createPipelineModule();
        const { context, registeredHandlers } = createMockContext(undefined);
        mod.init(context);
        expect(registeredHandlers.length).toBe(0);
    });

    it('registers DNS and handler for pipeline API', () => {
        const { context, registeredHandlers, registeredDNS, emittedEvents } = createMockContext(makePipelineSpec());
        createPipelineModule().init(context);

        expect(registeredHandlers.length).toBe(1);
        expect(registeredDNS.length).toBe(1);
        expect(registeredDNS[0]!.domain).toBe('pipeline.jenkins.variant.local');
        expect(registeredDNS[0]!.ip).toBe('172.16.2.10');

        // Check activation event
        expect(emittedEvents.length).toBe(1);
        expect(emittedEvents[0].type).toBe('sim:alert');
        expect(emittedEvents[0].message).toContain('2 pipelines');
        expect(emittedEvents[0].message).toContain('3 runners');
    });
});

describe('Pipeline API - List and Get', () => {
    let handler: ExternalServiceHandler;

    beforeEach(() => {
        const { context, registeredHandlers } = createMockContext(makePipelineSpec());
        createPipelineModule().init(context);
        handler = registeredHandlers[0]!;
    });

    it('lists all pipelines', () => {
        const data = responseJson(handler, makeRequest('GET', '/api/v1/pipelines'));
        expect(data.pipelines).toHaveLength(2);
        expect(data.pipelines[0].name).toBe('build-and-test');
        expect(data.pipelines[1].name).toBe('security-scan');
    });

    it('lists pipelines with stage counts', () => {
        const data = responseJson(handler, makeRequest('GET', '/api/v1/pipelines'));
        expect(data.pipelines[0].stageCount).toBe(3);
        expect(data.pipelines[1].stageCount).toBe(1);
    });

    it('lists pipelines with vulnerabilities', () => {
        const data = responseJson(handler, makeRequest('GET', '/api/v1/pipelines'));
        expect(data.pipelines[0].vulnerabilities).toContain('exposed-env-vars');
        expect(data.pipelines[0].vulnerabilities).toContain('weak-secrets');
    });

    it('gets specific pipeline by ID', () => {
        const data = responseJson(handler, makeRequest('GET', '/api/v1/pipelines/build-and-test'));
        expect(data.name).toBe('build-and-test');
        expect(data.trigger).toBe('push');
        expect(data.stages).toHaveLength(3);
        expect(data.stages[0]?.name).toBe('build');
        expect(data.stages[0]?.commands).toContain('npm install');
    });

    it('returns 404 for nonexistent pipeline', () => {
        const status = responseStatus(handler, makeRequest('GET', '/api/v1/pipelines/nonexistent'));
        expect(status).toBe(404);
    });
});

describe('Pipeline API - Environment Variables (Secrets)', () => {
    let handler: ExternalServiceHandler;
    let emittedEvents: any[];

    beforeEach(() => {
        const ctx = createMockContext(makePipelineSpec());
        createPipelineModule().init(ctx.context);
        handler = ctx.registeredHandlers[0]!;
        emittedEvents = ctx.emittedEvents;
    });

    it('gets pipeline environment variables', () => {
        const data = responseJson(handler, makeRequest('GET', '/api/v1/pipelines/build-and-test/env'));
        expect(data.pipeline).toBe('build-and-test');
        expect(data.environment).toBeDefined();
    });

    it('includes pipeline secrets in env endpoint', () => {
        const data = responseJson(handler, makeRequest('GET', '/api/v1/pipelines/build-and-test/env'));
        expect(data.environment.DOCKER_REGISTRY_TOKEN).toBe('dckr_pat_abcdef123456');
        expect(data.environment.GITHUB_TOKEN).toBe('ghp_xxxxxxxxxxxxxxxxxxxx');
    });

    it('includes stage environment variables', () => {
        const data = responseJson(handler, makeRequest('GET', '/api/v1/pipelines/build-and-test/env'));
        expect(data.environment['build.NODE_ENV']).toBe('production');
        expect(data.environment['build.BUILD_TOKEN']).toBe('sk-build-12345');
        expect(data.environment['test.TEST_API_KEY']).toBe('test-key-abc123');
    });

    it('emits credential-found event when accessing env vars', () => {
        responseJson(handler, makeRequest('GET', '/api/v1/pipelines/build-and-test/env'));

        const credEvents = emittedEvents.filter(e => e.type === 'auth:credential-found');
        expect(credEvents.length).toBeGreaterThan(0);
        expect(credEvents[0].credentialId).toBeDefined();
        expect(credEvents[0].location).toBe('pipeline-secrets');
    });

    it('emits credential-found for stage secrets', () => {
        responseJson(handler, makeRequest('GET', '/api/v1/pipelines/build-and-test/env'));

        const credEvents = emittedEvents.filter(e => e.type === 'auth:credential-found');
        const stageEvents = credEvents.filter(e => e.location === 'stage-build' || e.location === 'stage-test');
        expect(stageEvents.length).toBeGreaterThan(0);
    });
});

describe('Pipeline API - Trigger and Run Status', () => {
    let handler: ExternalServiceHandler;

    beforeEach(() => {
        const { context, registeredHandlers } = createMockContext(makePipelineSpec());
        createPipelineModule().init(context);
        handler = registeredHandlers[0]!;
    });

    it('triggers pipeline and returns run ID', () => {
        const data = responseJson(handler, makeRequest('POST', '/api/v1/pipelines/build-and-test/trigger'));
        expect(data.runId).toBe('build-and-test-run-1');
        expect(data.status).toBe('running');
        expect(data.pipeline).toBe('build-and-test');
    });

    it('generates deterministic run IDs', () => {
        const resp1 = responseJson(handler, makeRequest('POST', '/api/v1/pipelines/build-and-test/trigger'));
        const resp2 = responseJson(handler, makeRequest('POST', '/api/v1/pipelines/build-and-test/trigger'));
        const resp3 = responseJson(handler, makeRequest('POST', '/api/v1/pipelines/security-scan/trigger'));

        expect(resp1.runId).toBe('build-and-test-run-1');
        expect(resp2.runId).toBe('build-and-test-run-2');
        expect(resp3.runId).toBe('security-scan-run-1');
    });

    it('returns 404 for triggering nonexistent pipeline', () => {
        const status = responseStatus(handler, makeRequest('POST', '/api/v1/pipelines/nonexistent/trigger'));
        expect(status).toBe(404);
    });

    it('gets run status after triggering', () => {
        responseJson(handler, makeRequest('POST', '/api/v1/pipelines/build-and-test/trigger'));
        const data = responseJson(handler, makeRequest('GET', '/api/v1/runs/build-and-test-run-1'));

        expect(data.runId).toBe('build-and-test-run-1');
        expect(data.pipeline).toBe('build-and-test');
        expect(data.status).toMatch(/running|success|failed/);
        expect(data.stages).toHaveLength(3);
    });

    it('returns 404 for nonexistent run', () => {
        const status = responseStatus(handler, makeRequest('GET', '/api/v1/runs/nonexistent-run'));
        expect(status).toBe(404);
    });

    it('includes stage results in run status', () => {
        responseJson(handler, makeRequest('POST', '/api/v1/pipelines/build-and-test/trigger'));
        const data = responseJson(handler, makeRequest('GET', '/api/v1/runs/build-and-test-run-1'));

        expect(data.stages[0].name).toBe('build');
        expect(data.stages[0].status).toMatch(/pending|running|success|failed/);
    });
});

describe('Pipeline API - Runners', () => {
    let handler: ExternalServiceHandler;

    beforeEach(() => {
        const { context, registeredHandlers } = createMockContext(makePipelineSpec());
        createPipelineModule().init(context);
        handler = registeredHandlers[0]!;
    });

    it('lists all runners', () => {
        const data = responseJson(handler, makeRequest('GET', '/api/v1/runners'));
        expect(data.runners).toHaveLength(3);
        expect(data.runners[0].name).toBe('docker-runner-1');
        expect(data.runners[1].name).toBe('privileged-builder');
    });

    it('includes runner labels and status', () => {
        const data = responseJson(handler, makeRequest('GET', '/api/v1/runners'));
        expect(data.runners[0].labels).toContain('docker');
        expect(data.runners[0].labels).toContain('linux');
        expect(data.runners[0].status).toBe('online');
    });

    it('gets runner details with machine ID', () => {
        const data = responseJson(handler, makeRequest('GET', '/api/v1/runners/docker-runner-1'));
        expect(data.name).toBe('docker-runner-1');
        expect(data.machineId).toBe('runner-vm-1');
        expect(data.status).toBe('online');
    });

    it('returns 404 for nonexistent runner', () => {
        const status = responseStatus(handler, makeRequest('GET', '/api/v1/runners/nonexistent'));
        expect(status).toBe(404);
    });

    it('includes mounted secrets in runner details', () => {
        const data = responseJson(handler, makeRequest('GET', '/api/v1/runners/docker-runner-1'));
        expect(data.environment).toBeDefined();
        expect(data.environment.DOCKER_REGISTRY_TOKEN).toBe('dckr_pat_abcdef123456');
    });
});

describe('Pipeline API - Runner RCE', () => {
    let handler: ExternalServiceHandler;
    let emittedEvents: any[];

    beforeEach(() => {
        const ctx = createMockContext(makePipelineSpec());
        createPipelineModule().init(ctx.context);
        handler = ctx.registeredHandlers[0]!;
        emittedEvents = ctx.emittedEvents;
    });

    it('executes command on privileged runner', () => {
        const data = responseJson(handler, makeRequest(
            'POST',
            '/api/v1/runners/privileged-builder/exec',
            { 'content-type': 'application/json' },
            JSON.stringify({ command: 'echo hello' }),
        ));

        expect(data.exitCode).toBe(0);
        expect(data.privileged).toBe(true);
    });

    it('restricts execution on non-privileged runner', () => {
        const data = responseJson(handler, makeRequest(
            'POST',
            '/api/v1/runners/restricted-runner/exec',
            { 'content-type': 'application/json' },
            JSON.stringify({ command: 'echo hello' }),
        ));

        expect(data.exitCode).toBe(1);
        expect(data.privileged).toBe(false);
        expect(data.stderr).toContain('Permission denied');
    });

    it('emits defense alert on runner exec', () => {
        responseJson(handler, makeRequest(
            'POST',
            '/api/v1/runners/privileged-builder/exec',
            { 'content-type': 'application/json' },
            JSON.stringify({ command: 'cat /etc/passwd' }),
        ));

        const alertEvents = emittedEvents.filter(e => e.type === 'defense:alert');
        expect(alertEvents.length).toBeGreaterThan(0);
        expect(alertEvents[0].severity).toBe('critical');
        expect(alertEvents[0].detail).toContain('RCE detected');
    });

    it('returns env output on privileged runner for env command', () => {
        const data = responseJson(handler, makeRequest(
            'POST',
            '/api/v1/runners/privileged-builder/exec',
            { 'content-type': 'application/json' },
            JSON.stringify({ command: 'env' }),
        ));

        expect(data.exitCode).toBe(0);
        expect(data.stdout).toContain('DOCKER_REGISTRY_TOKEN');
    });

    it('returns 404 for exec on nonexistent runner', () => {
        const status = responseStatus(handler, makeRequest(
            'POST',
            '/api/v1/runners/nonexistent/exec',
            { 'content-type': 'application/json' },
            JSON.stringify({ command: 'echo hello' }),
        ));
        expect(status).toBe(404);
    });

    it('returns 400 for missing command', () => {
        const status = responseStatus(handler, makeRequest(
            'POST',
            '/api/v1/runners/privileged-builder/exec',
            { 'content-type': 'application/json' },
            JSON.stringify({}),
        ));
        expect(status).toBe(400);
    });
});

describe('Pipeline API - Stage Execution Events', () => {
    let handler: ExternalServiceHandler;
    let emittedEvents: any[];

    beforeEach(() => {
        const ctx = createMockContext(makePipelineSpec());
        createPipelineModule().init(ctx.context);
        handler = ctx.registeredHandlers[0]!;
        emittedEvents = ctx.emittedEvents;
    });

    it('emits net:request for curl commands', () => {
        responseJson(handler, makeRequest('POST', '/api/v1/pipelines/build-and-test/trigger'));

        const netEvents = emittedEvents.filter(e => e.type === 'net:request');
        expect(netEvents.length).toBeGreaterThan(0);
        expect(netEvents[0].url).toContain('api.example.com');
    });

    it('emits fs:exec for ssh commands', () => {
        responseJson(handler, makeRequest('POST', '/api/v1/pipelines/build-and-test/trigger'));

        const execEvents = emittedEvents.filter(e => e.type === 'fs:exec');
        const sshEvents = execEvents.filter(e => e.args?.includes('deploy@server'));
        expect(sshEvents.length).toBeGreaterThan(0);
    });
});

describe('Pipeline API - URL Encoding', () => {
    let handler: ExternalServiceHandler;

    beforeEach(() => {
        const { context, registeredHandlers } = createMockContext(makePipelineSpec());
        createPipelineModule().init(context);
        handler = registeredHandlers[0]!;
    });

    it('handles URL-encoded pipeline names', () => {
        // Pipeline names with spaces or special chars should work
        const status = responseStatus(handler, makeRequest('GET', '/api/v1/pipelines/build%20and%20test'));
        // This will 404 because the pipeline doesn't exist, but it shouldn't crash
        expect(status).toBe(404);
    });
});
