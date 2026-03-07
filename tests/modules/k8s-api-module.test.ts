/**
 * VARIANT — Kubernetes API Module Tests
 *
 * Tests for simulated Kubernetes API resources and RBAC:
 *   - Namespace/pod/secret/configmap/service account listing
 *   - Pod exec output
 *   - RBAC deny + wildcard admin access
 *   - Secret access event emission
 *   - Anonymous access behavior
 */

import { describe, it, expect } from 'vitest';
import { createK8sApiModule } from '../../src/modules/k8s-api-module';
import type { ExternalRequest, ExternalServiceHandler } from '../../src/core/fabric/types';
import type { KubernetesSpec } from '../../src/core/world/types';

// ── Helpers ────────────────────────────────────────────────────

const decoder = new TextDecoder();

function makeRequest(
    method: string,
    path: string,
    headers?: Record<string, string>,
    body?: string,
): ExternalRequest {
    const headerMap = new Map<string, string>();
    if (headers !== undefined) {
        for (const [name, value] of Object.entries(headers)) {
            headerMap.set(name, value);
        }
    }
    return {
        method,
        path,
        headers: headerMap,
        body: body !== undefined ? new TextEncoder().encode(body) : null,
    };
}

function responseText(handler: ExternalServiceHandler, request: ExternalRequest): string {
    return decoder.decode(handler.handleRequest(request).body);
}

function responseJson(handler: ExternalServiceHandler, request: ExternalRequest): any {
    return JSON.parse(responseText(handler, request));
}

function responseStatus(handler: ExternalServiceHandler, request: ExternalRequest): number {
    return handler.handleRequest(request).status;
}

function createMockContext(spec: KubernetesSpec) {
    const registeredHandlers: ExternalServiceHandler[] = [];
    const registeredDNS: Array<{ domain: string; ip: string; type: string; ttl: number }> = [];
    const emittedEvents: any[] = [];

    const context = {
        world: { kubernetes: spec } as any,
        fabric: {
            addDNSRecord(record: { domain: string; ip: string; type: string; ttl: number }) {
                registeredDNS.push(record);
            },
            registerExternal(handler: ExternalServiceHandler) {
                registeredHandlers.push(handler);
            },
        } as any,
        events: {
            emit(event: any) {
                emittedEvents.push(event);
            },
        } as any,
        vms: new Map(),
        tick: 0,
        services: {} as any,
    };

    return { context, registeredHandlers, registeredDNS, emittedEvents };
}

function findHandler(handlers: ExternalServiceHandler[], domain: string): ExternalServiceHandler {
    return handlers.find(handler => handler.domain === domain) as ExternalServiceHandler;
}

function token(namespace: string, name: string, secret: string): string {
    return globalThis.btoa(`${namespace}:${name}:${secret}`);
}

// ── Fixtures ───────────────────────────────────────────────────

function makeKubernetesSpec(): KubernetesSpec {
    return {
        clusterName: 'demo-cluster',
        apiServerMachine: 'k8s-api.demo.internal',
        namespaces: [
            {
                name: 'default',
                pods: [
                    {
                        name: 'default-pod',
                        namespace: 'default',
                        image: 'alpine:3.19',
                        serviceAccount: 'admin-sa',
                        env: { APP: 'frontend' },
                    },
                    {
                        name: 'reader-pod',
                        namespace: 'default',
                        image: 'busybox:1.36',
                        serviceAccount: 'reader-sa',
                    },
                ],
                services: [],
                configMaps: [
                    {
                        name: 'app-config',
                        namespace: 'default',
                        data: {
                            APP_ENV: 'prod',
                            FEATURE_FLAG: 'true',
                        },
                    },
                ],
            },
            {
                name: 'workload',
                pods: [
                    {
                        name: 'workload-pod',
                        namespace: 'workload',
                        image: 'nginx:1.26',
                        serviceAccount: 'admin-sa',
                    },
                ],
                services: [],
                configMaps: [
                    {
                        name: 'workload-policy',
                        namespace: 'workload',
                        data: {
                            REGION: 'us-east-1',
                        },
                    },
                ],
            },
        ],
        rbac: [
            {
                subject: 'system:serviceaccount:default:admin-sa',
                role: 'cluster-admin',
                namespace: '*',
                resources: ['*'],
                verbs: ['*'],
            },
            {
                subject: 'default:reader-sa',
                role: 'reader',
                namespace: 'default',
                resources: ['pods', 'configmaps', 'serviceaccounts'],
                verbs: ['get', 'list'],
            },
            {
                subject: 'system:serviceaccount:other:limited-sa',
                role: 'limited',
                namespace: 'workload',
                resources: ['pods'],
                verbs: ['get', 'list'],
            },
            {
                subject: 'system:anonymous',
                role: 'none',
                namespace: 'default',
                resources: ['pods'],
                verbs: ['get'],
            },
        ],
        serviceAccounts: [
            {
                name: 'admin-sa',
                namespace: 'default',
                token: 'adminsecret',
            },
            {
                name: 'reader-sa',
                namespace: 'default',
                token: 'readersecret',
            },
            {
                name: 'admin-sa',
                namespace: 'workload',
                token: 'workloadadminsecret',
            },
            {
                name: 'limited-sa',
                namespace: 'other',
                token: 'limitedsecret',
            },
        ],
        secrets: [
            {
                name: 'db-credentials',
                namespace: 'default',
                type: 'Opaque',
                data: {
                    username: 'admin',
                    password: 'S3cr3t!',
                },
            },
            {
                name: 'api-token',
                namespace: 'workload',
                type: 'Opaque',
                data: {
                    token: 'top-secret',
                },
            },
        ],
        networkPolicies: [
            {
                name: 'default-egress',
                namespace: 'default',
                labels: { purpose: 'isolation' },
            },
            {
                name: 'workload-allow-http',
                namespace: 'workload',
                labels: { purpose: 'egress' },
            },
        ],
    };
}

// ── Tests ──────────────────────────────────────────────────────

describe('createK8sApiModule', () => {
    const spec = makeKubernetesSpec();
    const adminToken = token('default', 'admin-sa', 'adminsecret');
    const readerToken = token('default', 'reader-sa', 'readersecret');
    const limitedToken = token('other', 'limited-sa', 'limitedsecret');

    it('creates module with correct metadata', () => {
        const module = createK8sApiModule();
        expect(module.id).toBe('kubernetes-api');
        expect(module.version).toBe('1.0.0');
        expect(module.provides).toEqual([{ name: 'kubernetes' }, { name: 'k8s-api' }]);
        expect(module.requires).toEqual([{ name: 'variant-internet' }]);
    });

    it('registers DNS and a single external handler', () => {
        const { context, registeredHandlers, registeredDNS } = createMockContext(spec);
        const module = createK8sApiModule(spec, context.events);
        module.init(context);
        expect(registeredDNS).toHaveLength(1);
        expect(registeredDNS[0]).toEqual({
            domain: spec.apiServerMachine,
            ip: expect.any(String),
            type: 'A',
            ttl: 3600,
        });
        expect(registeredHandlers).toHaveLength(1);
    });

    it('lists namespaces with valid auth', () => {
        const { context, registeredHandlers } = createMockContext(spec);
        createK8sApiModule(spec, context.events).init(context);
        const handler = findHandler(registeredHandlers, spec.apiServerMachine);
        const response = responseJson(handler, makeRequest('GET', '/api/v1/namespaces', {
            Authorization: `Bearer ${adminToken}`,
        }));

        expect(response.kind).toBe('NamespaceList');
        expect(response.items).toHaveLength(2);
        expect(response.items[0].metadata.name).toBe('default');
        expect(response.items[1].metadata.name).toBe('workload');
    });

    it('lists pods in namespace with valid auth', () => {
        const { context, registeredHandlers } = createMockContext(spec);
        createK8sApiModule(spec, context.events).init(context);
        const handler = findHandler(registeredHandlers, spec.apiServerMachine);
        const response = responseJson(handler, makeRequest('GET', '/api/v1/namespaces/default/pods', {
            Authorization: `Bearer ${readerToken}`,
        }));

        expect(response.kind).toBe('PodList');
        expect(response.items).toHaveLength(2);
        expect(response.items[0].metadata.name).toBe('default-pod');
        expect(response.items[1].metadata.name).toBe('reader-pod');
    });

    it('returns a secret with base64 data only after authz passes', () => {
        const { context, registeredHandlers } = createMockContext(spec);
        createK8sApiModule(spec, context.events).init(context);
        const handler = findHandler(registeredHandlers, spec.apiServerMachine);
        const response = responseJson(
            handler,
            makeRequest('GET', '/api/v1/namespaces/default/secrets/db-credentials', {
                Authorization: `Bearer ${adminToken}`,
            }),
        );

        expect(response.kind).toBe('Secret');
        expect(response.data.username).toBe('YWRtaW4=');
        expect(response.data.password).toBe('UzNjcjN0IQ==');
    });

    it('lists configmaps in namespace', () => {
        const { context, registeredHandlers } = createMockContext(spec);
        createK8sApiModule(spec, context.events).init(context);
        const handler = findHandler(registeredHandlers, spec.apiServerMachine);
        const response = responseJson(
            handler,
            makeRequest('GET', '/api/v1/namespaces/default/configmaps', {
                Authorization: `Bearer ${adminToken}`,
            }),
        );
        expect(response.kind).toBe('ConfigMapList');
        expect(response.items).toHaveLength(1);
        expect(response.items[0].metadata.name).toBe('app-config');
    });

    it('lists service accounts for namespace', () => {
        const { context, registeredHandlers } = createMockContext(spec);
        createK8sApiModule(spec, context.events).init(context);
        const handler = findHandler(registeredHandlers, spec.apiServerMachine);
        const response = responseJson(
            handler,
            makeRequest('GET', '/api/v1/namespaces/default/serviceaccounts', {
                Authorization: `Bearer ${adminToken}`,
            }),
        );
        expect(response.kind).toBe('ServiceAccountList');
        expect(response.items.map((i: any) => i.metadata.name)).toEqual(expect.arrayContaining(['admin-sa', 'reader-sa']));
    });

    it('denies RBAC access with 403 when no matching rule exists', () => {
        const { context, registeredHandlers, emittedEvents } = createMockContext(spec);
        createK8sApiModule(spec, context.events).init(context);
        const handler = findHandler(registeredHandlers, spec.apiServerMachine);
        const status = responseStatus(
            handler,
            makeRequest('GET', '/api/v1/namespaces/default/secrets', {
                Authorization: `Bearer ${readerToken}`,
            }),
        );

        expect(status).toBe(403);
        expect(emittedEvents.some(e => e.type === 'defense:alert')).toBe(true);
    });

    it('allows wildcard RBAC for cluster-admin service account', () => {
        const { context, registeredHandlers } = createMockContext(spec);
        createK8sApiModule(spec, context.events).init(context);
        const handler = findHandler(registeredHandlers, spec.apiServerMachine);
        const response = responseJson(
            handler,
            makeRequest('GET', '/api/v1/namespaces/workload/pods', {
                Authorization: `Bearer ${adminToken}`,
            }),
        );

        expect(response.kind).toBe('PodList');
        expect(response.items).toHaveLength(1);
        expect(response.items[0].metadata.name).toBe('workload-pod');
    });

    it('emits auth:credential-found when a secret is read', () => {
        const { context, registeredHandlers, emittedEvents } = createMockContext(spec);
        const mod = createK8sApiModule(spec, context.events);
        mod.init(context);
        const handler = findHandler(registeredHandlers, spec.apiServerMachine);
        responseJson(
            handler,
            makeRequest('GET', '/api/v1/namespaces/default/secrets/db-credentials', {
                Authorization: `Bearer ${adminToken}`,
            }),
        );

        const credentialEvents = emittedEvents.filter(e => e.type === 'auth:credential-found');
        expect(credentialEvents).toHaveLength(1);
        expect(credentialEvents[0]).toMatchObject({
            credentialId: 'db-credentials',
            machine: spec.apiServerMachine,
            location: '/api/v1/namespaces/default/secrets/db-credentials',
        });
    });

    it('execs into pods and returns command output', () => {
        const { context, registeredHandlers } = createMockContext(spec);
        createK8sApiModule(spec, context.events).init(context);
        const handler = findHandler(registeredHandlers, spec.apiServerMachine);
        const response = responseText(
            handler,
            makeRequest('POST', '/api/v1/namespaces/default/pods/default-pod/exec?command=cat%20/etc/hostname', {
                Authorization: `Bearer ${adminToken}`,
            }),
        );

        expect(response).toBe('exec into default-pod (alpine:3.19) -> cat /etc/hostname');
    });

    it('rejects anonymous access with 401 by default', () => {
        const { context, registeredHandlers } = createMockContext(spec);
        createK8sApiModule(spec, context.events).init(context);
        const handler = findHandler(registeredHandlers, spec.apiServerMachine);
        const status = responseStatus(handler, makeRequest('GET', '/api/v1/namespaces'));
        expect(status).toBe(401);
    });

    it('does not allow namespace crossing without cluster-wide RBAC', () => {
        const { context, registeredHandlers, emittedEvents } = createMockContext(spec);
        createK8sApiModule(spec, context.events).init(context);
        const handler = findHandler(registeredHandlers, spec.apiServerMachine);
        const inNamespace = responseStatus(
            handler,
            makeRequest('GET', '/api/v1/namespaces/default/pods', {
                Authorization: `Bearer ${limitedToken}`,
            }),
        );
        expect(inNamespace).toBe(403);

        const deniedInOtherNs = responseStatus(
            handler,
            makeRequest('GET', '/api/v1/namespaces/workload/pods', {
                Authorization: `Bearer ${readerToken}`,
            }),
        );
        expect(deniedInOtherNs).toBe(403);
        expect(emittedEvents.filter(e => e.type === 'defense:alert').length).toBeGreaterThanOrEqual(1);
    });

    it('lists network policies for namespace recon', () => {
        const { context, registeredHandlers } = createMockContext(spec);
        createK8sApiModule(spec, context.events).init(context);
        const handler = findHandler(registeredHandlers, spec.apiServerMachine);
        const response = responseJson(
            handler,
            makeRequest('GET', '/apis/networking.k8s.io/v1/namespaces/workload/networkpolicies', {
                Authorization: `Bearer ${adminToken}`,
            }),
        );

        expect(response.kind).toBe('NetworkPolicyList');
        expect(response.items).toHaveLength(1);
        expect(response.items[0].metadata.name).toBe('workload-allow-http');
    });
});
