/**
 * VARIANT — Kubernetes API Simulation Module
 *
 * Simulates a subset of the Kubernetes API server for post-exploitation
 * recon and attack simulation:
 *   - Namespaces
 *   - Pods
 *   - Secrets
 *   - ConfigMaps
 *   - ServiceAccounts
 *   - NetworkPolicies
 *   - Pod exec (container image-configured output)
 *
 * SECURITY model:
 * - Bearer token auth via service account tokens.
 * - RBAC authorization checks use Kubernetes-style verb/resource/namespace policy.
 * - Unauthorized access emits defense:alert and returns kubectl-compatible
 *   Status responses with realistic payloads.
 */

import type { Module, SimulationContext } from '../core/modules';
import type { EventBus } from '../core/events';
import type { ExternalRequest, ExternalResponse, ExternalServiceHandler } from '../core/fabric/types';
import type {
    KubernetesSpec,
    K8sNamespaceSpec,
    K8sPodSpec,
    K8sRBACRuleSpec,
    K8sServiceAccountSpec,
    K8sSecretSpec,
    K8sNetworkPolicySpec,
    K8sConfigMapSpec,
} from '../core/world/types';

// ── Module metadata ──────────────────────────────────────────

const MODULE_ID = 'kubernetes-api';
const MODULE_VERSION = '1.0.0';
const ANONYMOUS_SUBJECT = 'system:anonymous';
let activeKubernetes: KubernetesSpec | undefined;
let activeServiceAccountIndex: ReadonlyMap<string, K8sServiceAccountSpec> = new Map<string, K8sServiceAccountSpec>();
let activeEventBus: EventBus | undefined;

// ── Runtime constants ────────────────────────────────────────

const encoder = new TextEncoder();
const API_SERVER_IP = '172.16.1.12';

// ── Helper types ────────────────────────────────────────────

interface ResolvedServiceAccount {
    readonly subject: string;
    readonly subjectLegacy: string;
    readonly namespace: string;
    readonly name: string;
}

interface AuthResult {
    readonly subject: string;
    readonly isAnonymous: boolean;
    readonly rawToken: string;
    readonly errorCode?: 401 | 403;
}

type K8sResource = 'namespaces' | 'pods' | 'pods/exec' | 'secrets' | 'configmaps' | 'serviceaccounts' | 'networkpolicies';

interface K8sItemMetadata {
    name: string;
    namespace: string | undefined;
    uid: string;
    creationTimestamp: string;
}

// ── Response helpers ────────────────────────────────────────

function makeJsonResponse(status: number, data: unknown): ExternalResponse {
    const headers = new Map<string, string>();
    headers.set('content-type', 'application/json');
    headers.set('server', 'VARIANT-Kubernetes-API/1.0');
    return { status, headers, body: encoder.encode(JSON.stringify(data, null, 2)) };
}

function makeTextResponse(status: number, text: string): ExternalResponse {
    const headers = new Map<string, string>();
    headers.set('content-type', 'text/plain');
    headers.set('server', 'VARIANT-Kubernetes-API/1.0');
    return { status, headers, body: encoder.encode(text) };
}

function makeAuthError(status: number, verb: string, resource: string, namespace: string): ExternalResponse {
    return makeJsonResponse(status, {
        kind: 'Status',
        apiVersion: 'v1',
        metadata: {},
        status: status === 404 ? 'Failure' : 'Failure',
        reason: status === 401 ? 'Unauthorized' : status === 403 ? 'Forbidden' : 'NotFound',
        code: status,
        message: status === 401
            ? `Unauthorized to ${verb.toUpperCase()} ${resource} in namespace ${namespace}`
            : `Forbidden to ${verb.toUpperCase()} ${resource} in namespace ${namespace}`,
    });
}

function makeNotFound(resourcePath: string): ExternalResponse {
    return makeJsonResponse(404, {
        kind: 'Status',
        apiVersion: 'v1',
        metadata: {},
        status: 'Failure',
        reason: 'NotFound',
        code: 404,
        message: `resource ${resourcePath} not found`,
    });
}

function makeNotAllowed(method: string): ExternalResponse {
    return makeTextResponse(405, `Method ${method} is not allowed for this endpoint`);
}

// ── Serialization helpers ──────────────────────────────────

function encodedBase64(value: string): string {
    return globalThis.btoa(value);
}

function base64Decode(token: string): string | null {
    try {
        return globalThis.atob(token);
    } catch {
        return null;
    }
}

function parseHeader(headers: ReadonlyMap<string, string>, key: string): string | undefined {
    const normalizedKey = key.toLowerCase();
    for (const [headerName, headerValue] of headers) {
        if (headerName.toLowerCase() === normalizedKey) {
            return headerValue;
        }
    }
    return undefined;
}

function parseBearerToken(request: ExternalRequest): string | null {
    const authHeader = parseHeader(request.headers, 'authorization');
    if (authHeader === undefined) {
        return null;
    }
    const [scheme, token] = authHeader.split(' ');
    if (scheme?.toLowerCase() !== 'bearer' || token === undefined || token.trim() === '') {
        return null;
    }
    return token;
}

function splitPath(path: string): string[] {
    const normalized = path.split('?')[0]!.replace(/\/+$/, '');
    if (normalized === '') {
        return [];
    }
    return normalized.replace(/^\//, '').split('/');
}

function parseServiceAccountFromToken(
    serviceAccounts: ReadonlyMap<string, K8sServiceAccountSpec>,
    token: string,
): ResolvedServiceAccount | null {
    const decoded = base64Decode(token);
    if (decoded === null) {
        return null;
    }

    const decodedParts = decoded.split(':');
    if (decodedParts.length < 3) {
        return null;
    }

    const secret = decodedParts.slice(2).join(':');
    const namespace = decodedParts[0] ?? '';
    const serviceAccountName = decodedParts[1] ?? '';
    if (namespace === '' || serviceAccountName === '') {
        return null;
    }

    const serviceAccount = serviceAccounts.get(`${namespace}/${serviceAccountName}`);
    if (serviceAccount?.token === undefined || serviceAccount.token !== secret) {
        return null;
    }

    return {
        subject: `system:serviceaccount:${namespace}:${serviceAccountName}`,
        subjectLegacy: `${namespace}:${serviceAccountName}`,
        namespace,
        name: serviceAccountName,
    };
}

function subjectMatchesRule(ruleSubject: string, subject: string, legacySubject: string): boolean {
    return ruleSubject === subject || ruleSubject === legacySubject;
}

function verbAllowed(allowedVerbs: readonly K8sRBACRuleSpec['verbs'][number][], verb: string): boolean {
    for (const allowed of allowedVerbs) {
        if (allowed === '*' || allowed === verb) {
            return true;
        }
    }
    return false;
}

function resourceAllowed(allowedResources: readonly string[], resource: string): boolean {
    for (const allowed of allowedResources) {
        if (allowed === '*' || allowed === resource) {
            return true;
        }
    }
    return false;
}

function namespaceAllowed(ruleNamespace: string | undefined, namespace: string): boolean {
    return ruleNamespace === undefined || ruleNamespace === '*' || ruleNamespace === namespace;
}

function makeItemMetadata(name: string, namespace: string | undefined): K8sItemMetadata {
    return {
        name,
        namespace,
        uid: namespace === undefined ? `uid:${name}` : `uid:${namespace}:${name}`,
        creationTimestamp: '2024-01-01T00:00:00Z',
    };
}

function namespaceByName(namespaces: readonly K8sNamespaceSpec[], namespace: string): K8sNamespaceSpec | undefined {
    return namespaces.find(ns => ns.name === namespace);
}

// Exposed helper for RBAC checks.
// parse token -> resolve identity -> verify rule matches verb/resource/namespace
export function checkRBAC(
    token: string,
    verb: string,
    resource: string,
    namespace: string,
    kubernetes?: KubernetesSpec,
    serviceAccountIndex?: ReadonlyMap<string, K8sServiceAccountSpec>,
    eventBus?: EventBus,
): boolean {
    const resolvedKubernetes = kubernetes ?? activeKubernetes;
    if (resolvedKubernetes === undefined) {
        return false;
    }
    const resolvedServiceAccountIndex = serviceAccountIndex ?? activeServiceAccountIndex;

    const resolvedEventBus = eventBus ?? activeEventBus;

    const tokenTrimmed = token.trim();
    const isAnonymous = tokenTrimmed === ANONYMOUS_SUBJECT;
    if (isAnonymous) {
        const anonymousRule = resolvedKubernetes.rbac.find(rule => (
            rule.subject === ANONYMOUS_SUBJECT
            && verbAllowed(rule.verbs, verb)
            && resourceAllowed(rule.resources, resource)
            && namespaceAllowed(rule.namespace, namespace)
        ));
        if (anonymousRule === undefined) {
            if (resolvedEventBus !== undefined) {
                resolvedEventBus.emit({
                    type: 'defense:alert',
                    machine: resolvedKubernetes.apiServerMachine,
                    ruleId: 'kubernetes-rbac',
                    severity: 'low',
                    detail: `RBAC denied ${verb} ${resource} in namespace ${namespace} for anonymous`,
                    timestamp: Date.now(),
                });
            }
            return false;
        }
        return true;
    }

    const resolved = parseServiceAccountFromToken(resolvedServiceAccountIndex, tokenTrimmed);
    if (resolved === null) {
        return false;
    }

    const subjectsToCheck = [resolved.subject, resolved.subjectLegacy];
    for (const rule of resolvedKubernetes.rbac) {
        if (!subjectsToCheck.some(subject => subjectMatchesRule(
            rule.subject,
            subject,
            resolved.subjectLegacy,
        ))) {
            continue;
        }
        if (!verbAllowed(rule.verbs, verb)) {
            continue;
        }
        if (!resourceAllowed(rule.resources, resource)) {
            continue;
        }
        if (!namespaceAllowed(rule.namespace, namespace)) {
            continue;
        }
        return true;
    }

    if (resolvedEventBus !== undefined) {
        resolvedEventBus.emit({
            type: 'defense:alert',
            machine: resolvedKubernetes.apiServerMachine,
            ruleId: 'kubernetes-rbac',
            severity: 'medium',
            detail: `RBAC denied ${verb} ${resource} in namespace ${namespace}`,
            timestamp: Date.now(),
        });
    }

    return false;
}

function buildPolicyJson(policy: K8sNetworkPolicySpec) {
    return {
        apiVersion: 'networking.k8s.io/v1',
        kind: 'NetworkPolicy',
        metadata: makeItemMetadata(policy.name, policy.namespace),
        spec: {
            podSelector: {},
            policyTypes: ['Ingress', 'Egress'],
            ingress: [],
            egress: [],
        },
    };
}

function buildServiceAccountJson(namespace: string, serviceAccount: K8sServiceAccountSpec) {
    return {
        apiVersion: 'v1',
        kind: 'ServiceAccount',
        metadata: makeItemMetadata(serviceAccount.name, namespace),
    };
}

function buildSecretJson(namespace: string, secret: K8sSecretSpec) {
    const data = new Map<string, string>();
    for (const [key, value] of Object.entries(secret.data)) {
        data.set(key, encodedBase64(value));
    }
    return {
        apiVersion: 'v1',
        kind: 'Secret',
        metadata: makeItemMetadata(secret.name, namespace),
        type: secret.type,
        data: Object.fromEntries(data.entries()),
    };
}

function buildConfigMapJson(namespace: string, configMap: K8sConfigMapSpec) {
    return {
        apiVersion: 'v1',
        kind: 'ConfigMap',
        metadata: makeItemMetadata(configMap.name, namespace),
        data: configMap.data,
    };
}

function buildPodJson(namespace: string, pod: K8sPodSpec) {
    return {
        apiVersion: 'v1',
        kind: 'Pod',
        metadata: makeItemMetadata(pod.name, namespace),
        spec: {
            containers: [{
                name: 'default',
                image: pod.image,
                env: pod.env ?? {},
                securityContext: pod.securityContext ?? {},
                volumeMounts: pod.volumes?.map(volume => ({
                    name: volume.name,
                    mountPath: volume.mountPath,
                    type: volume.type ?? 'default',
                })) ?? [],
            }],
            serviceAccountName: pod.serviceAccount ?? 'default',
        },
        status: { phase: 'Running' },
    };
}

function resolveAuth(
    serviceAccountIndex: ReadonlyMap<string, K8sServiceAccountSpec>,
    request: ExternalRequest,
): AuthResult {
    const bearerToken = parseBearerToken(request);
    if (bearerToken === null) {
        return { subject: ANONYMOUS_SUBJECT, isAnonymous: true, rawToken: ANONYMOUS_SUBJECT, errorCode: 401 };
    }

    const resolved = parseServiceAccountFromToken(serviceAccountIndex, bearerToken);
    if (resolved === null) {
        return { subject: ANONYMOUS_SUBJECT, isAnonymous: true, rawToken: ANONYMOUS_SUBJECT, errorCode: 401 };
    }

    return { subject: resolved.subject, isAnonymous: false, rawToken: bearerToken };
}

function authorize(
    kubernetes: KubernetesSpec,
    serviceAccountIndex: ReadonlyMap<string, K8sServiceAccountSpec>,
    request: ExternalRequest,
    verb: string,
    resource: K8sResource,
    namespace: string,
    eventBus: EventBus,
): AuthResult {
    const auth = resolveAuth(serviceAccountIndex, request);
    const tokenForCheck = auth.isAnonymous ? ANONYMOUS_SUBJECT : auth.rawToken;

    if (auth.errorCode !== undefined) {
        if (!auth.isAnonymous) {
            return { ...auth };
        }
        // anonymous may still be explicitly allowed
        if (!checkRBAC(tokenForCheck, verb, resource, namespace, kubernetes, serviceAccountIndex, eventBus)) {
            return { subject: ANONYMOUS_SUBJECT, isAnonymous: true, rawToken: ANONYMOUS_SUBJECT, errorCode: 401 };
        }
        return { subject: ANONYMOUS_SUBJECT, isAnonymous: true, rawToken: ANONYMOUS_SUBJECT };
    }

    if (!checkRBAC(tokenForCheck, verb, resource, namespace, kubernetes, serviceAccountIndex, eventBus)) {
        return { ...auth, errorCode: 403 };
    }
    return auth;
}

function listNamespaces(kubernetes: KubernetesSpec): ExternalResponse {
    const namespaceItems = kubernetes.namespaces.map(ns => ({
        apiVersion: 'v1',
        kind: 'Namespace',
        metadata: makeItemMetadata(ns.name, undefined),
        spec: { finalizers: ['kubernetes'] },
        status: { phase: 'Active' },
    }));

    return makeJsonResponse(200, {
        apiVersion: 'v1',
        kind: 'NamespaceList',
        metadata: { resourceVersion: '1' },
        items: namespaceItems,
    });
}

function listPods(kubernetes: KubernetesSpec, namespace: string): ExternalResponse {
    const namespaceSpec = namespaceByName(kubernetes.namespaces, namespace);
    if (namespaceSpec === undefined) {
        return makeNotFound(`/api/v1/namespaces/${namespace}/pods`);
    }

    return makeJsonResponse(200, {
        apiVersion: 'v1',
        kind: 'PodList',
        metadata: { resourceVersion: '1' },
        items: namespaceSpec.pods.map(pod => buildPodJson(namespace, pod)),
    });
}

function getPod(kubernetes: KubernetesSpec, namespace: string, podName: string): ExternalResponse {
    const namespaceSpec = namespaceByName(kubernetes.namespaces, namespace);
    const pod = namespaceSpec?.pods.find(p => p.name === podName);
    if (pod === undefined) {
        return makeNotFound(`/api/v1/namespaces/${namespace}/pods/${podName}`);
    }
    return makeJsonResponse(200, buildPodJson(namespace, pod));
}

function executePod(
    kubernetes: KubernetesSpec,
    namespace: string,
    podName: string,
    request: ExternalRequest,
): ExternalResponse {
    const namespaceSpec = namespaceByName(kubernetes.namespaces, namespace);
    const pod = namespaceSpec?.pods.find(p => p.name === podName);
    if (pod === undefined) {
        return makeNotFound(`/api/v1/namespaces/${namespace}/pods/${podName}/exec`);
    }

    const queryString = request.path.includes('?') ? request.path.split('?').slice(1).join('?') : '';
    const query = new URLSearchParams(queryString);
    const command = query.get('command') ?? 'id';

    return makeTextResponse(200, `exec into ${pod.name} (${pod.image}) -> ${command}`);
}

function listSecrets(kubernetes: KubernetesSpec, namespace: string): ExternalResponse {
    const secrets = kubernetes.secrets.filter(s => s.namespace === namespace);
    return makeJsonResponse(200, {
        apiVersion: 'v1',
        kind: 'SecretList',
        metadata: { resourceVersion: '1' },
        items: secrets.map(secret => buildSecretJson(namespace, secret)),
    });
}

function getSecret(
    kubernetes: KubernetesSpec,
    namespace: string,
    name: string,
    auth: AuthResult,
    eventBus: EventBus,
    secretAccessLog: Map<string, Set<string>>,
): ExternalResponse {
    const secret = kubernetes.secrets.find(s => s.namespace === namespace && s.name === name);
    if (secret === undefined) {
        return makeNotFound(`/api/v1/namespaces/${namespace}/secrets/${name}`);
    }

    const response = makeJsonResponse(200, buildSecretJson(namespace, secret));
    const accessKey = `${namespace}/${name}`;
    const subject = auth.isAnonymous ? ANONYMOUS_SUBJECT : auth.subject;
    const accessed = secretAccessLog.get(subject);
    if (accessed === undefined) {
        secretAccessLog.set(subject, new Set([accessKey]));
    } else {
        accessed.add(accessKey);
    }

    eventBus.emit({
        type: 'auth:credential-found',
        credentialId: secret.name,
        machine: kubernetes.apiServerMachine,
        location: `/api/v1/namespaces/${namespace}/secrets/${name}`,
        timestamp: Date.now(),
    });

    return response;
}

function listConfigMaps(kubernetes: KubernetesSpec, namespace: string): ExternalResponse {
    const namespaceSpec = namespaceByName(kubernetes.namespaces, namespace);
    const configMaps = namespaceSpec?.configMaps ?? [];
    return makeJsonResponse(200, {
        apiVersion: 'v1',
        kind: 'ConfigMapList',
        metadata: { resourceVersion: '1' },
        items: configMaps.map(configMap => buildConfigMapJson(namespace, configMap)),
    });
}

function getConfigMap(kubernetes: KubernetesSpec, namespace: string, name: string): ExternalResponse {
    const namespaceSpec = namespaceByName(kubernetes.namespaces, namespace);
    const configMap = namespaceSpec?.configMaps?.find(c => c.name === name);
    if (configMap === undefined) {
        return makeNotFound(`/api/v1/namespaces/${namespace}/configmaps/${name}`);
    }
    return makeJsonResponse(200, buildConfigMapJson(namespace, configMap));
}

function listServiceAccounts(kubernetes: KubernetesSpec, namespace: string): ExternalResponse {
    const accounts = kubernetes.serviceAccounts.filter(sa => sa.namespace === namespace);
    return makeJsonResponse(200, {
        apiVersion: 'v1',
        kind: 'ServiceAccountList',
        metadata: { resourceVersion: '1' },
        items: accounts.map(sa => buildServiceAccountJson(namespace, sa)),
    });
}

function listNetworkPolicies(kubernetes: KubernetesSpec, namespace: string): ExternalResponse {
    const policies = kubernetes.networkPolicies?.filter(policy => policy.namespace === namespace) ?? [];
    return makeJsonResponse(200, {
        apiVersion: 'networking.k8s.io/v1',
        kind: 'NetworkPolicyList',
        metadata: { resourceVersion: '1' },
        items: policies.map(policy => buildPolicyJson(policy)),
    });
}

function handleKubernetesRequest(
    kubernetes: KubernetesSpec,
    eventBus: EventBus,
    serviceAccountIndex: ReadonlyMap<string, K8sServiceAccountSpec>,
    secretAccessLog: Map<string, Set<string>>,
    request: ExternalRequest,
): ExternalResponse {
    const segments = splitPath(request.path);
    const method = request.method.toUpperCase();
    if (segments.length === 0) {
        return makeNotFound('/');
    }

    if (segments[0] === 'api' && segments[1] === 'v1' && segments[2] === 'namespaces') {
        if (segments.length === 3) {
            if (method !== 'GET') return makeNotAllowed(method);
            const auth = authorize(kubernetes, serviceAccountIndex, request, 'get', 'namespaces', '*', eventBus);
            if (auth.errorCode === 401) {
                return makeAuthError(401, 'get', 'namespaces', '*');
            }
            if (auth.errorCode === 403) {
                return makeAuthError(403, 'get', 'namespaces', '*');
            }
            return listNamespaces(kubernetes);
        }

        const namespace = segments[3];
        if (namespace === undefined || namespace === '') {
            return makeNotFound('/api/v1/namespaces');
        }

        if (segments.length >= 5 && segments[4] === 'pods') {
            if (segments.length === 5) {
                if (method !== 'GET') {
                    return makeNotAllowed(method);
                }
                const auth = authorize(kubernetes, serviceAccountIndex, request, 'list', 'pods', namespace, eventBus);
                if (auth.errorCode === 401) return makeAuthError(401, 'list', 'pods', namespace);
                if (auth.errorCode === 403) return makeAuthError(403, 'list', 'pods', namespace);
                return listPods(kubernetes, namespace);
            }

            const podName = segments[5];
            if (podName === undefined || podName === '') {
                return makeNotFound(`/api/v1/namespaces/${namespace}/pods`);
            }

            if (segments.length === 7 && segments[6] === 'exec') {
                if (method !== 'POST') {
                    return makeNotAllowed(method);
                }
                const auth = authorize(kubernetes, serviceAccountIndex, request, 'exec', 'pods/exec', namespace, eventBus);
                if (auth.errorCode === 401) return makeAuthError(401, 'exec', 'pods/exec', namespace);
                if (auth.errorCode === 403) return makeAuthError(403, 'exec', 'pods/exec', namespace);
                return executePod(kubernetes, namespace, podName, request);
            }

            if (segments.length === 6 && method === 'GET') {
                const auth = authorize(kubernetes, serviceAccountIndex, request, 'get', 'pods', namespace, eventBus);
                if (auth.errorCode === 401) return makeAuthError(401, 'get', 'pods', namespace);
                if (auth.errorCode === 403) return makeAuthError(403, 'get', 'pods', namespace);
                return getPod(kubernetes, namespace, podName);
            }

            return makeNotFound(request.path);
        }

        if (segments.length >= 5 && segments[4] === 'secrets') {
            if (segments.length === 5) {
                if (method !== 'GET') return makeNotAllowed(method);
                const auth = authorize(kubernetes, serviceAccountIndex, request, 'list', 'secrets', namespace, eventBus);
                if (auth.errorCode === 401) return makeAuthError(401, 'list', 'secrets', namespace);
                if (auth.errorCode === 403) return makeAuthError(403, 'list', 'secrets', namespace);
                return listSecrets(kubernetes, namespace);
            }

            if (segments.length === 6 && method === 'GET') {
                const secretName = segments[5]!;
                const auth = authorize(kubernetes, serviceAccountIndex, request, 'get', 'secrets', namespace, eventBus);
                if (auth.errorCode === 401) return makeAuthError(401, 'get', 'secrets', namespace);
                if (auth.errorCode === 403) return makeAuthError(403, 'get', 'secrets', namespace);
                return getSecret(kubernetes, namespace, secretName, auth, eventBus, secretAccessLog);
            }

            return makeNotFound(request.path);
        }

        if (segments.length >= 5 && segments[4] === 'configmaps') {
            if (segments.length === 5) {
                if (method !== 'GET') return makeNotAllowed(method);
                const auth = authorize(kubernetes, serviceAccountIndex, request, 'list', 'configmaps', namespace, eventBus);
                if (auth.errorCode === 401) return makeAuthError(401, 'list', 'configmaps', namespace);
                if (auth.errorCode === 403) return makeAuthError(403, 'list', 'configmaps', namespace);
                return listConfigMaps(kubernetes, namespace);
            }
            if (segments.length === 6 && method === 'GET') {
                const configMapName = segments[5]!;
                const auth = authorize(kubernetes, serviceAccountIndex, request, 'get', 'configmaps', namespace, eventBus);
                if (auth.errorCode === 401) return makeAuthError(401, 'get', 'configmaps', namespace);
                if (auth.errorCode === 403) return makeAuthError(403, 'get', 'configmaps', namespace);
                return getConfigMap(kubernetes, namespace, configMapName);
            }
            return makeNotFound(request.path);
        }

        if (segments.length >= 5 && segments[4] === 'serviceaccounts') {
            if (segments.length === 5) {
                if (method !== 'GET') return makeNotAllowed(method);
                const auth = authorize(
                    kubernetes,
                    serviceAccountIndex,
                    request,
                    'list',
                    'serviceaccounts',
                    namespace,
                    eventBus,
                );
                if (auth.errorCode === 401) return makeAuthError(401, 'list', 'serviceaccounts', namespace);
                if (auth.errorCode === 403) return makeAuthError(403, 'list', 'serviceaccounts', namespace);
                return listServiceAccounts(kubernetes, namespace);
            }
            return makeNotFound(request.path);
        }
    }

    if (
        segments[0] === 'apis'
        && segments[1] === 'networking.k8s.io'
        && segments[2] === 'v1'
        && segments[3] === 'namespaces'
    ) {
        const namespace = segments[4];
        if (namespace === undefined || namespace === '') {
            return makeNotFound('/apis/networking.k8s.io/v1/namespaces');
        }
        if (segments[5] === 'networkpolicies' && segments.length === 6) {
            if (method !== 'GET') return makeNotAllowed(method);
            const auth = authorize(
                kubernetes,
                serviceAccountIndex,
                request,
                'list',
                'networkpolicies',
                namespace,
                eventBus,
            );
            if (auth.errorCode === 401) return makeAuthError(401, 'list', 'networkpolicies', namespace);
            if (auth.errorCode === 403) return makeAuthError(403, 'list', 'networkpolicies', namespace);
            return listNetworkPolicies(kubernetes, namespace);
        }
    }

    return makeNotFound(request.path);
}

// ── Factory ─────────────────────────────────────────────────

export function createK8sApiModule(spec?: KubernetesSpec, eventBus?: EventBus): Module {
    const injectedSpec = spec;
    const injectedEventBus = eventBus;

    return {
        id: MODULE_ID,
        type: 'engine',
        version: MODULE_VERSION,
        description: 'Simulates the Kubernetes API server with RBAC and secret exposure telemetry',
        provides: [{ name: 'kubernetes' }, { name: 'k8s-api' }] as const,
        requires: [{ name: 'variant-internet' }] as const,

        init(context: SimulationContext): void {
            const kubernetes = injectedSpec ?? context.world.kubernetes;
            if (kubernetes === undefined) {
                return;
            }

            const effectiveEventBus = injectedEventBus ?? context.events;
            const serviceAccountIndex = new Map<string, K8sServiceAccountSpec>();
            const secretAccessLog = new Map<string, Set<string>>();

            for (const serviceAccount of kubernetes.serviceAccounts) {
                serviceAccountIndex.set(`${serviceAccount.namespace}/${serviceAccount.name}`, serviceAccount);
            }
            activeKubernetes = kubernetes;
            activeServiceAccountIndex = serviceAccountIndex;
            activeEventBus = effectiveEventBus;

            const handler: ExternalServiceHandler = {
                domain: kubernetes.apiServerMachine,
                description: `VARIANT Kubernetes API at ${kubernetes.apiServerMachine}`,
                handleRequest(request: ExternalRequest): ExternalResponse {
                    return handleKubernetesRequest(
                        kubernetes,
                        effectiveEventBus,
                        serviceAccountIndex,
                        secretAccessLog,
                        request,
                    );
                },
            };

            context.fabric.addDNSRecord({
                domain: kubernetes.apiServerMachine,
                ip: API_SERVER_IP,
                type: 'A',
                ttl: 3600,
            });
            context.fabric.registerExternal(handler);

            context.events.emit({
                type: 'sim:alert',
                source: MODULE_ID,
                message: `Kubernetes API activated on ${kubernetes.apiServerMachine} for cluster ${kubernetes.clusterName}`,
                timestamp: Date.now(),
            });
        },

        destroy(): void {
            // DNS and external handlers are owned by the fabric
            activeKubernetes = undefined;
            activeServiceAccountIndex = new Map<string, K8sServiceAccountSpec>();
            activeEventBus = undefined;
        },
    };
}
