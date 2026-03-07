/**
 * VARIANT — Load Balancer / Reverse Proxy Engine
 *
 * Simulates L4/L7 load balancing with:
 * - Round-robin, least-connections, IP hash, weighted algorithms
 * - Route matching (path, host, headers, method)
 * - Per-IP rate limiting
 * - Backend health tracking
 *
 * All operations are synchronous and pure-data.
 */

import type {
    ProxyEngine,
    Backend,
    BackendConfig,
    RouteRule,
    RateLimitRule,
    ProxyRequest,
    ProxyResponse,
    BalancingAlgorithm,
} from './types';

// ── Helpers ───────────────────────────────────────────────

let backendCounter = 0;
let routeCounter = 0;
let rateLimitCounter = 0;

function generateBackendId(): string {
    return `backend-${++backendCounter}`;
}

function generateRouteId(): string {
    return `route-${++routeCounter}`;
}

function generateRateLimitId(): string {
    return `rl-${++rateLimitCounter}`;
}

function simpleHash(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) - hash + str.charCodeAt(i)) | 0;
    }
    return Math.abs(hash);
}

// ── Factory ──────────────────────────────────────────────

export function createProxyEngine(): ProxyEngine {
    const backends = new Map<string, Backend & {
        _healthy: boolean;
        _activeConns: number;
        _totalReqs: number;
        _totalErrs: number;
        _totalResponseTime: number;
    }>();
    const routes: Array<RouteRule & { _enabled: boolean }> = [];
    const rateLimits = new Map<string, RateLimitRule>();
    const rateLimitCounters = new Map<string, { count: number; windowStart: number }>();
    let algorithm: BalancingAlgorithm = 'round_robin';
    let rrIndex = 0;
    let totalRequests = 0;
    let totalErrors = 0;
    let totalRateLimited = 0;
    let totalResponseTime = 0;

    function getHealthyBackends(ids?: readonly string[]): Array<Backend & { _healthy: boolean; _activeConns: number; _totalReqs: number; _totalErrs: number; _totalResponseTime: number }> {
        const all = ids
            ? ids.map(id => backends.get(id)).filter((b): b is NonNullable<typeof b> => b !== undefined)
            : Array.from(backends.values());
        return all.filter(b => b._healthy);
    }

    function selectBackend(healthy: ReturnType<typeof getHealthyBackends>, request: ProxyRequest): typeof healthy[0] | undefined {
        if (healthy.length === 0) return undefined;

        switch (algorithm) {
            case 'round_robin':
                return healthy[rrIndex++ % healthy.length];

            case 'least_connections':
                return healthy.reduce((min, b) => b._activeConns < min._activeConns ? b : min, healthy[0]!);

            case 'ip_hash':
                return healthy[simpleHash(request.sourceIP) % healthy.length];

            case 'weighted_round_robin': {
                const totalWeight = healthy.reduce((sum, b) => sum + b.weight, 0);
                let target = rrIndex++ % totalWeight;
                for (const b of healthy) {
                    target -= b.weight;
                    if (target < 0) return b;
                }
                return healthy[0];
            }

            case 'random':
                return healthy[Math.floor(Math.random() * healthy.length)];

            default:
                return healthy[rrIndex++ % healthy.length];
        }
    }

    function matchRoute(request: ProxyRequest): RouteRule | undefined {
        const sorted = routes
            .filter(r => r._enabled)
            .sort((a, b) => b.priority - a.priority);

        for (const rule of sorted) {
            const m = rule.match;
            if (m.pathExact && request.path !== m.pathExact) continue;
            if (m.pathPrefix && !request.path.startsWith(m.pathPrefix)) continue;
            if (m.hostHeader && request.host !== m.hostHeader) continue;
            if (m.method && request.method !== m.method) continue;
            if (m.headers) {
                let headersMatch = true;
                for (const [k, v] of Object.entries(m.headers)) {
                    if (request.headers[k] !== v) { headersMatch = false; break; }
                }
                if (!headersMatch) continue;
            }
            return rule;
        }
        return undefined;
    }

    function checkRateLimit(request: ProxyRequest, now: number): boolean {
        for (const rule of rateLimits.values()) {
            if (!rule.enabled) continue;

            let key: string;
            switch (rule.key) {
                case 'ip': key = `rl:${rule.id}:${request.sourceIP}`; break;
                case 'path': key = `rl:${rule.id}:${request.path}`; break;
                case 'header': key = `rl:${rule.id}:${request.headers[rule.headerName ?? ''] ?? ''}`; break;
                default: key = `rl:${rule.id}:${request.sourceIP}`;
            }

            const counter = rateLimitCounters.get(key);
            const windowMs = rule.windowSeconds * 1000;

            if (!counter || now - counter.windowStart >= windowMs) {
                rateLimitCounters.set(key, { count: 1, windowStart: now });
            } else {
                counter.count++;
                if (counter.count > rule.maxRequests) {
                    return true; // Rate limited
                }
            }
        }
        return false;
    }

    const engine: ProxyEngine = {
        addBackend(config: BackendConfig) {
            const id = generateBackendId();
            const backend = {
                id,
                host: config.host,
                port: config.port,
                weight: config.weight ?? 1,
                healthy: true,
                activeConnections: 0,
                totalRequests: 0,
                totalErrors: 0,
                responseTimeMs: 0,
                _healthy: true,
                _activeConns: 0,
                _totalReqs: 0,
                _totalErrs: 0,
                _totalResponseTime: 0,
            };
            backends.set(id, backend);
            return Object.freeze({
                id, host: backend.host, port: backend.port, weight: backend.weight,
                healthy: true, activeConnections: 0, totalRequests: 0, totalErrors: 0, responseTimeMs: 0,
            });
        },

        removeBackend(id) {
            return backends.delete(id);
        },

        getBackend(id) {
            const b = backends.get(id);
            if (!b) return null;
            return Object.freeze({
                id: b.id, host: b.host, port: b.port, weight: b.weight,
                healthy: b._healthy, activeConnections: b._activeConns,
                totalRequests: b._totalReqs, totalErrors: b._totalErrs,
                responseTimeMs: b._totalReqs > 0 ? Math.round(b._totalResponseTime / b._totalReqs) : 0,
            });
        },

        listBackends() {
            return Object.freeze(Array.from(backends.values()).map(b => ({
                id: b.id, host: b.host, port: b.port, weight: b.weight,
                healthy: b._healthy, activeConnections: b._activeConns,
                totalRequests: b._totalReqs, totalErrors: b._totalErrs,
                responseTimeMs: b._totalReqs > 0 ? Math.round(b._totalResponseTime / b._totalReqs) : 0,
            })));
        },

        setBackendHealth(id, healthy) {
            const b = backends.get(id);
            if (!b) return false;
            b._healthy = healthy;
            return true;
        },

        setAlgorithm(algo) {
            algorithm = algo;
            rrIndex = 0;
        },

        addRoute(rule) {
            const id = generateRouteId();
            const full = { ...rule, id, _enabled: rule.enabled };
            routes.push(full);
            return Object.freeze({ id, match: rule.match, backendIds: rule.backendIds, priority: rule.priority, enabled: rule.enabled });
        },

        removeRoute(id) {
            const idx = routes.findIndex(r => r.id === id);
            if (idx === -1) return false;
            routes.splice(idx, 1);
            return true;
        },

        listRoutes() {
            return Object.freeze(routes.map(r => ({
                id: r.id, match: r.match, backendIds: r.backendIds, priority: r.priority, enabled: r._enabled,
            })));
        },

        addRateLimit(rule) {
            const id = generateRateLimitId();
            const full: RateLimitRule = Object.freeze({ ...rule, id });
            rateLimits.set(id, full);
            return full;
        },

        removeRateLimit(id) {
            return rateLimits.delete(id);
        },

        handleRequest(request: ProxyRequest): ProxyResponse {
            totalRequests++;
            const now = Date.now();

            // Rate limiting
            if (checkRateLimit(request, now)) {
                totalRateLimited++;
                return Object.freeze({
                    backendId: '',
                    backendHost: '',
                    statusCode: 429,
                    responseTimeMs: 0,
                    cached: false,
                    rateLimited: true,
                });
            }

            // Route matching
            const route = matchRoute(request);
            const backendPool = route ? route.backendIds : undefined;

            // Select backend
            const healthy = getHealthyBackends(backendPool);
            const selected = selectBackend(healthy, request);

            if (!selected) {
                totalErrors++;
                return Object.freeze({
                    backendId: '',
                    backendHost: '',
                    statusCode: 502,
                    responseTimeMs: 0,
                    cached: false,
                    rateLimited: false,
                });
            }

            // Simulate response
            const responseTime = 5 + Math.floor(Math.random() * 50);
            selected._totalReqs++;
            selected._activeConns++;
            selected._totalResponseTime += responseTime;
            totalResponseTime += responseTime;

            // Simulate occasional errors (very low rate)
            const isError = Math.random() < 0.01;
            if (isError) {
                selected._totalErrs++;
                totalErrors++;
            }
            selected._activeConns = Math.max(0, selected._activeConns - 1);

            return Object.freeze({
                backendId: selected.id,
                backendHost: `${selected.host}:${selected.port}`,
                statusCode: isError ? 500 : 200,
                responseTimeMs: responseTime,
                cached: false,
                rateLimited: false,
            });
        },

        getStats() {
            let active = 0;
            let unhealthy = 0;
            const byBackend: Record<string, number> = {};

            for (const b of backends.values()) {
                if (b._healthy) active++;
                else unhealthy++;
                byBackend[b.id] = b._totalReqs;
            }

            return Object.freeze({
                totalRequests,
                totalErrors,
                totalRateLimited,
                activeBackends: active,
                unhealthyBackends: unhealthy,
                avgResponseTimeMs: totalRequests > 0 ? Math.round(totalResponseTime / totalRequests) : 0,
                requestsByBackend: Object.freeze(byBackend),
                algorithm,
            });
        },
    };

    return engine;
}
