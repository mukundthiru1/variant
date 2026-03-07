/**
 * VARIANT — Load Balancer / Reverse Proxy Types
 *
 * Simulates L4/L7 load balancing and reverse proxy:
 * - Multiple balancing algorithms (round-robin, least-conn, IP hash, weighted)
 * - Backend health checking
 * - Request routing rules
 * - TLS termination tracking
 * - Rate limiting
 *
 * EXTENSIBILITY: Custom algorithms via open union.
 * SWAPPABILITY: Implements ProxyEngine interface.
 */

// ── Backend ──────────────────────────────────────────────

export interface Backend {
    readonly id: string;
    readonly host: string;
    readonly port: number;
    readonly weight: number;
    readonly healthy: boolean;
    readonly activeConnections: number;
    readonly totalRequests: number;
    readonly totalErrors: number;
    readonly responseTimeMs: number;
}

export interface BackendConfig {
    readonly host: string;
    readonly port: number;
    readonly weight?: number;
    readonly healthCheckPath?: string;
}

// ── Routing ──────────────────────────────────────────────

export interface RouteRule {
    readonly id: string;
    readonly match: RouteMatch;
    readonly backendIds: readonly string[];
    readonly priority: number;
    readonly enabled: boolean;
}

export interface RouteMatch {
    readonly pathPrefix?: string;
    readonly pathExact?: string;
    readonly hostHeader?: string;
    readonly headers?: Readonly<Record<string, string>>;
    readonly method?: string;
}

// ── Proxy Request / Response ─────────────────────────────

export interface ProxyRequest {
    readonly method: string;
    readonly path: string;
    readonly host: string;
    readonly headers: Readonly<Record<string, string>>;
    readonly sourceIP: string;
    readonly bodySize: number;
}

export interface ProxyResponse {
    readonly backendId: string;
    readonly backendHost: string;
    readonly statusCode: number;
    readonly responseTimeMs: number;
    readonly cached: boolean;
    readonly rateLimited: boolean;
}

// ── Rate Limiting ────────────────────────────────────────

export interface RateLimitRule {
    readonly id: string;
    readonly key: 'ip' | 'path' | 'header';
    readonly headerName?: string;
    readonly maxRequests: number;
    readonly windowSeconds: number;
    readonly enabled: boolean;
}

// ── Load Balancing Algorithm ─────────────────────────────

export type BalancingAlgorithm =
    | 'round_robin' | 'least_connections' | 'ip_hash'
    | 'weighted_round_robin' | 'random'
    | (string & {});

// ── Proxy Engine Interface ───────────────────────────────

export interface ProxyEngine {
    /** Add a backend server. */
    addBackend(config: BackendConfig): Backend;
    /** Remove a backend. */
    removeBackend(id: string): boolean;
    /** Get backend by ID. */
    getBackend(id: string): Backend | null;
    /** List all backends. */
    listBackends(): readonly Backend[];
    /** Set backend health status. */
    setBackendHealth(id: string, healthy: boolean): boolean;
    /** Set the balancing algorithm. */
    setAlgorithm(algorithm: BalancingAlgorithm): void;
    /** Add a routing rule. */
    addRoute(rule: Omit<RouteRule, 'id'>): RouteRule;
    /** Remove a routing rule. */
    removeRoute(id: string): boolean;
    /** List routing rules. */
    listRoutes(): readonly RouteRule[];
    /** Add a rate limit rule. */
    addRateLimit(rule: Omit<RateLimitRule, 'id'>): RateLimitRule;
    /** Remove a rate limit rule. */
    removeRateLimit(id: string): boolean;
    /** Route a request through the proxy. */
    handleRequest(request: ProxyRequest): ProxyResponse;
    /** Get stats. */
    getStats(): ProxyStats;
}

export interface ProxyStats {
    readonly totalRequests: number;
    readonly totalErrors: number;
    readonly totalRateLimited: number;
    readonly activeBackends: number;
    readonly unhealthyBackends: number;
    readonly avgResponseTimeMs: number;
    readonly requestsByBackend: Readonly<Record<string, number>>;
    readonly algorithm: BalancingAlgorithm;
}
