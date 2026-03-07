/**
 * VARIANT — Service Request Processing Pipeline
 *
 * Composable middleware chain for service handlers.
 * Intercepts, transforms, validates, and audits requests
 * before they reach the service handler, and responses
 * before they leave.
 *
 * DESIGN:
 *   A request pipeline wraps a ServiceHandler. Middleware
 *   functions are called in order. Each can:
 *     1. Pass through (call next)
 *     2. Short-circuit (return a response without calling next)
 *     3. Transform the request before passing to next
 *     4. Transform the response after next returns
 *     5. Side-effect (logging, metrics, detection) then pass through
 *
 * CONFIGURABILITY:
 *   - Middleware order is explicit (priority-based)
 *   - Middleware can be enabled/disabled at runtime
 *   - Middleware can be added/removed without modifying handlers
 *   - Built-in middleware factories for common patterns
 *
 * SWAPPABILITY: Each middleware is independent. The pipeline
 * implements ServiceHandler — drop it in anywhere a handler
 * is expected. Replace any middleware without touching others.
 */

import type { ServiceHandler, ServiceRequest, ServiceResponse, ServiceContext } from './types';

// ── Middleware Types ────────────────────────────────────────

/**
 * A request/response middleware function.
 *
 * Receives the request, context, and a `next` function.
 * Must call `next(request)` to continue the chain, or
 * return a response directly to short-circuit.
 *
 * Can modify the request before calling next.
 * Can modify the response after next returns.
 */
export type RequestMiddleware = (
    request: ServiceRequest,
    ctx: ServiceContext,
    next: (request: ServiceRequest) => ServiceResponse | null,
) => ServiceResponse | null;

/**
 * Named middleware with priority and lifecycle control.
 */
export interface NamedRequestMiddleware {
    /** Unique middleware ID. */
    readonly id: string;

    /** Human-readable description. */
    readonly description: string;

    /** Priority (lower = runs first). Default: 100. */
    readonly priority: number;

    /** Whether this middleware is currently active. */
    enabled: boolean;

    /** The middleware function. */
    readonly handler: RequestMiddleware;
}

// ── Pipeline Interface ─────────────────────────────────────

/**
 * A request processing pipeline wraps a ServiceHandler
 * and applies middleware in order.
 */
export interface RequestPipeline extends ServiceHandler {
    /** Add middleware to the pipeline. */
    use(middleware: NamedRequestMiddleware): void;

    /** Remove middleware by ID. */
    remove(id: string): boolean;

    /** Get all middleware (sorted by priority). */
    getMiddleware(): readonly NamedRequestMiddleware[];

    /** Enable/disable a middleware by ID. */
    setEnabled(id: string, enabled: boolean): boolean;

    /** Get the inner handler. */
    getInnerHandler(): ServiceHandler;

    /** Get pipeline statistics. */
    getStats(): PipelineStats;
}

export interface PipelineStats {
    /** Total requests processed. */
    readonly totalRequests: number;

    /** Requests short-circuited by middleware. */
    readonly shortCircuited: number;

    /** Requests that reached the inner handler. */
    readonly passedThrough: number;

    /** Requests where the inner handler returned null. */
    readonly dropped: number;

    /** Per-middleware hit counts. */
    readonly middlewareHits: Readonly<Record<string, number>>;
}

// ── Pipeline Implementation ────────────────────────────────

export interface RequestPipelineConfig {
    /** The inner service handler to wrap. */
    readonly handler: ServiceHandler;

    /** Initial middleware list. */
    readonly middleware?: readonly NamedRequestMiddleware[];

    /** Whether to track per-middleware stats. Default: true. */
    readonly trackStats?: boolean;
}

export function createRequestPipeline(config: RequestPipelineConfig): RequestPipeline {
    const inner = config.handler;
    const middlewareList: NamedRequestMiddleware[] = [...(config.middleware ?? [])];
    const trackStats = config.trackStats !== false;

    let totalRequests = 0;
    let shortCircuited = 0;
    let passedThrough = 0;
    let dropped = 0;
    const middlewareHits = new Map<string, number>();

    function sortMiddleware(): void {
        middlewareList.sort((a, b) => a.priority - b.priority);
    }

    // Initial sort
    sortMiddleware();

    const pipeline: RequestPipeline = {
        // ── ServiceHandler interface ────────────────────────
        name: inner.name,
        port: inner.port,
        protocol: inner.protocol,

        handle(request: ServiceRequest, ctx: ServiceContext): ServiceResponse | null {
            if (trackStats) totalRequests++;

            // Build the middleware chain
            const active = middlewareList.filter(m => m.enabled);

            // Chain execution: each middleware calls next() to proceed
            function executeChain(index: number, req: ServiceRequest): ServiceResponse | null {
                if (index >= active.length) {
                    // End of chain — call the inner handler
                    if (trackStats) passedThrough++;
                    const response = inner.handle(req, ctx);
                    if (response === null && trackStats) dropped++;
                    return response;
                }

                const mw = active[index]!;
                if (trackStats) {
                    middlewareHits.set(mw.id, (middlewareHits.get(mw.id) ?? 0) + 1);
                }

                let nextCalled = false;
                const response = mw.handler(req, ctx, (modifiedReq) => {
                    nextCalled = true;
                    return executeChain(index + 1, modifiedReq);
                });

                if (!nextCalled && trackStats) {
                    shortCircuited++;
                }

                return response;
            }

            return executeChain(0, request);
        },

        start(ctx: ServiceContext): void {
            inner.start?.(ctx);
        },

        stop(): void {
            inner.stop?.();
        },

        // ── Pipeline management ─────────────────────────────

        use(middleware: NamedRequestMiddleware): void {
            const existing = middlewareList.findIndex(m => m.id === middleware.id);
            if (existing !== -1) {
                throw new Error(`RequestPipeline: middleware '${middleware.id}' already registered`);
            }
            middlewareList.push(middleware);
            sortMiddleware();
        },

        remove(id: string): boolean {
            const index = middlewareList.findIndex(m => m.id === id);
            if (index === -1) return false;
            middlewareList.splice(index, 1);
            return true;
        },

        getMiddleware(): readonly NamedRequestMiddleware[] {
            return [...middlewareList];
        },

        setEnabled(id: string, enabled: boolean): boolean {
            const mw = middlewareList.find(m => m.id === id);
            if (mw === undefined) return false;
            mw.enabled = enabled;
            return true;
        },

        getInnerHandler(): ServiceHandler {
            return inner;
        },

        getStats(): PipelineStats {
            return {
                totalRequests,
                shortCircuited,
                passedThrough,
                dropped,
                middlewareHits: Object.fromEntries(middlewareHits),
            };
        },
    };

    return pipeline;
}

// ── Built-in Middleware Factories ───────────────────────────

/**
 * IP allowlist middleware. Only allows requests from
 * specified IP addresses. Rejects others with a configurable response.
 */
export function createIPAllowlistMiddleware(
    id: string,
    allowedIPs: readonly string[],
    rejectResponse?: ServiceResponse,
): NamedRequestMiddleware {
    const allowSet = new Set(allowedIPs);
    const reject = rejectResponse ?? {
        payload: new TextEncoder().encode('403 Forbidden'),
        close: true,
    };

    return {
        id,
        description: `IP allowlist: ${allowedIPs.length} IPs allowed`,
        priority: 10,
        enabled: true,
        handler(request, _ctx, next) {
            if (!allowSet.has(request.sourceIP)) {
                return reject;
            }
            return next(request);
        },
    };
}

/**
 * Rate limit middleware. Limits requests per source IP
 * within a time window.
 */
export function createRequestRateLimitMiddleware(
    id: string,
    maxRequests: number,
    windowMs: number,
    rejectResponse?: ServiceResponse,
): NamedRequestMiddleware {
    const windows = new Map<string, number[]>();
    const reject = rejectResponse ?? {
        payload: new TextEncoder().encode('429 Too Many Requests'),
        close: false,
    };

    return {
        id,
        description: `Rate limit: ${maxRequests} req/${windowMs}ms per IP`,
        priority: 20,
        enabled: true,
        handler(request, _ctx, next) {
            const now = Date.now();
            const cutoff = now - windowMs;

            let timestamps = windows.get(request.sourceIP);
            if (timestamps === undefined) {
                timestamps = [];
                windows.set(request.sourceIP, timestamps);
            }

            // Prune old timestamps
            while (timestamps.length > 0 && timestamps[0]! < cutoff) {
                timestamps.shift();
            }

            if (timestamps.length >= maxRequests) {
                return reject;
            }

            timestamps.push(now);
            return next(request);
        },
    };
}

/**
 * Request logging middleware. Logs all requests via the
 * service context's emit function.
 */
export function createRequestLoggingMiddleware(
    id: string,
    logFn?: (request: ServiceRequest, response: ServiceResponse | null) => void,
): NamedRequestMiddleware {
    const entries: Array<{
        readonly timestamp: number;
        readonly sourceIP: string;
        readonly payloadLength: number;
        readonly responded: boolean;
    }> = [];

    return {
        id,
        description: 'Request logging middleware',
        priority: 5,
        enabled: true,
        handler(request, _ctx, next) {
            const response = next(request);

            entries.push({
                timestamp: Date.now(),
                sourceIP: request.sourceIP,
                payloadLength: request.payload.length,
                responded: response !== null,
            });

            if (logFn !== undefined) {
                logFn(request, response);
            }

            return response;
        },
    };
}

/**
 * Request transformation middleware. Transforms request
 * payloads before they reach the handler.
 */
export function createRequestTransformMiddleware(
    id: string,
    transform: (request: ServiceRequest) => ServiceRequest,
    priority: number = 50,
): NamedRequestMiddleware {
    return {
        id,
        description: `Request transform: ${id}`,
        priority,
        enabled: true,
        handler(request, _ctx, next) {
            return next(transform(request));
        },
    };
}

/**
 * Response transformation middleware. Transforms responses
 * before they leave the pipeline.
 */
export function createResponseTransformMiddleware(
    id: string,
    transform: (response: ServiceResponse) => ServiceResponse,
    priority: number = 150,
): NamedRequestMiddleware {
    return {
        id,
        description: `Response transform: ${id}`,
        priority,
        enabled: true,
        handler(request, _ctx, next) {
            const response = next(request);
            if (response === null) return null;
            return transform(response);
        },
    };
}

/**
 * Detection middleware. Runs input through a detection function
 * and optionally blocks detected attacks.
 */
export function createDetectionMiddleware(
    id: string,
    detect: (input: string) => boolean,
    blockOnDetection: boolean = false,
    blockResponse?: ServiceResponse,
): NamedRequestMiddleware {
    const reject = blockResponse ?? {
        payload: new TextEncoder().encode('400 Bad Request'),
        close: true,
    };

    return {
        id,
        description: `Detection middleware: ${id}`,
        priority: 30,
        enabled: true,
        handler(request, ctx, next) {
            const isAttack = detect(request.payloadText);

            if (isAttack) {
                ctx.emit({
                    type: 'service:custom',
                    service: 'detection',
                    action: 'attack-detected',
                    details: {
                        middlewareId: id,
                        sourceIP: request.sourceIP,
                        payloadLength: request.payload.length,
                    },
                });

                if (blockOnDetection) {
                    return reject;
                }
            }

            return next(request);
        },
    };
}
