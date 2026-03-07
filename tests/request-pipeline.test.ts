import { describe, it, expect, vi } from 'vitest';
import {
    createRequestPipeline,
    createIPAllowlistMiddleware,
    createRequestRateLimitMiddleware,
    createRequestLoggingMiddleware,
    createRequestTransformMiddleware,
    createResponseTransformMiddleware,
    createDetectionMiddleware,
} from '../src/lib/services/request-pipeline';
import type { ServiceHandler, ServiceRequest, ServiceResponse, ServiceContext } from '../src/lib/services/types';

// ── Helpers ─────────────────────────────────────────────────

function createMockHandler(response?: ServiceResponse): ServiceHandler {
    const resp = response ?? {
        payload: new TextEncoder().encode('200 OK'),
        close: false,
    };

    return {
        name: 'test-http',
        port: 80,
        protocol: 'tcp',
        handle: vi.fn(() => resp),
        start: vi.fn(),
        stop: vi.fn(),
    };
}

function createMockRequest(overrides?: Partial<ServiceRequest>): ServiceRequest {
    const text = overrides?.payloadText ?? 'GET / HTTP/1.1\r\nHost: test\r\n\r\n';
    return {
        sourceIP: overrides?.sourceIP ?? '10.0.0.1',
        sourcePort: overrides?.sourcePort ?? 12345,
        payload: new TextEncoder().encode(text),
        payloadText: text,
        ...overrides,
    };
}

function createMockContext(): ServiceContext {
    return {
        vfs: {} as ServiceContext['vfs'],
        shell: {} as ServiceContext['shell'],
        hostname: 'test-host',
        ip: '10.0.0.100',
        emit: vi.fn(),
    };
}

// ── Basic Pipeline ──────────────────────────────────────────

describe('Request Pipeline', () => {
    describe('Core Pipeline', () => {
        it('passes requests through to inner handler', () => {
            const handler = createMockHandler();
            const pipeline = createRequestPipeline({ handler });

            const req = createMockRequest();
            const ctx = createMockContext();
            const response = pipeline.handle(req, ctx);

            expect(response).not.toBeNull();
            expect(handler.handle).toHaveBeenCalledWith(req, ctx);
        });

        it('delegates start/stop to inner handler', () => {
            const handler = createMockHandler();
            const pipeline = createRequestPipeline({ handler });
            const ctx = createMockContext();

            pipeline.start!(ctx);
            expect(handler.start).toHaveBeenCalledWith(ctx);

            pipeline.stop!();
            expect(handler.stop).toHaveBeenCalled();
        });

        it('preserves handler metadata', () => {
            const handler = createMockHandler();
            const pipeline = createRequestPipeline({ handler });

            expect(pipeline.name).toBe('test-http');
            expect(pipeline.port).toBe(80);
            expect(pipeline.protocol).toBe('tcp');
        });

        it('exposes inner handler', () => {
            const handler = createMockHandler();
            const pipeline = createRequestPipeline({ handler });
            expect(pipeline.getInnerHandler()).toBe(handler);
        });
    });

    describe('Middleware Chain', () => {
        it('executes middleware in priority order', () => {
            const order: string[] = [];
            const handler = createMockHandler();
            const pipeline = createRequestPipeline({
                handler,
                middleware: [
                    {
                        id: 'second', description: '', priority: 20, enabled: true,
                        handler(req, _ctx, next) { order.push('second'); return next(req); },
                    },
                    {
                        id: 'first', description: '', priority: 10, enabled: true,
                        handler(req, _ctx, next) { order.push('first'); return next(req); },
                    },
                    {
                        id: 'third', description: '', priority: 30, enabled: true,
                        handler(req, _ctx, next) { order.push('third'); return next(req); },
                    },
                ],
            });

            pipeline.handle(createMockRequest(), createMockContext());
            expect(order).toEqual(['first', 'second', 'third']);
        });

        it('allows middleware to short-circuit', () => {
            const handler = createMockHandler();
            const blocked = { payload: new TextEncoder().encode('BLOCKED'), close: true };
            const pipeline = createRequestPipeline({
                handler,
                middleware: [{
                    id: 'blocker', description: '', priority: 10, enabled: true,
                    handler() { return blocked; },
                }],
            });

            const response = pipeline.handle(createMockRequest(), createMockContext());
            expect(response).toBe(blocked);
            expect(handler.handle).not.toHaveBeenCalled();
        });

        it('allows middleware to transform requests', () => {
            const handler = createMockHandler();
            const pipeline = createRequestPipeline({
                handler,
                middleware: [{
                    id: 'transform', description: '', priority: 10, enabled: true,
                    handler(req, _ctx, next) {
                        return next({
                            ...req,
                            sourceIP: '1.2.3.4',
                        });
                    },
                }],
            });

            pipeline.handle(createMockRequest(), createMockContext());
            const callArg = (handler.handle as ReturnType<typeof vi.fn>).mock.calls[0]![0] as ServiceRequest;
            expect(callArg.sourceIP).toBe('1.2.3.4');
        });

        it('allows middleware to transform responses', () => {
            const handler = createMockHandler();
            const pipeline = createRequestPipeline({
                handler,
                middleware: [{
                    id: 'resp-transform', description: '', priority: 10, enabled: true,
                    handler(req, _ctx, next) {
                        const resp = next(req);
                        if (resp === null) return null;
                        return { ...resp, close: true };
                    },
                }],
            });

            const response = pipeline.handle(createMockRequest(), createMockContext());
            expect(response!.close).toBe(true);
        });

        it('skips disabled middleware', () => {
            const handler = createMockHandler();
            const called: string[] = [];
            const pipeline = createRequestPipeline({
                handler,
                middleware: [
                    {
                        id: 'active', description: '', priority: 10, enabled: true,
                        handler(req, _ctx, next) { called.push('active'); return next(req); },
                    },
                    {
                        id: 'inactive', description: '', priority: 20, enabled: false,
                        handler(req, _ctx, next) { called.push('inactive'); return next(req); },
                    },
                ],
            });

            pipeline.handle(createMockRequest(), createMockContext());
            expect(called).toEqual(['active']);
        });
    });

    describe('Middleware Management', () => {
        it('adds middleware dynamically', () => {
            const handler = createMockHandler();
            const pipeline = createRequestPipeline({ handler });

            pipeline.use({
                id: 'added', description: '', priority: 10, enabled: true,
                handler(req, _ctx, next) { return next(req); },
            });

            expect(pipeline.getMiddleware().length).toBe(1);
        });

        it('rejects duplicate middleware IDs', () => {
            const handler = createMockHandler();
            const pipeline = createRequestPipeline({ handler });

            const mw = {
                id: 'dup', description: '', priority: 10, enabled: true,
                handler: ((req: ServiceRequest, _ctx: ServiceContext, next: (r: ServiceRequest) => ServiceResponse | null) => next(req)) as any,
            };

            pipeline.use(mw);
            expect(() => pipeline.use(mw)).toThrow();
        });

        it('removes middleware by ID', () => {
            const handler = createMockHandler();
            const pipeline = createRequestPipeline({
                handler,
                middleware: [{
                    id: 'removable', description: '', priority: 10, enabled: true,
                    handler(req, _ctx, next) { return next(req); },
                }],
            });

            expect(pipeline.remove('removable')).toBe(true);
            expect(pipeline.getMiddleware().length).toBe(0);
        });

        it('returns false when removing nonexistent middleware', () => {
            const pipeline = createRequestPipeline({ handler: createMockHandler() });
            expect(pipeline.remove('nonexistent')).toBe(false);
        });

        it('enables/disables middleware at runtime', () => {
            const handler = createMockHandler();
            const called: boolean[] = [];
            const pipeline = createRequestPipeline({
                handler,
                middleware: [{
                    id: 'togglable', description: '', priority: 10, enabled: true,
                    handler(req, _ctx, next) { called.push(true); return next(req); },
                }],
            });

            pipeline.handle(createMockRequest(), createMockContext());
            expect(called.length).toBe(1);

            pipeline.setEnabled('togglable', false);
            pipeline.handle(createMockRequest(), createMockContext());
            expect(called.length).toBe(1); // not called again
        });
    });

    describe('Statistics', () => {
        it('tracks total requests', () => {
            const pipeline = createRequestPipeline({ handler: createMockHandler() });

            pipeline.handle(createMockRequest(), createMockContext());
            pipeline.handle(createMockRequest(), createMockContext());

            expect(pipeline.getStats().totalRequests).toBe(2);
        });

        it('tracks short-circuited requests', () => {
            const pipeline = createRequestPipeline({
                handler: createMockHandler(),
                middleware: [{
                    id: 'block', description: '', priority: 10, enabled: true,
                    handler() { return { payload: new Uint8Array(), close: true }; },
                }],
            });

            pipeline.handle(createMockRequest(), createMockContext());
            expect(pipeline.getStats().shortCircuited).toBe(1);
            expect(pipeline.getStats().passedThrough).toBe(0);
        });

        it('tracks passed-through and dropped', () => {
            const handler: ServiceHandler = {
                name: 'test', port: 80, protocol: 'tcp',
                handle: () => null,
            };
            const pipeline = createRequestPipeline({ handler });

            pipeline.handle(createMockRequest(), createMockContext());
            expect(pipeline.getStats().passedThrough).toBe(1);
            expect(pipeline.getStats().dropped).toBe(1);
        });

        it('tracks per-middleware hits', () => {
            const pipeline = createRequestPipeline({
                handler: createMockHandler(),
                middleware: [{
                    id: 'counted', description: '', priority: 10, enabled: true,
                    handler(req, _ctx, next) { return next(req); },
                }],
            });

            pipeline.handle(createMockRequest(), createMockContext());
            pipeline.handle(createMockRequest(), createMockContext());

            expect(pipeline.getStats().middlewareHits['counted']).toBe(2);
        });
    });
});

// ── Built-in Middleware ─────────────────────────────────────

describe('Built-in Request Middleware', () => {
    describe('IP Allowlist', () => {
        it('allows IPs in the allowlist', () => {
            const mw = createIPAllowlistMiddleware('ip-filter', ['10.0.0.1', '10.0.0.2']);
            const handler = createMockHandler();
            const pipeline = createRequestPipeline({ handler, middleware: [mw] });

            const response = pipeline.handle(createMockRequest({ sourceIP: '10.0.0.1' }), createMockContext());
            expect(response).not.toBeNull();
            expect(handler.handle).toHaveBeenCalled();
        });

        it('blocks IPs not in the allowlist', () => {
            const mw = createIPAllowlistMiddleware('ip-filter', ['10.0.0.1']);
            const handler = createMockHandler();
            const pipeline = createRequestPipeline({ handler, middleware: [mw] });

            const response = pipeline.handle(createMockRequest({ sourceIP: '192.168.1.1' }), createMockContext());
            const text = new TextDecoder().decode(response!.payload);
            expect(text).toContain('403');
            expect(handler.handle).not.toHaveBeenCalled();
        });
    });

    describe('Rate Limit', () => {
        it('allows requests within limit', () => {
            const mw = createRequestRateLimitMiddleware('rate', 3, 60_000);
            const handler = createMockHandler();
            const pipeline = createRequestPipeline({ handler, middleware: [mw] });
            const ctx = createMockContext();

            pipeline.handle(createMockRequest(), ctx);
            pipeline.handle(createMockRequest(), ctx);
            pipeline.handle(createMockRequest(), ctx);

            expect((handler.handle as ReturnType<typeof vi.fn>).mock.calls.length).toBe(3);
        });

        it('blocks requests over the limit', () => {
            const mw = createRequestRateLimitMiddleware('rate', 2, 60_000);
            const handler = createMockHandler();
            const pipeline = createRequestPipeline({ handler, middleware: [mw] });
            const ctx = createMockContext();

            pipeline.handle(createMockRequest(), ctx);
            pipeline.handle(createMockRequest(), ctx);
            const response = pipeline.handle(createMockRequest(), ctx);

            const text = new TextDecoder().decode(response!.payload);
            expect(text).toContain('429');
        });

        it('rate limits per source IP', () => {
            const mw = createRequestRateLimitMiddleware('rate', 1, 60_000);
            const handler = createMockHandler();
            const pipeline = createRequestPipeline({ handler, middleware: [mw] });
            const ctx = createMockContext();

            pipeline.handle(createMockRequest({ sourceIP: '10.0.0.1' }), ctx);
            pipeline.handle(createMockRequest({ sourceIP: '10.0.0.2' }), ctx);

            // Both should pass — different IPs
            expect((handler.handle as ReturnType<typeof vi.fn>).mock.calls.length).toBe(2);
        });
    });

    describe('Logging', () => {
        it('logs requests and passes through', () => {
            const logFn = vi.fn();
            const mw = createRequestLoggingMiddleware('logger', logFn);
            const handler = createMockHandler();
            const pipeline = createRequestPipeline({ handler, middleware: [mw] });

            pipeline.handle(createMockRequest(), createMockContext());
            expect(logFn).toHaveBeenCalledTimes(1);
            expect(handler.handle).toHaveBeenCalled();
        });
    });

    describe('Request Transform', () => {
        it('transforms requests before handler', () => {
            const mw = createRequestTransformMiddleware('xform', (req) => ({
                ...req,
                payloadText: req.payloadText.toUpperCase(),
            }));
            const handler = createMockHandler();
            const pipeline = createRequestPipeline({ handler, middleware: [mw] });

            pipeline.handle(createMockRequest({ payloadText: 'hello' }), createMockContext());
            const callArg = (handler.handle as ReturnType<typeof vi.fn>).mock.calls[0]![0] as ServiceRequest;
            expect(callArg.payloadText).toBe('HELLO');
        });
    });

    describe('Response Transform', () => {
        it('transforms responses after handler', () => {
            const mw = createResponseTransformMiddleware('resp-xform', (resp) => ({
                ...resp,
                close: true,
            }));
            const handler = createMockHandler({
                payload: new TextEncoder().encode('OK'),
                close: false,
            });
            const pipeline = createRequestPipeline({ handler, middleware: [mw] });

            const response = pipeline.handle(createMockRequest(), createMockContext());
            expect(response!.close).toBe(true);
        });

        it('passes null responses through unchanged', () => {
            const mw = createResponseTransformMiddleware('resp-xform', (resp) => ({
                ...resp, close: true,
            }));
            const handler: ServiceHandler = {
                name: 'test', port: 80, protocol: 'tcp',
                handle: () => null,
            };
            const pipeline = createRequestPipeline({ handler, middleware: [mw] });

            const response = pipeline.handle(createMockRequest(), createMockContext());
            expect(response).toBeNull();
        });
    });

    describe('Detection', () => {
        it('emits event on detection (pass-through mode)', () => {
            const mw = createDetectionMiddleware(
                'sqli-detect',
                (input) => input.includes('UNION SELECT'),
                false, // don't block
            );
            const handler = createMockHandler();
            const pipeline = createRequestPipeline({ handler, middleware: [mw] });
            const ctx = createMockContext();

            pipeline.handle(createMockRequest({ payloadText: "' UNION SELECT * FROM users" }), ctx);

            expect(ctx.emit).toHaveBeenCalledTimes(1);
            expect(handler.handle).toHaveBeenCalled(); // still passes through
        });

        it('blocks on detection when configured', () => {
            const mw = createDetectionMiddleware(
                'sqli-block',
                (input) => input.includes('UNION SELECT'),
                true, // block
            );
            const handler = createMockHandler();
            const pipeline = createRequestPipeline({ handler, middleware: [mw] });
            const ctx = createMockContext();

            const response = pipeline.handle(
                createMockRequest({ payloadText: "' UNION SELECT * FROM users" }),
                ctx,
            );

            const text = new TextDecoder().decode(response!.payload);
            expect(text).toContain('400');
            expect(handler.handle).not.toHaveBeenCalled();
        });

        it('passes through benign requests', () => {
            const mw = createDetectionMiddleware('sqli-detect', () => false, true);
            const handler = createMockHandler();
            const pipeline = createRequestPipeline({ handler, middleware: [mw] });

            pipeline.handle(createMockRequest(), createMockContext());
            expect(handler.handle).toHaveBeenCalled();
        });
    });
});
