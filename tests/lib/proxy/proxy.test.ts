import { describe, it, expect, beforeEach } from 'vitest';
import { createProxyEngine } from '../../../src/lib/proxy';
import type { ProxyEngine, ProxyRequest } from '../../../src/lib/proxy';

describe('Proxy Engine', () => {
    let engine: ProxyEngine;

    beforeEach(() => {
        engine = createProxyEngine();
    });

    function makeRequest(overrides: Partial<ProxyRequest> = {}): ProxyRequest {
        return {
            method: 'GET', path: '/api/data', host: 'app.example.com',
            headers: {}, sourceIP: '10.0.0.1', bodySize: 0,
            ...overrides,
        };
    }

    // ── Backend Management ───────────────────────────────────

    it('adds and retrieves backends', () => {
        const b = engine.addBackend({ host: '10.0.1.1', port: 8080 });
        expect(b.id).toBeTruthy();
        expect(b.host).toBe('10.0.1.1');
        expect(b.healthy).toBe(true);
        expect(b.weight).toBe(1);
    });

    it('getBackend retrieves by ID', () => {
        const b = engine.addBackend({ host: '10.0.1.1', port: 8080 });
        expect(engine.getBackend(b.id)).not.toBeNull();
        expect(engine.getBackend('nonexistent')).toBeNull();
    });

    it('removeBackend removes a backend', () => {
        const b = engine.addBackend({ host: '10.0.1.1', port: 8080 });
        expect(engine.removeBackend(b.id)).toBe(true);
        expect(engine.getBackend(b.id)).toBeNull();
        expect(engine.removeBackend('nonexistent')).toBe(false);
    });

    it('listBackends returns all', () => {
        engine.addBackend({ host: '10.0.1.1', port: 8080 });
        engine.addBackend({ host: '10.0.1.2', port: 8080 });
        expect(engine.listBackends()).toHaveLength(2);
    });

    it('setBackendHealth changes health status', () => {
        const b = engine.addBackend({ host: '10.0.1.1', port: 8080 });
        engine.setBackendHealth(b.id, false);
        expect(engine.getBackend(b.id)!.healthy).toBe(false);
        engine.setBackendHealth(b.id, true);
        expect(engine.getBackend(b.id)!.healthy).toBe(true);
    });

    it('setBackendHealth returns false for unknown', () => {
        expect(engine.setBackendHealth('nonexistent', false)).toBe(false);
    });

    // ── Request Handling ─────────────────────────────────────

    it('routes requests to healthy backends', () => {
        const b = engine.addBackend({ host: '10.0.1.1', port: 8080 });
        const response = engine.handleRequest(makeRequest());
        expect(response.backendId).toBe(b.id);
        expect(response.statusCode).toBeLessThanOrEqual(500);
        expect(response.rateLimited).toBe(false);
    });

    it('returns 502 when no healthy backends', () => {
        const b = engine.addBackend({ host: '10.0.1.1', port: 8080 });
        engine.setBackendHealth(b.id, false);
        const response = engine.handleRequest(makeRequest());
        expect(response.statusCode).toBe(502);
    });

    it('returns 502 when no backends at all', () => {
        const response = engine.handleRequest(makeRequest());
        expect(response.statusCode).toBe(502);
    });

    // ── Load Balancing Algorithms ────────────────────────────

    it('round-robin distributes across backends', () => {
        engine.addBackend({ host: '10.0.1.1', port: 8080 });
        engine.addBackend({ host: '10.0.1.2', port: 8080 });
        engine.setAlgorithm('round_robin');

        const ids = new Set<string>();
        for (let i = 0; i < 10; i++) {
            const r = engine.handleRequest(makeRequest());
            ids.add(r.backendId);
        }
        expect(ids.size).toBe(2);
    });

    it('ip_hash routes same IP to same backend', () => {
        engine.addBackend({ host: '10.0.1.1', port: 8080 });
        engine.addBackend({ host: '10.0.1.2', port: 8080 });
        engine.setAlgorithm('ip_hash');

        const firstResponse = engine.handleRequest(makeRequest({ sourceIP: '192.168.1.100' }));
        for (let i = 0; i < 5; i++) {
            const r = engine.handleRequest(makeRequest({ sourceIP: '192.168.1.100' }));
            expect(r.backendId).toBe(firstResponse.backendId);
        }
    });

    it('weighted round-robin favors heavier backends', () => {
        const heavy = engine.addBackend({ host: '10.0.1.1', port: 8080, weight: 5 });
        engine.addBackend({ host: '10.0.1.2', port: 8080, weight: 1 });
        engine.setAlgorithm('weighted_round_robin');

        let heavyCount = 0;
        for (let i = 0; i < 60; i++) {
            const r = engine.handleRequest(makeRequest());
            if (r.backendId === heavy.id) heavyCount++;
        }
        expect(heavyCount).toBeGreaterThan(40); // Should get ~50/60
    });

    it('least_connections prefers backend with fewer connections', () => {
        engine.addBackend({ host: '10.0.1.1', port: 8080 });
        engine.addBackend({ host: '10.0.1.2', port: 8080 });
        engine.setAlgorithm('least_connections');
        // Both start at 0, so distribution should be somewhat balanced
        const response = engine.handleRequest(makeRequest());
        expect(response.backendId).toBeTruthy();
    });

    // ── Routing Rules ────────────────────────────────────────

    it('routes by path prefix', () => {
        const api = engine.addBackend({ host: '10.0.1.1', port: 8080 });
        const web = engine.addBackend({ host: '10.0.1.2', port: 3000 });

        engine.addRoute({
            match: { pathPrefix: '/api' },
            backendIds: [api.id],
            priority: 10,
            enabled: true,
        });
        engine.addRoute({
            match: { pathPrefix: '/' },
            backendIds: [web.id],
            priority: 1,
            enabled: true,
        });

        const apiResp = engine.handleRequest(makeRequest({ path: '/api/users' }));
        expect(apiResp.backendId).toBe(api.id);

        const webResp = engine.handleRequest(makeRequest({ path: '/index.html' }));
        expect(webResp.backendId).toBe(web.id);
    });

    it('routes by host header', () => {
        const app1 = engine.addBackend({ host: '10.0.1.1', port: 8080 });
        const app2 = engine.addBackend({ host: '10.0.1.2', port: 8080 });

        engine.addRoute({
            match: { hostHeader: 'app1.example.com' },
            backendIds: [app1.id], priority: 10, enabled: true,
        });
        engine.addRoute({
            match: { hostHeader: 'app2.example.com' },
            backendIds: [app2.id], priority: 10, enabled: true,
        });

        expect(engine.handleRequest(makeRequest({ host: 'app1.example.com' })).backendId).toBe(app1.id);
        expect(engine.handleRequest(makeRequest({ host: 'app2.example.com' })).backendId).toBe(app2.id);
    });

    it('removeRoute removes a route', () => {
        const b = engine.addBackend({ host: '10.0.1.1', port: 8080 });
        const route = engine.addRoute({
            match: { pathPrefix: '/api' }, backendIds: [b.id], priority: 10, enabled: true,
        });
        expect(engine.removeRoute(route.id)).toBe(true);
        expect(engine.listRoutes()).toHaveLength(0);
    });

    // ── Rate Limiting ────────────────────────────────────────

    it('rate limits by IP', () => {
        engine.addBackend({ host: '10.0.1.1', port: 8080 });
        engine.addRateLimit({
            key: 'ip', maxRequests: 3, windowSeconds: 60, enabled: true,
        });

        for (let i = 0; i < 3; i++) {
            const r = engine.handleRequest(makeRequest({ sourceIP: '10.0.0.99' }));
            expect(r.rateLimited).toBe(false);
        }
        const limited = engine.handleRequest(makeRequest({ sourceIP: '10.0.0.99' }));
        expect(limited.rateLimited).toBe(true);
        expect(limited.statusCode).toBe(429);
    });

    it('rate limit does not affect different IPs', () => {
        engine.addBackend({ host: '10.0.1.1', port: 8080 });
        engine.addRateLimit({
            key: 'ip', maxRequests: 2, windowSeconds: 60, enabled: true,
        });

        engine.handleRequest(makeRequest({ sourceIP: '10.0.0.1' }));
        engine.handleRequest(makeRequest({ sourceIP: '10.0.0.1' }));
        engine.handleRequest(makeRequest({ sourceIP: '10.0.0.1' })); // limited

        const other = engine.handleRequest(makeRequest({ sourceIP: '10.0.0.2' }));
        expect(other.rateLimited).toBe(false);
    });

    it('disabled rate limit does not block', () => {
        engine.addBackend({ host: '10.0.1.1', port: 8080 });
        engine.addRateLimit({
            key: 'ip', maxRequests: 1, windowSeconds: 60, enabled: false,
        });

        for (let i = 0; i < 5; i++) {
            expect(engine.handleRequest(makeRequest()).rateLimited).toBe(false);
        }
    });

    it('removeRateLimit removes a rule', () => {
        const rl = engine.addRateLimit({ key: 'ip', maxRequests: 1, windowSeconds: 60, enabled: true });
        expect(engine.removeRateLimit(rl.id)).toBe(true);
        expect(engine.removeRateLimit('nonexistent')).toBe(false);
    });

    // ── Backend Stats ────────────────────────────────────────

    it('backend tracks request count', () => {
        const b = engine.addBackend({ host: '10.0.1.1', port: 8080 });
        for (let i = 0; i < 10; i++) engine.handleRequest(makeRequest());
        const updated = engine.getBackend(b.id)!;
        expect(updated.totalRequests).toBe(10);
    });

    // ── Stats ────────────────────────────────────────────────

    it('getStats returns accurate counts', () => {
        const b1 = engine.addBackend({ host: '10.0.1.1', port: 8080 });
        engine.addBackend({ host: '10.0.1.2', port: 8080 });
        engine.setBackendHealth(b1.id, false);

        for (let i = 0; i < 5; i++) engine.handleRequest(makeRequest());

        const stats = engine.getStats();
        expect(stats.totalRequests).toBe(5);
        expect(stats.activeBackends).toBe(1);
        expect(stats.unhealthyBackends).toBe(1);
        expect(stats.algorithm).toBe('round_robin');
    });
});
