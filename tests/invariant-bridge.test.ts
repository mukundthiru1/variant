import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
    createInvariantBridge,
    createMockInvariantAdapter,
} from '../src/core/invariant-bridge';
import type {
    InvariantAdapter,
    InvariantPayload,
    PayloadCategory,
    BridgeConfig,
} from '../src/core/invariant-bridge';

// ── Test Fixtures ────────────────────────────────────────────

function createTestPayload(category: PayloadCategory, count: number = 3): InvariantPayload {
    const difficulties = ['easy', 'medium', 'hard'] as const;
    const entries = Array.from({ length: count }, (_, i) => ({
        id: `${category}-${i}`,
        value: `payload-${i}`,
        malicious: i % 2 === 0,
        difficulty: difficulties[i % 3]!,
        tags: ['test'],
    }));

    return {
        category,
        updatedAt: Date.now(),
        count,
        entries,
        source: { id: 'test-source', live: false, maxAgeMs: 60_000 },
    };
}

// ── Mock Adapter Tests ──────────────────────────────────────

describe('Mock Invariant Adapter', () => {
    it('returns payload for registered categories', async () => {
        const adapter = createMockInvariantAdapter({
            'sqli-payloads': createTestPayload('sqli-payloads', 5),
        });

        const result = await adapter.fetchPayloads('sqli-payloads');
        expect(result).not.toBeNull();
        expect(result!.category).toBe('sqli-payloads');
        expect(result!.count).toBe(5);
        expect(result!.entries.length).toBe(5);
    });

    it('returns null for unregistered categories', async () => {
        const adapter = createMockInvariantAdapter({});
        const result = await adapter.fetchPayloads('xss-payloads');
        expect(result).toBeNull();
    });

    it('respects limit option', async () => {
        const adapter = createMockInvariantAdapter({
            'sqli-payloads': createTestPayload('sqli-payloads', 10),
        });

        const result = await adapter.fetchPayloads('sqli-payloads', { limit: 3 });
        expect(result).not.toBeNull();
        expect(result!.entries.length).toBe(3);
        expect(result!.count).toBe(3);
    });

    it('reports healthy', async () => {
        const adapter = createMockInvariantAdapter({});
        expect(await adapter.isHealthy()).toBe(true);
    });

    it('reports capabilities from registered data', () => {
        const adapter = createMockInvariantAdapter({
            'sqli-payloads': createTestPayload('sqli-payloads'),
            'xss-payloads': createTestPayload('xss-payloads'),
        });

        const caps = adapter.getCapabilities();
        expect(caps.categories).toContain('sqli-payloads');
        expect(caps.categories).toContain('xss-payloads');
        expect(caps.liveData).toBe(false);
        expect(caps.ruleValidation).toBe(true);
    });

    it('validates detection rules against corpus', async () => {
        const payload = createTestPayload('sqli-payloads', 6);
        const adapter = createMockInvariantAdapter({
            'sqli-payloads': payload,
        });

        // Rule that catches everything
        const result = await adapter.validateRule('sqli-payloads', () => true);
        expect(result.testCaseCount).toBe(6);
        expect(result.truePositiveRate).toBeGreaterThan(0);
    });

    it('returns zero scores for empty category', async () => {
        const adapter = createMockInvariantAdapter({});
        const result = await adapter.validateRule('sqli-payloads', () => true);
        expect(result.testCaseCount).toBe(0);
        expect(result.f1Score).toBe(0);
    });
});

// ── Bridge Trust Boundary Tests ─────────────────────────────

describe('Invariant Bridge', () => {
    let adapter: InvariantAdapter;
    let config: BridgeConfig;

    beforeEach(() => {
        adapter = createMockInvariantAdapter({
            'sqli-payloads': createTestPayload('sqli-payloads', 5),
            'xss-payloads': createTestPayload('xss-payloads', 3),
            'detection-corpus': createTestPayload('detection-corpus', 10),
        });
        config = { adapter };
    });

    describe('Trust Level Enforcement', () => {
        it('allows curated levels to access all categories', async () => {
            const bridge = createInvariantBridge(config);
            const result = await bridge.requestPayloads('curated', 'sqli-payloads');
            expect(result).not.toBeNull();
            expect(result!.category).toBe('sqli-payloads');
        });

        it('blocks community levels by default', async () => {
            const bridge = createInvariantBridge(config);
            const result = await bridge.requestPayloads('community', 'sqli-payloads');
            expect(result).toBeNull();
        });

        it('blocks community from rule validation', async () => {
            const bridge = createInvariantBridge(config);
            const result = await bridge.validateRule('community', 'sqli-payloads', () => true);
            expect(result).toBeNull();
        });

        it('allows curated levels to validate rules', async () => {
            const bridge = createInvariantBridge(config);
            const result = await bridge.validateRule('curated', 'sqli-payloads', () => true);
            expect(result).not.toBeNull();
            expect(result!.testCaseCount).toBeGreaterThan(0);
        });

        it('allows community access to explicitly allowed categories', async () => {
            const bridge = createInvariantBridge({
                adapter,
                communityAllowedCategories: ['detection-corpus'],
            });

            const allowed = await bridge.requestPayloads('community', 'detection-corpus');
            expect(allowed).not.toBeNull();

            const blocked = await bridge.requestPayloads('community', 'sqli-payloads');
            expect(blocked).toBeNull();
        });
    });

    describe('Available Categories', () => {
        it('returns all categories for curated', () => {
            const bridge = createInvariantBridge(config);
            const cats = bridge.getAvailableCategories('curated');
            expect(cats.length).toBe(3);
        });

        it('returns empty for community by default', () => {
            const bridge = createInvariantBridge(config);
            const cats = bridge.getAvailableCategories('community');
            expect(cats.length).toBe(0);
        });

        it('returns only allowed categories for community', () => {
            const bridge = createInvariantBridge({
                adapter,
                communityAllowedCategories: ['detection-corpus'],
            });
            const cats = bridge.getAvailableCategories('community');
            expect(cats.length).toBe(1);
            expect(cats[0]).toBe('detection-corpus');
        });
    });

    describe('Caching', () => {
        it('caches payloads on first fetch', async () => {
            const fetchSpy = vi.spyOn(adapter, 'fetchPayloads');
            const bridge = createInvariantBridge(config);

            await bridge.requestPayloads('curated', 'sqli-payloads');
            await bridge.requestPayloads('curated', 'sqli-payloads');

            expect(fetchSpy).toHaveBeenCalledTimes(1);
        });

        it('bypasses cache when useCache=false', async () => {
            const fetchSpy = vi.spyOn(adapter, 'fetchPayloads');
            const bridge = createInvariantBridge(config);

            await bridge.requestPayloads('curated', 'sqli-payloads');
            await bridge.requestPayloads('curated', 'sqli-payloads', { useCache: false });

            expect(fetchSpy).toHaveBeenCalledTimes(2);
        });

        it('uses different cache keys for different difficulties', async () => {
            const fetchSpy = vi.spyOn(adapter, 'fetchPayloads');
            const bridge = createInvariantBridge(config);

            await bridge.requestPayloads('curated', 'sqli-payloads', { difficulty: 'easy' });
            await bridge.requestPayloads('curated', 'sqli-payloads', { difficulty: 'hard' });

            expect(fetchSpy).toHaveBeenCalledTimes(2);
        });
    });

    describe('Rate Limiting', () => {
        it('enforces rate limit', async () => {
            const bridge = createInvariantBridge({
                adapter,
                rateLimitPerMinute: 3,
            });

            const r1 = await bridge.requestPayloads('curated', 'sqli-payloads', { useCache: false });
            const r2 = await bridge.requestPayloads('curated', 'xss-payloads');
            const r3 = await bridge.requestPayloads('curated', 'detection-corpus');
            const r4 = await bridge.requestPayloads('curated', 'sqli-payloads', {
                useCache: false, difficulty: 'hard',
            });

            expect(r1).not.toBeNull();
            expect(r2).not.toBeNull();
            expect(r3).not.toBeNull();
            // 4th request should be rate limited
            expect(r4).toBeNull();
        });

        it('rate limits validateRule too', async () => {
            const bridge = createInvariantBridge({
                adapter,
                rateLimitPerMinute: 1,
            });

            await bridge.requestPayloads('curated', 'sqli-payloads', { useCache: false });
            const result = await bridge.validateRule('curated', 'sqli-payloads', () => true);
            expect(result).toBeNull();
        });
    });

    describe('Health Check', () => {
        it('delegates health check to adapter', async () => {
            const bridge = createInvariantBridge(config);
            expect(await bridge.isAvailable()).toBe(true);
        });

        it('reports unhealthy when adapter is unhealthy', async () => {
            const unhealthyAdapter: InvariantAdapter = {
                ...adapter,
                async isHealthy() { return false; },
            };
            const bridge = createInvariantBridge({ adapter: unhealthyAdapter });
            expect(await bridge.isAvailable()).toBe(false);
        });
    });

    describe('Null Returns', () => {
        it('returns null for unavailable category', async () => {
            const bridge = createInvariantBridge(config);
            const result = await bridge.requestPayloads('curated', 'nonexistent-category');
            expect(result).toBeNull();
        });
    });
});
