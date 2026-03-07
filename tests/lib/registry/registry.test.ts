/**
 * VARIANT — Capability Registry tests
 */
import { describe, it, expect } from 'vitest';
import { createCapabilityRegistry } from '../../../src/lib/registry/registry-engine';
import type { CapabilityProvider, CapabilityDependency } from '../../../src/lib/registry/types';

function makeProvider(
    id: string,
    capability: string,
    version: string = '1.0.0',
    priority: number = 0,
    tags: string[] = [],
    metadata: Record<string, unknown> = {},
): CapabilityProvider {
    return {
        id,
        capability,
        version,
        description: `Provider ${id}`,
        tags,
        priority,
        metadata,
    };
}

describe('CapabilityRegistry', () => {
    // ── Registration ───────────────────────────────────────────

    it('registers and retrieves providers', () => {
        const reg = createCapabilityRegistry();
        reg.register(makeProvider('a/fs-monitor', 'filesystem-monitor'));

        expect(reg.getProvider('a/fs-monitor')).not.toBeNull();
        expect(reg.getProvider('nonexistent')).toBeNull();
    });

    it('throws on duplicate provider ID', () => {
        const reg = createCapabilityRegistry();
        reg.register(makeProvider('a/x', 'cap-a'));
        expect(() => reg.register(makeProvider('a/x', 'cap-b'))).toThrow();
    });

    it('lists all providers', () => {
        const reg = createCapabilityRegistry();
        reg.register(makeProvider('a/1', 'cap-a'));
        reg.register(makeProvider('b/1', 'cap-b'));
        reg.register(makeProvider('c/1', 'cap-a'));
        expect(reg.listAll().length).toBe(3);
    });

    // ── Capability Queries ─────────────────────────────────────

    it('hasCapability returns true when provider exists', () => {
        const reg = createCapabilityRegistry();
        reg.register(makeProvider('a/1', 'detection'));
        expect(reg.hasCapability('detection')).toBe(true);
        expect(reg.hasCapability('nonexistent')).toBe(false);
    });

    it('listCapabilities returns all capability names', () => {
        const reg = createCapabilityRegistry();
        reg.register(makeProvider('a/1', 'detection'));
        reg.register(makeProvider('b/1', 'scoring'));
        reg.register(makeProvider('c/1', 'detection'));

        const caps = reg.listCapabilities();
        expect(caps).toContain('detection');
        expect(caps).toContain('scoring');
        expect(caps.length).toBe(2);
    });

    it('listProviders returns all providers for a capability sorted by priority', () => {
        const reg = createCapabilityRegistry();
        reg.register(makeProvider('a/low', 'detect', '1.0.0', 1));
        reg.register(makeProvider('a/high', 'detect', '1.0.0', 10));
        reg.register(makeProvider('a/mid', 'detect', '1.0.0', 5));

        const providers = reg.listProviders('detect');
        expect(providers.length).toBe(3);
        expect(providers[0]!.id).toBe('a/high');
        expect(providers[1]!.id).toBe('a/mid');
        expect(providers[2]!.id).toBe('a/low');
    });

    it('listProviders returns empty for unknown capability', () => {
        const reg = createCapabilityRegistry();
        expect(reg.listProviders('nonexistent').length).toBe(0);
    });

    // ── Querying ───────────────────────────────────────────────

    it('query by capability name', () => {
        const reg = createCapabilityRegistry();
        reg.register(makeProvider('a/1', 'detection'));
        reg.register(makeProvider('b/1', 'scoring'));

        const result = reg.query({ capability: 'detection' });
        expect(result.found).toBe(true);
        expect(result.providers.length).toBe(1);
    });

    it('query with minVersion filters older versions', () => {
        const reg = createCapabilityRegistry();
        reg.register(makeProvider('a/old', 'detect', '1.0.0'));
        reg.register(makeProvider('a/new', 'detect', '2.0.0'));

        const result = reg.query({ capability: 'detect', minVersion: '1.5.0' });
        expect(result.found).toBe(true);
        expect(result.providers.length).toBe(1);
        expect(result.providers[0]!.id).toBe('a/new');
    });

    it('query with minVersion exact match', () => {
        const reg = createCapabilityRegistry();
        reg.register(makeProvider('a/exact', 'detect', '2.0.0'));

        const result = reg.query({ capability: 'detect', minVersion: '2.0.0' });
        expect(result.found).toBe(true);
    });

    it('query with requiredTags', () => {
        const reg = createCapabilityRegistry();
        reg.register(makeProvider('a/1', 'detect', '1.0.0', 0, ['network', 'ids']));
        reg.register(makeProvider('a/2', 'detect', '1.0.0', 0, ['host', 'ids']));
        reg.register(makeProvider('a/3', 'detect', '1.0.0', 0, ['network']));

        const result = reg.query({ capability: 'detect', requiredTags: ['network', 'ids'] });
        expect(result.found).toBe(true);
        expect(result.providers.length).toBe(1);
        expect(result.providers[0]!.id).toBe('a/1');
    });

    it('query preferHighestPriority returns single result', () => {
        const reg = createCapabilityRegistry();
        reg.register(makeProvider('a/low', 'detect', '1.0.0', 1));
        reg.register(makeProvider('a/high', 'detect', '1.0.0', 10));

        const result = reg.query({ capability: 'detect', preferHighestPriority: true });
        expect(result.found).toBe(true);
        expect(result.providers.length).toBe(1);
        expect(result.providers[0]!.id).toBe('a/high');
    });

    it('query returns not found for no matches', () => {
        const reg = createCapabilityRegistry();
        const result = reg.query({ capability: 'nonexistent' });
        expect(result.found).toBe(false);
        expect(result.providers.length).toBe(0);
    });

    // ── Dependency Resolution ──────────────────────────────────

    it('resolves all required dependencies', () => {
        const reg = createCapabilityRegistry();
        reg.register(makeProvider('a/detect', 'detection', '2.0.0'));
        reg.register(makeProvider('a/score', 'scoring', '1.0.0'));

        const deps: CapabilityDependency[] = [
            { capability: 'detection', required: true },
            { capability: 'scoring', required: true },
        ];

        const result = reg.resolveDependencies(deps);
        expect(result.satisfied).toBe(true);
        expect(result.missing.length).toBe(0);
        expect(result.resolved.size).toBe(2);
    });

    it('reports missing required dependencies', () => {
        const reg = createCapabilityRegistry();
        reg.register(makeProvider('a/detect', 'detection'));

        const deps: CapabilityDependency[] = [
            { capability: 'detection', required: true },
            { capability: 'scoring', required: true },
        ];

        const result = reg.resolveDependencies(deps);
        expect(result.satisfied).toBe(false);
        expect(result.missing).toContain('scoring');
    });

    it('optional dependencies do not block satisfaction', () => {
        const reg = createCapabilityRegistry();
        reg.register(makeProvider('a/detect', 'detection'));

        const deps: CapabilityDependency[] = [
            { capability: 'detection', required: true },
            { capability: 'scoring', required: false },
        ];

        const result = reg.resolveDependencies(deps);
        expect(result.satisfied).toBe(true);
        expect(result.resolved.size).toBe(1);
    });

    it('dependency resolution respects minVersion', () => {
        const reg = createCapabilityRegistry();
        reg.register(makeProvider('a/old', 'detection', '1.0.0'));

        const deps: CapabilityDependency[] = [
            { capability: 'detection', required: true, minVersion: '2.0.0' },
        ];

        const result = reg.resolveDependencies(deps);
        expect(result.satisfied).toBe(false);
        expect(result.missing).toContain('detection');
    });

    it('dependency resolution picks highest-priority provider', () => {
        const reg = createCapabilityRegistry();
        reg.register(makeProvider('a/low', 'detection', '1.0.0', 1));
        reg.register(makeProvider('a/high', 'detection', '1.0.0', 10));

        const deps: CapabilityDependency[] = [
            { capability: 'detection', required: true },
        ];

        const result = reg.resolveDependencies(deps);
        expect(result.resolved.get('detection')!.id).toBe('a/high');
    });

    // ── Semver Comparison ──────────────────────────────────────

    it('semver comparison handles patch versions', () => {
        const reg = createCapabilityRegistry();
        reg.register(makeProvider('a/1', 'cap', '1.2.3'));

        expect(reg.query({ capability: 'cap', minVersion: '1.2.2' }).found).toBe(true);
        expect(reg.query({ capability: 'cap', minVersion: '1.2.3' }).found).toBe(true);
        expect(reg.query({ capability: 'cap', minVersion: '1.2.4' }).found).toBe(false);
    });

    it('semver comparison handles major/minor differences', () => {
        const reg = createCapabilityRegistry();
        reg.register(makeProvider('a/1', 'cap', '2.1.0'));

        expect(reg.query({ capability: 'cap', minVersion: '1.9.9' }).found).toBe(true);
        expect(reg.query({ capability: 'cap', minVersion: '2.0.0' }).found).toBe(true);
        expect(reg.query({ capability: 'cap', minVersion: '2.1.0' }).found).toBe(true);
        expect(reg.query({ capability: 'cap', minVersion: '2.2.0' }).found).toBe(false);
        expect(reg.query({ capability: 'cap', minVersion: '3.0.0' }).found).toBe(false);
    });

    // ── Metadata ───────────────────────────────────────────────

    it('preserves provider metadata', () => {
        const reg = createCapabilityRegistry();
        reg.register(makeProvider('a/1', 'cap', '1.0.0', 0, [], { engine: 'snort', version: 3 }));

        const provider = reg.getProvider('a/1')!;
        expect(provider.metadata['engine']).toBe('snort');
        expect(provider.metadata['version']).toBe(3);
    });

    // ── Clear ──────────────────────────────────────────────────

    it('clear removes everything', () => {
        const reg = createCapabilityRegistry();
        reg.register(makeProvider('a/1', 'cap-a'));
        reg.register(makeProvider('b/1', 'cap-b'));

        reg.clear();

        expect(reg.listAll().length).toBe(0);
        expect(reg.listCapabilities().length).toBe(0);
        expect(reg.hasCapability('cap-a')).toBe(false);
    });
});
