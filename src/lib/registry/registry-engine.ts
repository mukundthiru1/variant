/**
 * VARIANT — Capability Registry Implementation
 *
 * General-purpose service discovery for cross-module capability resolution.
 *
 * SWAPPABILITY: Implements CapabilityRegistry. Replace this file.
 */

import type {
    CapabilityRegistry,
    CapabilityProvider,
    CapabilityQuery,
    CapabilityQueryResult,
    CapabilityDependency,
    DependencyResolutionResult,
} from './types';

/**
 * Compare two semver strings. Returns:
 *   -1 if a < b
 *    0 if a === b
 *    1 if a > b
 */
function compareSemver(a: string, b: string): -1 | 0 | 1 {
    const partsA = a.split('.').map(Number);
    const partsB = b.split('.').map(Number);
    const len = Math.max(partsA.length, partsB.length);

    for (let i = 0; i < len; i++) {
        const va = partsA[i] ?? 0;
        const vb = partsB[i] ?? 0;
        if (va < vb) return -1;
        if (va > vb) return 1;
    }
    return 0;
}

export function createCapabilityRegistry(): CapabilityRegistry {
    const providers = new Map<string, CapabilityProvider>();
    // Capability name → provider IDs for fast lookup
    const capabilityIndex = new Map<string, Set<string>>();

    function indexProvider(provider: CapabilityProvider): void {
        let set = capabilityIndex.get(provider.capability);
        if (set === undefined) {
            set = new Set();
            capabilityIndex.set(provider.capability, set);
        }
        set.add(provider.id);
    }

    function getProvidersForCapability(capability: string): CapabilityProvider[] {
        const ids = capabilityIndex.get(capability);
        if (ids === undefined) return [];
        const result: CapabilityProvider[] = [];
        for (const id of ids) {
            const p = providers.get(id);
            if (p !== undefined) result.push(p);
        }
        // Sort by priority descending
        result.sort((a, b) => b.priority - a.priority);
        return result;
    }

    function matchesQuery(provider: CapabilityProvider, q: CapabilityQuery): boolean {
        if (provider.capability !== q.capability) return false;

        if (q.minVersion !== undefined) {
            if (compareSemver(provider.version, q.minVersion) < 0) return false;
        }

        if (q.requiredTags !== undefined && q.requiredTags.length > 0) {
            for (const tag of q.requiredTags) {
                if (!provider.tags.includes(tag)) return false;
            }
        }

        return true;
    }

    return {
        register(provider: CapabilityProvider): void {
            if (providers.has(provider.id)) {
                throw new Error(`Provider '${provider.id}' already registered`);
            }
            providers.set(provider.id, provider);
            indexProvider(provider);
        },

        getProvider(id: string): CapabilityProvider | null {
            return providers.get(id) ?? null;
        },

        query(q: CapabilityQuery): CapabilityQueryResult {
            const candidates = getProvidersForCapability(q.capability);
            const matching = candidates.filter(p => matchesQuery(p, q));

            if (q.preferHighestPriority && matching.length > 0) {
                return { found: true, providers: [matching[0]!] };
            }

            return { found: matching.length > 0, providers: matching };
        },

        hasCapability(capability: string): boolean {
            const ids = capabilityIndex.get(capability);
            return ids !== undefined && ids.size > 0;
        },

        listCapabilities(): readonly string[] {
            return [...capabilityIndex.keys()];
        },

        listProviders(capability: string): readonly CapabilityProvider[] {
            return getProvidersForCapability(capability);
        },

        listAll(): readonly CapabilityProvider[] {
            return [...providers.values()];
        },

        resolveDependencies(deps: readonly CapabilityDependency[]): DependencyResolutionResult {
            const missing: string[] = [];
            const resolved = new Map<string, CapabilityProvider>();

            for (const dep of deps) {
                const candidates = getProvidersForCapability(dep.capability);
                let found: CapabilityProvider | undefined;

                for (const candidate of candidates) {
                    if (dep.minVersion !== undefined) {
                        if (compareSemver(candidate.version, dep.minVersion) < 0) continue;
                    }
                    found = candidate;
                    break; // Take highest-priority match (already sorted)
                }

                if (found !== undefined) {
                    resolved.set(dep.capability, found);
                } else if (dep.required) {
                    missing.push(dep.capability);
                }
            }

            return {
                satisfied: missing.length === 0,
                missing,
                resolved,
            };
        },

        clear(): void {
            providers.clear();
            capabilityIndex.clear();
        },
    };
}
