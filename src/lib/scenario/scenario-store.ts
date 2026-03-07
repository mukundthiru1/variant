/**
 * VARIANT — Scenario Store Implementation
 *
 * In-memory scenario store with save/load/fork/diff operations.
 * The storage backend is swappable (IndexedDB, remote API, etc.).
 *
 * SWAPPABILITY: Implements ScenarioStore. Replace this file.
 */

import type { WorldSpec } from '../../core/world/types';
import type {
    ScenarioStore,
    ScenarioMeta,
    ScenarioDiff,
    DiffChange,
    ForkConfig,
} from './types';

/** DJB2 hash for content-addressable identification. */
function contentHash(input: string): string {
    let hash = 5381;
    for (let i = 0; i < input.length; i++) {
        hash = ((hash << 5) + hash + input.charCodeAt(i)) | 0;
    }
    const unsigned = hash >>> 0;
    return unsigned.toString(16).padStart(8, '0') +
           ((unsigned * 2654435761) >>> 0).toString(16).padStart(8, '0');
}

function deepClone<T>(obj: T): T {
    return JSON.parse(JSON.stringify(obj));
}

/**
 * Compute structural diff between two objects.
 * Returns a flat list of changes with dot-notation paths.
 */
function computeDiff(base: unknown, target: unknown, path: string): DiffChange[] {
    const changes: DiffChange[] = [];

    if (base === target) return changes;

    // Both are null/undefined
    if (base == null && target == null) return changes;

    // One is null/undefined
    if (base == null) {
        changes.push({ path, kind: 'added', before: undefined, after: target });
        return changes;
    }
    if (target == null) {
        changes.push({ path, kind: 'removed', before: base, after: undefined });
        return changes;
    }

    // Different types
    if (typeof base !== typeof target) {
        changes.push({ path, kind: 'modified', before: base, after: target });
        return changes;
    }

    // Primitives
    if (typeof base !== 'object') {
        if (base !== target) {
            changes.push({ path, kind: 'modified', before: base, after: target });
        }
        return changes;
    }

    // Arrays
    if (Array.isArray(base) && Array.isArray(target)) {
        const maxLen = Math.max(base.length, (target as unknown[]).length);
        for (let i = 0; i < maxLen; i++) {
            const itemPath = `${path}[${i}]`;
            if (i >= base.length) {
                changes.push({ path: itemPath, kind: 'added', before: undefined, after: (target as unknown[])[i] });
            } else if (i >= (target as unknown[]).length) {
                changes.push({ path: itemPath, kind: 'removed', before: base[i], after: undefined });
            } else {
                changes.push(...computeDiff(base[i], (target as unknown[])[i], itemPath));
            }
        }
        return changes;
    }

    // Objects
    const baseObj = base as Record<string, unknown>;
    const targetObj = target as Record<string, unknown>;
    const allKeys = new Set([...Object.keys(baseObj), ...Object.keys(targetObj)]);

    for (const key of allKeys) {
        const childPath = path.length > 0 ? `${path}.${key}` : key;
        if (!(key in baseObj)) {
            changes.push({ path: childPath, kind: 'added', before: undefined, after: targetObj[key] });
        } else if (!(key in targetObj)) {
            changes.push({ path: childPath, kind: 'removed', before: baseObj[key], after: undefined });
        } else {
            changes.push(...computeDiff(baseObj[key], targetObj[key], childPath));
        }
    }

    return changes;
}

export function createScenarioStore(): ScenarioStore {
    const specs = new Map<string, WorldSpec>();
    const metas = new Map<string, ScenarioMeta>();

    return {
        serialize(spec: WorldSpec): string {
            return JSON.stringify(spec, null, 2);
        },

        deserialize(json: string): WorldSpec | null {
            try {
                return JSON.parse(json) as WorldSpec;
            } catch {
                return null;
            }
        },

        hash(spec: WorldSpec): string {
            return contentHash(JSON.stringify(spec));
        },

        save(spec: WorldSpec, versionTag: string, tags?: readonly string[]): ScenarioMeta {
            const serialized = JSON.stringify(spec);
            const hash = contentHash(serialized);

            const meta: ScenarioMeta = {
                hash,
                versionTag,
                savedAt: new Date().toISOString(),
                parentHash: null,
                forkDepth: 0,
                tags: tags ?? [],
                sizeBytes: serialized.length,
            };

            specs.set(hash, deepClone(spec));
            metas.set(hash, meta);
            return meta;
        },

        load(hash: string): WorldSpec | null {
            const spec = specs.get(hash);
            if (spec === undefined) return null;
            return deepClone(spec);
        },

        list(): readonly ScenarioMeta[] {
            return [...metas.values()];
        },

        searchByTag(tag: string): readonly ScenarioMeta[] {
            return [...metas.values()].filter(m => m.tags.includes(tag));
        },

        searchByTitle(query: string): readonly ScenarioMeta[] {
            const lower = query.toLowerCase();
            const results: ScenarioMeta[] = [];
            for (const [hash, meta] of metas.entries()) {
                const spec = specs.get(hash);
                if (spec !== undefined && spec.meta.title.toLowerCase().includes(lower)) {
                    results.push(meta);
                }
            }
            return results;
        },

        fork(hash: string, config: ForkConfig): { spec: WorldSpec; meta: ScenarioMeta } | null {
            const original = specs.get(hash);
            const originalMeta = metas.get(hash);
            if (original === undefined || originalMeta === undefined) return null;

            const forked = deepClone(original) as unknown as Record<string, unknown>;

            // Update metadata
            const meta = forked['meta'] as Record<string, unknown>;
            if (config.title !== undefined) {
                meta['title'] = config.title;
            }
            meta['author'] = {
                name: config.author,
                id: config.authorId,
                type: 'community',
            };

            // Add fork tags
            const existingTags = (originalMeta.tags ?? []) as string[];
            const newTags = [...existingTags, ...(config.addTags ?? [])];

            const forkedSpec = forked as unknown as WorldSpec;
            const serialized = JSON.stringify(forkedSpec);
            const forkedHash = contentHash(serialized);

            const forkedMeta: ScenarioMeta = {
                hash: forkedHash,
                versionTag: config.versionTag,
                savedAt: new Date().toISOString(),
                parentHash: hash,
                forkDepth: originalMeta.forkDepth + 1,
                tags: newTags,
                sizeBytes: serialized.length,
            };

            specs.set(forkedHash, deepClone(forkedSpec));
            metas.set(forkedHash, forkedMeta);

            return { spec: forkedSpec, meta: forkedMeta };
        },

        diff(baseHash: string, targetHash: string): ScenarioDiff | null {
            const baseSpec = specs.get(baseHash);
            const targetSpec = specs.get(targetHash);
            if (baseSpec === undefined || targetSpec === undefined) return null;

            const changes = computeDiff(baseSpec, targetSpec, '');

            return {
                baseHash,
                targetHash,
                changes,
                stats: {
                    added: changes.filter(c => c.kind === 'added').length,
                    removed: changes.filter(c => c.kind === 'removed').length,
                    modified: changes.filter(c => c.kind === 'modified').length,
                    total: changes.length,
                },
            };
        },

        remove(hash: string): boolean {
            const existed = specs.has(hash);
            specs.delete(hash);
            metas.delete(hash);
            return existed;
        },

        count(): number {
            return specs.size;
        },

        clear(): void {
            specs.clear();
            metas.clear();
        },
    };
}
