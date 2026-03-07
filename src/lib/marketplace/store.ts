/**
 * VARIANT — Marketplace Store (IndexedDB-backed)
 *
 * Client-side persistent storage for community levels.
 * Uses IndexedDB for durable storage that survives page reloads.
 *
 * SECURITY: Every imported WorldSpec passes through the full
 * validator. Invalid levels are rejected at import time.
 * Trust level is forced to 'community' for all imports.
 *
 * DESIGN: All operations are async. The store handles its own
 * schema migrations. Multiple tabs can use the store concurrently.
 */

import type {
    LevelPackage,
    LevelMetadata,
    LevelAuthor,
    LevelRating,
    LevelStats,
    LevelSearchQuery,
    LevelSearchResult,
    MarketplaceStore,
    ImportResult,
    LevelBuilder,
    LevelDifficulty,
} from './types';
import type { WorldSpec } from '../../core/world/types';

// ── IndexedDB Constants ─────────────────────────────────────────

const DB_NAME = 'variant-marketplace';
const DB_VERSION = 1;
const STORE_LEVELS = 'levels';
const STORE_RATINGS = 'ratings';
const STORE_COMPLETIONS = 'completions';

// ── Database Initialization ─────────────────────────────────────

function openDatabase(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);

        request.onupgradeneeded = () => {
            const db = request.result;

            if (!db.objectStoreNames.contains(STORE_LEVELS)) {
                const levelsStore = db.createObjectStore(STORE_LEVELS, { keyPath: 'id' });
                levelsStore.createIndex('difficulty', 'metadata.difficulty', { unique: false });
                levelsStore.createIndex('createdAt', 'createdAt', { unique: false });
                levelsStore.createIndex('updatedAt', 'updatedAt', { unique: false });
            }

            if (!db.objectStoreNames.contains(STORE_RATINGS)) {
                db.createObjectStore(STORE_RATINGS, { keyPath: 'levelId' });
            }

            if (!db.objectStoreNames.contains(STORE_COMPLETIONS)) {
                const completionsStore = db.createObjectStore(STORE_COMPLETIONS, { autoIncrement: true });
                completionsStore.createIndex('levelId', 'levelId', { unique: false });
            }
        };

        request.onsuccess = () => { resolve(request.result); };
        request.onerror = () => { reject(new Error(`Failed to open database: ${request.error?.message ?? 'unknown'}`)); };
    });
}

function idbRequest<T>(request: IDBRequest<T>): Promise<T> {
    return new Promise((resolve, reject) => {
        request.onsuccess = () => { resolve(request.result); };
        request.onerror = () => { reject(new Error(`IDB request failed: ${request.error?.message ?? 'unknown'}`)); };
    });
}

function idbTransaction(db: IDBDatabase, stores: string | string[], mode: IDBTransactionMode): IDBTransaction {
    return db.transaction(stores, mode);
}

// ── Marketplace Store Implementation ────────────────────────────

export function createMarketplaceStore(): MarketplaceStore {
    let dbPromise: Promise<IDBDatabase> | null = null;

    function getDb(): Promise<IDBDatabase> {
        if (dbPromise === null) {
            dbPromise = openDatabase();
        }
        return dbPromise;
    }

    const store: MarketplaceStore = {
        async importLevel(pkg: LevelPackage): Promise<ImportResult> {
            const errors = validateLevelPackage(pkg);
            if (errors.length > 0) {
                return { success: false, errors };
            }

            // Force community trust
            const sanitized: LevelPackage = {
                ...pkg,
                worldSpec: { ...pkg.worldSpec, trust: 'community' },
            };

            const db = await getDb();
            const tx = idbTransaction(db, STORE_LEVELS, 'readwrite');
            const levelsStore = tx.objectStore(STORE_LEVELS);
            await idbRequest(levelsStore.put(sanitized));

            return { success: true, levelId: sanitized.id };
        },

        async importFromJson(json: string): Promise<ImportResult> {
            let parsed: unknown;
            try {
                parsed = JSON.parse(json);
            } catch {
                return { success: false, errors: ['Invalid JSON'] };
            }

            if (typeof parsed !== 'object' || parsed === null) {
                return { success: false, errors: ['Expected a JSON object'] };
            }

            const pkg = parsed as LevelPackage;
            return store.importLevel(pkg);
        },

        async importFromUrl(_url: string): Promise<ImportResult> {
            // URL imports are disabled in the browser for security.
            // Levels must be imported via JSON paste or file upload.
            return {
                success: false,
                errors: ['URL imports are disabled. Please download the level file and import it directly.'],
            };
        },

        async getLevel(id: string): Promise<LevelPackage | null> {
            const db = await getDb();
            const tx = idbTransaction(db, STORE_LEVELS, 'readonly');
            const result = await idbRequest(tx.objectStore(STORE_LEVELS).get(id));
            return (result as LevelPackage | undefined) ?? null;
        },

        async search(query: LevelSearchQuery): Promise<LevelSearchResult> {
            const all = await store.listInstalled();
            let filtered = [...all];

            // Text search
            if (query.text !== undefined && query.text.trim().length > 0) {
                const terms = query.text.toLowerCase().trim().split(/\s+/);
                filtered = filtered.filter(pkg => {
                    const haystack = [
                        pkg.metadata.title,
                        pkg.metadata.tagline,
                        pkg.metadata.description,
                        ...pkg.metadata.tags,
                        ...pkg.metadata.skills,
                        pkg.author.name,
                    ].join(' ').toLowerCase();
                    return terms.every(term => haystack.includes(term));
                });
            }

            // Difficulty filter
            if (query.difficulty !== undefined && query.difficulty.length > 0) {
                const diffs = new Set(query.difficulty);
                filtered = filtered.filter(pkg => diffs.has(pkg.metadata.difficulty));
            }

            // Tags filter
            if (query.tags !== undefined && query.tags.length > 0) {
                const tags = new Set(query.tags);
                filtered = filtered.filter(pkg =>
                    pkg.metadata.tags.some(t => tags.has(t)),
                );
            }

            // Skills filter
            if (query.skills !== undefined && query.skills.length > 0) {
                const skills = new Set(query.skills);
                filtered = filtered.filter(pkg =>
                    pkg.metadata.skills.some(s => skills.has(s)),
                );
            }

            // MITRE filter
            if (query.mitreTechniques !== undefined && query.mitreTechniques.length > 0) {
                const techniques = new Set(query.mitreTechniques);
                filtered = filtered.filter(pkg =>
                    pkg.metadata.mitreTechniques.some(t => techniques.has(t)),
                );
            }

            // Sort
            const sortBy = query.sortBy ?? 'newest';
            switch (sortBy) {
                case 'newest':
                    filtered.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
                    break;
                case 'difficulty':
                    filtered.sort((a, b) =>
                        DIFFICULTY_ORDER.indexOf(a.metadata.difficulty) -
                        DIFFICULTY_ORDER.indexOf(b.metadata.difficulty),
                    );
                    break;
                case 'rating':
                case 'popular':
                    // These would need stats, fall back to newest
                    filtered.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
                    break;
            }

            const offset = query.offset ?? 0;
            const limit = query.limit ?? 20;
            const paginated = filtered.slice(offset, offset + limit);

            return {
                levels: paginated,
                total: filtered.length,
                offset,
                limit,
            };
        },

        async listInstalled(): Promise<readonly LevelPackage[]> {
            const db = await getDb();
            const tx = idbTransaction(db, STORE_LEVELS, 'readonly');
            const result = await idbRequest(tx.objectStore(STORE_LEVELS).getAll());
            return result as LevelPackage[];
        },

        async removeLevel(id: string): Promise<boolean> {
            const db = await getDb();
            const tx = idbTransaction(db, STORE_LEVELS, 'readwrite');
            await idbRequest(tx.objectStore(STORE_LEVELS).delete(id));
            return true;
        },

        async rateLevel(levelId: string, stars: number, review?: string): Promise<void> {
            const clamped = Math.max(1, Math.min(5, Math.round(stars)));
            const rating: LevelRating = {
                levelId,
                stars: clamped,
                ratedAt: new Date().toISOString(),
                ...(review !== undefined ? { review } : {}),
            };

            const db = await getDb();
            const tx = idbTransaction(db, STORE_RATINGS, 'readwrite');
            await idbRequest(tx.objectStore(STORE_RATINGS).put(rating));
        },

        async getRating(levelId: string): Promise<LevelRating | null> {
            const db = await getDb();
            const tx = idbTransaction(db, STORE_RATINGS, 'readonly');
            const result = await idbRequest(tx.objectStore(STORE_RATINGS).get(levelId));
            return (result as LevelRating | undefined) ?? null;
        },

        async getStats(levelId: string): Promise<LevelStats> {
            const db = await getDb();

            // Get completions
            const completionsTx = idbTransaction(db, STORE_COMPLETIONS, 'readonly');
            const completionsIndex = completionsTx.objectStore(STORE_COMPLETIONS).index('levelId');
            const completions = await idbRequest(completionsIndex.getAll(levelId)) as Array<{
                levelId: string;
                score: number;
                durationMs: number;
            }>;

            // Get rating
            const rating = await store.getRating(levelId);

            const totalDuration = completions.reduce((sum, c) => sum + c.durationMs, 0);
            const bestScore = completions.reduce((best, c) => Math.max(best, c.score), 0);

            return {
                levelId,
                downloads: 0, // Client-side only — no download tracking
                completions: completions.length,
                averageRating: rating?.stars ?? 0,
                ratingCount: rating !== null ? 1 : 0,
                averageCompletionMinutes: completions.length > 0
                    ? Math.round(totalDuration / completions.length / 60000)
                    : 0,
                bestScore,
            };
        },

        async recordCompletion(levelId: string, score: number, durationMs: number): Promise<void> {
            const db = await getDb();
            const tx = idbTransaction(db, STORE_COMPLETIONS, 'readwrite');
            await idbRequest(tx.objectStore(STORE_COMPLETIONS).add({
                levelId,
                score,
                durationMs,
                completedAt: new Date().toISOString(),
            }));
        },

        async exportLevel(id: string): Promise<string | null> {
            const pkg = await store.getLevel(id);
            if (pkg === null) return null;
            return JSON.stringify(pkg, null, 2);
        },

        async count(): Promise<number> {
            const db = await getDb();
            const tx = idbTransaction(db, STORE_LEVELS, 'readonly');
            return idbRequest(tx.objectStore(STORE_LEVELS).count());
        },

        async getAllTags(): Promise<readonly string[]> {
            const all = await store.listInstalled();
            const tags = new Set<string>();
            for (const pkg of all) {
                for (const tag of pkg.metadata.tags) {
                    tags.add(tag);
                }
            }
            return [...tags].sort();
        },

        async getAllSkills(): Promise<readonly string[]> {
            const all = await store.listInstalled();
            const skills = new Set<string>();
            for (const pkg of all) {
                for (const skill of pkg.metadata.skills) {
                    skills.add(skill);
                }
            }
            return [...skills].sort();
        },
    };

    return store;
}

// ── Level Builder ───────────────────────────────────────────────

export function createLevelBuilder(): LevelBuilder {
    return {
        async build(
            worldSpec: WorldSpec,
            metadata: LevelMetadata,
            author: LevelAuthor,
        ): Promise<LevelPackage> {
            const contentHash = await hashWorldSpec(worldSpec);
            const now = new Date().toISOString();

            return {
                formatVersion: '1.0',
                id: `pkg-${contentHash.slice(0, 16)}`,
                worldSpec: { ...worldSpec, trust: 'community' },
                metadata,
                author,
                contentHash,
                createdAt: now,
                updatedAt: now,
            };
        },

        validate(pkg: LevelPackage): readonly string[] {
            return validateLevelPackage(pkg);
        },

        async hash(worldSpec: WorldSpec): Promise<string> {
            return hashWorldSpec(worldSpec);
        },
    };
}

// ── Validation ──────────────────────────────────────────────────

function validateLevelPackage(pkg: LevelPackage): readonly string[] {
    const errors: string[] = [];

    if (pkg.formatVersion !== '1.0') {
        errors.push(`Unsupported format version: ${pkg.formatVersion}`);
    }

    if (typeof pkg.id !== 'string' || pkg.id.length === 0) {
        errors.push('Package ID is required');
    }

    if (pkg.worldSpec === undefined || pkg.worldSpec === null) {
        errors.push('WorldSpec is required');
    } else {
        if (pkg.worldSpec.version !== '2.0') {
            errors.push(`Unsupported WorldSpec version: ${pkg.worldSpec.version}`);
        }

        if (typeof pkg.worldSpec.startMachine !== 'string') {
            errors.push('WorldSpec.startMachine is required');
        }

        if (pkg.worldSpec.machines === undefined || Object.keys(pkg.worldSpec.machines).length === 0) {
            errors.push('WorldSpec must have at least one machine');
        }

        if (pkg.worldSpec.startMachine !== undefined &&
            pkg.worldSpec.machines !== undefined &&
            !(pkg.worldSpec.startMachine in pkg.worldSpec.machines)) {
            errors.push(`startMachine '${pkg.worldSpec.startMachine}' is not in machines`);
        }
    }

    if (pkg.metadata === undefined || pkg.metadata === null) {
        errors.push('Metadata is required');
    } else {
        if (typeof pkg.metadata.title !== 'string' || pkg.metadata.title.trim().length === 0) {
            errors.push('Metadata.title is required');
        }
        if (typeof pkg.metadata.difficulty !== 'string' || !DIFFICULTY_ORDER.includes(pkg.metadata.difficulty)) {
            errors.push(`Invalid difficulty: ${pkg.metadata.difficulty}`);
        }
        if (!Array.isArray(pkg.metadata.tags)) {
            errors.push('Metadata.tags must be an array');
        }

        // Check cover image size (256KB max)
        if (pkg.metadata.coverImage !== undefined && pkg.metadata.coverImage.length > 256 * 1024 * 1.37) {
            errors.push('Cover image exceeds 256KB');
        }
    }

    if (pkg.author === undefined || pkg.author === null) {
        errors.push('Author is required');
    } else {
        if (typeof pkg.author.name !== 'string' || pkg.author.name.trim().length === 0) {
            errors.push('Author.name is required');
        }
    }

    return errors;
}

const DIFFICULTY_ORDER: readonly LevelDifficulty[] = [
    'beginner', 'easy', 'medium', 'hard', 'expert', 'insane',
];

// ── Hashing ─────────────────────────────────────────────────────

async function hashWorldSpec(worldSpec: WorldSpec): Promise<string> {
    const canonical = JSON.stringify(worldSpec, Object.keys(worldSpec).sort());
    const encoder = new TextEncoder();
    const data = encoder.encode(canonical);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Barrel Export ───────────────────────────────────────────────

export { type MarketplaceStore, type LevelBuilder };
