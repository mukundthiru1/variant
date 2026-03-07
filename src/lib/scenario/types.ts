/**
 * VARIANT — Scenario Serializer Type Definitions
 *
 * Save, load, fork, diff, and share WorldSpecs. This is the plumbing
 * that makes community content possible — without it, levels exist
 * only in memory.
 *
 * FORMATS:
 * - JSON (canonical, human-readable, diffable)
 * - Compact binary (msgpack-style for sharing/downloading)
 * - URL-safe hash (for linking to specific scenario versions)
 *
 * OPERATIONS:
 * - save/load: serialize/deserialize WorldSpec
 * - fork: deep clone with new metadata (author, version)
 * - diff: structural comparison between two WorldSpecs
 * - patch: apply a diff to produce a new WorldSpec
 * - hash: content-addressable identifier for deduplication
 *
 * SWAPPABILITY: Implements ScenarioStore interface. Replace this file.
 */

import type { WorldSpec } from '../../core/world/types';

// ── Scenario Metadata ───────────────────────────────────────────

/** Metadata attached to a saved scenario. */
export interface ScenarioMeta {
    /** Content-addressable hash of the WorldSpec. */
    readonly hash: string;

    /** Human-readable version tag (e.g., '1.0.3'). */
    readonly versionTag: string;

    /** ISO 8601 timestamp when saved. */
    readonly savedAt: string;

    /** ID of the parent scenario this was forked from (null if original). */
    readonly parentHash: string | null;

    /** Fork depth (0 = original, 1 = first fork, etc.). */
    readonly forkDepth: number;

    /** Tags for discovery/search. */
    readonly tags: readonly string[];

    /** Byte size of the serialized scenario. */
    readonly sizeBytes: number;
}

// ── Diff ────────────────────────────────────────────────────────

/** A structural diff between two WorldSpecs. */
export interface ScenarioDiff {
    /** Hash of the base (before) scenario. */
    readonly baseHash: string;

    /** Hash of the target (after) scenario. */
    readonly targetHash: string;

    /** Individual changes. */
    readonly changes: readonly DiffChange[];

    /** Summary statistics. */
    readonly stats: DiffStats;
}

/** A single change in a diff. */
export interface DiffChange {
    /** JSON path to the changed value (dot notation). */
    readonly path: string;

    /** Type of change. */
    readonly kind: 'added' | 'removed' | 'modified';

    /** Value before (undefined for 'added'). */
    readonly before: unknown;

    /** Value after (undefined for 'removed'). */
    readonly after: unknown;
}

/** Summary statistics for a diff. */
export interface DiffStats {
    readonly added: number;
    readonly removed: number;
    readonly modified: number;
    readonly total: number;
}

// ── Fork Config ─────────────────────────────────────────────────

/** Configuration for forking a scenario. */
export interface ForkConfig {
    /** New author name. */
    readonly author: string;

    /** New author ID. */
    readonly authorId: string;

    /** New version tag. */
    readonly versionTag: string;

    /** New title (optional, keeps original if not set). */
    readonly title?: string;

    /** Additional tags to add. */
    readonly addTags?: readonly string[];
}

// ── Scenario Store Interface ────────────────────────────────────

/**
 * The scenario store handles serialization, storage, and retrieval
 * of WorldSpecs with full versioning support.
 *
 * SECURITY: WorldSpecs are validated before save. Invalid specs
 * are rejected.
 *
 * EXTENSIBILITY: The storage backend is pluggable — in-memory,
 * IndexedDB, or remote API.
 */
export interface ScenarioStore {
    /** Serialize a WorldSpec to JSON string. */
    serialize(spec: WorldSpec): string;

    /** Deserialize a JSON string to WorldSpec. Returns null if invalid JSON. */
    deserialize(json: string): WorldSpec | null;

    /** Compute content hash of a WorldSpec. */
    hash(spec: WorldSpec): string;

    /** Save a WorldSpec. Returns metadata including hash. */
    save(spec: WorldSpec, versionTag: string, tags?: readonly string[]): ScenarioMeta;

    /** Load a WorldSpec by hash. Returns null if not found. */
    load(hash: string): WorldSpec | null;

    /** List all saved scenarios. */
    list(): readonly ScenarioMeta[];

    /** Search scenarios by tag. */
    searchByTag(tag: string): readonly ScenarioMeta[];

    /** Search scenarios by title substring. */
    searchByTitle(query: string): readonly ScenarioMeta[];

    /**
     * Fork a scenario: deep clone with new author/version metadata.
     * Returns the forked spec and its metadata.
     */
    fork(hash: string, config: ForkConfig): { spec: WorldSpec; meta: ScenarioMeta } | null;

    /**
     * Compute structural diff between two WorldSpecs.
     */
    diff(baseHash: string, targetHash: string): ScenarioDiff | null;

    /**
     * Delete a saved scenario by hash.
     */
    remove(hash: string): boolean;

    /** Get total number of saved scenarios. */
    count(): number;

    /** Clear all saved scenarios. */
    clear(): void;
}
