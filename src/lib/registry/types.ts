/**
 * VARIANT — Capability Registry Types
 *
 * General-purpose service registry for cross-module discovery.
 * Modules declare what they provide (capabilities). Consumers
 * query for providers by capability name, version, or metadata.
 *
 * USE CASES:
 * - Module A registers "filesystem-monitor" capability
 * - Module B queries for any "filesystem-monitor" provider
 * - Level packs register custom objective evaluators, scoring engines, etc.
 * - Community plugins discover each other without hardcoded coupling
 *
 * DESIGN:
 * - Append-only registration (capabilities cannot be unregistered mid-sim)
 * - Version-aware (semver string matching)
 * - Tag-based filtering for category queries
 * - Metadata for provider-specific configuration
 *
 * SWAPPABILITY: Implements CapabilityRegistry. Replace this file.
 */

// ── Capability Provider ─────────────────────────────────────────

/** A registered capability provider. */
export interface CapabilityProvider {
    /** Unique provider ID (e.g., 'variant/filesystem-monitor'). */
    readonly id: string;
    /** Capability name this provider offers (e.g., 'filesystem-monitor'). */
    readonly capability: string;
    /** Provider version (semver). */
    readonly version: string;
    /** Human-readable description. */
    readonly description: string;
    /** Tags for categorization and filtering. */
    readonly tags: readonly string[];
    /** Priority (higher = preferred when multiple providers exist). */
    readonly priority: number;
    /** Arbitrary metadata for consumers. */
    readonly metadata: Readonly<Record<string, unknown>>;
}

// ── Query ───────────────────────────────────────────────────────

/** Query for finding capability providers. */
export interface CapabilityQuery {
    /** Required capability name. */
    readonly capability: string;
    /** Minimum version (inclusive). If omitted, any version matches. */
    readonly minVersion?: string;
    /** Required tags (all must be present). */
    readonly requiredTags?: readonly string[];
    /** If true, return only the highest-priority provider. */
    readonly preferHighestPriority?: boolean;
}

/** Result of a capability query. */
export interface CapabilityQueryResult {
    /** Whether any matching providers were found. */
    readonly found: boolean;
    /** Matching providers, sorted by priority descending. */
    readonly providers: readonly CapabilityProvider[];
}

// ── Dependency ──────────────────────────────────────────────────

/** A dependency declaration. */
export interface CapabilityDependency {
    /** Required capability name. */
    readonly capability: string;
    /** Minimum version (inclusive). If omitted, any version is acceptable. */
    readonly minVersion?: string;
    /** Whether this dependency is mandatory or optional. */
    readonly required: boolean;
}

/** Result of dependency resolution. */
export interface DependencyResolutionResult {
    /** Whether all required dependencies are satisfied. */
    readonly satisfied: boolean;
    /** Missing required dependencies. */
    readonly missing: readonly string[];
    /** Resolved providers for each dependency. */
    readonly resolved: ReadonlyMap<string, CapabilityProvider>;
}

// ── Registry ────────────────────────────────────────────────────

/** The capability registry engine. */
export interface CapabilityRegistry {
    /** Register a capability provider. Throws if ID is duplicate. */
    register(provider: CapabilityProvider): void;

    /** Get a provider by ID. */
    getProvider(id: string): CapabilityProvider | null;

    /** Query for providers matching criteria. */
    query(q: CapabilityQuery): CapabilityQueryResult;

    /** Check if a capability has at least one provider. */
    hasCapability(capability: string): boolean;

    /** List all registered capability names. */
    listCapabilities(): readonly string[];

    /** List all providers for a given capability. */
    listProviders(capability: string): readonly CapabilityProvider[];

    /** List all registered providers. */
    listAll(): readonly CapabilityProvider[];

    /** Resolve a set of dependencies. */
    resolveDependencies(deps: readonly CapabilityDependency[]): DependencyResolutionResult;

    /** Clear all state. */
    clear(): void;
}
