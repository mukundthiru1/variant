/**
 * VARIANT — Marketplace Type Definitions
 *
 * The community level marketplace. Players browse, download,
 * rate, and publish levels. Everything is client-side — levels
 * are JSON blobs stored in IndexedDB or imported from URLs.
 *
 * SECURITY: All imported WorldSpecs pass through the full
 * validator before loading. No code execution. No network
 * requests beyond fetching the JSON. Trust level is always
 * 'community' for user-imported levels.
 *
 * EXTENSIBILITY: The marketplace schema is versioned.
 * Old clients can read new fields (ignored). New clients
 * can read old formats (migration).
 */

// ── Level Package ───────────────────────────────────────────────

/**
 * A published level package. This is what gets shared,
 * browsed, and downloaded in the marketplace.
 *
 * The `worldSpec` is the actual level data.
 * Everything else is marketplace metadata.
 */
export interface LevelPackage {
    /** Package format version. */
    readonly formatVersion: '1.0';

    /** Unique package ID. Deterministic hash of content. */
    readonly id: string;

    /** The actual level definition. */
    readonly worldSpec: import('../../core/world/types').WorldSpec;

    /** Marketplace metadata. */
    readonly metadata: LevelMetadata;

    /** Author information. */
    readonly author: LevelAuthor;

    /**
     * Content hash for integrity verification.
     * SHA-256 of the canonical JSON representation of worldSpec.
     */
    readonly contentHash: string;

    /** When this package was created (ISO 8601). */
    readonly createdAt: string;

    /** When this package was last updated (ISO 8601). */
    readonly updatedAt: string;
}

// ── Level Metadata ──────────────────────────────────────────────

export interface LevelMetadata {
    /** Short display title. */
    readonly title: string;

    /** One-line description for search results. */
    readonly tagline: string;

    /** Full description (Markdown supported). */
    readonly description: string;

    /** Difficulty rating. */
    readonly difficulty: LevelDifficulty;

    /** Estimated completion time in minutes. */
    readonly estimatedMinutes: number;

    /** Category tags. */
    readonly tags: readonly string[];

    /** MITRE ATT&CK techniques covered. */
    readonly mitreTechniques: readonly string[];

    /** Number of machines in the level. */
    readonly machineCount: number;

    /** Number of objectives. */
    readonly objectiveCount: number;

    /** What skills the player will practice. */
    readonly skills: readonly string[];

    /**
     * Cover image as a data URL (base64 PNG/JPEG).
     * Max 256KB. Optional — a default is generated.
     */
    readonly coverImage?: string;

    /**
     * Screenshots as data URLs.
     * Max 5, max 512KB each. Optional.
     */
    readonly screenshots?: readonly string[];

    /** Prerequisite levels (IDs) that should be completed first. */
    readonly prerequisites?: readonly string[];

    /** Custom extensions. */
    readonly extensions?: Readonly<Record<string, unknown>>;
}

export type LevelDifficulty =
    | 'beginner'
    | 'easy'
    | 'medium'
    | 'hard'
    | 'expert'
    | 'insane';

// ── Level Author ────────────────────────────────────────────────

export interface LevelAuthor {
    /** Display name. */
    readonly name: string;

    /** Optional URL (portfolio, GitHub, etc.). */
    readonly url?: string;

    /** Optional avatar as data URL. Max 64KB. */
    readonly avatar?: string;
}

// ── Level Rating ────────────────────────────────────────────────

export interface LevelRating {
    /** Level package ID. */
    readonly levelId: string;

    /** Star rating (1-5). */
    readonly stars: number;

    /** Optional review text. */
    readonly review?: string;

    /** When rated (ISO 8601). */
    readonly ratedAt: string;
}

// ── Level Stats (aggregated) ────────────────────────────────────

export interface LevelStats {
    readonly levelId: string;
    readonly downloads: number;
    readonly completions: number;
    readonly averageRating: number;
    readonly ratingCount: number;
    readonly averageCompletionMinutes: number;
    readonly bestScore: number;
}

// ── Search & Filter ─────────────────────────────────────────────

export interface LevelSearchQuery {
    /** Free text search. */
    readonly text?: string;

    /** Filter by difficulty. */
    readonly difficulty?: readonly LevelDifficulty[];

    /** Filter by tags. */
    readonly tags?: readonly string[];

    /** Filter by MITRE techniques. */
    readonly mitreTechniques?: readonly string[];

    /** Filter by skills. */
    readonly skills?: readonly string[];

    /** Sort order. */
    readonly sortBy?: 'newest' | 'popular' | 'rating' | 'difficulty';

    /** Pagination offset. */
    readonly offset?: number;

    /** Pagination limit. */
    readonly limit?: number;
}

export interface LevelSearchResult {
    readonly levels: readonly LevelPackage[];
    readonly total: number;
    readonly offset: number;
    readonly limit: number;
}

// ── Marketplace Store ───────────────────────────────────────────

/**
 * Client-side level store. Persists to IndexedDB.
 *
 * SECURITY: All WorldSpecs are validated on import.
 * Invalid specs are rejected — they never enter the store.
 */
export interface MarketplaceStore {
    /** Import a level package. Validates and stores it. */
    importLevel(pkg: LevelPackage): Promise<ImportResult>;

    /** Import from a JSON string. Parses, validates, stores. */
    importFromJson(json: string): Promise<ImportResult>;

    /** Import from a URL. Fetches, parses, validates, stores. */
    importFromUrl(url: string): Promise<ImportResult>;

    /** Get a level by ID. */
    getLevel(id: string): Promise<LevelPackage | null>;

    /** Search/browse levels. */
    search(query: LevelSearchQuery): Promise<LevelSearchResult>;

    /** Get all installed levels. */
    listInstalled(): Promise<readonly LevelPackage[]>;

    /** Remove a level. */
    removeLevel(id: string): Promise<boolean>;

    /** Rate a level. */
    rateLevel(levelId: string, stars: number, review?: string): Promise<void>;

    /** Get rating for a level. */
    getRating(levelId: string): Promise<LevelRating | null>;

    /** Get stats for a level. */
    getStats(levelId: string): Promise<LevelStats>;

    /** Record a completion. */
    recordCompletion(levelId: string, score: number, durationMs: number): Promise<void>;

    /** Export a level as JSON string. */
    exportLevel(id: string): Promise<string | null>;

    /** Get total count of installed levels. */
    count(): Promise<number>;

    /** Get all tags used across all levels. */
    getAllTags(): Promise<readonly string[]>;

    /** Get all skills used across all levels. */
    getAllSkills(): Promise<readonly string[]>;
}

export interface ImportResult {
    readonly success: boolean;
    readonly levelId?: string;
    readonly errors?: readonly string[];
}

// ── Level Builder ───────────────────────────────────────────────

/**
 * Helper for creating LevelPackage objects from WorldSpecs.
 * Used by level designers and the level editor.
 */
export interface LevelBuilder {
    /** Create a LevelPackage from a WorldSpec and metadata. */
    build(
        worldSpec: import('../../core/world/types').WorldSpec,
        metadata: LevelMetadata,
        author: LevelAuthor,
    ): Promise<LevelPackage>;

    /** Validate a LevelPackage. Returns errors (empty = valid). */
    validate(pkg: LevelPackage): readonly string[];

    /** Generate a content hash for a WorldSpec. */
    hash(worldSpec: import('../../core/world/types').WorldSpec): Promise<string>;
}

// ── Well-known Tags ─────────────────────────────────────────────

export const WELL_KNOWN_TAGS = [
    'web', 'network', 'forensics', 'cryptography', 'steganography',
    'reverse-engineering', 'binary-exploitation', 'privilege-escalation',
    'lateral-movement', 'persistence', 'exfiltration', 'social-engineering',
    'cloud', 'containers', 'active-directory', 'wireless', 'mobile',
    'iot', 'scada', 'malware-analysis', 'incident-response', 'threat-hunting',
    'osint', 'phishing', 'supply-chain', 'api-security', 'ci-cd',
    'red-team', 'blue-team', 'purple-team', 'ctf', 'beginner-friendly',
] as const;

export const WELL_KNOWN_SKILLS = [
    'sql-injection', 'xss', 'ssrf', 'command-injection', 'path-traversal',
    'file-upload', 'deserialization', 'xxe', 'ssti', 'jwt-attacks',
    'csrf', 'idor', 'race-conditions', 'buffer-overflow', 'format-string',
    'heap-exploitation', 'rop-chains', 'kernel-exploitation',
    'password-cracking', 'hash-cracking', 'wifi-cracking',
    'port-scanning', 'service-enumeration', 'dns-enumeration',
    'subdomain-enumeration', 'directory-bruteforce',
    'ssh-tunneling', 'pivoting', 'port-forwarding',
    'log-analysis', 'pcap-analysis', 'memory-forensics', 'disk-forensics',
    'docker-escape', 'kubernetes-exploitation', 'cloud-enumeration',
    'iam-exploitation', 'metadata-service-abuse',
    'kerberoasting', 'pass-the-hash', 'golden-ticket', 'dcsync',
    'firewall-evasion', 'ids-evasion', 'antivirus-evasion',
    'c2-setup', 'data-exfiltration', 'covert-channels',
] as const;
