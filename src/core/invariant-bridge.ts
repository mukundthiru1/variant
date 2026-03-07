/**
 * VARIANT — INVARIANT Bridge
 *
 * The trust boundary between VARIANT (the game engine) and
 * INVARIANT (the production defense system). This bridge
 * controls what data flows between the two systems.
 *
 * SECURITY INVARIANT:
 *   - Community levels CANNOT access INVARIANT payloads.
 *   - Only curated levels (trust='curated') can reference
 *     INVARIANT sensor data.
 *   - The bridge enforces this at the type level AND at runtime.
 *   - No function bypasses the trust check.
 *
 * DESIGN:
 *   VARIANT runs game logic. INVARIANT provides:
 *     1. Live attack payloads for "write-rule" objectives
 *     2. Real vulnerability patterns from production
 *     3. Detection rule validation against real-world data
 *     4. Scoring calibration from production metrics
 *
 *   Data flows ONE WAY: INVARIANT → VARIANT (read-only).
 *   VARIANT cannot write to INVARIANT. This prevents
 *   game state from contaminating production data.
 *
 * CONFIGURABILITY:
 *   - The bridge adapter is swappable (mock for testing,
 *     real API for production).
 *   - Payload categories are extensible.
 *   - Rate limiting and caching are configurable.
 *
 * SWAPPABILITY: The InvariantAdapter interface is the only
 * coupling point. Swap the adapter without touching anything
 * else in the system.
 */

// ── Trust Levels ────────────────────────────────────────────

/**
 * Trust level determines what a level can access.
 * This is set by the engine, never by the level author.
 */
export type TrustLevel = 'community' | 'curated';

// ── Payload Types ───────────────────────────────────────────

/**
 * Categories of data available from INVARIANT.
 * Each category has its own access control.
 */
export type PayloadCategory =
    | 'sqli-payloads'        // Live SQL injection payloads
    | 'xss-payloads'         // XSS payloads
    | 'cmdi-payloads'        // Command injection payloads
    | 'traversal-payloads'   // Path traversal payloads
    | 'ssrf-payloads'        // SSRF payloads
    | 'auth-bypass-payloads' // Authentication bypass payloads
    | 'vuln-patterns'        // Real vulnerability patterns
    | 'detection-corpus'     // Labeled test corpus for rule scoring
    | 'threat-intel'         // Threat intelligence feeds
    | (string & {});         // open union

/**
 * A payload from INVARIANT — a set of attack patterns
 * or detection data for training purposes.
 */
export interface InvariantPayload {
    /** Payload category. */
    readonly category: PayloadCategory;

    /** When this payload was last updated. */
    readonly updatedAt: number;

    /** Number of entries. */
    readonly count: number;

    /** The actual payload entries. */
    readonly entries: readonly PayloadEntry[];

    /** Metadata about the source. */
    readonly source: PayloadSource;
}

export interface PayloadEntry {
    /** Unique entry ID. */
    readonly id: string;

    /** The payload string. */
    readonly value: string;

    /** Whether this entry is malicious (for corpus entries). */
    readonly malicious?: boolean;

    /** Difficulty of detecting this entry. */
    readonly difficulty?: 'easy' | 'medium' | 'hard' | 'expert';

    /** MITRE ATT&CK technique. */
    readonly mitreTechnique?: string;

    /** Tags for filtering. */
    readonly tags?: readonly string[];
}

export interface PayloadSource {
    /** Source identifier. */
    readonly id: string;

    /** Whether this is from live production data. */
    readonly live: boolean;

    /** Data freshness guarantee (max age in ms). */
    readonly maxAgeMs: number;
}

// ── Adapter Interface ───────────────────────────────────────

/**
 * The adapter connects VARIANT to INVARIANT.
 *
 * In production: makes API calls to the INVARIANT service.
 * In testing: returns mock/static data.
 * In offline mode: returns cached data.
 *
 * SWAPPABILITY: This is the ONLY interface that bridges
 * the two systems. Replace the adapter, not the bridge.
 */
export interface InvariantAdapter {
    /**
     * Fetch payloads for a category.
     * Returns null if the category is unavailable.
     */
    fetchPayloads(
        category: PayloadCategory,
        options?: FetchOptions,
    ): Promise<InvariantPayload | null>;

    /**
     * Validate a player-written detection rule against
     * INVARIANT's live corpus.
     *
     * Returns scoring metrics.
     */
    validateRule(
        category: PayloadCategory,
        ruleFn: (input: string) => boolean,
    ): Promise<RuleValidationResult>;

    /**
     * Check if the adapter is connected and healthy.
     */
    isHealthy(): Promise<boolean>;

    /**
     * Get adapter capabilities.
     */
    getCapabilities(): AdapterCapabilities;
}

export interface FetchOptions {
    /** Maximum entries to return. Default: 100. */
    readonly limit?: number;

    /** Filter by difficulty. */
    readonly difficulty?: 'easy' | 'medium' | 'hard' | 'expert';

    /** Filter by tags. */
    readonly tags?: readonly string[];

    /** Whether to use cached data if available. Default: true. */
    readonly useCache?: boolean;
}

export interface RuleValidationResult {
    /** True positive rate. */
    readonly truePositiveRate: number;

    /** False positive rate. */
    readonly falsePositiveRate: number;

    /** F1 score. */
    readonly f1Score: number;

    /** Number of test cases used. */
    readonly testCaseCount: number;

    /** Breakdown by difficulty. */
    readonly byDifficulty: Readonly<Record<string, { detected: number; total: number }>>;
}

export interface AdapterCapabilities {
    /** Available payload categories. */
    readonly categories: readonly PayloadCategory[];

    /** Whether live data is available. */
    readonly liveData: boolean;

    /** Whether rule validation is available. */
    readonly ruleValidation: boolean;

    /** Maximum entries per request. */
    readonly maxEntriesPerRequest: number;
}

// ── Bridge Implementation ───────────────────────────────────

/**
 * The INVARIANT bridge. Enforces trust boundaries and
 * mediates all data flow from INVARIANT to VARIANT.
 */
export interface InvariantBridge {
    /**
     * Request payloads. Returns null if:
     *   1. Trust level is 'community' (access denied)
     *   2. Category is unavailable
     *   3. Adapter is not connected
     */
    requestPayloads(
        trustLevel: TrustLevel,
        category: PayloadCategory,
        options?: FetchOptions,
    ): Promise<InvariantPayload | null>;

    /**
     * Validate a detection rule against live data.
     * Only available for curated levels.
     */
    validateRule(
        trustLevel: TrustLevel,
        category: PayloadCategory,
        ruleFn: (input: string) => boolean,
    ): Promise<RuleValidationResult | null>;

    /**
     * Check bridge health.
     */
    isAvailable(): Promise<boolean>;

    /**
     * Get what's available for a given trust level.
     */
    getAvailableCategories(trustLevel: TrustLevel): readonly PayloadCategory[];
}

/**
 * Bridge configuration.
 */
export interface BridgeConfig {
    /** The adapter to use. */
    readonly adapter: InvariantAdapter;

    /**
     * Cache TTL in milliseconds.
     * Default: 300000 (5 minutes).
     */
    readonly cacheTtlMs?: number;

    /**
     * Rate limit: max requests per minute.
     * Default: 60.
     */
    readonly rateLimitPerMinute?: number;

    /**
     * Categories allowed for community levels.
     * Default: [] (none — community cannot access INVARIANT).
     * This exists for future expansion but defaults to locked down.
     */
    readonly communityAllowedCategories?: readonly PayloadCategory[];
}

/**
 * Create an INVARIANT bridge.
 */
export function createInvariantBridge(config: BridgeConfig): InvariantBridge {
    const adapter = config.adapter;
    const communityAllowed = new Set(config.communityAllowedCategories ?? []);
    const rateLimitPerMinute = config.rateLimitPerMinute ?? 60;
    const cacheTtlMs = config.cacheTtlMs ?? 300_000;

    // ── Rate limiting ─────────────────────────────────────
    const requestTimestamps: number[] = [];

    function checkRateLimit(): boolean {
        const now = Date.now();
        const oneMinuteAgo = now - 60_000;

        // Prune old timestamps
        while (requestTimestamps.length > 0 && requestTimestamps[0]! < oneMinuteAgo) {
            requestTimestamps.shift();
        }

        if (requestTimestamps.length >= rateLimitPerMinute) {
            return false;
        }

        requestTimestamps.push(now);
        return true;
    }

    // ── Cache ─────────────────────────────────────────────
    const cache = new Map<string, { payload: InvariantPayload; fetchedAt: number }>();

    function getCached(key: string): InvariantPayload | null {
        const entry = cache.get(key);
        if (entry === undefined) return null;
        if (Date.now() - entry.fetchedAt > cacheTtlMs) {
            cache.delete(key);
            return null;
        }
        return entry.payload;
    }

    function setCached(key: string, payload: InvariantPayload): void {
        cache.set(key, { payload, fetchedAt: Date.now() });
    }

    // ── Trust check ───────────────────────────────────────

    function canAccess(trustLevel: TrustLevel, category: PayloadCategory): boolean {
        if (trustLevel === 'curated') return true;
        return communityAllowed.has(category);
    }

    return {
        async requestPayloads(
            trustLevel: TrustLevel,
            category: PayloadCategory,
            options?: FetchOptions,
        ): Promise<InvariantPayload | null> {
            // SECURITY: Trust boundary enforcement
            if (!canAccess(trustLevel, category)) {
                return null;
            }

            // Check cache first
            const cacheKey = `${category}:${options?.difficulty ?? 'all'}`;
            if (options?.useCache !== false) {
                const cached = getCached(cacheKey);
                if (cached !== null) return cached;
            }

            // Rate limit
            if (!checkRateLimit()) {
                return null;
            }

            const payload = await adapter.fetchPayloads(category, options);
            if (payload !== null) {
                setCached(cacheKey, payload);
            }

            return payload;
        },

        async validateRule(
            trustLevel: TrustLevel,
            category: PayloadCategory,
            ruleFn: (input: string) => boolean,
        ): Promise<RuleValidationResult | null> {
            if (!canAccess(trustLevel, category)) {
                return null;
            }

            if (!checkRateLimit()) {
                return null;
            }

            return adapter.validateRule(category, ruleFn);
        },

        async isAvailable(): Promise<boolean> {
            return adapter.isHealthy();
        },

        getAvailableCategories(trustLevel: TrustLevel): readonly PayloadCategory[] {
            const capabilities = adapter.getCapabilities();

            if (trustLevel === 'curated') {
                return capabilities.categories;
            }

            return capabilities.categories.filter(c => communityAllowed.has(c));
        },
    };
}

// ── Mock Adapter (for testing) ──────────────────────────────

/**
 * Create a mock INVARIANT adapter for testing and offline use.
 * Returns static payloads without requiring network access.
 */
export function createMockInvariantAdapter(
    payloads?: Readonly<Record<string, InvariantPayload>>,
): InvariantAdapter {
    const data = new Map<string, InvariantPayload>(
        Object.entries(payloads ?? {}),
    );

    return {
        async fetchPayloads(
            category: PayloadCategory,
            options?: FetchOptions,
        ): Promise<InvariantPayload | null> {
            const payload = data.get(category);
            if (payload === undefined) return null;

            if (options?.limit !== undefined) {
                return {
                    ...payload,
                    entries: payload.entries.slice(0, options.limit),
                    count: Math.min(payload.count, options.limit),
                };
            }

            return payload;
        },

        async validateRule(
            category: PayloadCategory,
            ruleFn: (input: string) => boolean,
        ): Promise<RuleValidationResult> {
            const payload = data.get(category);
            if (payload === undefined) {
                return {
                    truePositiveRate: 0,
                    falsePositiveRate: 0,
                    f1Score: 0,
                    testCaseCount: 0,
                    byDifficulty: {},
                };
            }

            let tp = 0, fp = 0, fn = 0, tn = 0;
            const byDiff = new Map<string, { detected: number; total: number }>();

            for (const entry of payload.entries) {
                const detected = ruleFn(entry.value);
                const malicious = entry.malicious ?? true;
                const diff = entry.difficulty ?? 'medium';

                const diffEntry = byDiff.get(diff) ?? { detected: 0, total: 0 };
                diffEntry.total++;
                if (detected) diffEntry.detected++;
                byDiff.set(diff, diffEntry);

                if (malicious && detected) tp++;
                else if (malicious && !detected) fn++;
                else if (!malicious && detected) fp++;
                else tn++;
            }

            void tn;
            const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
            const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
            const f1 = precision + recall > 0 ? 2 * precision * recall / (precision + recall) : 0;

            return {
                truePositiveRate: recall,
                falsePositiveRate: fp / (fp + (payload.entries.length - tp - fn - fp)),
                f1Score: Math.round(f1 * 1000) / 1000,
                testCaseCount: payload.entries.length,
                byDifficulty: Object.fromEntries(byDiff),
            };
        },

        async isHealthy(): Promise<boolean> {
            return true;
        },

        getCapabilities(): AdapterCapabilities {
            return {
                categories: [...data.keys()] as PayloadCategory[],
                liveData: false,
                ruleValidation: true,
                maxEntriesPerRequest: 1000,
            };
        },
    };
}
