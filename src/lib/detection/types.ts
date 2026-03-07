/**
 * VARIANT — Detection Engine Types
 *
 * Shared detection primitives for identifying injection attacks,
 * XSS, command injection, path traversal, and other attack patterns.
 *
 * These engines are DUAL-PURPOSE:
 *   1. VARIANT: Evaluate player-written detection rules, score
 *      their accuracy, and provide feedback.
 *   2. INVARIANT (future): Power production defense systems
 *      with the same battle-tested detection logic.
 *
 * CONFIGURABILITY: Every engine is configurable via DetectionEngineConfig.
 * Sensitivity, pattern sets, and scoring parameters are all tunable.
 *
 * EXTENSIBILITY: The DetectionEngineRegistry allows third-party
 * detection engines to be registered and composed.
 *
 * SWAPPABILITY: Each engine implements the DetectionEngine interface.
 * Swap any engine without touching callers.
 */

// ── Detection Result ────────────────────────────────────────

export interface DetectionResult {
    /** Whether the input was detected as malicious. */
    readonly detected: boolean;

    /** Confidence score (0-1). */
    readonly confidence: number;

    /** Which patterns matched. */
    readonly matches: readonly PatternMatch[];

    /** Human-readable explanation of why it was flagged. */
    readonly explanation: string;

    /** MITRE ATT&CK technique IDs (if applicable). */
    readonly mitreTechniques?: readonly string[];

    /** Category of the detection. */
    readonly category: DetectionCategory;

    /** Sub-category for more specific classification. */
    readonly subCategory?: string;
}

export interface PatternMatch {
    /** Pattern ID that matched. */
    readonly patternId: string;

    /** The substring that triggered the match. */
    readonly matchedText: string;

    /** Position in the input string. */
    readonly offset: number;

    /** Severity of this specific match. */
    readonly severity: 'info' | 'low' | 'medium' | 'high' | 'critical';

    /** Description of what was detected. */
    readonly description: string;
}

// ── Detection Categories ────────────────────────────────────

export type DetectionCategory =
    | 'sqli'                // SQL injection
    | 'xss'                 // Cross-site scripting
    | 'command-injection'   // OS command injection
    | 'path-traversal'      // Directory traversal
    | 'ssrf'                // Server-side request forgery
    | 'xxe'                 // XML external entity
    | 'ssti'                // Server-side template injection
    | 'ldap-injection'      // LDAP injection
    | 'header-injection'    // HTTP header injection
    | (string & {});        // open union

// ── Detection Engine Interface ──────────────────────────────

/**
 * A detection engine analyzes input strings for attack patterns.
 *
 * Every detection engine:
 *   1. Is pure — no side effects, no I/O, no state mutation
 *   2. Is configurable — sensitivity and patterns are tunable
 *   3. Is composable — engines can be chained
 *   4. Returns structured results with confidence scores
 */
export interface DetectionEngine {
    /** Unique engine ID. */
    readonly id: string;

    /** Detection category this engine handles. */
    readonly category: DetectionCategory;

    /** Version string. */
    readonly version: string;

    /** Human-readable description. */
    readonly description: string;

    /**
     * Analyze input for attack patterns.
     * @param input The string to analyze.
     * @param context Optional context (e.g., where the input came from).
     * @returns Detection result with confidence and matches.
     */
    analyze(input: string, context?: DetectionContext): DetectionResult;

    /**
     * Batch analyze multiple inputs.
     * Default implementation calls analyze() on each.
     */
    analyzeBatch?(inputs: readonly string[]): readonly DetectionResult[];

    /**
     * Get the current pattern set (for display/export).
     */
    getPatterns(): readonly DetectionPattern[];

    /**
     * Get the engine's configuration.
     */
    getConfig(): DetectionEngineConfig;
}

// ── Detection Context ───────────────────────────────────────

export interface DetectionContext {
    /** Where the input came from (URL parameter, header, body, etc). */
    readonly source?: string;

    /** The HTTP method (for web context). */
    readonly method?: string;

    /** Content type of the request. */
    readonly contentType?: string;

    /** Whether the input is URL-encoded. */
    readonly urlEncoded?: boolean;

    /** Additional metadata. */
    readonly metadata?: Readonly<Record<string, string>>;
}

// ── Detection Pattern ───────────────────────────────────────

export interface DetectionPattern {
    /** Pattern ID. */
    readonly id: string;

    /** Human-readable name. */
    readonly name: string;

    /** The pattern to match (regex string or literal). */
    readonly pattern: string;

    /** Whether the pattern is a regex or literal string. */
    readonly type: 'regex' | 'literal' | 'function';

    /** Severity if matched. */
    readonly severity: 'info' | 'low' | 'medium' | 'high' | 'critical';

    /** Description of what this pattern detects. */
    readonly description: string;

    /** Whether this pattern is enabled. */
    readonly enabled: boolean;

    /** Tags for filtering/grouping. */
    readonly tags?: readonly string[];
}

// ── Detection Engine Config ─────────────────────────────────

export interface DetectionEngineConfig {
    /**
     * Sensitivity level. Controls which patterns are active
     * and the confidence threshold for detection.
     * 'low'    — only critical patterns, high threshold
     * 'medium' — common patterns, moderate threshold
     * 'high'   — all patterns, low threshold
     * 'paranoid' — everything, zero threshold
     * Default: 'medium'.
     */
    readonly sensitivity: 'low' | 'medium' | 'high' | 'paranoid';

    /**
     * Minimum confidence to consider detected.
     * 0.0 = flag everything, 1.0 = only flag certainties.
     * Default depends on sensitivity level.
     */
    readonly confidenceThreshold: number;

    /**
     * Maximum input length to analyze.
     * Prevents DoS from extremely long inputs.
     * Default: 65536.
     */
    readonly maxInputLength: number;

    /**
     * Whether to decode URL encoding before analysis.
     * Default: true.
     */
    readonly decodeUrl: boolean;

    /**
     * Whether to normalize whitespace.
     * Default: true.
     */
    readonly normalizeWhitespace: boolean;

    /**
     * Patterns to exclude by ID.
     */
    readonly excludePatterns?: readonly string[];

    /**
     * Additional patterns to include.
     */
    readonly additionalPatterns?: readonly DetectionPattern[];

    /**
     * Custom confidence scoring weights.
     */
    readonly weights?: Readonly<Record<string, number>>;
}

// ── Detection Engine Registry ───────────────────────────────

/**
 * Registry for detection engines. Allows composition of
 * multiple engines for comprehensive coverage.
 */
export interface DetectionEngineRegistry {
    /** Register an engine. */
    register(engine: DetectionEngine): void;

    /** Get engine by ID. */
    get(id: string): DetectionEngine | undefined;

    /** Get all engines. */
    getAll(): readonly DetectionEngine[];

    /** Get engines by category. */
    getByCategory(category: DetectionCategory): readonly DetectionEngine[];

    /**
     * Analyze input against all registered engines.
     * Returns aggregated results.
     */
    analyzeAll(input: string, context?: DetectionContext): readonly DetectionResult[];

    /**
     * Analyze input against engines in a specific category.
     */
    analyzeByCategory(
        input: string,
        category: DetectionCategory,
        context?: DetectionContext,
    ): readonly DetectionResult[];
}

// ── Scoring for player-written rules ────────────────────────

/**
 * Measures the quality of player-written detection rules
 * against a test corpus of known-good and known-bad inputs.
 */
export interface RuleScoringResult {
    /** True positive rate (sensitivity). */
    readonly truePositiveRate: number;

    /** True negative rate (specificity). */
    readonly trueNegativeRate: number;

    /** False positive rate. */
    readonly falsePositiveRate: number;

    /** False negative rate. */
    readonly falseNegativeRate: number;

    /** F1 score (harmonic mean of precision and recall). */
    readonly f1Score: number;

    /** Total inputs tested. */
    readonly totalInputs: number;

    /** Breakdown of results. */
    readonly breakdown: {
        readonly truePositives: number;
        readonly trueNegatives: number;
        readonly falsePositives: number;
        readonly falseNegatives: number;
    };
}

/**
 * A test corpus entry — input paired with expected classification.
 */
export interface TestCorpusEntry {
    /** The input string. */
    readonly input: string;

    /** Whether this input is malicious (true) or benign (false). */
    readonly malicious: boolean;

    /** Category of attack (if malicious). */
    readonly category?: DetectionCategory;

    /** Description/source of this test case. */
    readonly description?: string;

    /** Difficulty of detecting this case. */
    readonly difficulty?: 'easy' | 'medium' | 'hard' | 'expert';
}
