/**
 * VARIANT — SQL Injection Detection Engine
 *
 * Detects SQL injection patterns across multiple SQL dialects.
 * Used for:
 *   1. Evaluating player-written detection rules (VARIANT training)
 *   2. Scoring player payloads for sophistication
 *   3. Powering the SIEM engine's SQLi detection rules
 *
 * CONFIGURABILITY:
 *   - Sensitivity levels control pattern strictness
 *   - Pattern sets are extensible (add/exclude individual patterns)
 *   - URL decoding, normalization, and recursion depth are configurable
 *   - Confidence weights are tunable per-pattern
 *
 * SWAPPABILITY: Implements DetectionEngine. Replace this file.
 */

import type {
    DetectionEngine,
    DetectionResult,
    DetectionContext,
    DetectionPattern,
    DetectionEngineConfig,
    PatternMatch,
} from './types';

// ── Default Config ──────────────────────────────────────────

const SENSITIVITY_THRESHOLDS: Record<string, number> = {
    'low': 0.8,
    'medium': 0.5,
    'high': 0.3,
    'paranoid': 0.1,
};

function defaultConfig(overrides?: Partial<DetectionEngineConfig>): DetectionEngineConfig {
    const sensitivity = overrides?.sensitivity ?? 'medium';
    return {
        sensitivity,
        confidenceThreshold: overrides?.confidenceThreshold ?? SENSITIVITY_THRESHOLDS[sensitivity] ?? 0.5,
        maxInputLength: overrides?.maxInputLength ?? 65536,
        decodeUrl: overrides?.decodeUrl ?? true,
        normalizeWhitespace: overrides?.normalizeWhitespace ?? true,
        ...(overrides?.excludePatterns !== undefined ? { excludePatterns: overrides.excludePatterns } : {}),
        ...(overrides?.additionalPatterns !== undefined ? { additionalPatterns: overrides.additionalPatterns } : {}),
        ...(overrides?.weights !== undefined ? { weights: overrides.weights } : {}),
    };
}

// ── Built-in SQLi Patterns ──────────────────────────────────

function createSQLiPatterns(): DetectionPattern[] {
    return [
        // ── Classic injection ─────────────────────────────
        {
            id: 'sqli/union-select',
            name: 'UNION SELECT',
            pattern: '\\bunion\\s+(all\\s+)?select\\b',
            type: 'regex',
            severity: 'critical',
            description: 'UNION-based SQL injection to extract data from other tables',
            enabled: true,
            tags: ['classic', 'union'],
        },
        {
            id: 'sqli/or-true',
            name: 'OR 1=1',
            pattern: "\\bor\\s+['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d+['\"]?",
            type: 'regex',
            severity: 'high',
            description: 'Boolean-based always-true condition for auth bypass',
            enabled: true,
            tags: ['classic', 'boolean'],
        },
        {
            id: 'sqli/or-string-true',
            name: "OR 'a'='a'",
            pattern: "\\bor\\s+['\"][^'\"]+['\"]\\s*=\\s*['\"][^'\"]+['\"]",
            type: 'regex',
            severity: 'high',
            description: 'String-based always-true condition',
            enabled: true,
            tags: ['classic', 'boolean'],
        },
        {
            id: 'sqli/comment-terminate',
            name: 'Comment Termination',
            pattern: "(?:--|#|/\\*)[\\s\\S]*$",
            type: 'regex',
            severity: 'medium',
            description: 'SQL comment used to terminate query',
            enabled: true,
            tags: ['classic', 'comment'],
        },
        {
            id: 'sqli/single-quote-escape',
            name: 'Single Quote Injection',
            pattern: "(?:^|\\s|=)['\"]\\s*(?:or|and|union|select|insert|update|delete|drop|exec|execute)",
            type: 'regex',
            severity: 'high',
            description: 'Quote followed by SQL keyword',
            enabled: true,
            tags: ['classic', 'quote'],
        },

        // ── Stacked queries ───────────────────────────────
        {
            id: 'sqli/stacked-query',
            name: 'Stacked Query',
            pattern: ";\\s*(?:select|insert|update|delete|drop|alter|create|exec|execute|declare|xp_)\\b",
            type: 'regex',
            severity: 'critical',
            description: 'Semicolon followed by SQL statement (stacked query)',
            enabled: true,
            tags: ['stacked'],
        },

        // ── Time-based blind ──────────────────────────────
        {
            id: 'sqli/sleep',
            name: 'SLEEP/WAITFOR',
            pattern: '\\b(?:sleep|waitfor\\s+delay|benchmark|pg_sleep)\\s*\\(',
            type: 'regex',
            severity: 'high',
            description: 'Time-based blind SQL injection via delay functions',
            enabled: true,
            tags: ['blind', 'time'],
        },

        // ── Error-based ───────────────────────────────────
        {
            id: 'sqli/extractvalue',
            name: 'EXTRACTVALUE/UPDATEXML',
            pattern: '\\b(?:extractvalue|updatexml|xmltype)\\s*\\(',
            type: 'regex',
            severity: 'high',
            description: 'Error-based injection via XML functions',
            enabled: true,
            tags: ['error-based'],
        },

        // ── Information schema ────────────────────────────
        {
            id: 'sqli/information-schema',
            name: 'Information Schema Access',
            pattern: '\\binformation_schema\\b',
            type: 'regex',
            severity: 'high',
            description: 'Accessing information_schema for database enumeration',
            enabled: true,
            tags: ['enumeration'],
        },

        // ── Destructive ───────────────────────────────────
        {
            id: 'sqli/drop-table',
            name: 'DROP TABLE',
            pattern: '\\bdrop\\s+(?:table|database|schema)\\b',
            type: 'regex',
            severity: 'critical',
            description: 'Attempting to drop database objects',
            enabled: true,
            tags: ['destructive'],
        },

        // ── Function-based ────────────────────────────────
        {
            id: 'sqli/concat',
            name: 'CONCAT/GROUP_CONCAT',
            pattern: '\\b(?:concat|group_concat|concat_ws)\\s*\\(',
            type: 'regex',
            severity: 'medium',
            description: 'String concatenation functions (data extraction)',
            enabled: true,
            tags: ['function'],
        },
        {
            id: 'sqli/load-file',
            name: 'LOAD_FILE/INTO OUTFILE',
            pattern: '\\b(?:load_file|into\\s+(?:out|dump)file)\\b',
            type: 'regex',
            severity: 'critical',
            description: 'File read/write via SQL',
            enabled: true,
            tags: ['file-access'],
        },

        // ── Encoding evasion ──────────────────────────────
        {
            id: 'sqli/hex-encoding',
            name: 'Hex Encoding',
            pattern: '0x[0-9a-fA-F]{4,}',
            type: 'regex',
            severity: 'medium',
            description: 'Hex-encoded values (potential evasion)',
            enabled: true,
            tags: ['evasion', 'encoding'],
        },
        {
            id: 'sqli/char-function',
            name: 'CHAR() Function',
            pattern: '\\bchar\\s*\\(\\s*\\d+(?:\\s*,\\s*\\d+)*\\s*\\)',
            type: 'regex',
            severity: 'medium',
            description: 'CHAR() function for encoding evasion',
            enabled: true,
            tags: ['evasion', 'encoding'],
        },

        // ── Conditional ───────────────────────────────────
        {
            id: 'sqli/case-when',
            name: 'CASE WHEN (Blind)',
            pattern: '\\bcase\\s+when\\b.*\\bthen\\b',
            type: 'regex',
            severity: 'medium',
            description: 'CASE WHEN conditional (blind injection)',
            enabled: true,
            tags: ['blind', 'conditional'],
        },
        {
            id: 'sqli/if-function',
            name: 'IF() Function (Blind)',
            pattern: '\\bif\\s*\\(.*,.*,.*\\)',
            type: 'regex',
            severity: 'medium',
            description: 'IF() conditional (blind injection)',
            enabled: true,
            tags: ['blind', 'conditional'],
        },

        // ── NoSQL injection ───────────────────────────────
        {
            id: 'sqli/nosql-operator',
            name: 'NoSQL Operator Injection',
            pattern: '\\$(?:gt|gte|lt|lte|ne|in|nin|regex|where|exists|type)\\b',
            type: 'regex',
            severity: 'high',
            description: 'MongoDB/NoSQL operator injection',
            enabled: true,
            tags: ['nosql'],
        },
    ];
}

// ── SQLi Engine ─────────────────────────────────────────────

export function createSQLiEngine(configOverrides?: Partial<DetectionEngineConfig>): DetectionEngine {
    const config = defaultConfig(configOverrides);
    const excludeSet = new Set(config.excludePatterns ?? []);

    // Build active pattern set
    const patterns: DetectionPattern[] = [];
    for (const p of createSQLiPatterns()) {
        if (!excludeSet.has(p.id)) {
            patterns.push(p);
        }
    }
    if (config.additionalPatterns !== undefined) {
        for (const p of config.additionalPatterns) {
            if (!excludeSet.has(p.id)) {
                patterns.push(p);
            }
        }
    }

    // Pre-compile regex patterns
    const compiledPatterns = new Map<string, RegExp>();
    for (const p of patterns) {
        if (p.type === 'regex' && p.enabled) {
            compiledPatterns.set(p.id, new RegExp(p.pattern, 'gi'));
        }
    }

    function preprocess(input: string): string {
        let processed = input;

        // Truncate
        if (processed.length > config.maxInputLength) {
            processed = processed.slice(0, config.maxInputLength);
        }

        // URL decode (recursive to handle double encoding)
        if (config.decodeUrl) {
            for (let i = 0; i < 3; i++) {
                const decoded = decodeURIComponentSafe(processed);
                if (decoded === processed) break;
                processed = decoded;
            }
        }

        // Normalize whitespace
        if (config.normalizeWhitespace) {
            processed = processed.replace(/\s+/g, ' ');
        }

        return processed;
    }

    const engine: DetectionEngine = {
        id: 'sqli-detection',
        category: 'sqli',
        version: '1.0.0',
        description: 'SQL injection detection engine covering UNION, blind, time-based, error-based, and NoSQL injection patterns',

        analyze(input: string, _context?: DetectionContext): DetectionResult {
            const processed = preprocess(input);
            const matches: PatternMatch[] = [];

            for (const pattern of patterns) {
                if (!pattern.enabled) continue;

                if (pattern.type === 'regex') {
                    const regex = compiledPatterns.get(pattern.id);
                    if (regex === undefined) continue;

                    // Reset lastIndex for global regex
                    regex.lastIndex = 0;
                    let match: RegExpExecArray | null;

                    while ((match = regex.exec(processed)) !== null) {
                        matches.push({
                            patternId: pattern.id,
                            matchedText: match[0],
                            offset: match.index,
                            severity: pattern.severity,
                            description: pattern.description,
                        });
                        // Prevent infinite loops on zero-length matches
                        if (match[0].length === 0) break;
                    }
                } else if (pattern.type === 'literal') {
                    const lower = processed.toLowerCase();
                    const search = pattern.pattern.toLowerCase();
                    let idx = lower.indexOf(search);
                    while (idx !== -1) {
                        matches.push({
                            patternId: pattern.id,
                            matchedText: processed.slice(idx, idx + search.length),
                            offset: idx,
                            severity: pattern.severity,
                            description: pattern.description,
                        });
                        idx = lower.indexOf(search, idx + 1);
                    }
                }
            }

            // Calculate confidence
            const confidence = calculateConfidence(matches, processed, config);
            const detected = confidence >= config.confidenceThreshold && matches.length > 0;

            return {
                detected,
                confidence,
                matches,
                explanation: detected
                    ? `SQL injection detected: ${matches.map(m => m.description).join('; ')}`
                    : 'No SQL injection patterns detected',
                ...(detected ? { mitreTechniques: ['T1190'] } : {}),
                category: 'sqli',
            };
        },

        getPatterns(): readonly DetectionPattern[] {
            return [...patterns];
        },

        getConfig(): DetectionEngineConfig {
            return config;
        },
    };

    return engine;
}

// ── Confidence Calculation ──────────────────────────────────

function calculateConfidence(
    matches: readonly PatternMatch[],
    input: string,
    config: DetectionEngineConfig,
): number {
    if (matches.length === 0) return 0;

    const weights = config.weights ?? {};

    // Base confidence from severity
    const severityWeights: Record<string, number> = {
        'info': 0.1,
        'low': 0.2,
        'medium': 0.4,
        'high': 0.7,
        'critical': 0.9,
    };

    let maxSeverityScore = 0;
    let totalScore = 0;
    const uniquePatterns = new Set<string>();

    for (const match of matches) {
        const patternWeight = weights[match.patternId] ?? 1.0;
        const severityScore = (severityWeights[match.severity] ?? 0.3) * patternWeight;

        if (severityScore > maxSeverityScore) {
            maxSeverityScore = severityScore;
        }
        totalScore += severityScore;
        uniquePatterns.add(match.patternId);
    }

    // Multiple different pattern matches increase confidence
    const diversityBonus = Math.min(0.3, (uniquePatterns.size - 1) * 0.1);

    // Longer inputs with matches are more suspicious
    const lengthFactor = input.length > 10 ? 1.0 : 0.7;

    const confidence = Math.min(1.0, (maxSeverityScore + diversityBonus) * lengthFactor);
    void totalScore; // Reserved for future weighted scoring

    return Math.round(confidence * 100) / 100;
}

// ── URL Decode (safe) ───────────────────────────────────────

function decodeURIComponentSafe(str: string): string {
    try {
        return decodeURIComponent(str);
    } catch {
        return str;
    }
}
