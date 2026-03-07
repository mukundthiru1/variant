/**
 * VARIANT — CSRF Detection Engine
 *
 * Detects missing or weak CSRF protections in request and cookie data.
 */

import type {
    DetectionEngine,
    DetectionResult,
    DetectionContext,
    DetectionPattern,
    DetectionEngineConfig,
    PatternMatch,
} from './types';

type DetectCapableEngine = DetectionEngine & {
    detect(input: string, context?: DetectionContext): DetectionResult[];
};

const SENSITIVITY_THRESHOLDS: Record<string, number> = {
    'low': 0.8,
    'medium': 0.5,
    'high': 0.3,
    'paranoid': 0.1,
};

const MITRE_BY_PATTERN: Record<string, readonly string[]> = {
    'csrf/state-changing-method': ['T1190'],
    'csrf/missing-token': ['T1190'],
    'csrf/weak-token': ['T1190'],
    'csrf/cookie-samesite-none': ['T1539', 'T1190'],
    'csrf/cookie-samesite-missing': ['T1539', 'T1190'],
    'csrf/origin-bypass': ['T1190'],
    'csrf/referer-bypass': ['T1190'],
};

const CWE_BY_PATTERN: Record<string, readonly string[]> = {
    'csrf/state-changing-method': ['CWE-352'],
    'csrf/missing-token': ['CWE-352'],
    'csrf/weak-token': ['CWE-352', 'CWE-330'],
    'csrf/cookie-samesite-none': ['CWE-1275', 'CWE-352'],
    'csrf/cookie-samesite-missing': ['CWE-1275', 'CWE-352'],
    'csrf/origin-bypass': ['CWE-346', 'CWE-352'],
    'csrf/referer-bypass': ['CWE-293', 'CWE-352'],
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

function createCSRFPaterns(): DetectionPattern[] {
    return [
        {
            id: 'csrf/state-changing-method',
            name: 'State-changing Method',
            pattern: '\\b(?:POST|PUT|PATCH|DELETE)\\b',
            type: 'regex',
            severity: 'medium',
            description: 'State-changing HTTP method requires CSRF defenses',
            enabled: true,
            tags: ['method'],
        },
        {
            id: 'csrf/missing-token',
            name: 'Missing CSRF Token Indicators',
            pattern: '(?:csrf|xsrf)[_-]?(?:token|key)\\s*[:=]\\s*(?:""|\'\'|null|undefined)',
            type: 'regex',
            severity: 'critical',
            description: 'CSRF token appears empty or missing',
            enabled: true,
            tags: ['token'],
        },
        {
            id: 'csrf/weak-token',
            name: 'Weak CSRF Token Pattern',
            pattern: '(?:csrf|xsrf)[_-]?(?:token|key)\\s*[:=]\\s*["\']?[A-Za-z0-9]{1,8}["\']?',
            type: 'regex',
            severity: 'high',
            description: 'CSRF token is too short and likely guessable',
            enabled: true,
            tags: ['token'],
        },
        {
            id: 'csrf/cookie-samesite-none',
            name: 'SameSite=None Cookie',
            pattern: 'Set-Cookie:[^\\n]*(?:session|auth|token)[^\\n]*SameSite=None',
            type: 'regex',
            severity: 'high',
            description: 'Session/auth cookie explicitly allows cross-site requests',
            enabled: true,
            tags: ['cookie', 'samesite'],
        },
        {
            id: 'csrf/cookie-samesite-missing',
            name: 'Missing SameSite Attribute',
            pattern: 'Set-Cookie:[^\\n]*(?:session|auth|token)(?![^\\n]*SameSite)',
            type: 'regex',
            severity: 'high',
            description: 'Session/auth cookie missing SameSite protection',
            enabled: true,
            tags: ['cookie', 'samesite'],
        },
        {
            id: 'csrf/origin-bypass',
            name: 'Origin Validation Bypass',
            pattern: '(?:Origin|origin)\\s*[:=]\\s*(?:null|\\*|""|\'\')',
            type: 'regex',
            severity: 'critical',
            description: 'Origin validation can be bypassed with null/wildcard origin',
            enabled: true,
            tags: ['origin'],
        },
        {
            id: 'csrf/referer-bypass',
            name: 'Referer Validation Bypass',
            pattern: '(?:Referer|referer)\\s*[:=]\\s*(?:$|""|\'\'|https?://[^\\s]*@)',
            type: 'regex',
            severity: 'high',
            description: 'Weak referer validation pattern',
            enabled: true,
            tags: ['referer'],
        },
    ];
}

export function createCSRFAngine(configOverrides?: Partial<DetectionEngineConfig>): DetectionEngine {
    const config = defaultConfig(configOverrides);
    const excludeSet = new Set(config.excludePatterns ?? []);

    const patterns: DetectionPattern[] = [];
    for (const p of createCSRFPaterns()) {
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

    const compiledPatterns = new Map<string, RegExp>();
    for (const p of patterns) {
        if (p.type === 'regex' && p.enabled) {
            compiledPatterns.set(p.id, new RegExp(p.pattern, 'gi'));
        }
    }

    function preprocess(input: string): string {
        let processed = input;

        if (processed.length > config.maxInputLength) {
            processed = processed.slice(0, config.maxInputLength);
        }

        if (config.decodeUrl) {
            for (let i = 0; i < 3; i++) {
                const decoded = decodeURIComponentSafe(processed);
                if (decoded === processed) break;
                processed = decoded;
            }
        }

        if (config.normalizeWhitespace) {
            processed = processed.replace(/\s+/g, ' ');
        }

        return processed;
    }

    function analyzeInput(input: string, context?: DetectionContext): DetectionResult {
        const processed = preprocess(input);
        const matches: PatternMatch[] = [];

        for (const pattern of patterns) {
            if (!pattern.enabled) continue;
            if (pattern.type === 'regex') {
                const regex = compiledPatterns.get(pattern.id);
                if (regex === undefined) continue;
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
                    if (match[0].length === 0) break;
                }
            }
        }

        applyCSRFHeuristics(processed, context, matches);

        const confidence = calculateConfidence(matches, processed, config);
        const detected = confidence >= config.confidenceThreshold && matches.length > 0;
        const mitreTechniques = collectMappedValues(matches, MITRE_BY_PATTERN);
        const cweIds = collectMappedValues(matches, CWE_BY_PATTERN);

        return {
            detected,
            confidence,
            matches,
            explanation: detected
                ? `CSRF weakness detected: ${matches.map(m => m.description).join('; ')}. CWE: ${cweIds.join(', ')}`
                : 'No CSRF weakness patterns detected',
            ...(detected && mitreTechniques.length > 0 ? { mitreTechniques } : {}),
            category: 'csrf',
            ...(detected && cweIds.length > 0 ? { subCategory: `cwe:${cweIds.join('|')}` } : {}),
        };
    }

    const engine: DetectCapableEngine = {
        id: 'csrf-detection',
        category: 'csrf',
        version: '1.0.0',
        description: 'CSRF detection engine for missing tokens, weak SameSite, and origin/referer validation bypasses',

        analyze(input: string, context?: DetectionContext): DetectionResult {
            return analyzeInput(input, context);
        },

        detect(input: string, context?: DetectionContext): DetectionResult[] {
            return [analyzeInput(input, context)];
        },

        analyzeBatch(inputs: readonly string[]): readonly DetectionResult[] {
            return inputs.map(i => analyzeInput(i));
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

function applyCSRFHeuristics(input: string, context: DetectionContext | undefined, matches: PatternMatch[]): void {
    const method = (context?.method ?? '').toUpperCase();
    const maybeStateChanging = method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE';
    const lower = input.toLowerCase();
    const hasCsrfToken = /(csrf|xsrf)[_-]?(token|key)/.test(lower);

    if (maybeStateChanging && !hasCsrfToken) {
        matches.push({
            patternId: 'csrf/missing-token',
            matchedText: method,
            offset: 0,
            severity: 'critical',
            description: `State-changing request (${method}) without CSRF token evidence`,
        });
    }

    if (lower.includes('samesite=none') && !lower.includes('secure')) {
        matches.push({
            patternId: 'csrf/cookie-samesite-none',
            matchedText: 'SameSite=None',
            offset: lower.indexOf('samesite=none'),
            severity: 'critical',
            description: 'SameSite=None cookie missing Secure attribute',
        });
    }

    if (lower.includes('origin: null') || lower.includes('origin=*') || lower.includes('origin: *')) {
        matches.push({
            patternId: 'csrf/origin-bypass',
            matchedText: 'Origin bypass indicator',
            offset: Math.max(lower.indexOf('origin: null'), lower.indexOf('origin: *')),
            severity: 'critical',
            description: 'Origin validation bypass indicator detected',
        });
    }
}

function calculateConfidence(
    matches: readonly PatternMatch[],
    input: string,
    config: DetectionEngineConfig,
): number {
    if (matches.length === 0) return 0;

    const weights = config.weights ?? {};

    const severityWeights: Record<string, number> = {
        'info': 0.1,
        'low': 0.2,
        'medium': 0.4,
        'high': 0.7,
        'critical': 0.9,
    };

    let maxSeverityScore = 0;
    const uniquePatterns = new Set<string>();

    for (const match of matches) {
        const patternWeight = weights[match.patternId] ?? 1.0;
        const severityScore = (severityWeights[match.severity] ?? 0.3) * patternWeight;

        if (severityScore > maxSeverityScore) {
            maxSeverityScore = severityScore;
        }
        uniquePatterns.add(match.patternId);
    }

    const diversityBonus = Math.min(0.3, (uniquePatterns.size - 1) * 0.1);
    const lengthFactor = input.length > 10 ? 1.0 : 0.7;

    const confidence = Math.min(1.0, (maxSeverityScore + diversityBonus) * lengthFactor);
    return Math.round(confidence * 100) / 100;
}

function collectMappedValues(
    matches: readonly PatternMatch[],
    mapping: Record<string, readonly string[]>,
): string[] {
    const values = new Set<string>();
    for (const match of matches) {
        const mapped = mapping[match.patternId];
        if (mapped === undefined) continue;
        for (const value of mapped) {
            values.add(value);
        }
    }
    return [...values];
}

function decodeURIComponentSafe(str: string): string {
    try {
        return decodeURIComponent(str);
    } catch {
        return str;
    }
}
