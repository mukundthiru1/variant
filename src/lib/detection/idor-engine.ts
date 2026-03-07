/**
 * VARIANT — IDOR Detection Engine
 *
 * Detects insecure direct object reference patterns and parameter tampering.
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
    'idor/object-id-parameter': ['T1190'],
    'idor/sequential-id': ['T1087', 'T1190'],
    'idor/uuid-parameter': ['T1190'],
    'idor/parameter-tampering': ['T1565', 'T1190'],
    'idor/ownership-mismatch': ['T1078', 'T1190'],
    'idor/bulk-object-enumeration': ['T1087', 'T1190'],
};

const CWE_BY_PATTERN: Record<string, readonly string[]> = {
    'idor/object-id-parameter': ['CWE-639'],
    'idor/sequential-id': ['CWE-639'],
    'idor/uuid-parameter': ['CWE-639'],
    'idor/parameter-tampering': ['CWE-472', 'CWE-639'],
    'idor/ownership-mismatch': ['CWE-285', 'CWE-639'],
    'idor/bulk-object-enumeration': ['CWE-200', 'CWE-639'],
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

function createIDORPatterns(): DetectionPattern[] {
    return [
        {
            id: 'idor/object-id-parameter',
            name: 'Direct Object ID Parameter',
            pattern: '(?:^|[?&/])(?:id|user_id|account_id|order_id|invoice_id|profile_id)=\\d{1,12}(?:$|[&#])',
            type: 'regex',
            severity: 'medium',
            description: 'Direct object identifier exposed in request parameters',
            enabled: true,
            tags: ['identifier', 'parameter'],
        },
        {
            id: 'idor/sequential-id',
            name: 'Sequential Numeric ID',
            pattern: '(?:/|=)(?:[1-9]\\d{0,8})(?:$|[/?&#])',
            type: 'regex',
            severity: 'high',
            description: 'Potentially enumerable sequential numeric object ID',
            enabled: true,
            tags: ['enumeration'],
        },
        {
            id: 'idor/uuid-parameter',
            name: 'UUID Object Reference',
            pattern: '(?:id|uuid|object|resource)[=_/:]([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})',
            type: 'regex',
            severity: 'medium',
            description: 'UUID object reference potentially vulnerable to authorization bypass',
            enabled: true,
            tags: ['uuid'],
        },
        {
            id: 'idor/parameter-tampering',
            name: 'Parameter Tampering Keywords',
            pattern: '(?:role|is_admin|account_type|owner|user|tenant)\\s*[:=]\\s*(?:admin|true|1|root|other)',
            type: 'regex',
            severity: 'high',
            description: 'Privilege or ownership parameter tampering attempt',
            enabled: true,
            tags: ['tampering'],
        },
        {
            id: 'idor/ownership-mismatch',
            name: 'Ownership Mismatch Indicators',
            pattern: '(?:userId|ownerId|accountId)\\s*[:=]\\s*["\']?\\d+["\']?\\s*[,;&]\\s*(?:requesterId|sessionUser|authUser)\\s*[:=]\\s*["\']?\\d+["\']?',
            type: 'regex',
            severity: 'critical',
            description: 'Input includes different target and authenticated user identifiers',
            enabled: true,
            tags: ['authorization'],
        },
        {
            id: 'idor/bulk-object-enumeration',
            name: 'Bulk Object Enumeration',
            pattern: '(?:range|start|offset|page|limit)\\s*[:=]\\s*(?:\\d{1,6})',
            type: 'regex',
            severity: 'low',
            description: 'Bulk traversal parameter that can aid object enumeration',
            enabled: true,
            tags: ['enumeration'],
        },
    ];
}

export function createIDOREngine(configOverrides?: Partial<DetectionEngineConfig>): DetectionEngine {
    const config = defaultConfig(configOverrides);
    const excludeSet = new Set(config.excludePatterns ?? []);

    const patterns: DetectionPattern[] = [];
    for (const p of createIDORPatterns()) {
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

    function analyzeInput(input: string): DetectionResult {
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

        applyIDORHeuristics(processed, matches);

        const confidence = calculateConfidence(matches, processed, config);
        const detected = confidence >= config.confidenceThreshold && matches.length > 0;
        const mitreTechniques = collectMappedValues(matches, MITRE_BY_PATTERN);
        const cweIds = collectMappedValues(matches, CWE_BY_PATTERN);

        return {
            detected,
            confidence,
            matches,
            explanation: detected
                ? `IDOR risk detected: ${matches.map(m => m.description).join('; ')}. CWE: ${cweIds.join(', ')}`
                : 'No IDOR patterns detected',
            ...(detected && mitreTechniques.length > 0 ? { mitreTechniques } : {}),
            category: 'idor',
            ...(detected && cweIds.length > 0 ? { subCategory: `cwe:${cweIds.join('|')}` } : {}),
        };
    }

    const engine: DetectCapableEngine = {
        id: 'idor-detection',
        category: 'idor',
        version: '1.0.0',
        description: 'IDOR detection engine for direct object identifiers, parameter tampering, and enumeration',

        analyze(input: string, _context?: DetectionContext): DetectionResult {
            return analyzeInput(input);
        },

        detect(input: string, context?: DetectionContext): DetectionResult[] {
            void context;
            return [analyzeInput(input)];
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

function applyIDORHeuristics(input: string, matches: PatternMatch[]): void {
    const idPairs = [...input.matchAll(/(?:^|[?&])(?:id|user_id|account_id)=(\d{1,12})/gi)].map(m => Number(m[1]));
    if (idPairs.length > 1) {
        let sequential = true;
        for (let i = 1; i < idPairs.length; i++) {
            const current = idPairs[i];
            const previous = idPairs[i - 1];
            if (current === undefined || previous === undefined) {
                sequential = false;
                break;
            }
            if (Math.abs(current - previous) > 1) {
                sequential = false;
                break;
            }
        }
        if (sequential) {
            matches.push({
                patternId: 'idor/sequential-id',
                matchedText: idPairs.join(','),
                offset: 0,
                severity: 'critical',
                description: 'Multiple sequential object IDs suggest enumeration/tampering',
            });
        }
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
        for (const value of mapped) values.add(value);
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
