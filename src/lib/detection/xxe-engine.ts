/**
 * VARIANT — XXE Detection Engine
 *
 * Detects XML External Entity injection payload patterns.
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
    'xxe/entity': ['T1190'],
    'xxe/system': ['T1190'],
    'xxe/public': ['T1190'],
    'xxe/file-scheme': ['T1005', 'T1190'],
    'xxe/expect-scheme': ['T1059', 'T1190'],
    'xxe/parameter-entity': ['T1190'],
    'xxe/doctype-external': ['T1190'],
    'xxe/oob-http': ['T1041', 'T1190'],
};

const CWE_BY_PATTERN: Record<string, readonly string[]> = {
    'xxe/entity': ['CWE-611'],
    'xxe/system': ['CWE-611'],
    'xxe/public': ['CWE-611'],
    'xxe/file-scheme': ['CWE-611', 'CWE-827'],
    'xxe/expect-scheme': ['CWE-611'],
    'xxe/parameter-entity': ['CWE-611'],
    'xxe/doctype-external': ['CWE-611'],
    'xxe/oob-http': ['CWE-611', 'CWE-918'],
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

function createXXEPatterns(): DetectionPattern[] {
    return [
        {
            id: 'xxe/entity',
            name: 'XML Entity Declaration',
            pattern: '<!ENTITY\\s+[^>]+>',
            type: 'regex',
            severity: 'high',
            description: 'DTD entity declaration used in XXE payloads',
            enabled: true,
            tags: ['dtd', 'entity'],
        },
        {
            id: 'xxe/system',
            name: 'SYSTEM External Entity',
            pattern: '<!ENTITY\\s+[^>]*\\sSYSTEM\\s+["\'][^"\']+["\']',
            type: 'regex',
            severity: 'critical',
            description: 'SYSTEM external entity declaration',
            enabled: true,
            tags: ['dtd', 'external-entity'],
        },
        {
            id: 'xxe/public',
            name: 'PUBLIC External Entity',
            pattern: '<!ENTITY\\s+[^>]*\\sPUBLIC\\s+["\'][^"\']+["\']',
            type: 'regex',
            severity: 'high',
            description: 'PUBLIC external entity declaration',
            enabled: true,
            tags: ['dtd', 'external-entity'],
        },
        {
            id: 'xxe/file-scheme',
            name: 'file:// Entity Reference',
            pattern: 'file://(?:/[\\w.\\-]+)+',
            type: 'regex',
            severity: 'critical',
            description: 'External entity attempting local file access',
            enabled: true,
            tags: ['file-read'],
        },
        {
            id: 'xxe/expect-scheme',
            name: 'expect:// Entity Reference',
            pattern: 'expect://[^\"\'\\s>]+',
            type: 'regex',
            severity: 'critical',
            description: 'PHP expect:// wrapper usage for code execution via XXE',
            enabled: true,
            tags: ['rce', 'wrapper'],
        },
        {
            id: 'xxe/parameter-entity',
            name: 'Parameter Entity Expansion',
            pattern: '<!ENTITY\\s+%\\s+\\w+\\s+SYSTEM\\s+["\'][^"\']+["\']',
            type: 'regex',
            severity: 'critical',
            description: 'Parameter entity for chained XXE expansion',
            enabled: true,
            tags: ['parameter-entity'],
        },
        {
            id: 'xxe/doctype-external',
            name: 'DOCTYPE with External Subset',
            pattern: '<!DOCTYPE\\s+[^>]+\\s(?:SYSTEM|PUBLIC)\\s+["\'][^"\']+["\']',
            type: 'regex',
            severity: 'high',
            description: 'DOCTYPE declaration loading external DTD subset',
            enabled: true,
            tags: ['doctype'],
        },
        {
            id: 'xxe/oob-http',
            name: 'Out-of-Band Entity URL',
            pattern: '(?:https?|ftp)://[^\"\'\\s>]+',
            type: 'regex',
            severity: 'medium',
            description: 'External URL reference in XML payload (potential OOB XXE)',
            enabled: true,
            tags: ['oob', 'exfiltration'],
        },
    ];
}

export function createXXEEngine(configOverrides?: Partial<DetectionEngineConfig>): DetectionEngine {
    const config = defaultConfig(configOverrides);
    const excludeSet = new Set(config.excludePatterns ?? []);

    const patterns: DetectionPattern[] = [];
    for (const p of createXXEPatterns()) {
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

        const confidence = calculateConfidence(matches, processed, config);
        const detected = confidence >= config.confidenceThreshold && matches.length > 0;
        const mitreTechniques = collectMappedValues(matches, MITRE_BY_PATTERN);
        const cweIds = collectMappedValues(matches, CWE_BY_PATTERN);

        return {
            detected,
            confidence,
            matches,
            explanation: detected
                ? `XXE detected: ${matches.map(m => m.description).join('; ')}. CWE: ${cweIds.join(', ')}`
                : 'No XXE patterns detected',
            ...(detected && mitreTechniques.length > 0 ? { mitreTechniques } : {}),
            category: 'xxe',
            ...(detected && cweIds.length > 0 ? { subCategory: `cwe:${cweIds.join('|')}` } : {}),
        };
    }

    const engine: DetectCapableEngine = {
        id: 'xxe-detection',
        category: 'xxe',
        version: '1.0.0',
        description: 'XML External Entity detection engine for DTD entity abuse, local file inclusion, and OOB references',

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
