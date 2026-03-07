/**
 * VARIANT — SSTI Detection Engine
 *
 * Detects server-side template injection payload patterns.
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
    'ssti/mustache-expression': ['T1190'],
    'ssti/jinja-control': ['T1190'],
    'ssti/el-expression': ['T1190'],
    'ssti/erb-tag': ['T1190'],
    'ssti/jinja-mro': ['T1190', 'T1059'],
    'ssti/twig-registerundefined': ['T1190', 'T1059'],
    'ssti/freemarker-exec': ['T1190', 'T1059'],
    'ssti/spring-expression': ['T1190', 'T1059'],
};

const CWE_BY_PATTERN: Record<string, readonly string[]> = {
    'ssti/mustache-expression': ['CWE-1336', 'CWE-94'],
    'ssti/jinja-control': ['CWE-1336'],
    'ssti/el-expression': ['CWE-917'],
    'ssti/erb-tag': ['CWE-94', 'CWE-1336'],
    'ssti/jinja-mro': ['CWE-94', 'CWE-1336'],
    'ssti/twig-registerundefined': ['CWE-94', 'CWE-1336'],
    'ssti/freemarker-exec': ['CWE-94', 'CWE-1336'],
    'ssti/spring-expression': ['CWE-917', 'CWE-94'],
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

function createSSTIPatterns(): DetectionPattern[] {
    return [
        {
            id: 'ssti/mustache-expression',
            name: 'Mustache/Jinja Expression',
            pattern: '\\{\\{[^}]{0,120}\\}\\}',
            type: 'regex',
            severity: 'medium',
            description: 'Double-curly template expression marker',
            enabled: true,
            tags: ['jinja2', 'twig', 'mustache'],
        },
        {
            id: 'ssti/jinja-control',
            name: 'Jinja/Twig Control Block',
            pattern: '\\{%(?:.|\\n){0,120}?%\\}',
            type: 'regex',
            severity: 'high',
            description: 'Template control block delimiters',
            enabled: true,
            tags: ['jinja2', 'twig'],
        },
        {
            id: 'ssti/el-expression',
            name: 'EL Expression',
            pattern: '\\\$\\{[^}]{1,120}\\}',
            type: 'regex',
            severity: 'high',
            description: 'Expression language injection syntax',
            enabled: true,
            tags: ['jsp', 'el', 'freemarker'],
        },
        {
            id: 'ssti/erb-tag',
            name: 'ERB Tag',
            pattern: '<%(?:=|-|#)?(?:.|\\n){0,120}?%>',
            type: 'regex',
            severity: 'high',
            description: 'Ruby ERB server-side template tag',
            enabled: true,
            tags: ['erb', 'ruby'],
        },
        {
            id: 'ssti/jinja-mro',
            name: 'Jinja2 MRO Gadget',
            pattern: '(?:__mro__|__subclasses__|cycler\\.__init__)',
            type: 'regex',
            severity: 'critical',
            description: 'Jinja2 object traversal primitives for RCE',
            enabled: true,
            tags: ['jinja2', 'gadget', 'rce'],
        },
        {
            id: 'ssti/twig-registerundefined',
            name: 'Twig registerUndefinedFilterCallback',
            pattern: 'registerUndefinedFilterCallback|getFilter\\s*\\(',
            type: 'regex',
            severity: 'critical',
            description: 'Twig callback abuse for command execution',
            enabled: true,
            tags: ['twig', 'rce'],
        },
        {
            id: 'ssti/freemarker-exec',
            name: 'Freemarker Execute Utility',
            pattern: '(?:freemarker\\.template\\.utility\\.Execute|\\?new\\s*\\()',
            type: 'regex',
            severity: 'critical',
            description: 'Freemarker Execute gadget invocation',
            enabled: true,
            tags: ['freemarker', 'rce'],
        },
        {
            id: 'ssti/spring-expression',
            name: 'Spring SPEL in Templates',
            pattern: 'T\\([^)]+\\)|new\\s+java\\.|Runtime\\.getRuntime\\s*\\(',
            type: 'regex',
            severity: 'critical',
            description: 'SPEL expression capable of Java method execution',
            enabled: true,
            tags: ['spel', 'java', 'rce'],
        },
    ];
}

export function createSSTIEngine(configOverrides?: Partial<DetectionEngineConfig>): DetectionEngine {
    const config = defaultConfig(configOverrides);
    const excludeSet = new Set(config.excludePatterns ?? []);

    const patterns: DetectionPattern[] = [];
    for (const p of createSSTIPatterns()) {
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
                ? `SSTI detected: ${matches.map(m => m.description).join('; ')}. CWE: ${cweIds.join(', ')}`
                : 'No SSTI patterns detected',
            ...(detected && mitreTechniques.length > 0 ? { mitreTechniques } : {}),
            category: 'ssti',
            ...(detected && cweIds.length > 0 ? { subCategory: `cwe:${cweIds.join('|')}` } : {}),
        };
    }

    const engine: DetectCapableEngine = {
        id: 'ssti-detection',
        category: 'ssti',
        version: '1.0.0',
        description: 'Server-side template injection detection for Jinja2, Twig, ERB, EL, and Freemarker',

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
