/**
 * VARIANT — Insecure Deserialization Detection Engine
 *
 * Detects unsafe deserialization payload markers across ecosystems.
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
    'deser/java-serialization-magic': ['T1190', 'T1059'],
    'deser/java-gadget-chain': ['T1190', 'T1059'],
    'deser/pickle-opcode': ['T1190', 'T1059'],
    'deser/php-unserialize': ['T1190'],
    'deser/yaml-object-tag': ['T1190', 'T1059'],
    'deser/json-type-gadget': ['T1190', 'T1059'],
    'deser/dotnet-binaryformatter': ['T1190', 'T1059'],
};

const CWE_BY_PATTERN: Record<string, readonly string[]> = {
    'deser/java-serialization-magic': ['CWE-502'],
    'deser/java-gadget-chain': ['CWE-502', 'CWE-94'],
    'deser/pickle-opcode': ['CWE-502', 'CWE-94'],
    'deser/php-unserialize': ['CWE-502'],
    'deser/yaml-object-tag': ['CWE-502'],
    'deser/json-type-gadget': ['CWE-502'],
    'deser/dotnet-binaryformatter': ['CWE-502'],
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

function createDeserializationPatterns(): DetectionPattern[] {
    return [
        {
            id: 'deser/java-serialization-magic',
            name: 'Java Serialization Magic',
            pattern: '(?:\\xac\\xed\\x00\\x05|rO0AB)',
            type: 'regex',
            severity: 'critical',
            description: 'Java serialized stream magic bytes/base64 prefix',
            enabled: true,
            tags: ['java', 'serialized'],
        },
        {
            id: 'deser/java-gadget-chain',
            name: 'Java Gadget Chain Classes',
            pattern: '(?:InvokerTransformer|TemplatesImpl|ChainedTransformer|JdbcRowSetImpl)',
            type: 'regex',
            severity: 'critical',
            description: 'Known Java gadget chain classes used in deserialization exploits',
            enabled: true,
            tags: ['java', 'gadget'],
        },
        {
            id: 'deser/pickle-opcode',
            name: 'Python Pickle RCE Markers',
            pattern: '(?:__reduce__|c__builtin__\\n|cos\\nsystem\\n|pickle\\.loads)',
            type: 'regex',
            severity: 'critical',
            description: 'Pickle execution gadget markers',
            enabled: true,
            tags: ['python', 'pickle'],
        },
        {
            id: 'deser/php-unserialize',
            name: 'PHP unserialize Payload',
            pattern: '(?:^|[;{])(?:O|C):\\d+:"[^"]+":\\d+:[{]|unserialize\\s*\\(',
            type: 'regex',
            severity: 'high',
            description: 'PHP object deserialization payload or sink',
            enabled: true,
            tags: ['php'],
        },
        {
            id: 'deser/yaml-object-tag',
            name: 'YAML Object Tag',
            pattern: '!!(?:python/object|python/name|javax\\.|ruby/object|map:)',
            type: 'regex',
            severity: 'high',
            description: 'Unsafe YAML type tags allowing object construction',
            enabled: true,
            tags: ['yaml'],
        },
        {
            id: 'deser/json-type-gadget',
            name: 'JSON Type Gadget',
            pattern: '"(?:@type|\\$type|type)"\\s*:\\s*"(?:java\\.|com\\.|org\\.|System\\.|javax\\.)',
            type: 'regex',
            severity: 'high',
            description: 'Polymorphic type field potentially enabling gadget deserialization',
            enabled: true,
            tags: ['json'],
        },
        {
            id: 'deser/dotnet-binaryformatter',
            name: '.NET BinaryFormatter Markers',
            pattern: '(?:BinaryFormatter|LosFormatter|ObjectStateFormatter|AAEAAAD/////AQ)',
            type: 'regex',
            severity: 'critical',
            description: '.NET insecure formatter usage/payload marker',
            enabled: true,
            tags: ['dotnet'],
        },
    ];
}

export function createDeserializationEngine(configOverrides?: Partial<DetectionEngineConfig>): DetectionEngine {
    const config = defaultConfig(configOverrides);
    const excludeSet = new Set(config.excludePatterns ?? []);

    const patterns: DetectionPattern[] = [];
    for (const p of createDeserializationPatterns()) {
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
                ? `Insecure deserialization detected: ${matches.map(m => m.description).join('; ')}. CWE: ${cweIds.join(', ')}`
                : 'No insecure deserialization patterns detected',
            ...(detected && mitreTechniques.length > 0 ? { mitreTechniques } : {}),
            category: 'deserialization',
            ...(detected && cweIds.length > 0 ? { subCategory: `cwe:${cweIds.join('|')}` } : {}),
        };
    }

    const engine: DetectCapableEngine = {
        id: 'deserialization-detection',
        category: 'deserialization',
        version: '1.0.0',
        description: 'Insecure deserialization detection engine for Java, pickle, PHP, YAML, JSON gadgets, and .NET formatters',

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
