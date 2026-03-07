/**
 * VARIANT — File Upload Detection Engine
 *
 * Detects dangerous file-upload payload patterns and bypass tricks.
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
    'upload/double-extension': ['T1190', 'T1505'],
    'upload/executable-extension': ['T1505', 'T1059'],
    'upload/mime-mismatch': ['T1036', 'T1190'],
    'upload/polyglot-header': ['T1027', 'T1190'],
    'upload/path-traversal-filename': ['T1190'],
    'upload/null-byte-truncation': ['T1036', 'T1190'],
    'upload/archive-slip': ['T1190'],
};

const CWE_BY_PATTERN: Record<string, readonly string[]> = {
    'upload/double-extension': ['CWE-434', 'CWE-436'],
    'upload/executable-extension': ['CWE-434'],
    'upload/mime-mismatch': ['CWE-436', 'CWE-434'],
    'upload/polyglot-header': ['CWE-434', 'CWE-173'],
    'upload/path-traversal-filename': ['CWE-22', 'CWE-73'],
    'upload/null-byte-truncation': ['CWE-158', 'CWE-434'],
    'upload/archive-slip': ['CWE-22', 'CWE-434'],
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

function createFileUploadPatterns(): DetectionPattern[] {
    return [
        {
            id: 'upload/double-extension',
            name: 'Double Extension Upload',
            pattern: '\\.(?:php|asp|aspx|jsp|jspx|exe|sh|cgi)\\.(?:jpg|jpeg|png|gif|txt|pdf|docx?)\\b',
            type: 'regex',
            severity: 'critical',
            description: 'File upload with executable + benign double extension',
            enabled: true,
            tags: ['double-extension'],
        },
        {
            id: 'upload/executable-extension',
            name: 'Executable Web Extension',
            pattern: '\\.(?:php[0-9]?|phtml|phar|asp|aspx|jsp|jspx|war|cgi|pl|py|sh|exe)\\b',
            type: 'regex',
            severity: 'critical',
            description: 'Direct upload of executable/script extension',
            enabled: true,
            tags: ['extension'],
        },
        {
            id: 'upload/mime-mismatch',
            name: 'MIME-Type Mismatch',
            pattern: '(?:Content-Type\\s*:\\s*(?:image/(?:png|jpeg|gif)|text/plain)).{0,150}filename\\s*=\\s*"[^"]+\\.(?:php|jsp|aspx|exe|sh)"',
            type: 'regex',
            severity: 'high',
            description: 'Claimed benign MIME type with executable filename',
            enabled: true,
            tags: ['mime'],
        },
        {
            id: 'upload/polyglot-header',
            name: 'Polyglot File Header',
            pattern: '(?:GIF89a|\\x89PNG\\r\\n\\x1a\\n|PK\\x03\\x04).{0,80}(?:<\\?php|<script|<jsp:|<%|MZ)',
            type: 'regex',
            severity: 'critical',
            description: 'Polyglot file content mixing valid header and executable payload',
            enabled: true,
            tags: ['polyglot'],
        },
        {
            id: 'upload/path-traversal-filename',
            name: 'Path Traversal Filename',
            pattern: '(?:filename\\s*=\\s*"?[^"]*(?:\\.\\./|\\.\\.\\\\|/etc/passwd|C:\\\\Windows\\\\))',
            type: 'regex',
            severity: 'critical',
            description: 'Path traversal sequence in upload filename',
            enabled: true,
            tags: ['traversal'],
        },
        {
            id: 'upload/null-byte-truncation',
            name: 'Null Byte Truncation',
            pattern: '\\x00|%00',
            type: 'regex',
            severity: 'high',
            description: 'Null byte used to bypass extension validation',
            enabled: true,
            tags: ['null-byte'],
        },
        {
            id: 'upload/archive-slip',
            name: 'Archive Slip Path',
            pattern: '(?:^|\\n)(?:.*)(?:\\.\\./|\\.\\.\\\\).+\\.(?:php|jsp|aspx|sh|exe|dll)',
            type: 'regex',
            severity: 'high',
            description: 'ZipSlip/TarSlip path traversal inside archive entries',
            enabled: true,
            tags: ['archive', 'slip'],
        },
    ];
}

export function createFileUploadEngine(configOverrides?: Partial<DetectionEngineConfig>): DetectionEngine {
    const config = defaultConfig(configOverrides);
    const excludeSet = new Set(config.excludePatterns ?? []);

    const patterns: DetectionPattern[] = [];
    for (const p of createFileUploadPatterns()) {
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
            compiledPatterns.set(p.id, new RegExp(p.pattern, 'g'));
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

        applyFileUploadHeuristics(processed, matches);

        const confidence = calculateConfidence(matches, processed, config);
        const detected = confidence >= config.confidenceThreshold && matches.length > 0;
        const mitreTechniques = collectMappedValues(matches, MITRE_BY_PATTERN);
        const cweIds = collectMappedValues(matches, CWE_BY_PATTERN);

        return {
            detected,
            confidence,
            matches,
            explanation: detected
                ? `Dangerous upload pattern detected: ${matches.map(m => m.description).join('; ')}. CWE: ${cweIds.join(', ')}`
                : 'No dangerous file upload patterns detected',
            ...(detected && mitreTechniques.length > 0 ? { mitreTechniques } : {}),
            category: 'file-upload',
            ...(detected && cweIds.length > 0 ? { subCategory: `cwe:${cweIds.join('|')}` } : {}),
        };
    }

    const engine: DetectCapableEngine = {
        id: 'file-upload-detection',
        category: 'file-upload',
        version: '1.0.0',
        description: 'Dangerous file upload detection for extension bypasses, MIME mismatch, polyglots, and path traversal filenames',

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

function applyFileUploadHeuristics(input: string, matches: PatternMatch[]): void {
    const lowered = input.toLowerCase();
    if ((lowered.includes('content-type: image/') || lowered.includes('content-type: text/plain'))
        && /(filename\s*=\s*"?[^"]+\.(php|jsp|aspx|exe|sh))/i.test(input)) {
        matches.push({
            patternId: 'upload/mime-mismatch',
            matchedText: 'content-type/filename mismatch',
            offset: 0,
            severity: 'high',
            description: 'Declared MIME type mismatches dangerous filename extension',
        });
    }

    if (/(\.php\.|\.jsp\.|\.aspx\.)/i.test(input)) {
        matches.push({
            patternId: 'upload/double-extension',
            matchedText: 'double-extension indicator',
            offset: 0,
            severity: 'critical',
            description: 'Double extension indicates extension filter bypass attempt',
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
