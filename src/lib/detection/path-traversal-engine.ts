/**
 * VARIANT — Path Traversal Detection Engine
 *
 * Detects directory traversal, LFI, and RFI patterns.
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

const SENSITIVITY_THRESHOLDS: Record<string, number> = {
    'low': 0.8, 'medium': 0.5, 'high': 0.3, 'paranoid': 0.1,
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

function createPathPatterns(): DetectionPattern[] {
    return [
        {
            id: 'path/dot-dot-slash',
            name: 'Directory Traversal (../)',
            pattern: '(?:\\.\\./){2,}',
            type: 'regex',
            severity: 'high',
            description: 'Multiple ../ sequences indicating path traversal',
            enabled: true,
            tags: ['traversal'],
        },
        {
            id: 'path/dot-dot-backslash',
            name: 'Directory Traversal (..\\)',
            pattern: '(?:\\.\\.\\\\){2,}',
            type: 'regex',
            severity: 'high',
            description: 'Windows-style path traversal',
            enabled: true,
            tags: ['traversal', 'windows'],
        },
        {
            id: 'path/encoded-traversal',
            name: 'Encoded Traversal',
            pattern: '(?:%2e%2e%2f|%2e%2e/|%2e%2e%5c|\\.\\.%2f|\\.\\.%5c)',
            type: 'regex',
            severity: 'high',
            description: 'URL-encoded directory traversal',
            enabled: true,
            tags: ['traversal', 'evasion'],
        },
        {
            id: 'path/double-encoded',
            name: 'Double Encoded Traversal',
            pattern: '%252e%252e%252f|%252e%252e/',
            type: 'regex',
            severity: 'critical',
            description: 'Double URL-encoded traversal (evasion)',
            enabled: true,
            tags: ['traversal', 'evasion'],
        },
        {
            id: 'path/null-byte',
            name: 'Null Byte Injection',
            pattern: '%00|\\x00',
            type: 'regex',
            severity: 'critical',
            description: 'Null byte injection to truncate file extension',
            enabled: true,
            tags: ['null-byte'],
        },
        {
            id: 'path/sensitive-files',
            name: 'Sensitive File Access',
            pattern: '(?:/etc/(?:passwd|shadow|hosts|resolv\\.conf|issue)|/proc/self|/proc/version|/var/log/|wp-config\\.php|\\.env|\\.git/)',
            type: 'regex',
            severity: 'high',
            description: 'Access to known sensitive files/directories',
            enabled: true,
            tags: ['lfi'],
        },
        {
            id: 'path/windows-sensitive',
            name: 'Windows Sensitive Files',
            pattern: '(?:boot\\.ini|win\\.ini|system32|windows\\\\system)',
            type: 'regex',
            severity: 'high',
            description: 'Access to Windows system files',
            enabled: true,
            tags: ['lfi', 'windows'],
        },
        {
            id: 'path/rfi-http',
            name: 'Remote File Inclusion',
            pattern: '(?:https?|ftp|php|data|expect|input|zip|phar)://',
            type: 'regex',
            severity: 'critical',
            description: 'Remote file inclusion via URL scheme',
            enabled: true,
            tags: ['rfi'],
        },
        {
            id: 'path/php-wrapper',
            name: 'PHP Wrapper',
            pattern: 'php://(?:filter|input|output|fd|memory|temp)',
            type: 'regex',
            severity: 'critical',
            description: 'PHP stream wrapper exploitation',
            enabled: true,
            tags: ['rfi', 'php'],
        },
        {
            id: 'path/absolute-unix',
            name: 'Absolute Unix Path',
            pattern: '^/(?:etc|var|usr|tmp|opt|proc|sys|dev|home|root)/',
            type: 'regex',
            severity: 'medium',
            description: 'Absolute Unix path in user input',
            enabled: true,
            tags: ['traversal'],
        },
        {
            id: 'path/absolute-windows',
            name: 'Absolute Windows Path',
            pattern: '^[A-Za-z]:\\\\',
            type: 'regex',
            severity: 'medium',
            description: 'Absolute Windows path in user input',
            enabled: true,
            tags: ['traversal', 'windows'],
        },
    ];
}

export function createPathTraversalEngine(configOverrides?: Partial<DetectionEngineConfig>): DetectionEngine {
    const config = defaultConfig(configOverrides);
    const excludeSet = new Set(config.excludePatterns ?? []);

    const patterns: DetectionPattern[] = [];
    for (const p of createPathPatterns()) {
        if (!excludeSet.has(p.id)) patterns.push(p);
    }
    if (config.additionalPatterns !== undefined) {
        for (const p of config.additionalPatterns) {
            if (!excludeSet.has(p.id)) patterns.push(p);
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
        return processed;
    }

    const engine: DetectionEngine = {
        id: 'path-traversal-detection',
        category: 'path-traversal',
        version: '1.0.0',
        description: 'Path traversal detection covering LFI, RFI, null byte, and encoding evasion',

        analyze(input: string, _context?: DetectionContext): DetectionResult {
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

            const confidence = calculateConfidence(matches, config);
            const detected = confidence >= config.confidenceThreshold && matches.length > 0;

            return {
                detected,
                confidence,
                matches,
                explanation: detected
                    ? `Path traversal detected: ${matches.map(m => m.description).join('; ')}`
                    : 'No path traversal patterns detected',
                ...(detected ? { mitreTechniques: ['T1083'] } : {}),
                category: 'path-traversal',
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

function calculateConfidence(
    matches: readonly PatternMatch[],
    config: DetectionEngineConfig,
): number {
    if (matches.length === 0) return 0;
    const weights = config.weights ?? {};
    const severityWeights: Record<string, number> = {
        'info': 0.1, 'low': 0.2, 'medium': 0.4, 'high': 0.7, 'critical': 0.9,
    };
    let maxScore = 0;
    const uniquePatterns = new Set<string>();
    for (const match of matches) {
        const w = weights[match.patternId] ?? 1.0;
        const s = (severityWeights[match.severity] ?? 0.3) * w;
        if (s > maxScore) maxScore = s;
        uniquePatterns.add(match.patternId);
    }
    const diversityBonus = Math.min(0.3, (uniquePatterns.size - 1) * 0.1);
    return Math.min(1.0, Math.round((maxScore + diversityBonus) * 100) / 100);
}

function decodeURIComponentSafe(str: string): string {
    try { return decodeURIComponent(str); } catch { return str; }
}
