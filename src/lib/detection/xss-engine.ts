/**
 * VARIANT — XSS Detection Engine
 *
 * Detects cross-site scripting patterns including reflected,
 * stored, DOM-based, and mutation-based XSS vectors.
 *
 * CONFIGURABILITY: Sensitivity, patterns, and confidence
 * weights are all tunable via DetectionEngineConfig.
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

// ── Built-in XSS Patterns ───────────────────────────────────

function createXSSPatterns(): DetectionPattern[] {
    return [
        // ── Script tags ───────────────────────────────────
        {
            id: 'xss/script-tag',
            name: 'Script Tag',
            pattern: '<\\s*script[^>]*>',
            type: 'regex',
            severity: 'critical',
            description: 'HTML script tag injection',
            enabled: true,
            tags: ['reflected', 'stored'],
        },
        {
            id: 'xss/script-close',
            name: 'Script Close Tag',
            pattern: '<\\s*/\\s*script\\s*>',
            type: 'regex',
            severity: 'high',
            description: 'Script closing tag (paired with opening)',
            enabled: true,
            tags: ['reflected', 'stored'],
        },

        // ── Event handlers ────────────────────────────────
        {
            id: 'xss/event-handler',
            name: 'Event Handler Attribute',
            pattern: '\\bon(?:error|load|click|mouseover|mouseout|focus|blur|submit|change|input|keydown|keyup|keypress|drag|drop|touchstart|animationend|webkittransitionend)\\s*=',
            type: 'regex',
            severity: 'high',
            description: 'HTML event handler attribute injection',
            enabled: true,
            tags: ['reflected', 'dom'],
        },

        // ── JavaScript URI ────────────────────────────────
        {
            id: 'xss/javascript-uri',
            name: 'JavaScript URI',
            pattern: 'javascript\\s*:',
            type: 'regex',
            severity: 'high',
            description: 'javascript: URI scheme',
            enabled: true,
            tags: ['reflected', 'dom'],
        },
        {
            id: 'xss/data-uri',
            name: 'Data URI with Script',
            pattern: 'data\\s*:\\s*(?:text/html|application/javascript)',
            type: 'regex',
            severity: 'high',
            description: 'Data URI with executable content type',
            enabled: true,
            tags: ['evasion'],
        },

        // ── DOM manipulation ──────────────────────────────
        {
            id: 'xss/document-write',
            name: 'document.write',
            pattern: 'document\\s*\\.\\s*write\\s*\\(',
            type: 'regex',
            severity: 'high',
            description: 'document.write() DOM manipulation',
            enabled: true,
            tags: ['dom'],
        },
        {
            id: 'xss/innerhtml',
            name: 'innerHTML',
            pattern: '\\.\\s*innerHTML\\s*=',
            type: 'regex',
            severity: 'high',
            description: 'innerHTML assignment (DOM XSS sink)',
            enabled: true,
            tags: ['dom'],
        },
        {
            id: 'xss/eval',
            name: 'eval()',
            pattern: '\\beval\\s*\\(',
            type: 'regex',
            severity: 'critical',
            description: 'eval() code execution',
            enabled: true,
            tags: ['dom', 'code-execution'],
        },
        {
            id: 'xss/function-constructor',
            name: 'Function Constructor',
            pattern: '\\bFunction\\s*\\(',
            type: 'regex',
            severity: 'critical',
            description: 'Function constructor (dynamic code execution)',
            enabled: true,
            tags: ['dom', 'code-execution'],
        },

        // ── HTML injection ────────────────────────────────
        {
            id: 'xss/img-tag',
            name: 'IMG Tag with Handler',
            pattern: '<\\s*img[^>]+on\\w+\\s*=',
            type: 'regex',
            severity: 'high',
            description: 'IMG tag with event handler',
            enabled: true,
            tags: ['reflected'],
        },
        {
            id: 'xss/svg-tag',
            name: 'SVG Tag',
            pattern: '<\\s*svg[^>]*(?:on\\w+|<\\s*script)',
            type: 'regex',
            severity: 'high',
            description: 'SVG tag with embedded script or event handler',
            enabled: true,
            tags: ['mutation'],
        },
        {
            id: 'xss/iframe-tag',
            name: 'Iframe Injection',
            pattern: '<\\s*iframe[^>]*>',
            type: 'regex',
            severity: 'high',
            description: 'Iframe injection',
            enabled: true,
            tags: ['reflected', 'stored'],
        },
        {
            id: 'xss/object-embed',
            name: 'Object/Embed Tag',
            pattern: '<\\s*(?:object|embed|applet)[^>]*>',
            type: 'regex',
            severity: 'high',
            description: 'Object/embed/applet tag injection',
            enabled: true,
            tags: ['reflected'],
        },

        // ── CSS-based ─────────────────────────────────────
        {
            id: 'xss/style-expression',
            name: 'CSS Expression',
            pattern: 'expression\\s*\\(|behavior\\s*:|moz-binding\\s*:',
            type: 'regex',
            severity: 'medium',
            description: 'CSS expression/behavior (legacy XSS)',
            enabled: true,
            tags: ['css'],
        },

        // ── Template injection ────────────────────────────
        {
            id: 'xss/template-literal',
            name: 'Template Literal',
            pattern: '\\$\\{[^}]+\\}',
            type: 'regex',
            severity: 'medium',
            description: 'Template literal injection',
            enabled: true,
            tags: ['template'],
        },
        {
            id: 'xss/angular-expression',
            name: 'Angular Expression',
            pattern: '\\{\\{[^}]+\\}\\}',
            type: 'regex',
            severity: 'medium',
            description: 'Angular template expression injection',
            enabled: true,
            tags: ['template', 'angular'],
        },

        // ── Encoding evasion ──────────────────────────────
        {
            id: 'xss/html-entity',
            name: 'HTML Entity Evasion',
            pattern: '&(?:#(?:x[0-9a-f]+|\\d+)|[a-z]+);',
            type: 'regex',
            severity: 'low',
            description: 'HTML entity (potential encoding evasion)',
            enabled: true,
            tags: ['evasion'],
        },
        {
            id: 'xss/unicode-escape',
            name: 'Unicode Escape',
            pattern: '\\\\u[0-9a-fA-F]{4}',
            type: 'regex',
            severity: 'low',
            description: 'Unicode escape sequence (potential evasion)',
            enabled: true,
            tags: ['evasion'],
        },
    ];
}

// ── XSS Engine ──────────────────────────────────────────────

export function createXSSEngine(configOverrides?: Partial<DetectionEngineConfig>): DetectionEngine {
    const config = defaultConfig(configOverrides);
    const excludeSet = new Set(config.excludePatterns ?? []);

    const patterns: DetectionPattern[] = [];
    for (const p of createXSSPatterns()) {
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
        // Decode HTML entities
        processed = decodeHTMLEntities(processed);

        if (config.normalizeWhitespace) {
            processed = processed.replace(/\s+/g, ' ');
        }
        return processed;
    }

    const engine: DetectionEngine = {
        id: 'xss-detection',
        category: 'xss',
        version: '1.0.0',
        description: 'XSS detection engine covering reflected, stored, DOM-based, and mutation-based vectors',

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

            const confidence = calculateXSSConfidence(matches, config);
            const detected = confidence >= config.confidenceThreshold && matches.length > 0;

            return {
                detected,
                confidence,
                matches,
                explanation: detected
                    ? `XSS detected: ${matches.map(m => m.description).join('; ')}`
                    : 'No XSS patterns detected',
                ...(detected ? { mitreTechniques: ['T1059.007'] } : {}),
                category: 'xss',
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

// ── Confidence ──────────────────────────────────────────────

function calculateXSSConfidence(
    matches: readonly PatternMatch[],
    config: DetectionEngineConfig,
): number {
    if (matches.length === 0) return 0;

    const weights = config.weights ?? {};
    const severityWeights: Record<string, number> = {
        'info': 0.05,
        'low': 0.15,
        'medium': 0.35,
        'high': 0.65,
        'critical': 0.9,
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

// ── Helpers ─────────────────────────────────────────────────

function decodeURIComponentSafe(str: string): string {
    try {
        return decodeURIComponent(str);
    } catch {
        return str;
    }
}

function decodeHTMLEntities(str: string): string {
    const entityMap: Record<string, string> = {
        '&lt;': '<', '&gt;': '>', '&amp;': '&', '&quot;': '"',
        '&#39;': "'", '&apos;': "'", '&#x3c;': '<', '&#x3e;': '>',
        '&#60;': '<', '&#62;': '>',
    };
    return str.replace(/&(?:#(?:x[0-9a-f]+|\d+)|[a-z]+);/gi, (entity) => {
        const lower = entity.toLowerCase();
        if (lower in entityMap) return entityMap[lower]!;

        // Numeric entities
        if (lower.startsWith('&#x')) {
            const code = parseInt(lower.slice(3, -1), 16);
            return Number.isFinite(code) ? String.fromCharCode(code) : entity;
        }
        if (lower.startsWith('&#')) {
            const code = parseInt(lower.slice(2, -1), 10);
            return Number.isFinite(code) ? String.fromCharCode(code) : entity;
        }
        return entity;
    });
}
