/**
 * VARIANT — HTTP Header Injection & SSTI Detection Engine
 *
 * Detects HTTP header injection, CRLF injection, and
 * server-side template injection patterns.
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
        normalizeWhitespace: overrides?.normalizeWhitespace ?? false,
        ...(overrides?.excludePatterns !== undefined ? { excludePatterns: overrides.excludePatterns } : {}),
        ...(overrides?.additionalPatterns !== undefined ? { additionalPatterns: overrides.additionalPatterns } : {}),
        ...(overrides?.weights !== undefined ? { weights: overrides.weights } : {}),
    };
}

function createHeaderPatterns(): DetectionPattern[] {
    return [
        // ── CRLF Injection ────────────────────────────────
        {
            id: 'header/crlf',
            name: 'CRLF Injection',
            pattern: '(?:%0d%0a|%0a|%0d|\\r\\n|\\n)',
            type: 'regex',
            severity: 'high',
            description: 'CRLF characters in header value',
            enabled: true,
            tags: ['crlf'],
        },
        {
            id: 'header/crlf-header',
            name: 'CRLF + Header',
            pattern: '(?:%0d%0a|\\r\\n)\\s*(?:Set-Cookie|Location|Content-Type|X-[A-Za-z-]+|Access-Control[A-Za-z-]*)\\s*:',
            type: 'regex',
            severity: 'critical',
            description: 'CRLF followed by HTTP header (header injection)',
            enabled: true,
            tags: ['crlf', 'header-injection'],
        },

        // ── Host header attacks ───────────────────────────
        {
            id: 'header/host-override',
            name: 'Host Header Override',
            pattern: 'X-Forwarded-Host\\s*:|X-Host\\s*:|X-Forwarded-Server\\s*:',
            type: 'regex',
            severity: 'high',
            description: 'Host header override attempt',
            enabled: true,
            tags: ['host'],
        },

        // ── SSTI (Server-Side Template Injection) ─────────
        {
            id: 'ssti/jinja2',
            name: 'Jinja2 Template',
            pattern: '\\{\\{\\s*[^}]*(?:config|self|request|\\.__class__|lipsum|cycler|joiner|namespace)\\s*[^}]*\\}\\}',
            type: 'regex',
            severity: 'critical',
            description: 'Jinja2/Flask template injection',
            enabled: true,
            tags: ['ssti', 'python'],
        },
        {
            id: 'ssti/generic-expression',
            name: 'Template Expression',
            pattern: '\\{\\{\\s*\\d+\\s*[+*/-]\\s*\\d+\\s*\\}\\}',
            type: 'regex',
            severity: 'high',
            description: 'Template expression evaluation probe (e.g., {{7*7}})',
            enabled: true,
            tags: ['ssti', 'probe'],
        },
        {
            id: 'ssti/erb',
            name: 'ERB Template',
            pattern: '<%=?\\s*(?:system|exec|`|IO\\.popen|open\\().*%>',
            type: 'regex',
            severity: 'critical',
            description: 'Ruby ERB template injection',
            enabled: true,
            tags: ['ssti', 'ruby'],
        },
        {
            id: 'ssti/freemarker',
            name: 'FreeMarker Template',
            pattern: '<#assign|\\$\\{[^}]*(?:exec|Runtime|Process|getClass)',
            type: 'regex',
            severity: 'critical',
            description: 'FreeMarker template injection',
            enabled: true,
            tags: ['ssti', 'java'],
        },
        {
            id: 'ssti/velocity',
            name: 'Velocity Template',
            pattern: '#set\\s*\\(|#foreach|\\$\\{class\\.forName\\(|\\$\\{T\\(',
            type: 'regex',
            severity: 'critical',
            description: 'Velocity template injection',
            enabled: true,
            tags: ['ssti', 'java'],
        },
        {
            id: 'ssti/python-class',
            name: 'Python Class Traversal',
            pattern: '__(?:class|mro|subclasses|init|globals|builtins|import)__',
            type: 'regex',
            severity: 'critical',
            description: 'Python class/MRO traversal for RCE',
            enabled: true,
            tags: ['ssti', 'python'],
        },

        // ── XXE (XML External Entity) ────────────────────
        {
            id: 'xxe/entity-declaration',
            name: 'XXE Entity Declaration',
            pattern: '<!\\s*(?:DOCTYPE|ENTITY)[^>]*(?:SYSTEM|PUBLIC)',
            type: 'regex',
            severity: 'critical',
            description: 'XML external entity declaration',
            enabled: true,
            tags: ['xxe'],
        },
        {
            id: 'xxe/entity-reference',
            name: 'XXE Entity Reference',
            pattern: '&\\w+;.*<!\\s*ENTITY',
            type: 'regex',
            severity: 'high',
            description: 'XML entity reference with entity declaration',
            enabled: true,
            tags: ['xxe'],
        },
        {
            id: 'xxe/parameter-entity',
            name: 'XXE Parameter Entity',
            pattern: '<!\\s*ENTITY\\s+%\\s+\\w+\\s+(?:SYSTEM|PUBLIC)',
            type: 'regex',
            severity: 'critical',
            description: 'XML parameter entity (blind XXE)',
            enabled: true,
            tags: ['xxe', 'blind'],
        },

        // ── LDAP Injection ────────────────────────────────
        {
            id: 'ldap/injection',
            name: 'LDAP Injection',
            pattern: '\\)\\s*(?:\\(\\||\\(&|!\\()|\\.\\*\\)\\s*\\(|\\x00',
            type: 'regex',
            severity: 'high',
            description: 'LDAP filter injection',
            enabled: true,
            tags: ['ldap'],
        },
    ];
}

export function createHeaderInjectionEngine(configOverrides?: Partial<DetectionEngineConfig>): DetectionEngine {
    const config = defaultConfig(configOverrides);
    const excludeSet = new Set(config.excludePatterns ?? []);

    const patterns: DetectionPattern[] = [];
    for (const p of createHeaderPatterns()) {
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
        if (processed.length > config.maxInputLength) processed = processed.slice(0, config.maxInputLength);
        if (config.decodeUrl) {
            for (let i = 0; i < 3; i++) {
                try { const d = decodeURIComponent(processed); if (d === processed) break; processed = d; } catch { break; }
            }
        }
        return processed;
    }

    const engine: DetectionEngine = {
        id: 'header-injection-detection',
        category: 'header-injection',
        version: '1.0.0',
        description: 'HTTP header injection, CRLF, SSTI, XXE, and LDAP injection detection',

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

            // Determine specific category
            const hasSSti = matches.some(m => m.patternId.startsWith('ssti/'));
            const hasXxe = matches.some(m => m.patternId.startsWith('xxe/'));
            const subCategory = hasSSti ? 'ssti' : hasXxe ? 'xxe' : 'header-injection';

            return {
                detected, confidence, matches,
                explanation: detected
                    ? `Injection detected (${subCategory}): ${matches.map(m => m.description).join('; ')}`
                    : 'No injection patterns detected',
                ...(detected ? { mitreTechniques: ['T1190'] } : {}),
                category: 'header-injection',
                subCategory,
            };
        },

        getPatterns(): readonly DetectionPattern[] { return [...patterns]; },
        getConfig(): DetectionEngineConfig { return config; },
    };

    return engine;
}

function calculateConfidence(matches: readonly PatternMatch[], config: DetectionEngineConfig): number {
    if (matches.length === 0) return 0;
    const weights = config.weights ?? {};
    const sw: Record<string, number> = { 'info': 0.1, 'low': 0.2, 'medium': 0.4, 'high': 0.7, 'critical': 0.9 };
    let max = 0;
    const unique = new Set<string>();
    for (const m of matches) {
        const s = (sw[m.severity] ?? 0.3) * (weights[m.patternId] ?? 1.0);
        if (s > max) max = s;
        unique.add(m.patternId);
    }
    return Math.min(1.0, Math.round((max + Math.min(0.3, (unique.size - 1) * 0.1)) * 100) / 100);
}
