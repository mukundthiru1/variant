/**
 * VARIANT — JWT Detection Engine
 *
 * Detects weak or bypass-prone JWT configurations and payloads.
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
    'jwt/alg-none': ['T1552', 'T1190'],
    'jwt/alg-switch-hs-rs': ['T1552', 'T1190'],
    'jwt/weak-secret': ['T1110', 'T1552'],
    'jwt/expired-token': ['T1078'],
    'jwt/missing-signature': ['T1552', 'T1190'],
    'jwt/jku-kid-injection': ['T1190'],
};

const CWE_BY_PATTERN: Record<string, readonly string[]> = {
    'jwt/alg-none': ['CWE-345', 'CWE-347'],
    'jwt/alg-switch-hs-rs': ['CWE-347', 'CWE-287'],
    'jwt/weak-secret': ['CWE-798', 'CWE-521'],
    'jwt/expired-token': ['CWE-613'],
    'jwt/missing-signature': ['CWE-347'],
    'jwt/jku-kid-injection': ['CWE-20', 'CWE-347'],
};

const WEAK_SECRETS = [
    'secret',
    'password',
    'changeme',
    '123456',
    'jwtsecret',
    'qwerty',
    'admin',
];

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

function createJWTPatterns(): DetectionPattern[] {
    return [
        {
            id: 'jwt/alg-none',
            name: 'JWT alg:none',
            pattern: '"alg"\\s*:\\s*"none"',
            type: 'regex',
            severity: 'critical',
            description: 'JWT header algorithm set to none',
            enabled: true,
            tags: ['header', 'signature-bypass'],
        },
        {
            id: 'jwt/alg-switch-hs-rs',
            name: 'JWT Algorithm Confusion',
            pattern: '"alg"\\s*:\\s*"(?:HS256|HS384|HS512|RS256|RS384|RS512)"',
            type: 'regex',
            severity: 'high',
            description: 'JWT algorithm field present (validate for confusion attacks)',
            enabled: true,
            tags: ['alg-confusion'],
        },
        {
            id: 'jwt/weak-secret',
            name: 'Weak JWT Secret',
            pattern: '(?:jwt_secret|secret|signing_key)\\s*[:=]\\s*["\']?(?:secret|password|changeme|123456|jwtsecret|qwerty|admin)["\']?',
            type: 'regex',
            severity: 'high',
            description: 'Weak HMAC secret used for JWT signing',
            enabled: true,
            tags: ['weak-secret'],
        },
        {
            id: 'jwt/expired-token',
            name: 'Expired JWT Usage',
            pattern: '"exp"\\s*:\\s*(\\d{9,12})',
            type: 'regex',
            severity: 'medium',
            description: 'JWT expiration claim found; validate expiration handling',
            enabled: true,
            tags: ['expiration'],
        },
        {
            id: 'jwt/missing-signature',
            name: 'Unsigned JWT Format',
            pattern: '^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.?$',
            type: 'regex',
            severity: 'critical',
            description: 'JWT with missing or empty signature segment',
            enabled: true,
            tags: ['signature'],
        },
        {
            id: 'jwt/jku-kid-injection',
            name: 'JKU/KID Header Injection',
            pattern: '"(?:jku|kid|x5u)"\\s*:\\s*"[^"\\n]{1,200}"',
            type: 'regex',
            severity: 'high',
            description: 'JWT key reference headers that can be abused for key substitution',
            enabled: true,
            tags: ['header-injection'],
        },
    ];
}

export function createJWTEngine(configOverrides?: Partial<DetectionEngineConfig>): DetectionEngine {
    const config = defaultConfig(configOverrides);
    const excludeSet = new Set(config.excludePatterns ?? []);

    const patterns: DetectionPattern[] = [];
    for (const p of createJWTPatterns()) {
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

    function tryDecodeJwtParts(input: string): string[] {
        const parts = input.split('.');
        if (parts.length < 2 || parts.length > 3) return [];

        const decoded: string[] = [];
        for (const part of parts.slice(0, 2)) {
            const base64 = part.replace(/-/g, '+').replace(/_/g, '/');
            const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
            try {
                decoded.push(decodeURIComponent(escape(atob(padded))));
            } catch {
                return [];
            }
        }
        return decoded;
    }

    function analyzeInput(input: string): DetectionResult {
        const processed = preprocess(input);
        const decodedJwtParts = tryDecodeJwtParts(processed);
        const analysisCorpus = [processed, ...decodedJwtParts].join('\n');

        const matches: PatternMatch[] = [];

        for (const pattern of patterns) {
            if (!pattern.enabled) continue;
            if (pattern.type === 'regex') {
                const regex = compiledPatterns.get(pattern.id);
                if (regex === undefined) continue;
                regex.lastIndex = 0;
                let match: RegExpExecArray | null;
                while ((match = regex.exec(analysisCorpus)) !== null) {
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

        applyJWTHeuristics(processed, decodedJwtParts, matches);

        const confidence = calculateConfidence(matches, analysisCorpus, config);
        const detected = confidence >= config.confidenceThreshold && matches.length > 0;
        const mitreTechniques = collectMappedValues(matches, MITRE_BY_PATTERN);
        const cweIds = collectMappedValues(matches, CWE_BY_PATTERN);

        return {
            detected,
            confidence,
            matches,
            explanation: detected
                ? `JWT weakness detected: ${matches.map(m => m.description).join('; ')}. CWE: ${cweIds.join(', ')}`
                : 'No JWT security weaknesses detected',
            ...(detected && mitreTechniques.length > 0 ? { mitreTechniques } : {}),
            category: 'jwt',
            ...(detected && cweIds.length > 0 ? { subCategory: `cwe:${cweIds.join('|')}` } : {}),
        };
    }

    const engine: DetectCapableEngine = {
        id: 'jwt-detection',
        category: 'jwt',
        version: '1.0.0',
        description: 'JWT detection engine for alg:none, algorithm confusion, weak secrets, expiration abuse, and signature issues',

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

function applyJWTHeuristics(input: string, decodedParts: readonly string[], matches: PatternMatch[]): void {
    const nowEpoch = Math.floor(Date.now() / 1000);
    const payload = decodedParts.length > 1 ? decodedParts[1] : '';

    if (payload !== undefined && payload.length > 0) {
        const expMatch = payload.match(/"exp"\s*:\s*(\d{9,12})/);
        if (expMatch !== null) {
            const exp = Number(expMatch[1]);
            if (Number.isFinite(exp) && exp < nowEpoch) {
                matches.push({
                    patternId: 'jwt/expired-token',
                    matchedText: expMatch[0],
                    offset: input.indexOf(expMatch[0]),
                    severity: 'high',
                    description: 'JWT token appears expired but still present in input flow',
                });
            }
        }
    }

    const lowerInput = input.toLowerCase();
    for (const weak of WEAK_SECRETS) {
        if (lowerInput.includes(weak)) {
            matches.push({
                patternId: 'jwt/weak-secret',
                matchedText: weak,
                offset: lowerInput.indexOf(weak),
                severity: 'high',
                description: `Weak JWT secret candidate: ${weak}`,
            });
            break;
        }
    }

    const inputParts = input.split('.');
    if (inputParts.length === 2 || (inputParts.length === 3 && inputParts[2] !== undefined && inputParts[2].trim() === '')) {
        matches.push({
            patternId: 'jwt/missing-signature',
            matchedText: input,
            offset: 0,
            severity: 'critical',
            description: 'JWT has missing/empty signature segment',
        });
    }

    if (/"alg"\s*:\s*"(?:HS256|HS384|HS512)"/.test(input) && /public[_-]?key|BEGIN PUBLIC KEY/.test(input)) {
        matches.push({
            patternId: 'jwt/alg-switch-hs-rs',
            matchedText: 'alg/public-key combination',
            offset: 0,
            severity: 'critical',
            description: 'Potential algorithm confusion: HMAC alg with asymmetric key material',
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
