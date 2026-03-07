/**
 * VARIANT — SSRF Detection Engine
 *
 * Detects server-side request forgery patterns including
 * internal IP access, cloud metadata endpoints, and DNS rebinding.
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

function createSSRFPatterns(): DetectionPattern[] {
    return [
        {
            id: 'ssrf/localhost',
            name: 'Localhost Access',
            pattern: '(?:https?://)?(?:localhost|127\\.0\\.0\\.1|\\[::1\\]|0\\.0\\.0\\.0)',
            type: 'regex',
            severity: 'high',
            description: 'Request to localhost/loopback address',
            enabled: true,
            tags: ['internal'],
        },
        {
            id: 'ssrf/private-10',
            name: 'Private Network (10.x)',
            pattern: '(?:https?://)?10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}',
            type: 'regex',
            severity: 'high',
            description: 'Request to RFC1918 private address (10.0.0.0/8)',
            enabled: true,
            tags: ['internal'],
        },
        {
            id: 'ssrf/private-172',
            name: 'Private Network (172.16-31.x)',
            pattern: '(?:https?://)?172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}',
            type: 'regex',
            severity: 'high',
            description: 'Request to RFC1918 private address (172.16.0.0/12)',
            enabled: true,
            tags: ['internal'],
        },
        {
            id: 'ssrf/private-192',
            name: 'Private Network (192.168.x)',
            pattern: '(?:https?://)?192\\.168\\.\\d{1,3}\\.\\d{1,3}',
            type: 'regex',
            severity: 'high',
            description: 'Request to RFC1918 private address (192.168.0.0/16)',
            enabled: true,
            tags: ['internal'],
        },
        {
            id: 'ssrf/cloud-metadata-aws',
            name: 'AWS Metadata',
            pattern: '169\\.254\\.169\\.254',
            type: 'regex',
            severity: 'critical',
            description: 'AWS EC2 metadata endpoint access',
            enabled: true,
            tags: ['cloud', 'aws'],
        },
        {
            id: 'ssrf/cloud-metadata-gcp',
            name: 'GCP Metadata',
            pattern: 'metadata\\.google\\.internal',
            type: 'regex',
            severity: 'critical',
            description: 'GCP metadata endpoint access',
            enabled: true,
            tags: ['cloud', 'gcp'],
        },
        {
            id: 'ssrf/cloud-metadata-azure',
            name: 'Azure Metadata',
            pattern: '169\\.254\\.169\\.254.*Metadata',
            type: 'regex',
            severity: 'critical',
            description: 'Azure metadata endpoint access',
            enabled: true,
            tags: ['cloud', 'azure'],
        },
        {
            id: 'ssrf/file-scheme',
            name: 'File Scheme',
            pattern: 'file://',
            type: 'regex',
            severity: 'critical',
            description: 'file:// URL scheme (local file access)',
            enabled: true,
            tags: ['scheme'],
        },
        {
            id: 'ssrf/gopher-scheme',
            name: 'Gopher Scheme',
            pattern: 'gopher://',
            type: 'regex',
            severity: 'critical',
            description: 'gopher:// URL scheme (protocol smuggling)',
            enabled: true,
            tags: ['scheme'],
        },
        {
            id: 'ssrf/dict-scheme',
            name: 'Dict Scheme',
            pattern: 'dict://',
            type: 'regex',
            severity: 'high',
            description: 'dict:// URL scheme',
            enabled: true,
            tags: ['scheme'],
        },
        {
            id: 'ssrf/decimal-ip',
            name: 'Decimal IP Notation',
            pattern: '(?:https?://)?\\d{8,10}(?:[:/]|$)',
            type: 'regex',
            severity: 'high',
            description: 'Decimal IP notation (bypass filter)',
            enabled: true,
            tags: ['evasion'],
        },
        {
            id: 'ssrf/octal-ip',
            name: 'Octal IP Notation',
            pattern: '(?:https?://)?(?:\\d{1,3}\\.)*0[0-7]{2,}(?:\\.\\d{1,3})*',
            type: 'regex',
            severity: 'high',
            description: 'Octal IP notation (bypass filter)',
            enabled: true,
            tags: ['evasion'],
        },
        {
            id: 'ssrf/ipv6-mapped',
            name: 'IPv6-mapped IPv4',
            pattern: '\\[?::ffff:(?:127\\.0\\.0\\.1|10\\.|172\\.1[6-9]\\.|192\\.168\\.)',
            type: 'regex',
            severity: 'high',
            description: 'IPv6-mapped IPv4 address (bypass filter)',
            enabled: true,
            tags: ['evasion'],
        },
        {
            id: 'ssrf/redirect-header',
            name: 'Open Redirect for SSRF',
            pattern: '(?:url|redirect|next|return|goto|target|link|dest)=(?:https?|ftp|file)://',
            type: 'regex',
            severity: 'high',
            description: 'URL parameter suggesting open redirect chain',
            enabled: true,
            tags: ['redirect'],
        },
        {
            id: 'ssrf/ftp-scheme',
            name: 'FTP Scheme',
            pattern: 'ftp://',
            type: 'regex',
            severity: 'high',
            description: 'ftp:// URL scheme (internal file access)',
            enabled: true,
            tags: ['scheme'],
        },
        {
            id: 'ssrf/rfi-scheme',
            name: 'PHP/Data Scheme (RFI)',
            pattern: '(?:php|data|expect|phar)://',
            type: 'regex',
            severity: 'critical',
            description: 'PHP wrapper / data scheme (remote file inclusion)',
            enabled: true,
            tags: ['scheme', 'rfi'],
        },
    ];
}

export function createSSRFEngine(configOverrides?: Partial<DetectionEngineConfig>): DetectionEngine {
    const config = defaultConfig(configOverrides);
    const excludeSet = new Set(config.excludePatterns ?? []);

    const patterns: DetectionPattern[] = [];
    for (const p of createSSRFPatterns()) {
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
        id: 'ssrf-detection',
        category: 'ssrf',
        version: '1.0.0',
        description: 'SSRF detection covering internal IPs, cloud metadata, URL schemes, and evasion techniques',

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
                detected, confidence, matches,
                explanation: detected
                    ? `SSRF detected: ${matches.map(m => m.description).join('; ')}`
                    : 'No SSRF patterns detected',
                ...(detected ? { mitreTechniques: ['T1190'] } : {}),
                category: 'ssrf',
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
