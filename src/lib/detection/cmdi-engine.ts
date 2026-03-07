/**
 * VARIANT — Command Injection Detection Engine
 *
 * Detects OS command injection patterns across Unix and Windows
 * shell environments.
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
        normalizeWhitespace: overrides?.normalizeWhitespace ?? false,
        ...(overrides?.excludePatterns !== undefined ? { excludePatterns: overrides.excludePatterns } : {}),
        ...(overrides?.additionalPatterns !== undefined ? { additionalPatterns: overrides.additionalPatterns } : {}),
        ...(overrides?.weights !== undefined ? { weights: overrides.weights } : {}),
    };
}

// ── Built-in Command Injection Patterns ─────────────────────

function createCmdIPatterns(): DetectionPattern[] {
    return [
        // ── Shell metacharacters ──────────────────────────
        {
            id: 'cmdi/semicolon-chain',
            name: 'Semicolon Command Chain',
            pattern: ';\\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|python|perl|ruby|php|echo|printf|exec|eval)\\b',
            type: 'regex',
            severity: 'critical',
            description: 'Semicolon followed by shell command',
            enabled: true,
            tags: ['metachar'],
        },
        {
            id: 'cmdi/pipe-chain',
            name: 'Pipe Command Chain',
            pattern: '\\|\\s*(?:cat|ls|id|whoami|uname|bash|sh|python|perl|ruby|nc|ncat|exec|eval|tee|base64|xxd)\\b',
            type: 'regex',
            severity: 'critical',
            description: 'Pipe to shell command',
            enabled: true,
            tags: ['metachar'],
        },
        {
            id: 'cmdi/backtick',
            name: 'Backtick Substitution',
            pattern: '`[^`]+`',
            type: 'regex',
            severity: 'critical',
            description: 'Backtick command substitution',
            enabled: true,
            tags: ['substitution'],
        },
        {
            id: 'cmdi/dollar-paren',
            name: '$() Substitution',
            pattern: '\\$\\([^)]+\\)',
            type: 'regex',
            severity: 'critical',
            description: '$() command substitution',
            enabled: true,
            tags: ['substitution'],
        },
        {
            id: 'cmdi/and-chain',
            name: '&& Command Chain',
            pattern: '&&\\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python|perl|ruby|echo|exec|eval)\\b',
            type: 'regex',
            severity: 'critical',
            description: '&& chained command execution',
            enabled: true,
            tags: ['metachar'],
        },
        {
            id: 'cmdi/or-chain',
            name: '|| Command Chain',
            pattern: '\\|\\|\\s*(?:cat|ls|id|whoami|bash|sh)\\b',
            type: 'regex',
            severity: 'high',
            description: '|| fallback command execution',
            enabled: true,
            tags: ['metachar'],
        },

        // ── Reverse shells ────────────────────────────────
        {
            id: 'cmdi/reverse-shell-bash',
            name: 'Bash Reverse Shell',
            pattern: 'bash\\s+-[ic].*(?:/dev/tcp|/dev/udp)|/dev/tcp/[\\d.]+/\\d+',
            type: 'regex',
            severity: 'critical',
            description: 'Bash reverse shell via /dev/tcp',
            enabled: true,
            tags: ['reverse-shell'],
        },
        {
            id: 'cmdi/reverse-shell-nc',
            name: 'Netcat Reverse Shell',
            pattern: '(?:nc|ncat|netcat)\\s+.*-e\\s+(?:/bin/(?:ba)?sh|cmd)',
            type: 'regex',
            severity: 'critical',
            description: 'Netcat reverse shell',
            enabled: true,
            tags: ['reverse-shell'],
        },
        {
            id: 'cmdi/reverse-shell-python',
            name: 'Python Reverse Shell',
            pattern: 'python[23]?\\s+-c\\s+["\'].*(?:socket|subprocess|os\\.(?:system|popen))',
            type: 'regex',
            severity: 'critical',
            description: 'Python reverse shell',
            enabled: true,
            tags: ['reverse-shell'],
        },

        // ── File read/write ───────────────────────────────
        {
            id: 'cmdi/etc-passwd',
            name: '/etc/passwd Read',
            pattern: '(?:cat|head|tail|less|more|vim|nano)\\s+/etc/(?:passwd|shadow|group)',
            type: 'regex',
            severity: 'high',
            description: 'Reading sensitive system files',
            enabled: true,
            tags: ['file-read'],
        },
        {
            id: 'cmdi/output-redirect',
            name: 'Output Redirect',
            pattern: '>\\s*/(?:etc|var|tmp|dev)',
            type: 'regex',
            severity: 'high',
            description: 'Output redirection to system directory',
            enabled: true,
            tags: ['file-write'],
        },

        // ── Download and execute ──────────────────────────
        {
            id: 'cmdi/wget-exec',
            name: 'wget + Execute',
            pattern: '(?:wget|curl)\\s+.*(?:\\||;|&&).*(?:bash|sh|chmod|python|perl)',
            type: 'regex',
            severity: 'critical',
            description: 'Download and execute pattern',
            enabled: true,
            tags: ['download-exec'],
        },
        {
            id: 'cmdi/curl-pipe-bash',
            name: 'Curl Pipe to Shell',
            pattern: 'curl\\s+.*\\|\\s*(?:ba)?sh',
            type: 'regex',
            severity: 'critical',
            description: 'curl piped to shell (download & execute)',
            enabled: true,
            tags: ['download-exec'],
        },

        // ── Privilege escalation ──────────────────────────
        {
            id: 'cmdi/sudo-abuse',
            name: 'Sudo Abuse',
            pattern: 'sudo\\s+(?:-u\\s+\\w+\\s+)?(?:bash|sh|python|perl|ruby|vi|vim|nano|less|find|nmap)',
            type: 'regex',
            severity: 'high',
            description: 'Sudo used to escalate privileges',
            enabled: true,
            tags: ['privesc'],
        },
        {
            id: 'cmdi/chmod-suid',
            name: 'SUID/SGID Set',
            pattern: 'chmod\\s+[ugo+]*[0-7]*s[0-7]*|chmod\\s+[0-7]*[4-7][0-7]{2}',
            type: 'regex',
            severity: 'critical',
            description: 'Setting SUID/SGID bit',
            enabled: true,
            tags: ['privesc'],
        },

        // ── Encoding evasion ──────────────────────────────
        {
            id: 'cmdi/base64-decode',
            name: 'Base64 Decode + Execute',
            pattern: '(?:base64\\s+-d|echo\\s+[A-Za-z0-9+/=]+\\s*\\|\\s*base64)',
            type: 'regex',
            severity: 'high',
            description: 'Base64 decode (potential encoded payload)',
            enabled: true,
            tags: ['evasion'],
        },
        {
            id: 'cmdi/hex-decode',
            name: 'Hex Decode',
            pattern: '(?:xxd\\s+-r|printf\\s+["\']\\\\x)',
            type: 'regex',
            severity: 'medium',
            description: 'Hex decoding (potential encoded payload)',
            enabled: true,
            tags: ['evasion'],
        },

        // ── Windows-specific ──────────────────────────────
        {
            id: 'cmdi/windows-cmd',
            name: 'Windows CMD Injection',
            pattern: '(?:cmd\\s*/c|powershell\\s+-(?:e|enc|exec|command))\\s+',
            type: 'regex',
            severity: 'critical',
            description: 'Windows command execution',
            enabled: true,
            tags: ['windows'],
        },

        // ── Newline injection ─────────────────────────────
        {
            id: 'cmdi/newline-inject',
            name: 'Newline Injection',
            pattern: '(?:\\r\\n|\\n)\\s*(?:cat|ls|id|whoami|wget|curl|bash|sh)',
            type: 'regex',
            severity: 'high',
            description: 'Newline character followed by command',
            enabled: true,
            tags: ['metachar'],
        },
    ];
}

// ── Command Injection Engine ────────────────────────────────

export function createCmdIEngine(configOverrides?: Partial<DetectionEngineConfig>): DetectionEngine {
    const config = defaultConfig(configOverrides);
    const excludeSet = new Set(config.excludePatterns ?? []);

    const patterns: DetectionPattern[] = [];
    for (const p of createCmdIPatterns()) {
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
        id: 'cmdi-detection',
        category: 'command-injection',
        version: '1.0.0',
        description: 'Command injection detection covering Unix/Windows shells, reverse shells, and encoding evasion',

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
                    ? `Command injection detected: ${matches.map(m => m.description).join('; ')}`
                    : 'No command injection patterns detected',
                ...(detected ? { mitreTechniques: ['T1059'] } : {}),
                category: 'command-injection',
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
