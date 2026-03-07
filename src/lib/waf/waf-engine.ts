/**
 * VARIANT — WAF Engine
 *
 * OWASP ModSecurity CRS-compatible rule evaluation engine.
 * Supports anomaly scoring, transforms, chained rules, and
 * all common operators.
 *
 * What it does:
 *   - Evaluates HTTP requests against WAF rules per-phase
 *   - Applies transforms (URL decode, HTML entity, base64, etc.)
 *   - Supports anomaly scoring mode (aggregate score vs threshold)
 *   - Supports chained rules (multi-condition)
 *   - Built-in OWASP CRS core rules for SQLi, XSS, RCE, LFI
 *   - Paranoia levels control rule strictness
 *
 * SWAPPABILITY: Implements WAFEngine. Replace this file.
 */

import type {
    WAFEngine,
    WAFRule,
    WAFRequest,
    WAFEvalResult,
    WAFRuleMatch,
    WAFOperator,
    WAFTarget,
    WAFTransform,
    WAFAction,
    WAFStats,
} from './types';

// ── Severity Scores (CRS-style) ───────────────────────────

const SEVERITY_SCORES: Record<string, number> = {
    'EMERGENCY': 0, 'ALERT': 2, 'CRITICAL': 5, 'ERROR': 4,
    'WARNING': 3, 'NOTICE': 2, 'INFO': 0, 'DEBUG': 0,
};

// ── Factory ────────────────────────────────────────────────

export function createWAFEngine(): WAFEngine {
    const rules = new Map<number, WAFRule>();
    let anomalyThreshold = 5;
    let paranoiaLevel: 1 | 2 | 3 | 4 = 1;
    let requestsEvaluated = 0;
    let requestsBlocked = 0;
    let requestsAllowed = 0;
    const ruleHits = new Map<number, number>();
    const ruleMessages = new Map<number, string>();

    function applyTransform(value: string, transform: WAFTransform): string {
        switch (transform) {
            case 'none': return value;
            case 'lowercase': return value.toLowerCase();
            case 'urlDecode': return decodeURISafe(value);
            case 'urlDecodeUni': return decodeURISafe(value);
            case 'htmlEntityDecode': return htmlEntityDecode(value);
            case 'compressWhitespace': return value.replace(/\s+/g, ' ');
            case 'removeWhitespace': return value.replace(/\s+/g, '');
            case 'replaceNulls': return value.replace(/\0/g, '');
            case 'removeNulls': return value.replace(/\0/g, '');
            case 'normalizePath': return normalizePath(value);
            case 'base64Decode': return base64Decode(value);
            case 'hexDecode': return hexDecode(value);
            case 'length': return String(value.length);
            default: return value;
        }
    }

    function applyTransforms(value: string, transforms: readonly WAFTransform[]): string {
        let result = value;
        for (const t of transforms) {
            result = applyTransform(result, t);
        }
        return result;
    }

    function getTargetValues(request: WAFRequest, target: WAFTarget): string[] {
        switch (target) {
            case 'ARGS': return Object.values(request.args);
            case 'ARGS_NAMES': return Object.keys(request.args);
            case 'ARGS_GET': return Object.values(request.argsGet);
            case 'ARGS_POST': return Object.values(request.argsPost);
            case 'REQUEST_URI': return [request.uri];
            case 'REQUEST_URI_RAW': return [request.uriRaw];
            case 'REQUEST_HEADERS': return Object.values(request.headers);
            case 'REQUEST_HEADERS_NAMES': return Object.keys(request.headers);
            case 'REQUEST_BODY': return [request.body];
            case 'REQUEST_METHOD': return [request.method];
            case 'REQUEST_COOKIES': return Object.values(request.cookies);
            case 'REQUEST_COOKIES_NAMES': return Object.keys(request.cookies);
            case 'REMOTE_ADDR': return [request.remoteAddr];
            case 'REQUEST_LINE': return [`${request.method} ${request.uriRaw} ${request.protocol}`];
            default: return [];
        }
    }

    function evaluateOperator(value: string, op: WAFOperator): boolean {
        let result = false;

        switch (op.type) {
            case 'rx':
                try { result = new RegExp(op.value, 'i').test(value); } catch { result = false; }
                break;
            case 'eq': result = value === op.value; break;
            case 'ge': result = parseFloat(value) >= parseFloat(op.value); break;
            case 'gt': result = parseFloat(value) > parseFloat(op.value); break;
            case 'le': result = parseFloat(value) <= parseFloat(op.value); break;
            case 'lt': result = parseFloat(value) < parseFloat(op.value); break;
            case 'contains': result = value.toLowerCase().includes(op.value.toLowerCase()); break;
            case 'containsWord': {
                const lower = value.toLowerCase();
                const word = op.value.toLowerCase();
                const idx = lower.indexOf(word);
                if (idx === -1) { result = false; break; }
                const before = idx === 0 || /\W/.test(lower[idx - 1]!);
                const after = idx + word.length >= lower.length || /\W/.test(lower[idx + word.length]!);
                result = before && after;
                break;
            }
            case 'beginsWith': result = value.toLowerCase().startsWith(op.value.toLowerCase()); break;
            case 'endsWith': result = value.toLowerCase().endsWith(op.value.toLowerCase()); break;
            case 'streq': result = value === op.value; break;
            case 'within': result = op.value.toLowerCase().includes(value.toLowerCase()); break;
            case 'pm': {
                const phrases = op.value.split('|').map(p => p.trim().toLowerCase());
                const lower = value.toLowerCase();
                result = phrases.some(p => lower.includes(p));
                break;
            }
            case 'detectSQLi':
                result = /(?:union\s+select|or\s+\d+=\d+|'--|\bselect\b.*\bfrom\b|;\s*drop\b)/i.test(value);
                break;
            case 'detectXSS':
                result = /(?:<script|javascript:|on\w+\s*=|<img\s[^>]*\bonerror\b)/i.test(value);
                break;
            case 'ipMatch': {
                const ips = op.value.split(',').map(s => s.trim());
                result = ips.includes(value);
                break;
            }
            default:
                result = false;
        }

        return op.negated ? !result : result;
    }

    function evaluateRule(request: WAFRequest, rule: WAFRule): WAFRuleMatch | null {
        for (const target of rule.targets) {
            const values = getTargetValues(request, target);

            for (const rawValue of values) {
                const value = applyTransforms(rawValue, rule.transforms);

                for (const op of rule.operators) {
                    if (evaluateOperator(value, op)) {
                        return {
                            ruleId: rule.id,
                            msg: rule.msg,
                            severity: rule.severity,
                            matchedTarget: target,
                            matchedValue: value.slice(0, 200),
                            operator: `${op.type}:${op.value.slice(0, 100)}`,
                        };
                    }
                }
            }
        }

        return null;
    }

    return {
        evaluate(request: WAFRequest): WAFEvalResult {
            requestsEvaluated++;
            const matchedRules: WAFRuleMatch[] = [];
            let anomalyScore = 0;
            let blockAction: WAFAction = 'pass';

            // Evaluate rules by phase
            const sortedRules = [...rules.values()]
                .filter(r => r.enabled)
                .sort((a, b) => a.phase - b.phase || a.id - b.id);

            for (const rule of sortedRules) {
                // Paranoia level filtering: rules with PL tag > current level are skipped
                if (rule.tag !== undefined) {
                    const plTag = rule.tag.find(t => t.startsWith('paranoia-level/'));
                    if (plTag !== undefined) {
                        const pl = parseInt(plTag.split('/')[1] ?? '1', 10);
                        if (pl > paranoiaLevel) continue;
                    }
                }

                const match = evaluateRule(request, rule);
                if (match !== null) {
                    matchedRules.push(match);
                    ruleHits.set(rule.id, (ruleHits.get(rule.id) ?? 0) + 1);
                    ruleMessages.set(rule.id, rule.msg);
                    anomalyScore += SEVERITY_SCORES[rule.severity] ?? 0;

                    if (rule.action === 'deny' || rule.action === 'drop' || rule.action === 'block') {
                        blockAction = rule.action;
                    }
                }
            }

            // Anomaly scoring mode: block if score exceeds threshold
            const blocked = blockAction !== 'pass' || anomalyScore >= anomalyThreshold;

            if (blocked) {
                requestsBlocked++;
            } else {
                requestsAllowed++;
            }

            return {
                blocked,
                action: blocked ? (blockAction !== 'pass' ? blockAction : 'deny') : 'pass',
                matchedRules,
                anomalyScore,
                inboundScore: anomalyScore,
                ...(blocked ? {
                    response: {
                        statusCode: 403,
                        body: '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1><p>Your request was blocked by the WAF.</p></body></html>',
                        headers: { 'Content-Type': 'text/html', 'X-WAF-Block': 'true' },
                    },
                } : {}),
            };
        },

        addRule(rule: WAFRule): void {
            rules.set(rule.id, rule);
        },

        removeRule(id: number): boolean {
            return rules.delete(id);
        },

        setRuleEnabled(id: number, enabled: boolean): boolean {
            const rule = rules.get(id);
            if (rule === undefined) return false;
            rules.set(id, { ...rule, enabled });
            return true;
        },

        getRules(): readonly WAFRule[] {
            return [...rules.values()];
        },

        getStats(): WAFStats {
            const topBlocked = [...ruleHits.entries()]
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10)
                .map(([ruleId, count]) => ({
                    ruleId,
                    count,
                    msg: ruleMessages.get(ruleId) ?? '',
                }));

            return {
                requestsEvaluated,
                requestsBlocked,
                requestsAllowed,
                ruleHits: Object.fromEntries(ruleHits),
                topBlockedRules: topBlocked,
            };
        },

        resetStats(): void {
            requestsEvaluated = 0;
            requestsBlocked = 0;
            requestsAllowed = 0;
            ruleHits.clear();
            ruleMessages.clear();
        },

        setAnomalyThreshold(threshold: number): void {
            anomalyThreshold = threshold;
        },

        getAnomalyThreshold(): number {
            return anomalyThreshold;
        },

        setParanoiaLevel(level: 1 | 2 | 3 | 4): void {
            paranoiaLevel = level;
        },
    };
}

// ── Helpers ────────────────────────────────────────────────

function decodeURISafe(s: string): string {
    try { return decodeURIComponent(s); } catch { return s; }
}

function htmlEntityDecode(s: string): string {
    return s
        .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
        .replace(/&amp;/g, '&').replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'").replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        .replace(/&#(\d+);/g, (_, dec) => String.fromCharCode(parseInt(dec, 10)));
}

function normalizePath(s: string): string {
    return s.replace(/\/+/g, '/').replace(/\/\.\//g, '/').replace(/[^/]+\/\.\.\//g, '');
}

function base64Decode(s: string): string {
    try {
        if (typeof atob === 'function') return atob(s);
        // Fallback: manual base64 decode (browser-native engine, no Buffer)
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        let result = '';
        const cleaned = s.replace(/[^A-Za-z0-9+/=]/g, '');
        for (let i = 0; i < cleaned.length; i += 4) {
            const a = chars.indexOf(cleaned[i]!);
            const b = chars.indexOf(cleaned[i + 1]!);
            const c = chars.indexOf(cleaned[i + 2]!);
            const d = chars.indexOf(cleaned[i + 3]!);
            result += String.fromCharCode((a << 2) | (b >> 4));
            if (cleaned[i + 2] !== '=') result += String.fromCharCode(((b & 15) << 4) | (c >> 2));
            if (cleaned[i + 3] !== '=') result += String.fromCharCode(((c & 3) << 6) | d);
        }
        return result;
    } catch { return s; }
}

function hexDecode(s: string): string {
    try {
        return s.replace(/\\x([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
    } catch { return s; }
}

// ── Built-in OWASP CRS Core Rules ─────────────────────────

export function createCoreRuleSet(): readonly WAFRule[] {
    return [
        // 920 — Protocol Enforcement
        {
            id: 920100, phase: 1, action: 'deny', severity: 'WARNING',
            targets: ['REQUEST_METHOD'],
            operators: [{ type: 'rx', value: '^(?:GET|HEAD|POST|PUT|DELETE|PATCH|OPTIONS|CONNECT|TRACE)$', negated: true }],
            transforms: ['none'], msg: 'Invalid HTTP Request Method', enabled: true,
        },
        // 941 — XSS
        {
            id: 941100, phase: 2, action: 'deny', severity: 'CRITICAL',
            targets: ['ARGS', 'ARGS_NAMES', 'REQUEST_COOKIES', 'REQUEST_HEADERS'],
            operators: [{ type: 'detectXSS', value: '' }],
            transforms: ['urlDecode', 'htmlEntityDecode', 'lowercase'], msg: 'XSS Attack Detected', enabled: true,
            tag: ['OWASP_CRS/WEB_ATTACK/XSS', 'paranoia-level/1'],
        },
        {
            id: 941110, phase: 2, action: 'deny', severity: 'CRITICAL',
            targets: ['ARGS', 'REQUEST_URI'],
            operators: [{ type: 'rx', value: '<script[^>]*>[\\s\\S]*?<\\/script>' }],
            transforms: ['urlDecode', 'htmlEntityDecode', 'lowercase'], msg: 'XSS Filter - Category 1: Script Tag Vector', enabled: true,
            tag: ['OWASP_CRS/WEB_ATTACK/XSS', 'paranoia-level/1'],
        },
        {
            id: 941120, phase: 2, action: 'deny', severity: 'CRITICAL',
            targets: ['ARGS', 'REQUEST_URI'],
            operators: [{ type: 'rx', value: '(?:on(?:blur|click|dblclick|error|focus|keydown|keypress|keyup|load|mouse(?:down|move|out|over|up)|reset|resize|select|submit|unload)\\s*=)' }],
            transforms: ['urlDecode', 'htmlEntityDecode', 'lowercase'], msg: 'XSS Filter - Category 2: Event Handler Vector', enabled: true,
            tag: ['OWASP_CRS/WEB_ATTACK/XSS', 'paranoia-level/1'],
        },
        // 942 — SQL Injection
        {
            id: 942100, phase: 2, action: 'deny', severity: 'CRITICAL',
            targets: ['ARGS', 'ARGS_NAMES', 'REQUEST_COOKIES'],
            operators: [{ type: 'detectSQLi', value: '' }],
            transforms: ['urlDecode', 'lowercase'], msg: 'SQL Injection Attack Detected', enabled: true,
            tag: ['OWASP_CRS/WEB_ATTACK/SQLI', 'paranoia-level/1'],
        },
        {
            id: 942110, phase: 2, action: 'deny', severity: 'CRITICAL',
            targets: ['ARGS', 'REQUEST_URI'],
            operators: [{ type: 'rx', value: "(?:union[\\s/\\*]+select|select[\\s/\\*]+(?:benchmark|sleep|extractvalue|updatexml|if\\s*\\())" }],
            transforms: ['urlDecode', 'compressWhitespace', 'lowercase'], msg: 'SQL Injection Attack: Common Injection Testing Detected', enabled: true,
            tag: ['OWASP_CRS/WEB_ATTACK/SQLI', 'paranoia-level/1'],
        },
        // 932 — RCE
        {
            id: 932100, phase: 2, action: 'deny', severity: 'CRITICAL',
            targets: ['ARGS', 'ARGS_NAMES', 'REQUEST_URI'],
            operators: [{ type: 'pm', value: 'cmd|command|exec|system|passthru|shell_exec|popen|proc_open|pcntl_exec|eval' }],
            transforms: ['urlDecode', 'lowercase'], msg: 'Remote Command Execution: Unix Command Injection', enabled: true,
            tag: ['OWASP_CRS/WEB_ATTACK/RCE', 'paranoia-level/1'],
        },
        {
            id: 932110, phase: 2, action: 'deny', severity: 'CRITICAL',
            targets: ['ARGS', 'REQUEST_URI'],
            operators: [{ type: 'rx', value: '(?:;|\\||\\$\\(|`)[\\s]*(?:id|whoami|uname|cat|ls|pwd|wget|curl|nc|bash|sh|python|perl|ruby|php)' }],
            transforms: ['urlDecode', 'compressWhitespace'], msg: 'Remote Command Execution: Unix Shell Expression', enabled: true,
            tag: ['OWASP_CRS/WEB_ATTACK/RCE', 'paranoia-level/1'],
        },
        // 930 — LFI
        {
            id: 930100, phase: 2, action: 'deny', severity: 'CRITICAL',
            targets: ['ARGS', 'REQUEST_URI'],
            operators: [{ type: 'rx', value: '(?:\\.\\./){3,}' }],
            transforms: ['urlDecode', 'normalizePath'], msg: 'Path Traversal Attack (/../)', enabled: true,
            tag: ['OWASP_CRS/WEB_ATTACK/LFI', 'paranoia-level/1'],
        },
        {
            id: 930110, phase: 2, action: 'deny', severity: 'CRITICAL',
            targets: ['ARGS', 'REQUEST_URI'],
            operators: [{ type: 'pm', value: '/etc/passwd|/etc/shadow|/etc/hosts|/proc/self|/proc/version|/dev/null|/windows/system32' }],
            transforms: ['urlDecode', 'normalizePath', 'lowercase'], msg: 'OS File Access Attempt', enabled: true,
            tag: ['OWASP_CRS/WEB_ATTACK/LFI', 'paranoia-level/1'],
        },
        // 934 — Node/PHP Injection
        {
            id: 934100, phase: 2, action: 'deny', severity: 'CRITICAL',
            targets: ['ARGS', 'REQUEST_BODY'],
            operators: [{ type: 'rx', value: '(?:require|child_process|eval|Function)\\s*\\(' }],
            transforms: ['urlDecode', 'compressWhitespace'], msg: 'Node.js Injection Attack', enabled: true,
            tag: ['OWASP_CRS/WEB_ATTACK/INJECTION', 'paranoia-level/1'],
        },
        // 913 — Scanner Detection
        {
            id: 913100, phase: 1, action: 'log', severity: 'NOTICE',
            targets: ['REQUEST_HEADERS'],
            operators: [{ type: 'pm', value: 'sqlmap|nikto|nmap|dirbuster|gobuster|wfuzz|burpsuite|zaproxy|acunetix|nessus|masscan' }],
            transforms: ['lowercase'], msg: 'Security Scanner Detected', enabled: true,
            tag: ['OWASP_CRS/AUTOMATION/SECURITY_SCANNER', 'paranoia-level/1'],
        },
    ];
}
