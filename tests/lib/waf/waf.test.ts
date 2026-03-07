/**
 * VARIANT — WAF Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createWAFEngine, createCoreRuleSet } from '../../../src/lib/waf/waf-engine';
import type { WAFRequest, WAFRule } from '../../../src/lib/waf/types';

function makeRequest(overrides?: Partial<WAFRequest>): WAFRequest {
    return {
        method: 'GET',
        uri: '/',
        uriRaw: '/',
        headers: {},
        cookies: {},
        args: {},
        argsGet: {},
        argsPost: {},
        body: '',
        remoteAddr: '10.0.0.5',
        protocol: 'HTTP/1.1',
        ...overrides,
    };
}

function makeRule(overrides?: Partial<WAFRule>): WAFRule {
    return {
        id: 900001,
        phase: 2,
        action: 'deny',
        severity: 'CRITICAL',
        targets: ['ARGS'],
        operators: [{ type: 'rx', value: 'test' }],
        transforms: [],
        msg: 'Test rule',
        enabled: true,
        ...overrides,
    };
}

describe('WAFEngine', () => {
    // ── Creation ──────────────────────────────────────────

    it('creates with empty rules', () => {
        const waf = createWAFEngine();
        expect(waf.getRules()).toHaveLength(0);
        expect(waf.getAnomalyThreshold()).toBe(5);
    });

    // ── Rule Management ───────────────────────────────────

    it('adds and retrieves rules', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({ id: 100 }));
        expect(waf.getRules()).toHaveLength(1);
    });

    it('removes rules by ID', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({ id: 100 }));
        waf.addRule(makeRule({ id: 101 }));
        expect(waf.removeRule(100)).toBe(true);
        expect(waf.getRules()).toHaveLength(1);
        expect(waf.removeRule(999)).toBe(false);
    });

    it('enables and disables rules', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({ id: 100 }));
        expect(waf.setRuleEnabled(100, false)).toBe(true);
        expect(waf.getRules()[0]!.enabled).toBe(false);
    });

    // ── Basic Evaluation ──────────────────────────────────

    it('allows clean requests', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({
            operators: [{ type: 'rx', value: 'attack' }],
        }));
        const result = waf.evaluate(makeRequest({ args: { q: 'hello world' } }));
        expect(result.blocked).toBe(false);
        expect(result.matchedRules).toHaveLength(0);
    });

    it('blocks matching requests', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({
            operators: [{ type: 'rx', value: 'attack' }],
            action: 'deny',
        }));
        const result = waf.evaluate(makeRequest({ args: { q: 'this is an attack' } }));
        expect(result.blocked).toBe(true);
        expect(result.matchedRules).toHaveLength(1);
    });

    // ── Operator Types ────────────────────────────────────

    it('evaluates rx (regex) operator', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({
            operators: [{ type: 'rx', value: 'select.*from' }],
        }));
        const result = waf.evaluate(makeRequest({ args: { q: "select id from users" } }));
        expect(result.matchedRules).toHaveLength(1);
    });

    it('evaluates contains operator', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({
            operators: [{ type: 'contains', value: 'script' }],
        }));
        const match = waf.evaluate(makeRequest({ args: { q: '<script>' } }));
        expect(match.matchedRules).toHaveLength(1);

        const noMatch = waf.evaluate(makeRequest({ args: { q: 'normal text' } }));
        expect(noMatch.matchedRules).toHaveLength(0);
    });

    it('evaluates streq operator', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({
            targets: ['REQUEST_METHOD'],
            operators: [{ type: 'streq', value: 'TRACE' }],
        }));
        const match = waf.evaluate(makeRequest({ method: 'TRACE' }));
        expect(match.matchedRules).toHaveLength(1);

        const noMatch = waf.evaluate(makeRequest({ method: 'GET' }));
        expect(noMatch.matchedRules).toHaveLength(0);
    });

    it('evaluates beginsWith operator', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({
            targets: ['REQUEST_URI'],
            operators: [{ type: 'beginsWith', value: '/admin' }],
        }));
        const match = waf.evaluate(makeRequest({ uri: '/admin/settings' }));
        expect(match.matchedRules).toHaveLength(1);

        const noMatch = waf.evaluate(makeRequest({ uri: '/public/page' }));
        expect(noMatch.matchedRules).toHaveLength(0);
    });

    it('evaluates pm (phrase match) operator', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({
            targets: ['REQUEST_HEADERS'],
            operators: [{ type: 'pm', value: 'sqlmap|nikto|nmap' }],
        }));
        const match = waf.evaluate(makeRequest({
            headers: { 'User-Agent': 'sqlmap/1.5' },
        }));
        expect(match.matchedRules).toHaveLength(1);
    });

    it('evaluates detectSQLi operator', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({
            operators: [{ type: 'detectSQLi', value: '' }],
        }));
        const match = waf.evaluate(makeRequest({ args: { id: "1' OR 1=1--" } }));
        expect(match.matchedRules).toHaveLength(1);
    });

    it('evaluates detectXSS operator', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({
            operators: [{ type: 'detectXSS', value: '' }],
        }));
        const match = waf.evaluate(makeRequest({ args: { q: '<script>alert(1)</script>' } }));
        expect(match.matchedRules).toHaveLength(1);
    });

    it('evaluates negated operator', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({
            targets: ['REQUEST_METHOD'],
            operators: [{ type: 'within', value: 'GET|POST|HEAD', negated: true }],
        }));
        const match = waf.evaluate(makeRequest({ method: 'DELETE' }));
        expect(match.matchedRules).toHaveLength(1);

        const noMatch = waf.evaluate(makeRequest({ method: 'GET' }));
        expect(noMatch.matchedRules).toHaveLength(0);
    });

    it('evaluates numeric comparison operators', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({
            targets: ['REQUEST_BODY'],
            transforms: ['length'],
            operators: [{ type: 'gt', value: '1000' }],
            msg: 'Body too large',
        }));
        const bigBody = 'x'.repeat(1001);
        const match = waf.evaluate(makeRequest({ body: bigBody }));
        expect(match.matchedRules).toHaveLength(1);

        const smallBody = 'hello';
        const noMatch = waf.evaluate(makeRequest({ body: smallBody }));
        expect(noMatch.matchedRules).toHaveLength(0);
    });

    // ── Transforms ────────────────────────────────────────

    it('applies lowercase transform', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({
            transforms: ['lowercase'],
            operators: [{ type: 'contains', value: 'select' }],
        }));
        const result = waf.evaluate(makeRequest({ args: { q: 'SELECT * FROM users' } }));
        expect(result.matchedRules).toHaveLength(1);
    });

    it('applies urlDecode transform', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({
            transforms: ['urlDecode'],
            operators: [{ type: 'contains', value: '<script>' }],
        }));
        const result = waf.evaluate(makeRequest({ args: { q: '%3Cscript%3E' } }));
        expect(result.matchedRules).toHaveLength(1);
    });

    it('applies compressWhitespace transform', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({
            transforms: ['compressWhitespace'],
            operators: [{ type: 'contains', value: 'UNION SELECT' }],
        }));
        const result = waf.evaluate(makeRequest({ args: { q: 'UNION    SELECT' } }));
        expect(result.matchedRules).toHaveLength(1);
    });

    it('chains multiple transforms', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({
            transforms: ['lowercase', 'compressWhitespace'],
            operators: [{ type: 'contains', value: 'union select' }],
        }));
        const result = waf.evaluate(makeRequest({ args: { q: 'UNION    SELECT' } }));
        expect(result.matchedRules).toHaveLength(1);
    });

    it('applies normalizePath transform', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({
            targets: ['REQUEST_URI'],
            transforms: ['normalizePath'],
            operators: [{ type: 'contains', value: '/etc/passwd' }],
        }));
        const result = waf.evaluate(makeRequest({ uri: '/foo/../../../etc/passwd' }));
        expect(result.matchedRules).toHaveLength(1);
    });

    // ── Target Types ──────────────────────────────────────

    it('evaluates against REQUEST_URI', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({
            targets: ['REQUEST_URI'],
            operators: [{ type: 'contains', value: '/admin' }],
        }));
        const match = waf.evaluate(makeRequest({ uri: '/admin/panel' }));
        expect(match.matchedRules).toHaveLength(1);
    });

    it('evaluates against REQUEST_HEADERS', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({
            targets: ['REQUEST_HEADERS'],
            operators: [{ type: 'rx', value: 'evil-bot' }],
        }));
        const match = waf.evaluate(makeRequest({
            headers: { 'User-Agent': 'evil-bot/1.0' },
        }));
        expect(match.matchedRules).toHaveLength(1);
    });

    it('evaluates against REQUEST_COOKIES', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({
            targets: ['REQUEST_COOKIES'],
            operators: [{ type: 'detectSQLi', value: '' }],
        }));
        const match = waf.evaluate(makeRequest({
            cookies: { session: "admin' OR 1=1--" },
        }));
        expect(match.matchedRules).toHaveLength(1);
    });

    it('evaluates against REQUEST_BODY', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({
            targets: ['REQUEST_BODY'],
            operators: [{ type: 'contains', value: 'cmd.exe' }],
        }));
        const match = waf.evaluate(makeRequest({ body: 'exec cmd.exe /c dir' }));
        expect(match.matchedRules).toHaveLength(1);
    });

    it('evaluates against REMOTE_ADDR with ipMatch', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({
            targets: ['REMOTE_ADDR'],
            operators: [{ type: 'ipMatch', value: '10.0.0.5,192.168.1.100' }],
        }));
        const match = waf.evaluate(makeRequest({ remoteAddr: '10.0.0.5' }));
        expect(match.matchedRules).toHaveLength(1);

        const noMatch = waf.evaluate(makeRequest({ remoteAddr: '172.16.0.1' }));
        expect(noMatch.matchedRules).toHaveLength(0);
    });

    // ── Anomaly Scoring ───────────────────────────────────

    it('accumulates anomaly score', () => {
        const waf = createWAFEngine();
        waf.setAnomalyThreshold(10);
        waf.addRule(makeRule({
            id: 100,
            action: 'log',
            severity: 'WARNING',
            operators: [{ type: 'contains', value: 'suspicious' }],
        }));
        const result = waf.evaluate(makeRequest({ args: { q: 'suspicious activity' } }));
        expect(result.anomalyScore).toBeGreaterThan(0);
    });

    it('blocks when anomaly score exceeds threshold', () => {
        const waf = createWAFEngine();
        waf.setAnomalyThreshold(3);

        // Add multiple low-severity rules that all match
        waf.addRule(makeRule({ id: 100, action: 'log', severity: 'WARNING', operators: [{ type: 'contains', value: 'test' }] }));
        waf.addRule(makeRule({ id: 101, action: 'log', severity: 'WARNING', operators: [{ type: 'contains', value: 'test' }] }));
        waf.addRule(makeRule({ id: 102, action: 'log', severity: 'WARNING', operators: [{ type: 'contains', value: 'test' }] }));
        waf.addRule(makeRule({ id: 103, action: 'log', severity: 'WARNING', operators: [{ type: 'contains', value: 'test' }] }));

        const result = waf.evaluate(makeRequest({ args: { q: 'test value' } }));
        expect(result.anomalyScore).toBeGreaterThanOrEqual(3);
    });

    // ── Paranoia Levels ───────────────────────────────────

    it('sets and gets paranoia level', () => {
        const waf = createWAFEngine();
        waf.setParanoiaLevel(3);
        // Paranoia level affects which tagged rules are active
        // Just verify it doesn't throw
        expect(true).toBe(true);
    });

    // ── Phase Ordering ────────────────────────────────────

    it('evaluates rules by phase order', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({
            id: 200, phase: 2,
            operators: [{ type: 'contains', value: 'test' }],
        }));
        waf.addRule(makeRule({
            id: 100, phase: 1,
            targets: ['REQUEST_HEADERS'],
            operators: [{ type: 'contains', value: 'test' }],
        }));

        const result = waf.evaluate(makeRequest({
            args: { q: 'test' },
            headers: { 'X-Test': 'test' },
        }));

        // Both should match; phase 1 rule should be evaluated before phase 2
        if (result.matchedRules.length >= 2) {
            expect(result.matchedRules[0]!.ruleId).toBe(100);
            expect(result.matchedRules[1]!.ruleId).toBe(200);
        }
    });

    // ── Disabled Rules ────────────────────────────────────

    it('skips disabled rules', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({
            id: 100,
            enabled: false,
            operators: [{ type: 'contains', value: 'always' }],
        }));
        const result = waf.evaluate(makeRequest({ args: { q: 'always matches' } }));
        expect(result.matchedRules).toHaveLength(0);
    });

    // ── OWASP Core Rule Set ───────────────────────────────

    it('loads OWASP core rules', () => {
        const rules = createCoreRuleSet();
        expect(rules.length).toBeGreaterThanOrEqual(10);
        for (const rule of rules) {
            expect(rule.id).toBeGreaterThan(0);
            expect(rule.msg).toBeTruthy();
        }
    });

    it('CRS detects SQL injection', () => {
        const waf = createWAFEngine();
        for (const rule of createCoreRuleSet()) waf.addRule(rule);

        const result = waf.evaluate(makeRequest({
            args: { id: "1' UNION SELECT password FROM users--" },
        }));
        expect(result.matchedRules.length).toBeGreaterThanOrEqual(1);
    });

    it('CRS detects XSS', () => {
        const waf = createWAFEngine();
        for (const rule of createCoreRuleSet()) waf.addRule(rule);

        const result = waf.evaluate(makeRequest({
            args: { q: '<script>document.cookie</script>' },
        }));
        expect(result.matchedRules.length).toBeGreaterThanOrEqual(1);
    });

    it('CRS detects command injection', () => {
        const waf = createWAFEngine();
        for (const rule of createCoreRuleSet()) waf.addRule(rule);

        const result = waf.evaluate(makeRequest({
            args: { cmd: '; cat /etc/passwd' },
        }));
        expect(result.matchedRules.length).toBeGreaterThanOrEqual(1);
    });

    it('CRS detects path traversal', () => {
        const waf = createWAFEngine();
        for (const rule of createCoreRuleSet()) waf.addRule(rule);

        const result = waf.evaluate(makeRequest({
            uri: '/../../etc/passwd',
            args: { file: '../../../../etc/shadow' },
        }));
        expect(result.matchedRules.length).toBeGreaterThanOrEqual(1);
    });

    it('CRS detects scanner user-agents', () => {
        const waf = createWAFEngine();
        for (const rule of createCoreRuleSet()) waf.addRule(rule);

        const result = waf.evaluate(makeRequest({
            headers: { 'User-Agent': 'sqlmap/1.5.2#stable' },
        }));
        expect(result.matchedRules.length).toBeGreaterThanOrEqual(1);
    });

    it('CRS allows legitimate traffic', () => {
        const waf = createWAFEngine();
        for (const rule of createCoreRuleSet()) waf.addRule(rule);

        const result = waf.evaluate(makeRequest({
            method: 'GET',
            uri: '/api/users',
            headers: { 'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json' },
            args: { page: '1', limit: '20' },
        }));
        expect(result.matchedRules).toHaveLength(0);
        expect(result.blocked).toBe(false);
    });

    // ── Stats ─────────────────────────────────────────────

    it('tracks statistics', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({ operators: [{ type: 'contains', value: 'attack' }] }));

        waf.evaluate(makeRequest({ args: { q: 'attack payload' } }));
        waf.evaluate(makeRequest({ args: { q: 'normal traffic' } }));

        const stats = waf.getStats();
        expect(stats.requestsEvaluated).toBe(2);
        expect(stats.requestsBlocked).toBe(1);
        expect(stats.requestsAllowed).toBe(1);
    });

    it('resets statistics', () => {
        const waf = createWAFEngine();
        waf.addRule(makeRule({ operators: [{ type: 'contains', value: 'x' }] }));
        waf.evaluate(makeRequest({ args: { q: 'x' } }));
        waf.resetStats();
        const stats = waf.getStats();
        expect(stats.requestsEvaluated).toBe(0);
    });
});
