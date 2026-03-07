import { describe, it, expect, beforeEach } from 'vitest';
import { createVulnCatalog } from '../../../src/lib/vuln/catalog';
import type { VulnCatalog } from '../../../src/lib/vuln/catalog';
import type { VulnDefinition } from '../../../src/lib/vuln/types';

describe('Vulnerability Template Catalog', () => {
    let catalog: VulnCatalog;

    beforeEach(() => {
        catalog = createVulnCatalog();
    });

    // ── Retrieval ───────────────────────────────────────────────

    it('get returns template by ID', () => {
        const v = catalog.get('VART-0001');
        expect(v).not.toBeNull();
        expect(v!.name).toBe('Login Form SQL Injection');
        expect(v!.category).toBe('sqli');
    });

    it('get returns null for unknown ID', () => {
        expect(catalog.get('VART-9999')).toBeNull();
    });

    // ── Listing ─────────────────────────────────────────────────

    it('list returns all built-in vulns', () => {
        const all = catalog.list();
        expect(all.length).toBeGreaterThanOrEqual(12);
    });

    it('listByCategory returns SQLi vulns', () => {
        const sqli = catalog.listByCategory('sqli');
        expect(sqli.length).toBeGreaterThanOrEqual(2);
        for (const v of sqli) {
            expect(v.category).toBe('sqli');
        }
    });

    it('listByCategory returns XSS vulns', () => {
        const xss = catalog.listByCategory('xss');
        expect(xss.length).toBeGreaterThanOrEqual(2);
    });

    it('listByDifficulty returns beginner vulns', () => {
        const beginner = catalog.listByDifficulty('beginner');
        expect(beginner.length).toBeGreaterThanOrEqual(4);
        for (const v of beginner) {
            expect(v.difficulty).toBe('beginner');
        }
    });

    // ── Search ──────────────────────────────────────────────────

    it('search finds vulns by keyword', () => {
        const results = catalog.search('command injection');
        expect(results.length).toBeGreaterThan(0);
    });

    it('search finds vulns by tag', () => {
        const results = catalog.search('jwt');
        expect(results.length).toBeGreaterThan(0);
    });

    it('search returns empty for nonsense', () => {
        expect(catalog.search('zzzznonexistent')).toHaveLength(0);
    });

    // ── Template Quality ────────────────────────────────────────

    it('every vuln has patches', () => {
        for (const v of catalog.list()) {
            expect(v.patches.length).toBeGreaterThan(0);
        }
    });

    it('every vuln has detection triggers', () => {
        for (const v of catalog.list()) {
            expect(v.detection.triggers.length).toBeGreaterThan(0);
        }
    });

    it('every vuln has a valid severity score', () => {
        for (const v of catalog.list()) {
            expect(v.severity).toBeGreaterThanOrEqual(0);
            expect(v.severity).toBeLessThanOrEqual(10);
        }
    });

    it('every vuln has compatible bases', () => {
        for (const v of catalog.list()) {
            expect(v.compatibleBases.length).toBeGreaterThan(0);
        }
    });

    // ── Custom Vulns ────────────────────────────────────────────

    it('add adds a custom vulnerability', () => {
        const custom: VulnDefinition = {
            id: 'VART-CUSTOM', name: 'Custom Test Vuln',
            description: 'A test vulnerability.', category: 'custom',
            difficulty: 'beginner', compatibleBases: ['*'],
            severity: 5.0,
            patches: [{ type: 'create', path: '/tmp/test', content: 'test' }],
            detection: { mode: 'any', triggers: [{ type: 'file:read', path: '/tmp/test' }] },
        };
        catalog.add(custom);
        expect(catalog.get('VART-CUSTOM')).not.toBeNull();
    });

    // ── Stats ───────────────────────────────────────────────────

    it('getStats returns accurate counts', () => {
        const stats = catalog.getStats();
        expect(stats.totalVulns).toBe(catalog.list().length);
        expect(stats.byCategory['sqli']).toBeGreaterThanOrEqual(2);
        expect(stats.byDifficulty['beginner']).toBeGreaterThanOrEqual(4);
    });

    // ── Specific Vuln Content ───────────────────────────────────

    it('VART-0001 SQLi has login.php patch', () => {
        const v = catalog.get('VART-0001')!;
        expect(v.patches[0]!.path).toBe('/var/www/html/login.php');
        expect(v.patches[0]!.content).toContain('VULNERABLE');
    });

    it('VART-0020 RCE has command injection via shell_exec', () => {
        const v = catalog.get('VART-0020')!;
        expect(v.patches[0]!.content).toContain('shell_exec');
        expect(v.category).toBe('rce');
        expect(v.severity).toBeGreaterThanOrEqual(9);
    });

    it('VART-0030 SSRF has URL preview endpoint', () => {
        const v = catalog.get('VART-0030')!;
        expect(v.patches[0]!.content).toContain('file_get_contents($url)');
    });

    it('VART-0050 JWT none algorithm bypass', () => {
        const v = catalog.get('VART-0050')!;
        expect(v.category).toBe('jwt-bypass');
        expect(v.detection.triggers.length).toBeGreaterThan(0);
    });

    it('VART-0090 Git repo exposure has .git files', () => {
        const v = catalog.get('VART-0090')!;
        expect(v.patches.some(p => p.path === '/var/www/html/.git/HEAD')).toBe(true);
    });

    // ── MITRE Technique Mapping ───────────────────────────────

    it('every vuln has MITRE technique mappings', () => {
        for (const v of catalog.list()) {
            expect(v.mitreTechniques).toBeDefined();
            expect(v.mitreTechniques!.length).toBeGreaterThan(0);
        }
    });

    it('every vuln has CWE IDs', () => {
        for (const v of catalog.list()) {
            expect(v.cweIds).toBeDefined();
            expect(v.cweIds!.length).toBeGreaterThan(0);
        }
    });

    it('listByMitreTechnique finds SQLi vulns via T1190', () => {
        const results = catalog.listByMitreTechnique('T1190');
        expect(results.length).toBeGreaterThanOrEqual(2);
        for (const v of results) {
            expect(v.mitreTechniques).toContain('T1190');
        }
    });

    it('listByMitreTechnique returns empty for unknown technique', () => {
        expect(catalog.listByMitreTechnique('T9999')).toHaveLength(0);
    });

    // ── Data Integrity ──────────────────────────────────────────

    it('vulns are frozen', () => {
        const v = catalog.get('VART-0001');
        expect(v).not.toBeNull();
        expect(Object.isFrozen(v)).toBe(true);
    });
});
