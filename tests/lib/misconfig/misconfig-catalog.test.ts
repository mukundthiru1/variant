import { describe, it, expect, beforeEach } from 'vitest';
import { createMisconfigCatalog } from '../../../src/lib/misconfig/catalog';
import type { MisconfigCatalog, MisconfigTemplate } from '../../../src/lib/misconfig/types';

describe('Misconfiguration Catalog', () => {
    let catalog: MisconfigCatalog;

    beforeEach(() => {
        catalog = createMisconfigCatalog();
    });

    // ── Retrieval ───────────────────────────────────────────────

    it('get returns template by ID', () => {
        const t = catalog.get('MISC-0001');
        expect(t).not.toBeNull();
        expect(t!.name).toBe('Default SSH Root Password');
        expect(t!.category).toBe('authentication');
    });

    it('get returns null for unknown ID', () => {
        expect(catalog.get('MISC-9999')).toBeNull();
    });

    // ── Listing ─────────────────────────────────────────────────

    it('list returns all built-in templates', () => {
        const all = catalog.list();
        expect(all.length).toBeGreaterThanOrEqual(15);
    });

    it('listByCategory filters correctly', () => {
        const auth = catalog.listByCategory('authentication');
        expect(auth.length).toBeGreaterThanOrEqual(3);
        for (const t of auth) {
            expect(t.category).toBe('authentication');
        }
    });

    it('listBySeverity filters correctly', () => {
        const critical = catalog.listBySeverity('critical');
        expect(critical.length).toBeGreaterThanOrEqual(4);
        for (const t of critical) {
            expect(t.severity).toBe('critical');
        }
    });

    it('listByMitreTechnique finds templates for T1078 (Valid Accounts)', () => {
        const results = catalog.listByMitreTechnique('T1078');
        expect(results.length).toBeGreaterThan(0);
        for (const t of results) {
            expect(t.mitreTechniques).toContain('T1078');
        }
    });

    // ── Search ──────────────────────────────────────────────────

    it('search finds templates by keyword', () => {
        const results = catalog.search('ssh');
        expect(results.length).toBeGreaterThan(0);
        expect(results.some(t => t.id === 'MISC-0001')).toBe(true);
    });

    it('search finds templates by tag', () => {
        const results = catalog.search('redis');
        expect(results.length).toBeGreaterThan(0);
    });

    it('search returns empty for nonsense', () => {
        expect(catalog.search('zzzznonexistent')).toHaveLength(0);
    });

    // ── Template Quality ────────────────────────────────────────

    it('every template has files', () => {
        for (const t of catalog.list()) {
            expect(Object.keys(t.files).length).toBeGreaterThan(0);
        }
    });

    it('every template has clues', () => {
        for (const t of catalog.list()) {
            expect(t.clues.length).toBeGreaterThan(0);
        }
    });

    it('every template has detection hints', () => {
        for (const t of catalog.list()) {
            expect(t.detectionHints.length).toBeGreaterThan(0);
        }
    });

    it('every template has remediation steps', () => {
        for (const t of catalog.list()) {
            expect(t.remediation.length).toBeGreaterThan(0);
        }
    });

    it('every template has MITRE technique mappings', () => {
        for (const t of catalog.list()) {
            expect(t.mitreTechniques.length).toBeGreaterThan(0);
        }
    });

    it('every template has tags', () => {
        for (const t of catalog.list()) {
            expect(t.tags.length).toBeGreaterThan(0);
        }
    });

    it('every template has applicable roles', () => {
        for (const t of catalog.list()) {
            expect(t.applicableRoles.length).toBeGreaterThan(0);
        }
    });

    // ── Custom Templates ────────────────────────────────────────

    it('addTemplate adds a custom template', () => {
        const custom: MisconfigTemplate = {
            id: 'MISC-CUSTOM', name: 'Custom Test',
            description: 'A test misconfiguration.',
            realWorldContext: 'For testing.',
            category: 'authentication', severity: 'low',
            mitreTechniques: ['T1078'],
            files: { '/etc/test': { content: 'test', mode: 0o644 } },
            clues: [{ location: 'file', path: '/etc/test', content: 'test', visibility: 3 }],
            detectionHints: ['Check /etc/test'],
            remediation: ['Remove /etc/test'],
            tags: ['test'],
            applicableRoles: ['target'],
        };
        catalog.addTemplate(custom);
        expect(catalog.get('MISC-CUSTOM')).not.toBeNull();
        expect(catalog.get('MISC-CUSTOM')!.name).toBe('Custom Test');
    });

    // ── Stats ───────────────────────────────────────────────────

    it('getStats returns accurate counts', () => {
        const stats = catalog.getStats();
        expect(stats.totalTemplates).toBe(catalog.list().length);
        expect(stats.uniqueMitreTechniques).toBeGreaterThan(5);
        expect(stats.byCategory['authentication']).toBeGreaterThanOrEqual(3);
        expect(stats.bySeverity['critical']).toBeGreaterThanOrEqual(4);
    });

    // ── Data Integrity ──────────────────────────────────────────

    it('templates are frozen', () => {
        const t = catalog.get('MISC-0001');
        expect(t).not.toBeNull();
        expect(Object.isFrozen(t)).toBe(true);
    });

    it('lists are frozen', () => {
        const all = catalog.list();
        expect(Object.isFrozen(all)).toBe(true);
    });

    // ── Specific Template Content ───────────────────────────────

    it('MISC-0002 hardcoded creds has .env file with password', () => {
        const t = catalog.get('MISC-0002')!;
        expect(t.files['/var/www/html/.env']).toBeDefined();
        expect(t.files['/var/www/html/.env']!.content).toContain('DB_PASSWORD');
    });

    it('MISC-0011 SUID binary has correct file modes', () => {
        const t = catalog.get('MISC-0011')!;
        expect(t.files['/usr/bin/find']!.mode).toBe(0o4755);
    });

    it('MISC-0060 privileged container has .dockerenv', () => {
        const t = catalog.get('MISC-0060')!;
        expect(t.files['/.dockerenv']).toBeDefined();
        expect(t.mitreTechniques).toContain('T1611');
    });

    it('MISC-0070 cloud metadata references IMDS', () => {
        const t = catalog.get('MISC-0070')!;
        expect(t.files['/etc/cloud/cloud.cfg']!.content).toContain('169.254.169.254');
    });
});
