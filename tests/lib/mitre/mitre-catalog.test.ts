import { describe, it, expect, beforeEach } from 'vitest';
import { createMitreCatalog } from '../../../src/lib/mitre/catalog';
import type { MitreCatalog, TechniqueEntry } from '../../../src/lib/mitre/types';

describe('MITRE ATT&CK Catalog', () => {
    let catalog: MitreCatalog;

    beforeEach(() => {
        catalog = createMitreCatalog();
    });

    // ── Technique Retrieval ─────────────────────────────────────

    it('getTechnique returns known technique by ID', () => {
        const t = catalog.getTechnique('T1190');
        expect(t).not.toBeNull();
        expect(t!.name).toBe('Exploit Public-Facing Application');
        expect(t!.tactics).toContain('initial-access');
    });

    it('getTechnique returns sub-technique by ID', () => {
        const t = catalog.getTechnique('T1059.004');
        expect(t).not.toBeNull();
        expect(t!.name).toBe('Unix Shell');
        expect(t!.parent).toBe('T1059');
    });

    it('getTechnique returns null for unknown ID', () => {
        expect(catalog.getTechnique('T9999')).toBeNull();
    });

    // ── Listing ─────────────────────────────────────────────────

    it('listTechniques returns all built-in techniques', () => {
        const all = catalog.listTechniques();
        expect(all.length).toBeGreaterThan(70);
    });

    it('listByTactic returns techniques for a specific tactic', () => {
        const lateral = catalog.listByTactic('lateral-movement');
        expect(lateral.length).toBeGreaterThan(5);
        for (const t of lateral) {
            expect(t.tactics).toContain('lateral-movement');
        }
    });

    it('listByPlatform returns techniques for linux', () => {
        const linux = catalog.listByPlatform('linux');
        expect(linux.length).toBeGreaterThan(30);
        for (const t of linux) {
            expect(t.platforms).toContain('linux');
        }
    });

    it('listByPlatform returns techniques for containers', () => {
        const containers = catalog.listByPlatform('containers');
        expect(containers.length).toBeGreaterThan(0);
        const ids = containers.map(t => t.id);
        expect(ids).toContain('T1611');
    });

    it('listByEngine returns techniques simulated by lateral engine', () => {
        const lateral = catalog.listByEngine('lateral');
        expect(lateral.length).toBeGreaterThan(10);
        for (const t of lateral) {
            expect('lateral' in t.variantEngines).toBe(true);
        }
    });

    it('listDetectable returns techniques with detection rules', () => {
        const detectable = catalog.listDetectable();
        expect(detectable.length).toBeGreaterThan(30);
        for (const t of detectable) {
            expect(Object.keys(t.variantDetections).length).toBeGreaterThan(0);
        }
    });

    it('listSubTechniques returns children of a parent', () => {
        const subs = catalog.listSubTechniques('T1059');
        expect(subs.length).toBeGreaterThanOrEqual(3);
        for (const s of subs) {
            expect(s.parent).toBe('T1059');
        }
    });

    it('listSubTechniques returns empty for leaf technique', () => {
        expect(catalog.listSubTechniques('T1059.004')).toHaveLength(0);
    });

    // ── Search ──────────────────────────────────────────────────

    it('search finds techniques by name keyword', () => {
        const results = catalog.search('brute force');
        expect(results.length).toBeGreaterThan(0);
        expect(results.some(t => t.id === 'T1110')).toBe(true);
    });

    it('search finds techniques by tag', () => {
        const results = catalog.search('ssh');
        expect(results.length).toBeGreaterThan(0);
        expect(results.some(t => t.id === 'T1021.004')).toBe(true);
    });

    it('search finds techniques by ID', () => {
        const results = catalog.search('T1550');
        expect(results.length).toBeGreaterThan(0);
    });

    it('search returns empty for nonsense query', () => {
        expect(catalog.search('zzzznonexistent')).toHaveLength(0);
    });

    // ── Tactics ─────────────────────────────────────────────────

    it('listTactics returns all represented tactics', () => {
        const tactics = catalog.listTactics();
        expect(tactics.length).toBeGreaterThanOrEqual(10);
        expect(tactics).toContain('initial-access');
        expect(tactics).toContain('lateral-movement');
        expect(tactics).toContain('exfiltration');
        expect(tactics).toContain('persistence');
    });

    // ── Custom Techniques ───────────────────────────────────────

    it('addCustomTechnique adds a new technique', () => {
        const custom: TechniqueEntry = {
            id: 'T9999', name: 'Custom Test Technique',
            description: 'A test technique.',
            tactics: ['execution'], platforms: ['linux'],
            variantEngines: {}, variantDetections: {},
            detectionDifficulty: 'moderate',
            dataSources: ['Test: Test Data'],
            simulationSupport: 'planned',
            tags: ['test'],
        };
        catalog.addCustomTechnique(custom);
        const result = catalog.getTechnique('T9999');
        expect(result).not.toBeNull();
        expect(result!.name).toBe('Custom Test Technique');
    });

    // ── Stats ───────────────────────────────────────────────────

    it('getStats returns accurate counts', () => {
        const stats = catalog.getStats();
        expect(stats.totalTechniques).toBeGreaterThan(30);
        expect(stats.totalSubTechniques).toBeGreaterThan(30);
        expect(stats.totalTechniques + stats.totalSubTechniques).toBe(catalog.listTechniques().length);
        expect(stats.byTactic['lateral-movement']).toBeGreaterThan(5);
        expect(stats.bySimulationSupport['full']).toBeGreaterThan(40);
        expect(stats.totalDetectable).toBeGreaterThan(30);
    });

    // ── Coverage ────────────────────────────────────────────────

    it('getCoverage returns tactic-level breakdown', () => {
        const coverage = catalog.getCoverage();
        expect(coverage.byTactic.length).toBeGreaterThan(0);
        expect(coverage.overallSimulatable).toBeGreaterThan(50);
        expect(coverage.overallDetectable).toBeGreaterThan(30);

        const lateral = coverage.byTactic.find(t => t.tactic === 'lateral-movement');
        expect(lateral).toBeDefined();
        expect(lateral!.fullSupport).toBeGreaterThan(0);
        expect(lateral!.coveragePercent).toBeGreaterThan(0);
    });

    // ── Frozen Data ─────────────────────────────────────────────

    it('returned techniques are frozen', () => {
        const t = catalog.getTechnique('T1190');
        expect(t).not.toBeNull();
        expect(Object.isFrozen(t)).toBe(true);
    });

    it('technique lists are frozen', () => {
        const all = catalog.listTechniques();
        expect(Object.isFrozen(all)).toBe(true);
    });

    // ── VARIANT Engine Mapping ──────────────────────────────────

    it('lateral movement techniques map to lateral engine', () => {
        const pth = catalog.getTechnique('T1550.002');
        expect(pth).not.toBeNull();
        expect(pth!.variantEngines['lateral']).toBeDefined();
    });

    it('persistence techniques map to persistence engine', () => {
        const cron = catalog.getTechnique('T1053.003');
        expect(cron).not.toBeNull();
        expect(cron!.variantEngines['persistence']).toBeDefined();
    });

    it('exfiltration techniques map to exfiltration engine', () => {
        const exfil = catalog.getTechnique('T1048.003');
        expect(exfil).not.toBeNull();
        expect(exfil!.variantEngines['exfiltration']).toBeDefined();
    });

    it('container escape maps to container engine', () => {
        const escape = catalog.getTechnique('T1611');
        expect(escape).not.toBeNull();
        expect(escape!.variantEngines['container']).toBeDefined();
    });
});
