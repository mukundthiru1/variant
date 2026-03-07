/**
 * VARIANT — Threat Intelligence Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createThreatIntelEngine } from '../../../src/lib/threat-intel/threat-intel-engine';
import type {
    AttackTechnique,
    AttackTactic,
    IOCDefinition,
    KillChainPhase,
    ThreatActorProfile,
} from '../../../src/lib/threat-intel/types';

function makeTechnique(id: string, tactic: AttackTactic, name?: string): AttackTechnique {
    return {
        id,
        name: name ?? `Technique ${id}`,
        tactic,
        parent: null,
        dataSources: ['process-monitoring'],
        platforms: ['windows', 'linux'],
        description: `Description for ${id}`,
    };
}

function makeIOC(id: string, type: IOCDefinition['type'], value: string): IOCDefinition {
    return {
        id,
        type,
        value,
        location: { machine: 'workstation-1', source: 'log', path: '/var/log/syslog' },
        confidence: 0.85,
        techniques: ['T1059'],
    };
}

function makePhase(id: string, order: number, objectives: string[]): KillChainPhase {
    return {
        id,
        model: 'lockheed-martin',
        name: `Phase ${id}`,
        order,
        tactics: ['execution'],
        objectives,
    };
}

function makeActor(id: string): ThreatActorProfile {
    return {
        id,
        name: `Actor ${id}`,
        aliases: [`alias-${id}`],
        motivation: 'espionage',
        sophistication: 'advanced',
        techniques: ['T1059', 'T1071'],
        targetSectors: ['government', 'defense'],
        description: `Profile for ${id}`,
    };
}

describe('ThreatIntelEngine', () => {
    // ── Technique Management ──────────────────────────────────────

    it('loads and retrieves techniques', () => {
        const engine = createThreatIntelEngine();
        const t1 = makeTechnique('T1059', 'execution', 'Command and Scripting Interpreter');
        const t2 = makeTechnique('T1071', 'command-and-control', 'Application Layer Protocol');
        engine.loadTechniques([t1, t2]);

        expect(engine.getTechnique('T1059')).toEqual(t1);
        expect(engine.getTechnique('T1071')).toEqual(t2);
        expect(engine.getTechnique('T9999')).toBeNull();
    });

    it('gets techniques by tactic', () => {
        const engine = createThreatIntelEngine();
        engine.loadTechniques([
            makeTechnique('T1059', 'execution'),
            makeTechnique('T1059.001', 'execution'),
            makeTechnique('T1071', 'command-and-control'),
        ]);

        const exec = engine.getTechniquesByTactic('execution');
        expect(exec.length).toBe(2);
        expect(exec.every(t => t.tactic === 'execution')).toBe(true);

        const c2 = engine.getTechniquesByTactic('command-and-control');
        expect(c2.length).toBe(1);
    });

    it('searches techniques by name, id, and description', () => {
        const engine = createThreatIntelEngine();
        engine.loadTechniques([
            makeTechnique('T1059', 'execution', 'PowerShell'),
            makeTechnique('T1071', 'command-and-control', 'Application Layer Protocol'),
        ]);

        expect(engine.searchTechniques('powershell').length).toBe(1);
        expect(engine.searchTechniques('T1071').length).toBe(1);
        expect(engine.searchTechniques('Description for T1059').length).toBe(1);
        expect(engine.searchTechniques('nonexistent').length).toBe(0);
    });

    it('search is case-insensitive', () => {
        const engine = createThreatIntelEngine();
        engine.loadTechniques([makeTechnique('T1059', 'execution', 'PowerShell')]);

        expect(engine.searchTechniques('POWERSHELL').length).toBe(1);
        expect(engine.searchTechniques('powershell').length).toBe(1);
    });

    // ── IOC Management ────────────────────────────────────────────

    it('registers and retrieves IOCs', () => {
        const engine = createThreatIntelEngine();
        engine.registerIOCs([
            makeIOC('ioc-1', 'ip-address', '10.0.0.1'),
            makeIOC('ioc-2', 'domain', 'evil.example.com'),
        ]);

        const all = engine.getIOCs();
        expect(all.length).toBe(2);
    });

    it('filters IOCs by type', () => {
        const engine = createThreatIntelEngine();
        engine.registerIOCs([
            makeIOC('ioc-1', 'ip-address', '10.0.0.1'),
            makeIOC('ioc-2', 'domain', 'evil.example.com'),
            makeIOC('ioc-3', 'ip-address', '192.168.1.1'),
        ]);

        const ips = engine.getIOCsByType('ip-address');
        expect(ips.length).toBe(2);
        expect(ips.every(i => i.type === 'ip-address')).toBe(true);

        const domains = engine.getIOCsByType('domain');
        expect(domains.length).toBe(1);
    });

    it('marks IOCs as discovered', () => {
        const engine = createThreatIntelEngine();
        engine.registerIOCs([
            makeIOC('ioc-1', 'ip-address', '10.0.0.1'),
            makeIOC('ioc-2', 'domain', 'evil.example.com'),
        ]);

        expect(engine.getDiscovered().length).toBe(0);

        expect(engine.markDiscovered('ioc-1')).toBe(true);
        expect(engine.getDiscovered().length).toBe(1);
        expect(engine.getDiscovered()[0]!.id).toBe('ioc-1');

        expect(engine.markDiscovered('nonexistent')).toBe(false);
    });

    it('discovered state persists across getIOCs calls', () => {
        const engine = createThreatIntelEngine();
        engine.registerIOCs([makeIOC('ioc-1', 'ip-address', '10.0.0.1')]);
        engine.markDiscovered('ioc-1');

        const all = engine.getIOCs();
        expect(all[0]!.discovered).toBe(true);
    });

    // ── Kill Chain ────────────────────────────────────────────────

    it('loads kill chain phases sorted by order', () => {
        const engine = createThreatIntelEngine();
        engine.loadKillChain([
            makePhase('exploit', 3, ['run-exploit']),
            makePhase('recon', 1, ['scan-ports']),
            makePhase('deliver', 2, ['send-payload']),
        ]);

        // getCurrentPhase with recon objective should return recon
        const phase = engine.getCurrentPhase(['scan-ports']);
        expect(phase).not.toBeNull();
        expect(phase!.id).toBe('recon');
    });

    it('getCurrentPhase returns latest completed phase', () => {
        const engine = createThreatIntelEngine();
        engine.loadKillChain([
            makePhase('recon', 1, ['scan-ports']),
            makePhase('deliver', 2, ['send-payload']),
            makePhase('exploit', 3, ['run-exploit']),
        ]);

        const phase = engine.getCurrentPhase(['scan-ports', 'send-payload']);
        expect(phase!.id).toBe('deliver');
    });

    it('getCurrentPhase returns null when no objectives completed', () => {
        const engine = createThreatIntelEngine();
        engine.loadKillChain([makePhase('recon', 1, ['scan-ports'])]);

        expect(engine.getCurrentPhase([])).toBeNull();
    });

    it('getKillChainProgress computes correct ratio', () => {
        const engine = createThreatIntelEngine();
        engine.loadKillChain([
            makePhase('recon', 1, ['scan-ports', 'enumerate-hosts']),
            makePhase('exploit', 2, ['run-exploit']),
        ]);

        // 3 total objectives, 1 completed
        expect(engine.getKillChainProgress(['scan-ports'])).toBeCloseTo(1 / 3);

        // All completed
        expect(engine.getKillChainProgress(['scan-ports', 'enumerate-hosts', 'run-exploit'])).toBeCloseTo(1);
    });

    it('getKillChainProgress returns 0 for empty chain', () => {
        const engine = createThreatIntelEngine();
        expect(engine.getKillChainProgress([])).toBe(0);
    });

    // ── Threat Actors ─────────────────────────────────────────────

    it('loads and retrieves actors', () => {
        const engine = createThreatIntelEngine();
        const actor = makeActor('apt29');
        engine.loadActor(actor);

        expect(engine.getActor('apt29')).toEqual(actor);
        expect(engine.getActor('nonexistent')).toBeNull();
    });

    it('lists all actors', () => {
        const engine = createThreatIntelEngine();
        engine.loadActor(makeActor('apt29'));
        engine.loadActor(makeActor('fin7'));

        const all = engine.listActors();
        expect(all.length).toBe(2);
    });

    // ── Coverage Analysis ─────────────────────────────────────────

    it('computes technique coverage across scenarios', () => {
        const engine = createThreatIntelEngine();
        const map = new Map<string, readonly string[]>();
        map.set('scenario-1', ['T1059', 'T1071']);
        map.set('scenario-2', ['T1059', 'T1548']);

        const coverage = engine.computeCoverage(map);
        expect(coverage.length).toBe(3);

        const t1059 = coverage.find(c => c.techniqueId === 'T1059');
        expect(t1059).toBeDefined();
        expect(t1059!.scenarioIds).toContain('scenario-1');
        expect(t1059!.scenarioIds).toContain('scenario-2');
        expect(t1059!.scenarioIds.length).toBe(2);

        const t1548 = coverage.find(c => c.techniqueId === 'T1548');
        expect(t1548!.scenarioIds.length).toBe(1);
    });

    it('computes coverage for empty map', () => {
        const engine = createThreatIntelEngine();
        expect(engine.computeCoverage(new Map()).length).toBe(0);
    });

    // ── Heatmap Generation ────────────────────────────────────────

    it('generates heatmap from used and detected techniques', () => {
        const engine = createThreatIntelEngine();
        engine.loadTechniques([
            makeTechnique('T1059', 'execution'),
            makeTechnique('T1071', 'command-and-control'),
        ]);

        const cells = engine.generateHeatmap(
            ['T1059', 'T1059', 'T1071'],
            ['T1059'],
        );

        expect(cells.length).toBe(2);

        const t1059 = cells.find(c => c.techniqueId === 'T1059');
        expect(t1059!.count).toBe(2);
        expect(t1059!.detected).toBe(1);
        expect(t1059!.coverage).toBeCloseTo(0.5);
        expect(t1059!.tactic).toBe('execution');

        const t1071 = cells.find(c => c.techniqueId === 'T1071');
        expect(t1071!.count).toBe(1);
        expect(t1071!.detected).toBe(0);
        expect(t1071!.coverage).toBe(0);
    });

    it('heatmap uses execution as default tactic for unknown techniques', () => {
        const engine = createThreatIntelEngine();
        const cells = engine.generateHeatmap(['T9999'], []);

        expect(cells.length).toBe(1);
        expect(cells[0]!.tactic).toBe('execution');
    });

    // ── Clear ─────────────────────────────────────────────────────

    it('clear removes all state', () => {
        const engine = createThreatIntelEngine();
        engine.loadTechniques([makeTechnique('T1059', 'execution')]);
        engine.registerIOCs([makeIOC('ioc-1', 'ip-address', '10.0.0.1')]);
        engine.loadKillChain([makePhase('recon', 1, ['scan'])]);
        engine.loadActor(makeActor('apt29'));

        engine.clear();

        expect(engine.getTechnique('T1059')).toBeNull();
        expect(engine.getIOCs().length).toBe(0);
        expect(engine.getCurrentPhase(['scan'])).toBeNull();
        expect(engine.getActor('apt29')).toBeNull();
        expect(engine.listActors().length).toBe(0);
    });
});
