import { describe, it, expect, beforeEach } from 'vitest';
import { createMitreCatalog } from '../../../src/lib/mitre/catalog';
import { createLevelToolkit } from '../../../src/lib/level-tools/toolkit';
import { DEMO_01 } from '../../../src/levels/demo-01';
import type { LevelToolkit } from '../../../src/lib/level-tools/types';
import type { WorldSpec } from '../../../src/core/world/types';

describe('Level Designer Toolkit', () => {
    let toolkit: LevelToolkit;

    beforeEach(() => {
        const catalog = createMitreCatalog();
        toolkit = createLevelToolkit(catalog);
    });

    // ── Validation ──────────────────────────────────────────────

    describe('validate', () => {
        it('validates demo-01 as valid', () => {
            const result = toolkit.validate(DEMO_01);
            expect(result.valid).toBe(true);
            expect(result.errors).toHaveLength(0);
        });

        it('rejects non-object input', () => {
            const result = toolkit.validate('not an object');
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.code === 'INVALID_FORMAT')).toBe(true);
        });

        it('rejects null input', () => {
            const result = toolkit.validate(null);
            expect(result.valid).toBe(false);
        });

        it('detects missing title', () => {
            const world = makeMinimalWorld({ meta: { ...DEMO_01.meta, title: '' } });
            const result = toolkit.validate(world);
            expect(result.errors.some(e => e.code === 'MISSING_TITLE')).toBe(true);
        });

        it('detects missing scenario', () => {
            const world = makeMinimalWorld({ meta: { ...DEMO_01.meta, scenario: '' } });
            const result = toolkit.validate(world);
            expect(result.errors.some(e => e.code === 'MISSING_SCENARIO')).toBe(true);
        });

        it('detects no machines', () => {
            const world = makeMinimalWorld({ machines: {} });
            const result = toolkit.validate(world);
            expect(result.errors.some(e => e.code === 'NO_MACHINES')).toBe(true);
        });

        it('detects invalid startMachine', () => {
            const world = makeMinimalWorld({ startMachine: 'nonexistent' });
            const result = toolkit.validate(world);
            expect(result.errors.some(e => e.code === 'INVALID_START')).toBe(true);
        });

        it('detects no player machine', () => {
            const world = makeMinimalWorld({
                machines: {
                    'target': {
                        hostname: 'target', image: 'alpine', memoryMB: 64,
                        role: 'target', interfaces: [{ ip: '10.0.1.10', segment: 'corporate' }],
                    },
                },
                startMachine: 'target',
            });
            const result = toolkit.validate(world);
            expect(result.errors.some(e => e.code === 'NO_PLAYER')).toBe(true);
        });

        it('detects no objectives', () => {
            const world = makeMinimalWorld({ objectives: [] });
            const result = toolkit.validate(world);
            expect(result.errors.some(e => e.code === 'NO_OBJECTIVES')).toBe(true);
        });

        it('detects duplicate objective IDs', () => {
            const world = makeMinimalWorld({
                objectives: [
                    { id: 'dup', title: 'A', description: 'A', type: 'find-file', required: true, details: { kind: 'find-file', machine: 'web-server', path: '/test' } },
                    { id: 'dup', title: 'B', description: 'B', type: 'find-file', required: false, details: { kind: 'find-file', machine: 'web-server', path: '/test2' } },
                ],
            });
            const result = toolkit.validate(world);
            expect(result.errors.some(e => e.code === 'DUPLICATE_OBJ')).toBe(true);
        });

        it('detects invalid credential machine reference', () => {
            const world = makeMinimalWorld({
                credentials: [{
                    id: 'bad-cred', type: 'password', value: 'test',
                    foundAt: { machine: 'nonexistent' },
                    validAt: { machine: 'web-server', service: 'ssh', user: 'root' },
                }],
            });
            const result = toolkit.validate(world);
            expect(result.errors.some(e => e.code === 'CRED_INVALID_MACHINE')).toBe(true);
        });

        it('detects invalid network segment reference', () => {
            const world = makeMinimalWorld({
                machines: {
                    'web-server': {
                        ...DEMO_01.machines['web-server']!,
                        interfaces: [{ ip: '10.0.1.10', segment: 'nonexistent' }],
                    },
                },
                network: { segments: [{ id: 'corporate', subnet: '10.0.1.0/24' }], edges: [] },
            });
            const result = toolkit.validate(world);
            expect(result.errors.some(e => e.code === 'INVALID_SEGMENT')).toBe(true);
        });

        it('warns about no required objectives', () => {
            const world = makeMinimalWorld({
                objectives: [
                    { id: 'opt', title: 'Optional', description: 'Opt', type: 'find-file', required: false, details: { kind: 'find-file', machine: 'web-server', path: '/test' } },
                ],
            });
            const result = toolkit.validate(world);
            expect(result.warnings.some(w => w.code === 'NO_REQUIRED_OBJ')).toBe(true);
        });

        it('provides info about missing hints', () => {
            const world = makeMinimalWorld({ hints: [] });
            const result = toolkit.validate(world);
            expect(result.info.some(i => i.code === 'NO_HINTS')).toBe(true);
        });
    });

    // ── MITRE Coverage Analysis ─────────────────────────────────

    describe('analyzeMitreCoverage', () => {
        it('analyzes demo-01 coverage', () => {
            const coverage = toolkit.analyzeMitreCoverage(DEMO_01);
            expect(coverage.tacticsPresent.length).toBeGreaterThan(0);
            expect(coverage.tacticsMissing.length).toBeGreaterThan(0);
            expect(coverage.killChainCoveragePercent).toBeGreaterThan(0);
            expect(coverage.killChainCoveragePercent).toBeLessThanOrEqual(100);
        });

        it('infers tactics from objective types', () => {
            const world = makeMinimalWorld({
                objectives: [
                    { id: 'esc', title: 'Escalate', description: 'Escalate', type: 'escalate', required: true, details: { kind: 'escalate', machine: 'web-server', fromUser: 'user', toUser: 'root' } },
                    { id: 'lat', title: 'Lateral', description: 'Lateral', type: 'lateral-move', required: true, details: { kind: 'lateral-move', fromMachine: 'a', toMachine: 'b' } },
                ],
            });
            const coverage = toolkit.analyzeMitreCoverage(world);
            expect(coverage.tacticsPresent).toContain('privilege-escalation');
            expect(coverage.tacticsPresent).toContain('lateral-movement');
        });

        it('handles invalid input gracefully', () => {
            const coverage = toolkit.analyzeMitreCoverage('invalid');
            expect(coverage.tacticsPresent).toHaveLength(0);
            expect(coverage.killChainCoveragePercent).toBe(0);
        });
    });

    // ── Difficulty Analysis ─────────────────────────────────────

    describe('analyzeDifficulty', () => {
        it('analyzes demo-01 difficulty', () => {
            const result = toolkit.analyzeDifficulty(DEMO_01);
            expect(result.computedDifficulty).toBeTruthy();
            expect(result.factors.length).toBeGreaterThan(0);
            expect(result.score).toBeGreaterThan(0);
            expect(result.score).toBeLessThanOrEqual(100);
        });

        it('single-machine level with multiple objectives is easy/medium', () => {
            const result = toolkit.analyzeDifficulty(DEMO_01);
            expect(['easy', 'medium']).toContain(result.computedDifficulty);
        });

        it('multi-machine level scores higher', () => {
            const complexWorld = makeMinimalWorld({
                machines: {
                    'player': {
                        hostname: 'player', image: 'alpine', memoryMB: 64,
                        role: 'player', interfaces: [{ ip: '10.0.1.5', segment: 'corporate' }],
                        user: { username: 'user', password: 'pass' },
                    },
                    'web': {
                        hostname: 'web', image: 'alpine', memoryMB: 64,
                        role: 'target', interfaces: [{ ip: '10.0.1.10', segment: 'corporate' }],
                    },
                    'db': {
                        hostname: 'db', image: 'alpine', memoryMB: 64,
                        role: 'target', interfaces: [{ ip: '10.0.2.10', segment: 'database' }],
                    },
                    'dc': {
                        hostname: 'dc', image: 'alpine', memoryMB: 64,
                        role: 'target', interfaces: [{ ip: '10.0.3.10', segment: 'admin' }],
                    },
                },
                startMachine: 'player',
                network: {
                    segments: [
                        { id: 'corporate', subnet: '10.0.1.0/24' },
                        { id: 'database', subnet: '10.0.2.0/24' },
                        { id: 'admin', subnet: '10.0.3.0/24' },
                    ],
                    edges: [
                        { from: 'player', to: 'web' },
                        { from: 'web', to: 'db' },
                        { from: 'db', to: 'dc' },
                    ],
                },
                credentials: [
                    { id: 'c1', type: 'password', value: 'pass', foundAt: { machine: 'web' }, validAt: { machine: 'db', service: 'mysql', user: 'root' } },
                    { id: 'c2', type: 'ssh-key', value: 'key', foundAt: { machine: 'db' }, validAt: { machine: 'dc', service: 'ssh', user: 'admin' } },
                ],
                objectives: [
                    { id: 'o1', title: 'A', description: 'A', type: 'lateral-move', required: true, details: { kind: 'lateral-move', fromMachine: 'player', toMachine: 'web' } },
                    { id: 'o2', title: 'B', description: 'B', type: 'credential-find', required: true, details: { kind: 'credential-find', credentialId: 'c1' } },
                    { id: 'o3', title: 'C', description: 'C', type: 'lateral-move', required: true, details: { kind: 'lateral-move', fromMachine: 'web', toMachine: 'db' } },
                    { id: 'o4', title: 'D', description: 'D', type: 'escalate', required: true, details: { kind: 'escalate', machine: 'dc', fromUser: 'admin', toUser: 'root' } },
                ],
            });

            const simple = toolkit.analyzeDifficulty(DEMO_01);
            const complex = toolkit.analyzeDifficulty(complexWorld);
            expect(complex.score).toBeGreaterThan(simple.score);
        });

        it('handles invalid input gracefully', () => {
            const result = toolkit.analyzeDifficulty('invalid');
            expect(result.computedDifficulty).toBe('beginner');
            expect(result.score).toBe(0);
        });
    });

    // ── Completeness Analysis ───────────────────────────────────

    describe('analyzeCompleteness', () => {
        it('analyzes demo-01 completeness', () => {
            const result = toolkit.analyzeCompleteness(DEMO_01);
            expect(result.score).toBeGreaterThan(40);
            expect(result.present.length).toBeGreaterThan(5);
        });

        it('detects missing features', () => {
            const result = toolkit.analyzeCompleteness(DEMO_01);
            // demo-01 doesn't have dynamics or mail
            expect(result.improvements.some(i => i.includes('dynamic'))).toBe(true);
        });

        it('handles invalid input', () => {
            const result = toolkit.analyzeCompleteness(null);
            expect(result.score).toBe(0);
            expect(result.missing.length).toBeGreaterThan(0);
        });
    });

    // ── Full Analysis ───────────────────────────────────────────

    describe('fullAnalysis', () => {
        it('produces a complete report for demo-01', () => {
            const report = toolkit.fullAnalysis(DEMO_01);
            expect(report.validation.valid).toBe(true);
            expect(report.mitreCoverage.tacticsPresent.length).toBeGreaterThan(0);
            expect(report.difficulty.computedDifficulty).toBeTruthy();
            expect(report.completeness.score).toBeGreaterThan(0);
            expect(report.overallScore).toBeGreaterThan(0);
            expect(report.overallScore).toBeLessThanOrEqual(100);
            expect(report.summary).toBeTruthy();
        });

        it('produces a report for invalid input', () => {
            const report = toolkit.fullAnalysis('not a world');
            expect(report.validation.valid).toBe(false);
            expect(report.overallScore).toBeLessThan(30);
        });
    });
});

// ── Helper ──────────────────────────────────────────────────────

function makeMinimalWorld(overrides: Partial<WorldSpec> = {}): WorldSpec {
    return {
        version: '2.0',
        trust: 'community',
        meta: {
            title: 'Test Level',
            scenario: 'A test scenario.',
            briefing: ['Test briefing.'],
            difficulty: 'beginner',
            mode: 'attack',
            vulnClasses: ['web'],
            tags: ['test'],
            estimatedMinutes: 10,
            author: { name: 'Test', id: 'test', type: 'community' },
        },
        machines: {
            'web-server': {
                hostname: 'web-server', image: 'alpine', memoryMB: 64,
                role: 'player',
                user: { username: 'user', password: 'pass' },
                interfaces: [{ ip: '10.0.1.10', segment: 'corporate' }],
            },
        },
        startMachine: 'web-server',
        network: { segments: [{ id: 'corporate', subnet: '10.0.1.0/24' }], edges: [] },
        credentials: [],
        objectives: [
            { id: 'obj1', title: 'Find File', description: 'Find it', type: 'find-file', required: true, details: { kind: 'find-file', machine: 'web-server', path: '/flag.txt' } },
        ],
        modules: [],
        scoring: { maxScore: 100, timeBonus: true, stealthBonus: false, hintPenalty: 10, tiers: [{ name: 'PASS', minScore: 50, color: '#00ff00' }] },
        hints: ['Check the files.'],
        ...overrides,
    } as WorldSpec;
}
