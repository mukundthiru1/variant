import { describe, it, expect, beforeEach } from 'vitest';
import { createMitreCatalog } from '../../../src/lib/mitre/catalog';
import { createAttackChainComposer } from '../../../src/lib/mitre/attack-chain';
import type { AttackChainComposer } from '../../../src/lib/mitre/attack-chain';
import type { MitreCatalog } from '../../../src/lib/mitre/types';

describe('Attack Chain Composer', () => {
    let catalog: MitreCatalog;
    let composer: AttackChainComposer;

    beforeEach(() => {
        catalog = createMitreCatalog();
        composer = createAttackChainComposer(catalog);
    });

    // ── Templates ───────────────────────────────────────────────

    it('provides pre-built templates', () => {
        const templates = composer.getTemplates();
        expect(templates.length).toBeGreaterThanOrEqual(5);
    });

    it('templates have valid structure', () => {
        for (const template of composer.getTemplates()) {
            expect(template.id).toBeTruthy();
            expect(template.name).toBeTruthy();
            expect(template.steps.length).toBeGreaterThan(0);
            expect(template.tacticsUsed.length).toBeGreaterThan(0);
            expect(template.techniquesUsed.length).toBeGreaterThan(0);
        }
    });

    it('web-to-root template has correct kill chain progression', () => {
        const chain = composer.getTemplates().find(t => t.id === 'chain/web-to-root');
        expect(chain).toBeDefined();
        expect(chain!.steps).toHaveLength(5);
        expect(chain!.tacticsUsed).toContain('reconnaissance');
        expect(chain!.tacticsUsed).toContain('initial-access');
        expect(chain!.tacticsUsed).toContain('privilege-escalation');
    });

    it('AD domain takeover template is expert difficulty', () => {
        const chain = composer.getTemplates().find(t => t.id === 'chain/ad-domain-takeover');
        expect(chain).toBeDefined();
        expect(chain!.difficulty).toBe('expert');
        expect(chain!.steps.length).toBeGreaterThanOrEqual(7);
    });

    // ── Chain Building ──────────────────────────────────────────

    it('creates a chain with the builder API', () => {
        const chain = composer.create('test-chain', 'Test Chain', 'A test')
            .addStep({
                description: 'Scan target',
                techniqueId: 'T1595',
                tactic: 'reconnaissance',
                detectionRisk: 'medium',
                artifacts: ['Scan logs'],
                prerequisites: [],
            })
            .addStep({
                description: 'Exploit web app',
                techniqueId: 'T1190',
                tactic: 'initial-access',
                targetMachine: 'web-server',
                detectionRisk: 'high',
                artifacts: ['WAF logs'],
                prerequisites: [1],
            })
            .tags(['test', 'web'])
            .build();

        expect(chain.id).toBe('test-chain');
        expect(chain.steps).toHaveLength(2);
        expect(chain.tacticsUsed).toContain('reconnaissance');
        expect(chain.tacticsUsed).toContain('initial-access');
        expect(chain.techniquesUsed).toContain('T1595');
        expect(chain.techniquesUsed).toContain('T1190');
        expect(chain.tags).toContain('test');
    });

    it('builder auto-assigns step order', () => {
        const chain = composer.create('auto-order', 'Auto', 'Test')
            .addStep({ description: 'Step A', techniqueId: 'T1595', tactic: 'reconnaissance', detectionRisk: 'low', artifacts: [], prerequisites: [] })
            .addStep({ description: 'Step B', techniqueId: 'T1190', tactic: 'initial-access', detectionRisk: 'medium', artifacts: [], prerequisites: [1] })
            .addStep({ description: 'Step C', techniqueId: 'T1059', tactic: 'execution', detectionRisk: 'high', artifacts: [], prerequisites: [2] })
            .build();

        expect(chain.steps[0]!.order).toBe(1);
        expect(chain.steps[1]!.order).toBe(2);
        expect(chain.steps[2]!.order).toBe(3);
    });

    it('builder with explicit difficulty overrides auto-estimate', () => {
        const chain = composer.create('fixed', 'Fixed', 'Test')
            .addStep({ description: 'Simple', techniqueId: 'T1595', tactic: 'reconnaissance', detectionRisk: 'low', artifacts: [], prerequisites: [] })
            .difficulty('expert')
            .build();

        expect(chain.difficulty).toBe('expert');
    });

    it('built chain is frozen', () => {
        const chain = composer.create('frozen', 'Frozen', 'Test')
            .addStep({ description: 'Step', techniqueId: 'T1595', tactic: 'reconnaissance', detectionRisk: 'low', artifacts: [], prerequisites: [] })
            .build();

        expect(Object.isFrozen(chain)).toBe(true);
        expect(Object.isFrozen(chain.steps)).toBe(true);
    });

    // ── Validation ──────────────────────────────────────────────

    it('validates a correct chain', () => {
        const chain = composer.create('valid', 'Valid', 'A valid chain')
            .addStep({ description: 'Scan', techniqueId: 'T1595', tactic: 'reconnaissance', detectionRisk: 'low', artifacts: [], prerequisites: [] })
            .addStep({ description: 'Exploit', techniqueId: 'T1190', tactic: 'initial-access', detectionRisk: 'high', artifacts: [], prerequisites: [1] })
            .build();

        const result = composer.validate(chain);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
        expect(result.mitreCoverage.techniques).toContain('T1595');
        expect(result.mitreCoverage.techniques).toContain('T1190');
    });

    it('detects empty chain', () => {
        const chain = composer.create('empty', 'Empty', 'No steps').build();
        const result = composer.validate(chain);
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.includes('no steps'))).toBe(true);
    });

    it('warns about unknown techniques', () => {
        const chain = composer.create('unknown', 'Unknown', 'Test')
            .addStep({ description: 'Unknown', techniqueId: 'T9999', tactic: 'execution', detectionRisk: 'low', artifacts: [], prerequisites: [] })
            .build();

        const result = composer.validate(chain);
        expect(result.warnings.length).toBeGreaterThan(0);
        expect(result.mitreCoverage.missingFromCatalog).toContain('T9999');
    });

    it('detects forward prerequisite reference', () => {
        const chain = composer.create('forward-ref', 'Forward', 'Test')
            .addStep({ description: 'A', techniqueId: 'T1595', tactic: 'reconnaissance', detectionRisk: 'low', artifacts: [], prerequisites: [2] })
            .addStep({ description: 'B', techniqueId: 'T1190', tactic: 'initial-access', detectionRisk: 'low', artifacts: [], prerequisites: [] })
            .build();

        const result = composer.validate(chain);
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.includes('must come before'))).toBe(true);
    });

    it('warns about tactic mismatch', () => {
        const chain = composer.create('mismatch', 'Mismatch', 'Test')
            .addStep({
                description: 'SSH labeled as exfiltration',
                techniqueId: 'T1021.004', // SSH is lateral-movement, not exfiltration
                tactic: 'exfiltration',
                detectionRisk: 'low', artifacts: [], prerequisites: [],
            })
            .build();

        const result = composer.validate(chain);
        expect(result.warnings.some(w => w.includes('not typically associated'))).toBe(true);
    });

    it('validates all pre-built templates', () => {
        for (const template of composer.getTemplates()) {
            const result = composer.validate(template);
            expect(result.errors).toHaveLength(0);
        }
    });

    // ── Difficulty Estimation ───────────────────────────────────

    it('estimates simple chain as beginner', () => {
        const chain = composer.create('simple', 'Simple', 'Test')
            .addStep({ description: 'Scan', techniqueId: 'T1595', tactic: 'reconnaissance', detectionRisk: 'high', artifacts: [], prerequisites: [] })
            .build();

        expect(composer.estimateDifficulty(chain)).toBe('beginner');
    });

    it('estimates complex chain as advanced or expert', () => {
        const chain = composer.create('complex', 'Complex', 'Test')
            .addStep({ description: 'S1', techniqueId: 'T1595', tactic: 'reconnaissance', detectionRisk: 'low', artifacts: [], prerequisites: [] })
            .addStep({ description: 'S2', techniqueId: 'T1190', tactic: 'initial-access', detectionRisk: 'medium', artifacts: [], prerequisites: [1] })
            .addStep({ description: 'S3', techniqueId: 'T1059', tactic: 'execution', detectionRisk: 'high', artifacts: [], prerequisites: [2] })
            .addStep({ description: 'S4', techniqueId: 'T1003', tactic: 'credential-access', detectionRisk: 'medium', artifacts: [], prerequisites: [3] })
            .addStep({ description: 'S5', techniqueId: 'T1550.002', tactic: 'lateral-movement', detectionRisk: 'low', artifacts: [], prerequisites: [4] })
            .addStep({ description: 'S6', techniqueId: 'T1053.003', tactic: 'persistence', detectionRisk: 'medium', artifacts: [], prerequisites: [5] })
            .addStep({ description: 'S7', techniqueId: 'T1048.003', tactic: 'exfiltration', detectionRisk: 'high', artifacts: [], prerequisites: [6] })
            .build();

        const difficulty = composer.estimateDifficulty(chain);
        expect(['advanced', 'expert']).toContain(difficulty);
    });
});
