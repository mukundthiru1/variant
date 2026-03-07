/**
 * VARIANT — After-Action Report Generator tests
 */
import { describe, it, expect } from 'vitest';
import { createAfterActionGenerator } from '../../../src/lib/after-action/after-action-generator';
import type { AfterActionConfig } from '../../../src/lib/after-action/types';

function makeConfig(overrides?: Partial<AfterActionConfig>): AfterActionConfig {
    return {
        levelId: 'level-01',
        levelTitle: 'Test Level',
        difficulty: 'medium',
        maxScore: 1000,
        finalScore: 800,
        finalPhase: 'completed',
        totalTicks: 300,
        durationSeconds: 300,
        hintsUsed: 0,
        noiseLevel: 25,
        objectivesCompleted: ['obj-1'],
        totalObjectives: 2,
        techniquesUsed: ['sqli'],
        commandCount: 50,
        machinesAccessed: ['web-01'],
        stuckPeriods: [],
        ...overrides,
    };
}

describe('AfterActionGenerator', () => {
    it('generates a report with all sections', () => {
        const generator = createAfterActionGenerator();
        const report = generator.generate(makeConfig());

        expect(report.session.levelId).toBe('level-01');
        expect(report.session.completed).toBe(true);
        expect(report.scoring.finalScore).toBe(800);
        expect(report.grade).toBeDefined();
        expect(report.skills.length).toBeGreaterThan(0);
    });

    it('grades S for perfect performance', () => {
        const generator = createAfterActionGenerator();
        const report = generator.generate(makeConfig({ finalScore: 960, maxScore: 1000 }));
        expect(report.grade.letter).toBe('S');
    });

    it('grades A for excellent performance', () => {
        const generator = createAfterActionGenerator();
        const report = generator.generate(makeConfig({ finalScore: 870, maxScore: 1000 }));
        expect(report.grade.letter).toBe('A');
    });

    it('grades F for failure', () => {
        const generator = createAfterActionGenerator();
        const report = generator.generate(makeConfig({ finalPhase: 'failed' }));
        expect(report.grade.letter).toBe('F');
    });

    it('identifies stealth strength', () => {
        const generator = createAfterActionGenerator();
        const report = generator.generate(makeConfig({ noiseLevel: 5 }));
        expect(report.strengths.some(s => s.category === 'stealth')).toBe(true);
    });

    it('identifies hint-free strength', () => {
        const generator = createAfterActionGenerator();
        const report = generator.generate(makeConfig({ hintsUsed: 0 }));
        expect(report.strengths.some(s => s.category === 'independence')).toBe(true);
    });

    it('identifies noisy operations as improvement', () => {
        const generator = createAfterActionGenerator();
        const report = generator.generate(makeConfig({ noiseLevel: 80 }));
        expect(report.improvements.some(i => i.category === 'stealth')).toBe(true);
    });

    it('identifies hint dependency as improvement', () => {
        const generator = createAfterActionGenerator();
        const report = generator.generate(makeConfig({ hintsUsed: 5 }));
        expect(report.improvements.some(i => i.category === 'independence')).toBe(true);
    });

    it('identifies stuck periods as improvement', () => {
        const generator = createAfterActionGenerator();
        const report = generator.generate(makeConfig({
            stuckPeriods: [{ fromTick: 10, toTick: 80, durationTicks: 70, context: 'Stuck after nmap' }],
        }));
        expect(report.improvements.some(i => i.category === 'methodology')).toBe(true);
    });

    it('generates tips for noisy players', () => {
        const generator = createAfterActionGenerator();
        const report = generator.generate(makeConfig({ noiseLevel: 60 }));
        expect(report.tips.some(t => t.skill === 'stealth')).toBe(true);
    });

    it('generates tips for narrow technique usage', () => {
        const generator = createAfterActionGenerator();
        const report = generator.generate(makeConfig({ techniquesUsed: [] }));
        expect(report.tips.some(t => t.skill === 'reconnaissance')).toBe(true);
    });

    it('assesses skills', () => {
        const generator = createAfterActionGenerator();
        const report = generator.generate(makeConfig());

        expect(report.skills.some(s => s.skill === 'stealth')).toBe(true);
        expect(report.skills.some(s => s.skill === 'speed')).toBe(true);
        expect(report.skills.some(s => s.skill === 'methodology')).toBe(true);
        expect(report.skills.some(s => s.skill === 'breadth')).toBe(true);

        for (const skill of report.skills) {
            expect(skill.score).toBeGreaterThanOrEqual(0);
            expect(skill.score).toBeLessThanOrEqual(100);
        }
    });

    it('includes stuck periods in timeline', () => {
        const generator = createAfterActionGenerator();
        const report = generator.generate(makeConfig({
            stuckPeriods: [{ fromTick: 10, toTick: 80, durationTicks: 70, context: 'Stuck' }],
        }));

        expect(report.timeline.some(e => e.type === 'stuck-period')).toBe(true);
    });

    it('handles zero max score gracefully', () => {
        const generator = createAfterActionGenerator();
        const report = generator.generate(makeConfig({ maxScore: 0, finalScore: 0 }));
        // Should not crash or produce NaN
        expect(report.grade).toBeDefined();
    });

    it('identifies versatile attacker strength', () => {
        const generator = createAfterActionGenerator();
        const report = generator.generate(makeConfig({
            techniquesUsed: ['sqli', 'xss', 'path-traversal', 'privesc'],
        }));
        expect(report.strengths.some(s => s.category === 'versatility')).toBe(true);
    });
});
