/**
 * VARIANT — After-Action Report Generator
 *
 * Produces structured after-action reports from session data.
 *
 * SWAPPABILITY: Implements AfterActionGenerator. Replace this file.
 */

import type {
    AfterActionGenerator,
    AfterActionConfig,
    AfterActionReport,
    Grade,
    Observation,
    Tip,
    SkillAssessment,
    SkillLevel,
    TimelineEntry,
} from './types';

export function createAfterActionGenerator(): AfterActionGenerator {
    function computeGrade(scorePercent: number, completed: boolean): Grade {
        if (!completed) {
            return { letter: 'F', label: 'Failed', description: 'Objectives not completed.' };
        }
        if (scorePercent >= 95) return { letter: 'S', label: 'Perfect', description: 'Exceptional performance. Near-flawless execution.' };
        if (scorePercent >= 85) return { letter: 'A', label: 'Excellent', description: 'Outstanding performance with minor inefficiencies.' };
        if (scorePercent >= 70) return { letter: 'B', label: 'Good', description: 'Solid performance. Room for optimization.' };
        if (scorePercent >= 55) return { letter: 'C', label: 'Adequate', description: 'Completed, but with significant room for improvement.' };
        return { letter: 'D', label: 'Passing', description: 'Barely completed. Major improvement needed.' };
    }

    function computeSkillLevel(score: number): SkillLevel {
        if (score >= 90) return 'expert';
        if (score >= 70) return 'advanced';
        if (score >= 50) return 'intermediate';
        if (score >= 25) return 'beginner';
        return 'novice';
    }

    function analyzeStrengths(config: AfterActionConfig): Observation[] {
        const strengths: Observation[] = [];

        if (config.noiseLevel < 20 && config.finalPhase === 'completed') {
            strengths.push({
                category: 'stealth',
                title: 'Low Profile Operator',
                description: 'Maintained a very low noise level throughout the engagement.',
                evidence: `Noise level: ${config.noiseLevel}/100`,
            });
        }

        if (config.hintsUsed === 0 && config.finalPhase === 'completed') {
            strengths.push({
                category: 'independence',
                title: 'Self-Reliant',
                description: 'Completed the objective without using any hints.',
                evidence: '0 hints used',
            });
        }

        if (config.techniquesUsed.length >= 3) {
            strengths.push({
                category: 'versatility',
                title: 'Versatile Attacker',
                description: 'Used multiple attack techniques, demonstrating broad knowledge.',
                evidence: `Techniques: ${config.techniquesUsed.join(', ')}`,
            });
        }

        if (config.stuckPeriods.length === 0 && config.commandCount > 5) {
            strengths.push({
                category: 'methodology',
                title: 'Steady Progress',
                description: 'Maintained consistent forward momentum without getting stuck.',
                evidence: 'No stuck periods detected',
            });
        }

        return strengths;
    }

    function analyzeImprovements(config: AfterActionConfig): Observation[] {
        const improvements: Observation[] = [];

        if (config.noiseLevel > 60) {
            improvements.push({
                category: 'stealth',
                title: 'Noisy Operations',
                description: 'High noise level — in a real engagement, defensive tools would have detected you.',
                evidence: `Noise level: ${config.noiseLevel}/100`,
            });
        }

        if (config.hintsUsed > 2) {
            improvements.push({
                category: 'independence',
                title: 'Hint Dependency',
                description: 'Used multiple hints. Try to develop your enumeration methodology.',
                evidence: `${config.hintsUsed} hints used`,
            });
        }

        if (config.stuckPeriods.length > 0) {
            const totalStuck = config.stuckPeriods.reduce((sum, p) => sum + p.durationTicks, 0);
            improvements.push({
                category: 'methodology',
                title: 'Got Stuck',
                description: 'Spent time without making progress. Consider building a systematic enumeration checklist.',
                evidence: `${config.stuckPeriods.length} stuck periods, ${totalStuck} total ticks idle`,
            });
        }

        return improvements;
    }

    function generateTips(config: AfterActionConfig): Tip[] {
        const tips: Tip[] = [];

        if (config.noiseLevel > 40) {
            tips.push({
                id: 'tip-stealth',
                category: 'stealth',
                title: 'Reduce Your Footprint',
                description: 'Use targeted commands instead of broad scans. Avoid running noisy tools like nmap with -sS flags.',
                priority: 'high',
                skill: 'stealth',
                suggestedLevel: null,
            });
        }

        if (config.techniquesUsed.length <= 1) {
            tips.push({
                id: 'tip-variety',
                category: 'technique',
                title: 'Expand Your Toolkit',
                description: 'Try different attack vectors. Web apps often have multiple vulnerability types — SQL injection, XSS, path traversal, SSRF.',
                priority: 'medium',
                skill: 'reconnaissance',
                suggestedLevel: null,
            });
        }

        if (config.machinesAccessed.length <= 1 && config.totalObjectives > 1) {
            tips.push({
                id: 'tip-lateral',
                category: 'lateral-movement',
                title: 'Think Laterally',
                description: 'Credentials found on one machine often work on others. Look for credential reuse and lateral movement paths.',
                priority: 'medium',
                skill: 'lateral-movement',
                suggestedLevel: null,
            });
        }

        return tips;
    }

    function assessSkills(config: AfterActionConfig): SkillAssessment[] {
        const assessments: SkillAssessment[] = [];

        // Stealth
        const stealthScore = Math.max(0, 100 - config.noiseLevel);
        assessments.push({
            skill: 'stealth',
            displayName: 'Stealth & Evasion',
            level: computeSkillLevel(stealthScore),
            score: stealthScore,
            change: 0,
            evidence: `Noise level: ${config.noiseLevel}/100`,
        });

        // Speed
        const speedScore = config.finalPhase === 'completed'
            ? Math.min(100, Math.max(0, 100 - (config.durationSeconds / 60) * 5))
            : 0;
        assessments.push({
            skill: 'speed',
            displayName: 'Speed & Efficiency',
            level: computeSkillLevel(speedScore),
            score: Math.round(speedScore),
            change: 0,
            evidence: `Completed in ${Math.round(config.durationSeconds)}s`,
        });

        // Methodology
        const stuckPenalty = config.stuckPeriods.length * 15;
        const methodScore = Math.max(0, 100 - stuckPenalty - (config.hintsUsed * 10));
        assessments.push({
            skill: 'methodology',
            displayName: 'Methodology & Process',
            level: computeSkillLevel(methodScore),
            score: methodScore,
            change: 0,
            evidence: `${config.stuckPeriods.length} stuck periods, ${config.hintsUsed} hints`,
        });

        // Breadth
        const breadthScore = Math.min(100, config.techniquesUsed.length * 25);
        assessments.push({
            skill: 'breadth',
            displayName: 'Technical Breadth',
            level: computeSkillLevel(breadthScore),
            score: breadthScore,
            change: 0,
            evidence: `${config.techniquesUsed.length} techniques used`,
        });

        return assessments;
    }

    return {
        generate(config: AfterActionConfig): AfterActionReport {
            const completed = config.finalPhase === 'completed';
            const scorePercent = config.maxScore > 0 ? (config.finalScore / config.maxScore) * 100 : 0;

            const timeline: TimelineEntry[] = [];

            // Add stuck periods to timeline
            for (const stuck of config.stuckPeriods) {
                timeline.push({
                    tick: stuck.fromTick,
                    wallTimeSeconds: stuck.fromTick, // Approximation
                    type: 'stuck-period',
                    title: 'Got Stuck',
                    description: stuck.context,
                    significance: stuck.durationTicks > 120 ? 'major' : 'moderate',
                });
            }

            // Sort timeline by tick
            timeline.sort((a, b) => a.tick - b.tick);

            return {
                session: {
                    levelId: config.levelId,
                    levelTitle: config.levelTitle,
                    difficulty: config.difficulty,
                    durationSeconds: config.durationSeconds,
                    totalTicks: config.totalTicks,
                    phase: config.finalPhase,
                    completed,
                },
                scoring: {
                    maxScore: config.maxScore,
                    baseScore: config.finalScore,
                    timeBonus: 0,
                    stealthBonus: 0,
                    hintPenalty: config.hintsUsed * 50,
                    objectiveBonus: 0,
                    finalScore: config.finalScore,
                    percentile: 0,
                },
                timeline,
                strengths: analyzeStrengths(config),
                improvements: analyzeImprovements(config),
                tips: generateTips(config),
                missed: [],
                skills: assessSkills(config),
                grade: computeGrade(scorePercent, completed),
            };
        },
    };
}
