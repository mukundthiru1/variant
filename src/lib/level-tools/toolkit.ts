/**
 * VARIANT — Level Designer Toolkit
 *
 * Validates, analyzes, and scores levels for quality, MITRE coverage,
 * difficulty accuracy, and completeness. Level designers run this
 * against their WorldSpec to get actionable feedback.
 */

import type { WorldSpec } from '../../core/world/types';
import type { MitreCatalog, MitreTactic } from '../mitre/types';
import type {
    CompletenessAnalysis,
    DifficultyAnalysis,
    DifficultyFactor,
    LevelAnalysisReport,
    LevelToolkit,
    LevelValidationResult,
    MitreCoverageAnalysis,
    ValidationIssue,
} from './types';

const ALL_TACTICS: readonly MitreTactic[] = [
    'reconnaissance', 'resource-development', 'initial-access', 'execution',
    'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
    'discovery', 'lateral-movement', 'collection', 'command-and-control',
    'exfiltration', 'impact',
];

function isWorldSpec(w: unknown): w is WorldSpec {
    if (w === null || typeof w !== 'object') return false;
    const obj = w as Record<string, unknown>;
    return obj['version'] === '2.0' && typeof obj['meta'] === 'object' && typeof obj['machines'] === 'object';
}

export function createLevelToolkit(mitreCatalog: MitreCatalog): LevelToolkit {
    const toolkit: LevelToolkit = {
        validate(world: unknown): LevelValidationResult {
            const errors: ValidationIssue[] = [];
            const warnings: ValidationIssue[] = [];
            const info: ValidationIssue[] = [];

            if (!isWorldSpec(world)) {
                errors.push({ code: 'INVALID_FORMAT', message: 'Input is not a valid WorldSpec (requires version: "2.0", meta, machines)', severity: 'error' });
                return { valid: false, errors, warnings, info };
            }

            const w = world;

            // ── Structure validation ──
            if (!w.meta.title || w.meta.title.length === 0) {
                errors.push({ code: 'MISSING_TITLE', message: 'Level must have a title', path: 'meta.title', severity: 'error' });
            }
            if (!w.meta.scenario || w.meta.scenario.length === 0) {
                errors.push({ code: 'MISSING_SCENARIO', message: 'Level must have a scenario description', path: 'meta.scenario', severity: 'error' });
            }
            if (w.meta.briefing.length === 0) {
                errors.push({ code: 'EMPTY_BRIEFING', message: 'Briefing must have at least one line', path: 'meta.briefing', severity: 'error' });
            }

            // ── Machine validation ──
            const machineIds = Object.keys(w.machines);
            if (machineIds.length === 0) {
                errors.push({ code: 'NO_MACHINES', message: 'Level must have at least one machine', path: 'machines', severity: 'error' });
            }

            if (!(w.startMachine in w.machines)) {
                errors.push({ code: 'INVALID_START', message: `startMachine '${w.startMachine}' is not a key in machines`, path: 'startMachine', severity: 'error' });
            }

            let hasPlayerMachine = false;
            for (const [id, machine] of Object.entries(w.machines)) {
                if (machine.role === 'player') hasPlayerMachine = true;

                if (machine.interfaces.length === 0) {
                    warnings.push({ code: 'NO_INTERFACES', message: `Machine '${id}' has no network interfaces`, path: `machines.${id}.interfaces`, severity: 'warning' });
                }

                if (machine.memoryMB < 16 || machine.memoryMB > 256) {
                    warnings.push({ code: 'MEM_RANGE', message: `Machine '${id}' memoryMB (${machine.memoryMB}) outside recommended range [16, 256]`, path: `machines.${id}.memoryMB`, severity: 'warning' });
                }
            }

            if (!hasPlayerMachine) {
                errors.push({ code: 'NO_PLAYER', message: 'Level must have at least one machine with role "player"', path: 'machines', severity: 'error' });
            }

            // ── Objective validation ──
            if (w.objectives.length === 0) {
                errors.push({ code: 'NO_OBJECTIVES', message: 'Level must have at least one objective', path: 'objectives', severity: 'error' });
            }

            const requiredObjectives = w.objectives.filter(o => o.required);
            if (requiredObjectives.length === 0 && w.objectives.length > 0) {
                warnings.push({ code: 'NO_REQUIRED_OBJ', message: 'Level has objectives but none are required — player cannot win', path: 'objectives', severity: 'warning' });
            }

            const objectiveIds = new Set<string>();
            for (const obj of w.objectives) {
                if (objectiveIds.has(obj.id)) {
                    errors.push({ code: 'DUPLICATE_OBJ', message: `Duplicate objective ID: '${obj.id}'`, path: `objectives`, severity: 'error' });
                }
                objectiveIds.add(obj.id);
            }

            // ── Credential validation ──
            for (const cred of w.credentials) {
                if (!(cred.foundAt.machine in w.machines)) {
                    errors.push({ code: 'CRED_INVALID_MACHINE', message: `Credential '${cred.id}' foundAt.machine '${cred.foundAt.machine}' is not a valid machine`, path: 'credentials', severity: 'error' });
                }
                if (!(cred.validAt.machine in w.machines)) {
                    errors.push({ code: 'CRED_INVALID_TARGET', message: `Credential '${cred.id}' validAt.machine '${cred.validAt.machine}' is not a valid machine`, path: 'credentials', severity: 'error' });
                }
            }

            // ── Network validation ──
            const segmentIds = new Set(w.network.segments.map(s => s.id));
            for (const [id, machine] of Object.entries(w.machines)) {
                for (const iface of machine.interfaces) {
                    if (!segmentIds.has(iface.segment)) {
                        errors.push({ code: 'INVALID_SEGMENT', message: `Machine '${id}' interface references unknown segment '${iface.segment}'`, path: `machines.${id}.interfaces`, severity: 'error' });
                    }
                }
            }

            // ── Scoring validation ──
            if (w.scoring.maxScore <= 0) {
                errors.push({ code: 'INVALID_SCORE', message: 'maxScore must be positive', path: 'scoring.maxScore', severity: 'error' });
            }
            if (w.scoring.tiers.length === 0) {
                warnings.push({ code: 'NO_TIERS', message: 'No scoring tiers defined', path: 'scoring.tiers', severity: 'warning' });
            }

            // ── Quality hints ──
            if (w.hints.length === 0) {
                info.push({ code: 'NO_HINTS', message: 'Consider adding hints for a better player experience', path: 'hints', severity: 'info' });
            }
            if (w.meta.estimatedMinutes <= 0) {
                warnings.push({ code: 'INVALID_TIME', message: 'estimatedMinutes should be positive', path: 'meta.estimatedMinutes', severity: 'warning' });
            }

            return { valid: errors.length === 0, errors, warnings, info };
        },

        analyzeMitreCoverage(world: unknown): MitreCoverageAnalysis {
            if (!isWorldSpec(world)) {
                return { tacticsPresent: [], tacticsMissing: [...ALL_TACTICS], techniquesReferenced: [], killChainCoveragePercent: 0, suggestions: ['Invalid WorldSpec'] };
            }

            const w = world;
            const techniques = new Set<string>();
            const tactics = new Set<MitreTactic>();

            // Extract from vulnClasses
            for (const vc of w.meta.vulnClasses) {
                const results = mitreCatalog.search(vc);
                for (const r of results) {
                    techniques.add(r.id);
                    for (const t of r.tactics) tactics.add(t);
                }
            }

            // Extract from tags
            for (const tag of w.meta.tags) {
                const results = mitreCatalog.search(tag);
                for (const r of results) {
                    techniques.add(r.id);
                    for (const t of r.tactics) tactics.add(t);
                }
            }

            // Infer from objectives
            for (const obj of w.objectives) {
                switch (obj.type) {
                    case 'escalate': tactics.add('privilege-escalation'); break;
                    case 'lateral-move': tactics.add('lateral-movement'); break;
                    case 'exfiltrate': tactics.add('exfiltration'); break;
                    case 'credential-find': tactics.add('credential-access'); break;
                    case 'write-rule': tactics.add('defense-evasion'); break;
                    case 'survive': tactics.add('persistence'); break;
                    case 'find-file': tactics.add('discovery'); break;
                }
            }

            // Infer from machine roles
            for (const machine of Object.values(w.machines)) {
                if (machine.role === 'npc-attacker') {
                    tactics.add('initial-access');
                    tactics.add('execution');
                }
            }

            const tacticsPresent = [...tactics];
            const tacticsMissing = ALL_TACTICS.filter(t => !tactics.has(t));
            const killChainCoveragePercent = Math.round((tacticsPresent.length / ALL_TACTICS.length) * 100);

            const suggestions: string[] = [];
            if (!tactics.has('initial-access') && w.meta.mode === 'attack') {
                suggestions.push('Attack mode level should include an initial-access phase');
            }
            if (!tactics.has('persistence') && w.meta.mode === 'defense') {
                suggestions.push('Defense mode level should include persistence mechanisms to detect');
            }
            if (killChainCoveragePercent < 30) {
                suggestions.push('Consider adding more attack phases for a richer scenario');
            }
            if (techniques.size === 0) {
                suggestions.push('No MITRE techniques detected — add vulnClasses or tags that map to techniques');
            }

            return {
                tacticsPresent: Object.freeze(tacticsPresent),
                tacticsMissing: Object.freeze(tacticsMissing),
                techniquesReferenced: Object.freeze([...techniques]),
                killChainCoveragePercent,
                suggestions: Object.freeze(suggestions),
            };
        },

        analyzeDifficulty(world: unknown): DifficultyAnalysis {
            if (!isWorldSpec(world)) {
                return { computedDifficulty: 'beginner', matchesDeclared: false, factors: [], score: 0 };
            }

            const w = world;
            const factors: DifficultyFactor[] = [];
            let score = 0;

            // Factor: Number of machines
            const machineCount = Object.keys(w.machines).length;
            const machineFactor = Math.min(machineCount * 8, 30);
            score += machineFactor;
            factors.push({ name: 'Machine count', contribution: machineFactor, description: `${machineCount} machine(s)` });

            // Factor: Number of objectives
            const objCount = w.objectives.length;
            const objFactor = Math.min(objCount * 5, 20);
            score += objFactor;
            factors.push({ name: 'Objective count', contribution: objFactor, description: `${objCount} objective(s)` });

            // Factor: Number of credentials
            const credCount = w.credentials.length;
            const credFactor = Math.min(credCount * 4, 15);
            score += credFactor;
            factors.push({ name: 'Credential complexity', contribution: credFactor, description: `${credCount} credential(s) to manage` });

            // Factor: Network complexity
            const segmentCount = w.network.segments.length;
            const edgeCount = w.network.edges.length;
            const netFactor = Math.min((segmentCount + edgeCount) * 3, 15);
            score += netFactor;
            factors.push({ name: 'Network complexity', contribution: netFactor, description: `${segmentCount} segment(s), ${edgeCount} edge(s)` });

            // Factor: Dynamics present
            if (w.dynamics !== undefined) {
                const dynCount = (w.dynamics.timedEvents?.length ?? 0) + (w.dynamics.reactiveEvents?.length ?? 0);
                const dynFactor = Math.min(dynCount * 3, 10);
                score += dynFactor;
                factors.push({ name: 'Dynamic events', contribution: dynFactor, description: `${dynCount} dynamic event(s)` });
            }

            // Factor: Hint availability (more hints = easier)
            const hintPenalty = Math.max(0, 10 - w.hints.length * 3);
            score += hintPenalty;
            factors.push({ name: 'Hint scarcity', contribution: hintPenalty, description: `${w.hints.length} hint(s) available` });

            // Factor: Time pressure
            if (w.meta.estimatedMinutes <= 5) {
                score += 5;
                factors.push({ name: 'Time pressure', contribution: 5, description: 'Very short time estimate' });
            }

            // Compute difficulty from score
            let computed: 'beginner' | 'easy' | 'medium' | 'hard' | 'expert';
            if (score < 20) computed = 'beginner';
            else if (score < 35) computed = 'easy';
            else if (score < 55) computed = 'medium';
            else if (score < 75) computed = 'hard';
            else computed = 'expert';

            return {
                computedDifficulty: computed,
                matchesDeclared: computed === w.meta.difficulty,
                factors: Object.freeze(factors),
                score: Math.min(score, 100),
            };
        },

        analyzeCompleteness(world: unknown): CompletenessAnalysis {
            if (!isWorldSpec(world)) {
                return { score: 0, present: [], missing: ['Valid WorldSpec'], improvements: [] };
            }

            const w = world;
            const present: string[] = [];
            const missing: string[] = [];
            const improvements: string[] = [];
            let score = 0;

            // Core elements
            if (w.meta.title) { present.push('Title'); score += 5; }
            if (w.meta.scenario) { present.push('Scenario'); score += 5; }
            if (w.meta.briefing.length > 0) { present.push('Briefing'); score += 5; }
            if (w.meta.vulnClasses.length > 0) { present.push('Vulnerability classes'); score += 5; }
            else missing.push('Vulnerability classes (meta.vulnClasses)');
            if (w.meta.tags.length > 0) { present.push('Tags'); score += 3; }

            // Machines
            if (Object.keys(w.machines).length > 0) { present.push('Machines'); score += 10; }
            const hasFiles = Object.values(w.machines).some(m => m.files !== undefined && Object.keys(m.files).length > 0);
            if (hasFiles) { present.push('File overlays'); score += 5; }
            else missing.push('File overlays (realistic filesystem content)');

            const hasServices = Object.values(w.machines).some(m => m.services !== undefined && m.services.length > 0);
            if (hasServices) { present.push('Services'); score += 5; }
            else missing.push('Service definitions');

            const hasProcesses = Object.values(w.machines).some(m => m.processes !== undefined && m.processes.length > 0);
            if (hasProcesses) { present.push('Background processes'); score += 3; }
            else improvements.push('Add background processes for realism');

            // Network
            if (w.network.segments.length > 0) { present.push('Network segments'); score += 5; }
            if (w.network.edges.length > 0) { present.push('Network edges'); score += 5; }
            else if (Object.keys(w.machines).length > 1) missing.push('Network edges (multi-machine level needs connectivity)');

            // Credentials
            if (w.credentials.length > 0) { present.push('Credentials'); score += 5; }
            else if (w.meta.mode === 'attack') missing.push('Credential entries');

            // Objectives
            if (w.objectives.length > 0) { present.push('Objectives'); score += 10; }
            const hasBonus = w.objectives.some(o => !o.required);
            if (hasBonus) { present.push('Bonus objectives'); score += 3; }
            else improvements.push('Add bonus/optional objectives for replayability');

            // Dynamics
            if (w.dynamics !== undefined) {
                present.push('Dynamic events');
                score += 5;
            } else {
                improvements.push('Add dynamic events for a living world');
            }

            // Scoring
            if (w.scoring.tiers.length >= 2) { present.push('Scoring tiers'); score += 3; }
            if (w.scoring.timeBonus) { present.push('Time bonus'); score += 2; }
            if (w.scoring.stealthBonus) { present.push('Stealth bonus'); score += 2; }
            else if (w.meta.mode === 'attack') improvements.push('Add stealth bonus for attack mode');

            // Hints
            if (w.hints.length > 0) { present.push('Hints'); score += 5; }
            else missing.push('Hints (players need them)');
            if (w.hints.length >= 3) { present.push('Multiple hints'); score += 2; }

            // Mail system
            if (w.mail !== undefined) { present.push('Mail system'); score += 3; }
            else improvements.push('Add mail system for social engineering scenarios');

            // VARIANT Internet
            if (w.variantInternet !== undefined) { present.push('VARIANT Internet'); score += 3; }
            else if (Object.keys(w.machines).length > 1) improvements.push('Add VARIANT Internet for external service simulation');

            // Game over conditions
            if (w.gameOver !== undefined) { present.push('Game over conditions'); score += 3; }
            else if (w.meta.mode === 'defense') missing.push('Game over conditions (required for defense mode)');

            return { score: Math.min(score, 100), present: Object.freeze(present), missing: Object.freeze(missing), improvements: Object.freeze(improvements) };
        },

        fullAnalysis(world: unknown): LevelAnalysisReport {
            const validation = toolkit.validate(world);
            const mitreCoverage = toolkit.analyzeMitreCoverage(world);
            const difficulty = toolkit.analyzeDifficulty(world);
            const completeness = toolkit.analyzeCompleteness(world);

            const overallScore = Math.round(
                (completeness.score * 0.4) +
                (mitreCoverage.killChainCoveragePercent * 0.2) +
                (difficulty.matchesDeclared ? 20 : 10) +
                (validation.valid ? 20 : 0)
            );

            const parts: string[] = [];
            if (validation.valid) parts.push('Valid structure');
            else parts.push(`${validation.errors.length} error(s) found`);
            parts.push(`${mitreCoverage.killChainCoveragePercent}% kill chain coverage`);
            parts.push(`Difficulty: ${difficulty.computedDifficulty}${difficulty.matchesDeclared ? ' (matches declared)' : ' (mismatch!)'}`);
            parts.push(`Completeness: ${completeness.score}%`);

            return {
                validation,
                mitreCoverage,
                difficulty,
                completeness,
                overallScore,
                summary: parts.join(' | '),
            };
        },
    };

    return toolkit;
}
