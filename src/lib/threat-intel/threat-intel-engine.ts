/**
 * VARIANT — Threat Intelligence Engine Implementation
 *
 * MITRE ATT&CK mapping, IOC management, kill chain tracking,
 * threat actor profiles, and coverage analysis.
 *
 * SWAPPABILITY: Implements ThreatIntelEngine. Replace this file.
 */

import type {
    ThreatIntelEngine,
    AttackTechnique,
    AttackTactic,
    IOCDefinition,
    IOCType,
    KillChainPhase,
    ThreatActorProfile,
    TechniqueCoverage,
    HeatmapCell,
} from './types';

interface MutableIOC {
    id: string;
    type: IOCType;
    value: string;
    location: IOCDefinition['location'];
    confidence: number;
    techniques: readonly string[];
    discovered: boolean;
}

export function createThreatIntelEngine(): ThreatIntelEngine {
    const techniques = new Map<string, AttackTechnique>();
    const iocs = new Map<string, MutableIOC>();
    const killChain: KillChainPhase[] = [];
    const actors = new Map<string, ThreatActorProfile>();

    return {
        loadTechniques(techs: readonly AttackTechnique[]): void {
            for (const tech of techs) {
                techniques.set(tech.id, tech);
            }
        },

        getTechnique(id: string): AttackTechnique | null {
            return techniques.get(id) ?? null;
        },

        getTechniquesByTactic(tactic: AttackTactic): readonly AttackTechnique[] {
            return [...techniques.values()].filter(t => t.tactic === tactic);
        },

        searchTechniques(query: string): readonly AttackTechnique[] {
            const lower = query.toLowerCase();
            return [...techniques.values()].filter(
                t => t.name.toLowerCase().includes(lower) ||
                     t.id.toLowerCase().includes(lower) ||
                     t.description.toLowerCase().includes(lower),
            );
        },

        registerIOCs(defs: readonly IOCDefinition[]): void {
            for (const ioc of defs) {
                iocs.set(ioc.id, {
                    id: ioc.id,
                    type: ioc.type,
                    value: ioc.value,
                    location: ioc.location,
                    confidence: ioc.confidence,
                    techniques: ioc.techniques,
                    discovered: false,
                });
            }
        },

        getIOCs(): readonly IOCDefinition[] {
            return [...iocs.values()].map(toIOCDef);
        },

        getIOCsByType(type: IOCType): readonly IOCDefinition[] {
            return [...iocs.values()].filter(i => i.type === type).map(toIOCDef);
        },

        markDiscovered(iocId: string): boolean {
            const ioc = iocs.get(iocId);
            if (ioc === undefined) return false;
            ioc.discovered = true;
            return true;
        },

        getDiscovered(): readonly IOCDefinition[] {
            return [...iocs.values()].filter(i => i.discovered).map(toIOCDef);
        },

        loadKillChain(phases: readonly KillChainPhase[]): void {
            killChain.length = 0;
            killChain.push(...phases);
            killChain.sort((a, b) => a.order - b.order);
        },

        getCurrentPhase(completedObjectives: readonly string[]): KillChainPhase | null {
            const completed = new Set(completedObjectives);

            // Find the latest phase where at least one objective is completed
            let latest: KillChainPhase | null = null;
            for (const phase of killChain) {
                if (phase.objectives.some(obj => completed.has(obj))) {
                    latest = phase;
                }
            }

            return latest;
        },

        getKillChainProgress(completedObjectives: readonly string[]): number {
            if (killChain.length === 0) return 0;
            const completed = new Set(completedObjectives);

            let totalObjectives = 0;
            let completedCount = 0;

            for (const phase of killChain) {
                totalObjectives += phase.objectives.length;
                for (const obj of phase.objectives) {
                    if (completed.has(obj)) completedCount++;
                }
            }

            return totalObjectives === 0 ? 0 : completedCount / totalObjectives;
        },

        loadActor(actor: ThreatActorProfile): void {
            actors.set(actor.id, actor);
        },

        getActor(id: string): ThreatActorProfile | null {
            return actors.get(id) ?? null;
        },

        listActors(): readonly ThreatActorProfile[] {
            return [...actors.values()];
        },

        computeCoverage(scenarioTechniques: ReadonlyMap<string, readonly string[]>): readonly TechniqueCoverage[] {
            const coverageMap = new Map<string, { scenarioIds: string[]; type: 'offensive' | 'defensive' | 'both' }>();

            for (const [scenarioId, techIds] of scenarioTechniques) {
                for (const techId of techIds) {
                    const existing = coverageMap.get(techId);
                    if (existing !== undefined) {
                        existing.scenarioIds.push(scenarioId);
                    } else {
                        coverageMap.set(techId, { scenarioIds: [scenarioId], type: 'both' });
                    }
                }
            }

            return [...coverageMap.entries()].map(([techId, data]) => ({
                techniqueId: techId,
                coverageType: data.type,
                scenarioIds: data.scenarioIds,
                detectionRuleIds: [],
            }));
        },

        generateHeatmap(usedTechniques: readonly string[], detectedTechniques: readonly string[]): readonly HeatmapCell[] {
            const usedCounts = new Map<string, number>();
            for (const t of usedTechniques) {
                usedCounts.set(t, (usedCounts.get(t) ?? 0) + 1);
            }

            const detectedSet = new Set(detectedTechniques);
            const cells: HeatmapCell[] = [];

            for (const [techId, count] of usedCounts) {
                const tech = techniques.get(techId);
                const detected = detectedSet.has(techId) ? 1 : 0;

                cells.push({
                    techniqueId: techId,
                    tactic: tech?.tactic ?? 'execution',
                    count,
                    detected,
                    coverage: count > 0 ? detected / count : 0,
                });
            }

            return cells;
        },

        clear(): void {
            techniques.clear();
            iocs.clear();
            killChain.length = 0;
            actors.clear();
        },
    };
}

function toIOCDef(m: MutableIOC): IOCDefinition {
    return {
        id: m.id,
        type: m.type,
        value: m.value,
        location: m.location,
        confidence: m.confidence,
        techniques: m.techniques,
        discovered: m.discovered,
    };
}
