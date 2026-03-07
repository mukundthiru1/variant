/**
 * VARIANT — Threat Intelligence Type Definitions
 *
 * Maps simulation artifacts to real-world threat frameworks:
 * MITRE ATT&CK, STIX, Kill Chain, Diamond Model.
 *
 * Every action in a scenario can be tagged with ATT&CK techniques,
 * IOCs can be defined as evidence markers, and kill chain phases
 * structure the progression of an attack narrative.
 *
 * USE CASES:
 * - Enterprise training: map exercises to ATT&CK coverage
 * - Scenario authoring: tag objectives with techniques
 * - After-action reports: show ATT&CK heatmap of player actions
 * - Detection rules: auto-generate from technique definitions
 * - Threat modeling: simulate specific APT campaigns
 *
 * SWAPPABILITY: Implements ThreatIntelEngine. Replace this file.
 */

// ── ATT&CK Mapping ─────────────────────────────────────────────

/** A MITRE ATT&CK technique reference. */
export interface AttackTechnique {
    /** Technique ID (e.g., 'T1059.001'). */
    readonly id: string;

    /** Technique name (e.g., 'PowerShell'). */
    readonly name: string;

    /** Tactic this technique belongs to. */
    readonly tactic: AttackTactic;

    /** Sub-technique parent (null for top-level). */
    readonly parent: string | null;

    /** Detection data sources relevant to this technique. */
    readonly dataSources: readonly string[];

    /** Platforms this technique applies to. */
    readonly platforms: readonly string[];

    /** Description for display. */
    readonly description: string;
}

export type AttackTactic =
    | 'reconnaissance'
    | 'resource-development'
    | 'initial-access'
    | 'execution'
    | 'persistence'
    | 'privilege-escalation'
    | 'defense-evasion'
    | 'credential-access'
    | 'discovery'
    | 'lateral-movement'
    | 'collection'
    | 'command-and-control'
    | 'exfiltration'
    | 'impact';

// ── Indicators of Compromise ────────────────────────────────────

/** An IOC that can be planted in or discovered during a scenario. */
export interface IOCDefinition {
    /** Unique IOC ID within the scenario. */
    readonly id: string;

    /** IOC type. */
    readonly type: IOCType;

    /** The actual indicator value. */
    readonly value: string;

    /** Where this IOC can be found in the simulation. */
    readonly location: IOCLocation;

    /** Confidence level (0-1). */
    readonly confidence: number;

    /** Related ATT&CK technique IDs. */
    readonly techniques: readonly string[];

    /** Whether the player has discovered this IOC. */
    readonly discovered?: boolean;
}

export type IOCType =
    | 'ip-address'
    | 'domain'
    | 'url'
    | 'file-hash'
    | 'file-path'
    | 'email-address'
    | 'registry-key'
    | 'process-name'
    | 'command-line'
    | 'user-agent'
    | 'certificate'
    | (string & {});

export interface IOCLocation {
    /** Machine where this IOC exists. */
    readonly machine: string;

    /** Where to find it (log, file, process, network). */
    readonly source: 'log' | 'file' | 'process' | 'network' | 'registry' | 'memory';

    /** Specific path/identifier. */
    readonly path: string;
}

// ── Kill Chain ──────────────────────────────────────────────────

/** Kill chain phase mapping for attack progression. */
export interface KillChainPhase {
    /** Phase ID. */
    readonly id: string;

    /** Kill chain model (e.g., 'lockheed-martin', 'unified'). */
    readonly model: string;

    /** Phase name. */
    readonly name: string;

    /** Phase order (for sequencing). */
    readonly order: number;

    /** ATT&CK tactics that map to this phase. */
    readonly tactics: readonly AttackTactic[];

    /** Objectives in this phase. */
    readonly objectives: readonly string[];
}

// ── Threat Actor Profile ────────────────────────────────────────

/** A simulated threat actor with known TTPs. */
export interface ThreatActorProfile {
    /** Actor ID. */
    readonly id: string;

    /** Actor name (e.g., 'APT29', 'FIN7'). */
    readonly name: string;

    /** Actor aliases. */
    readonly aliases: readonly string[];

    /** Motivation. */
    readonly motivation: 'espionage' | 'financial' | 'hacktivism' | 'destruction' | 'unknown';

    /** Sophistication level. */
    readonly sophistication: 'novice' | 'intermediate' | 'advanced' | 'expert' | 'nation-state';

    /** Known ATT&CK techniques used by this actor. */
    readonly techniques: readonly string[];

    /** Known target sectors. */
    readonly targetSectors: readonly string[];

    /** Description. */
    readonly description: string;
}

// ── Technique Coverage ──────────────────────────────────────────

/** Coverage of ATT&CK techniques by a scenario or set of scenarios. */
export interface TechniqueCoverage {
    /** Technique ID. */
    readonly techniqueId: string;

    /** How the technique is covered. */
    readonly coverageType: 'offensive' | 'defensive' | 'both';

    /** Which scenarios cover this technique. */
    readonly scenarioIds: readonly string[];

    /** Detection rules that address this technique. */
    readonly detectionRuleIds: readonly string[];
}

// ── ATT&CK Heatmap ─────────────────────────────────────────────

/** A row in the ATT&CK heatmap visualization. */
export interface HeatmapCell {
    readonly techniqueId: string;
    readonly tactic: AttackTactic;
    readonly count: number;       // how many times used
    readonly detected: number;    // how many times detected
    readonly coverage: number;    // 0-1 detection coverage ratio
}

// ── Threat Intel Engine ─────────────────────────────────────────

/**
 * The threat intelligence engine manages ATT&CK mappings,
 * IOCs, kill chain phases, and coverage analysis.
 *
 * EXTENSIBILITY: Custom threat frameworks can be added.
 * The ATT&CK database is loadable (not hardcoded).
 */
export interface ThreatIntelEngine {
    /** Load ATT&CK technique definitions. */
    loadTechniques(techniques: readonly AttackTechnique[]): void;

    /** Get a technique by ID. */
    getTechnique(id: string): AttackTechnique | null;

    /** Get all techniques for a tactic. */
    getTechniquesByTactic(tactic: AttackTactic): readonly AttackTechnique[];

    /** Search techniques by name. */
    searchTechniques(query: string): readonly AttackTechnique[];

    /** Register IOCs for a scenario. */
    registerIOCs(iocs: readonly IOCDefinition[]): void;

    /** Get all registered IOCs. */
    getIOCs(): readonly IOCDefinition[];

    /** Get IOCs by type. */
    getIOCsByType(type: IOCType): readonly IOCDefinition[];

    /** Mark an IOC as discovered. */
    markDiscovered(iocId: string): boolean;

    /** Get discovered IOCs. */
    getDiscovered(): readonly IOCDefinition[];

    /** Register kill chain phases. */
    loadKillChain(phases: readonly KillChainPhase[]): void;

    /** Get current kill chain phase based on completed objectives. */
    getCurrentPhase(completedObjectives: readonly string[]): KillChainPhase | null;

    /** Get kill chain progress (0-1). */
    getKillChainProgress(completedObjectives: readonly string[]): number;

    /** Load a threat actor profile. */
    loadActor(actor: ThreatActorProfile): void;

    /** Get a threat actor by ID. */
    getActor(id: string): ThreatActorProfile | null;

    /** List all loaded actors. */
    listActors(): readonly ThreatActorProfile[];

    /** Compute technique coverage for a set of scenarios. */
    computeCoverage(scenarioTechniques: ReadonlyMap<string, readonly string[]>): readonly TechniqueCoverage[];

    /** Generate ATT&CK heatmap from a session's technique usage. */
    generateHeatmap(usedTechniques: readonly string[], detectedTechniques: readonly string[]): readonly HeatmapCell[];

    /** Clear all state. */
    clear(): void;
}
