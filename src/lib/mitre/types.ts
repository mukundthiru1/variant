/**
 * VARIANT — MITRE ATT&CK Type Definitions
 *
 * The single source of truth for all MITRE ATT&CK mappings in VARIANT.
 * Every engine, detection rule, vulnerability, and persistence mechanism
 * references techniques through this catalog.
 *
 * Based on MITRE ATT&CK Enterprise v15 (2024).
 *
 * SECURITY INVARIANT: All data is readonly and frozen. No mutation paths.
 * EXTENSIBILITY: Custom techniques can be added via addCustomTechnique().
 */

// ── MITRE ATT&CK Tactics (kill chain phases) ──────────────────

export type MitreTactic =
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

export type MitrePlatform = 'linux' | 'windows' | 'macos' | 'network' | 'cloud' | 'containers';

export type MitreDetectionDifficulty = 'trivial' | 'easy' | 'moderate' | 'hard' | 'very-hard';

// ── Technique Entry ─────────────────────────────────────────────

export interface TechniqueEntry {
    /** Technique ID (e.g., 'T1059' or 'T1059.001'). */
    readonly id: string;

    /** Human-readable name. */
    readonly name: string;

    /** Description of the technique. */
    readonly description: string;

    /** Parent technique ID (for sub-techniques). */
    readonly parent?: string;

    /** Tactics this technique is associated with. */
    readonly tactics: readonly MitreTactic[];

    /** Platforms this technique applies to. */
    readonly platforms: readonly MitrePlatform[];

    /**
     * Which VARIANT engines can simulate this technique.
     * Maps engine module name → capability description.
     */
    readonly variantEngines: Readonly<Record<string, string>>;

    /**
     * Detection signatures available in VARIANT.
     * Maps detection engine → rule/signature ID.
     */
    readonly variantDetections: Readonly<Record<string, string>>;

    /** How hard this technique is to detect in real-world scenarios. */
    readonly detectionDifficulty: MitreDetectionDifficulty;

    /** Data sources useful for detection (MITRE standard). */
    readonly dataSources: readonly string[];

    /** Whether VARIANT can fully simulate this technique. */
    readonly simulationSupport: 'full' | 'partial' | 'detection-only' | 'planned';

    /** Tags for filtering. */
    readonly tags: readonly string[];
}

// ── Attack Chain Types ──────────────────────────────────────────

export interface AttackChainStep {
    /** Step number (1-based). */
    readonly order: number;

    /** Human-readable description of this step. */
    readonly description: string;

    /** MITRE technique ID used in this step. */
    readonly techniqueId: string;

    /** Tactic this step falls under. */
    readonly tactic: MitreTactic;

    /** Source machine (where the attacker is). */
    readonly sourceMachine?: string;

    /** Target machine (what the attacker is hitting). */
    readonly targetMachine?: string;

    /** Credential used or obtained in this step. */
    readonly credential?: string;

    /** Detection risk level. */
    readonly detectionRisk: 'low' | 'medium' | 'high' | 'critical';

    /** Artifacts left by this step (for blue team training). */
    readonly artifacts: readonly string[];

    /** Prerequisites (step orders that must complete first). */
    readonly prerequisites: readonly number[];
}

export interface AttackChain {
    /** Unique chain ID. */
    readonly id: string;

    /** Human-readable name. */
    readonly name: string;

    /** Description of the overall attack scenario. */
    readonly description: string;

    /** Ordered steps in the attack chain. */
    readonly steps: readonly AttackChainStep[];

    /** All unique MITRE tactics covered. */
    readonly tacticsUsed: readonly MitreTactic[];

    /** All unique MITRE techniques used. */
    readonly techniquesUsed: readonly string[];

    /** Overall difficulty. */
    readonly difficulty: 'beginner' | 'intermediate' | 'advanced' | 'expert';

    /** Tags for filtering. */
    readonly tags: readonly string[];
}

// ── MITRE Catalog Interface ─────────────────────────────────────

export interface MitreCatalog {
    /** Get a technique by ID. Returns null if not found. */
    getTechnique(id: string): TechniqueEntry | null;

    /** List all techniques. */
    listTechniques(): readonly TechniqueEntry[];

    /** List techniques by tactic. */
    listByTactic(tactic: MitreTactic): readonly TechniqueEntry[];

    /** List techniques by platform. */
    listByPlatform(platform: MitrePlatform): readonly TechniqueEntry[];

    /** List techniques that a specific VARIANT engine can simulate. */
    listByEngine(engineName: string): readonly TechniqueEntry[];

    /** List techniques with available detection rules. */
    listDetectable(): readonly TechniqueEntry[];

    /** List sub-techniques of a parent technique. */
    listSubTechniques(parentId: string): readonly TechniqueEntry[];

    /** Search techniques by keyword (name, description, tags). */
    search(query: string): readonly TechniqueEntry[];

    /** Get all unique tactics in the catalog. */
    listTactics(): readonly MitreTactic[];

    /** Add a custom technique entry. */
    addCustomTechnique(entry: TechniqueEntry): void;

    /** Get catalog statistics. */
    getStats(): MitreCatalogStats;

    /** Get coverage report — what percentage of each tactic is simulatable. */
    getCoverage(): MitreCoverageReport;
}

export interface MitreCatalogStats {
    readonly totalTechniques: number;
    readonly totalSubTechniques: number;
    readonly byTactic: Readonly<Record<string, number>>;
    readonly bySimulationSupport: Readonly<Record<string, number>>;
    readonly byPlatform: Readonly<Record<string, number>>;
    readonly totalDetectable: number;
}

export interface MitreCoverageReport {
    readonly byTactic: readonly TacticCoverage[];
    readonly overallSimulatable: number;
    readonly overallDetectable: number;
}

export interface TacticCoverage {
    readonly tactic: MitreTactic;
    readonly totalTechniques: number;
    readonly fullSupport: number;
    readonly partialSupport: number;
    readonly detectionOnly: number;
    readonly planned: number;
    readonly coveragePercent: number;
}
