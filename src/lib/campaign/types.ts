/**
 * VARIANT — Campaign Engine Type Definitions
 *
 * Multi-level story campaigns with branching paths, persistent
 * state between levels, and narrative progression.
 *
 * DESIGN:
 * A campaign is a directed graph of levels. Players progress
 * through nodes based on their performance and choices. State
 * persists between levels (skills learned, items found, reputation).
 *
 * FEATURES:
 * - Branching paths: choices affect which levels come next
 * - Persistent state: carry items, credentials, reputation forward
 * - Story beats: narrative text between levels
 * - Prerequisites: levels unlock based on prior completion
 * - Difficulty scaling: later levels adapt to player skill
 * - Campaign scoring: aggregate across all levels
 *
 * SWAPPABILITY: Implements CampaignEngine. Replace this file.
 */

// ── Campaign Definition ─────────────────────────────────────────

/** A complete campaign definition. */
export interface CampaignDefinition {
    /** Unique campaign ID. */
    readonly id: string;

    /** Campaign title. */
    readonly title: string;

    /** Campaign description. */
    readonly description: string;

    /** Author info. */
    readonly author: string;

    /** Difficulty progression. */
    readonly difficulty: 'fixed' | 'adaptive' | 'escalating';

    /** Estimated total time in minutes. */
    readonly estimatedMinutes: number;

    /** Campaign nodes (levels + narrative beats). */
    readonly nodes: readonly CampaignNode[];

    /** Edges between nodes (progression paths). */
    readonly edges: readonly CampaignEdge[];

    /** Starting node ID. */
    readonly startNode: string;

    /** Ending node IDs (multiple possible endings). */
    readonly endNodes: readonly string[];

    /** Persistent state keys carried between levels. */
    readonly persistentState: readonly PersistentStateKey[];

    /** Tags for discovery. */
    readonly tags: readonly string[];
}

/** A node in the campaign graph. */
export interface CampaignNode {
    /** Unique node ID. */
    readonly id: string;

    /** Node type. */
    readonly type: CampaignNodeType;

    /** Level ID (for 'level' type nodes). */
    readonly levelId?: string;

    /** Narrative content (for 'story' type nodes). */
    readonly narrative?: CampaignNarrative;

    /** Title displayed in campaign map. */
    readonly title: string;

    /** Brief description. */
    readonly description: string;

    /** Minimum score from prior levels to reach this node. */
    readonly minScore?: number;

    /** Required persistent state to access this node. */
    readonly requires?: readonly StateRequirement[];

    /** State changes applied when this node is completed. */
    readonly grants?: readonly StateGrant[];

    /** Position in campaign map (for visualization). */
    readonly position?: { readonly x: number; readonly y: number };
}

export type CampaignNodeType =
    | 'level'        // playable scenario
    | 'story'        // narrative beat (text/cutscene)
    | 'choice'       // player decision point
    | 'checkpoint'   // save point
    | 'branch'       // conditional branch based on state
    | (string & {}); // extensible

/** Narrative content for story beats. */
export interface CampaignNarrative {
    /** Paragraphs of story text. */
    readonly paragraphs: readonly string[];

    /** Speaker/character (for dialogue). */
    readonly speaker?: string;

    /** Choices available at this narrative point. */
    readonly choices?: readonly NarrativeChoice[];
}

/** A choice the player can make at a narrative point. */
export interface NarrativeChoice {
    /** Choice text displayed to player. */
    readonly text: string;

    /** Edge ID to follow if this choice is selected. */
    readonly edgeId: string;

    /** State changes applied when this choice is made. */
    readonly grants?: readonly StateGrant[];
}

/** An edge connecting two campaign nodes. */
export interface CampaignEdge {
    /** Unique edge ID. */
    readonly id: string;

    /** Source node. */
    readonly from: string;

    /** Target node. */
    readonly to: string;

    /** Condition to traverse this edge. */
    readonly condition?: EdgeCondition;

    /** Label displayed on campaign map. */
    readonly label?: string;
}

/** Condition for traversing an edge. */
export type EdgeCondition =
    | { readonly kind: 'score'; readonly minScore: number }
    | { readonly kind: 'state'; readonly key: string; readonly value: unknown }
    | { readonly kind: 'choice'; readonly choiceId: string }
    | { readonly kind: 'grade'; readonly minGrade: string }
    | { readonly kind: 'always' };

// ── Persistent State ────────────────────────────────────────────

/** A key in the persistent state carried between levels. */
export interface PersistentStateKey {
    readonly key: string;
    readonly type: 'string' | 'number' | 'boolean' | 'string[]';
    readonly defaultValue: unknown;
    readonly description: string;
}

/** A requirement on persistent state. */
export interface StateRequirement {
    readonly key: string;
    readonly operator: '==' | '!=' | '>' | '<' | '>=' | '<=' | 'contains';
    readonly value: unknown;
}

/** A state change granted by completing a node or making a choice. */
export interface StateGrant {
    readonly key: string;
    readonly operation: 'set' | 'add' | 'subtract' | 'append' | 'remove';
    readonly value: unknown;
}

// ── Campaign Progress ───────────────────────────────────────────

/** Player's progress through a campaign. */
export interface CampaignProgress {
    /** Campaign ID. */
    readonly campaignId: string;

    /** Persistent state values. */
    readonly state: Readonly<Record<string, unknown>>;

    /** Completed node IDs. */
    readonly completedNodes: readonly string[];

    /** Current node ID. */
    readonly currentNode: string;

    /** Scores per level node. */
    readonly scores: Readonly<Record<string, number>>;

    /** Total campaign score. */
    readonly totalScore: number;

    /** Path taken (ordered node IDs). */
    readonly path: readonly string[];

    /** Whether the campaign is complete. */
    readonly completed: boolean;

    /** Start timestamp (ISO 8601). */
    readonly startedAt: string;

    /** Last played timestamp. */
    readonly lastPlayedAt: string;
}

// ── Campaign Engine Interface ───────────────────────────────────

/**
 * The campaign engine manages multi-level story progression.
 *
 * EXTENSIBILITY: Custom node types and edge conditions can be
 * added without schema changes.
 */
export interface CampaignEngine {
    /** Load a campaign definition. */
    loadCampaign(campaign: CampaignDefinition): void;

    /** Get a campaign by ID. */
    getCampaign(id: string): CampaignDefinition | null;

    /** List all loaded campaigns. */
    listCampaigns(): readonly CampaignDefinition[];

    /** Start a new campaign playthrough. Returns initial progress. */
    start(campaignId: string): CampaignProgress | null;

    /** Get current progress. */
    getProgress(campaignId: string): CampaignProgress | null;

    /** Complete the current node with a score. Returns available next nodes. */
    completeNode(campaignId: string, score: number, grants?: readonly StateGrant[]): readonly string[];

    /** Make a choice at a choice/story node. Returns the next node ID. */
    makeChoice(campaignId: string, edgeId: string): string | null;

    /** Get available next nodes from current position. */
    getAvailableNodes(campaignId: string): readonly CampaignNode[];

    /** Advance to a specific node (must be available). */
    advanceTo(campaignId: string, nodeId: string): boolean;

    /** Check if a state requirement is met. */
    checkRequirement(campaignId: string, req: StateRequirement): boolean;

    /** Get the campaign graph for visualization. */
    getGraph(campaignId: string): { nodes: readonly CampaignNode[]; edges: readonly CampaignEdge[] } | null;

    /** Reset campaign progress. */
    resetProgress(campaignId: string): boolean;

    /** Clear all campaigns and progress. */
    clear(): void;
}
