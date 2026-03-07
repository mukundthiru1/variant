/**
 * VARIANT — Forensics Engine Types
 *
 * Digital forensics simulation for incident response training.
 * Models artifacts, evidence collection, timeline reconstruction,
 * and analysis techniques that players use during IR scenarios.
 *
 * FEATURES:
 * - Artifact registry (files, logs, memory, network captures)
 * - Evidence collection workflow (acquire → hash → analyze)
 * - Timeline reconstruction from multiple artifact sources
 * - Chain of custody tracking
 * - IOC matching against collected artifacts
 * - Analysis report generation
 *
 * SWAPPABILITY: Implements ForensicsEngine. Replace this file.
 */

// ── Artifacts ───────────────────────────────────────────────────

/** Category of forensic artifact. */
export type ArtifactCategory =
    | 'file'
    | 'log'
    | 'memory'
    | 'network-capture'
    | 'registry'
    | 'process'
    | 'configuration';

/** A forensic artifact that can be collected and analyzed. */
export interface ForensicArtifact {
    /** Unique artifact ID. */
    readonly id: string;
    /** Source machine. */
    readonly machine: string;
    /** Artifact category. */
    readonly category: ArtifactCategory;
    /** Path or identifier on the source system. */
    readonly path: string;
    /** Content or data (simulated). */
    readonly content: string;
    /** Hash of the content (integrity verification). */
    readonly hash: string;
    /** When the artifact was created (tick). */
    readonly createdAt: number;
    /** When the artifact was last modified (tick). */
    readonly modifiedAt: number;
    /** Tags for categorization. */
    readonly tags: readonly string[];
    /** Whether this artifact contains evidence of compromise. */
    readonly isEvidence: boolean;
    /** IOC IDs found in this artifact (populated after analysis). */
    readonly matchedIOCs: readonly string[];
}

// ── Collection ──────────────────────────────────────────────────

/** Status of evidence collection. */
export type CollectionStatus = 'pending' | 'acquired' | 'analyzed' | 'reported';

/** A collected evidence item with chain of custody. */
export interface CollectedEvidence {
    /** Unique collection ID. */
    readonly collectionId: string;
    /** The artifact that was collected. */
    readonly artifactId: string;
    /** Who collected it. */
    readonly collectedBy: string;
    /** When it was collected (tick). */
    readonly collectedAt: number;
    /** Hash at time of collection (integrity check). */
    readonly acquisitionHash: string;
    /** Current status. */
    readonly status: CollectionStatus;
    /** Analysis notes added by the investigator. */
    readonly notes: readonly string[];
    /** Whether integrity has been verified. */
    readonly integrityVerified: boolean;
}

// ── Timeline ────────────────────────────────────────────────────

/** A single event in a forensic timeline. */
export interface TimelineEvent {
    /** Tick when the event occurred. */
    readonly tick: number;
    /** Source machine. */
    readonly machine: string;
    /** Event type/description. */
    readonly type: string;
    /** Detailed description. */
    readonly description: string;
    /** Source artifact ID (if derived from an artifact). */
    readonly sourceArtifactId?: string;
    /** Severity/importance. */
    readonly severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
    /** IOC IDs associated with this event. */
    readonly associatedIOCs: readonly string[];
}

// ── IOC Matching ────────────────────────────────────────────────

/** An indicator of compromise pattern. */
export interface ForensicIOC {
    /** Unique IOC ID. */
    readonly id: string;
    /** IOC type. */
    readonly type: 'ip' | 'domain' | 'hash' | 'filename' | 'pattern' | 'registry-key';
    /** The indicator value or pattern. */
    readonly value: string;
    /** Description. */
    readonly description: string;
    /** Severity. */
    readonly severity: 'low' | 'medium' | 'high' | 'critical';
}

// ── Engine ──────────────────────────────────────────────────────

/** The forensics simulation engine. */
export interface ForensicsEngine {
    // ── Artifact Management ─────────────────────────────────────

    /** Register a forensic artifact in the simulation. */
    addArtifact(artifact: ForensicArtifact): void;

    /** Get an artifact by ID. */
    getArtifact(id: string): ForensicArtifact | null;

    /** List artifacts by machine. */
    listArtifactsByMachine(machine: string): readonly ForensicArtifact[];

    /** List artifacts by category. */
    listArtifactsByCategory(category: ArtifactCategory): readonly ForensicArtifact[];

    /** List all artifacts. */
    listArtifacts(): readonly ForensicArtifact[];

    // ── Evidence Collection ─────────────────────────────────────

    /** Collect an artifact as evidence. Returns collection ID or null if artifact not found. */
    collectEvidence(artifactId: string, collectedBy: string, tick: number): string | null;

    /** Get collected evidence by collection ID. */
    getEvidence(collectionId: string): CollectedEvidence | null;

    /** Add analysis notes to collected evidence. */
    addNote(collectionId: string, note: string): boolean;

    /** Mark evidence as analyzed. */
    markAnalyzed(collectionId: string): boolean;

    /** Verify integrity of collected evidence (hash comparison). */
    verifyIntegrity(collectionId: string): boolean;

    /** List all collected evidence. */
    listEvidence(): readonly CollectedEvidence[];

    // ── IOC Management ──────────────────────────────────────────

    /** Register an IOC pattern. */
    addIOC(ioc: ForensicIOC): void;

    /** Get an IOC by ID. */
    getIOC(id: string): ForensicIOC | null;

    /** List all IOCs. */
    listIOCs(): readonly ForensicIOC[];

    /** Scan an artifact against all registered IOCs. Returns matched IOC IDs. */
    scanArtifact(artifactId: string): readonly string[];

    // ── Timeline ────────────────────────────────────────────────

    /** Add a timeline event. */
    addTimelineEvent(event: TimelineEvent): void;

    /** Get the full timeline, sorted by tick. */
    getTimeline(): readonly TimelineEvent[];

    /** Get timeline events for a specific machine. */
    getTimelineByMachine(machine: string): readonly TimelineEvent[];

    /** Get timeline events in a tick range. */
    getTimelineRange(startTick: number, endTick: number): readonly TimelineEvent[];

    // ── Reset ───────────────────────────────────────────────────

    /** Clear all state. */
    clear(): void;
}
