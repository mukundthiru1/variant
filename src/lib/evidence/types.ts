/**
 * VARIANT — Evidence Chain Type Definitions
 *
 * Cryptographic hash-chain for tamper-evident forensic audit trails.
 * Every action, log entry, packet capture, and shell command is
 * recorded as an evidence block with a hash linking to the previous.
 *
 * USE CASES:
 * - Training audit: prove a student actually performed the steps
 * - Compliance simulation: tamper-evident log export
 * - Replay verification: detect if a replay was modified
 * - Enterprise reporting: cryptographically signed session evidence
 *
 * SWAPPABILITY: Implements EvidenceChain interface. Replace this file.
 * The hash function, serialization, and export format are all swappable.
 */

// ── Evidence Block ──────────────────────────────────────────────

/**
 * A single evidence block in the chain. Immutable once created.
 * Each block's hash covers: prevHash + seq + tick + category + data.
 */
export interface EvidenceBlock {
    /** Monotonic sequence number (0-based). */
    readonly seq: number;

    /** Hash of the previous block (hex string). Genesis block has '0'. */
    readonly prevHash: string;

    /** Hash of this block (hex string). */
    readonly hash: string;

    /** Simulation tick when this evidence was recorded. */
    readonly tick: number;

    /** Wall-clock time (ms since epoch). */
    readonly wallTimeMs: number;

    /** Evidence category — determines how the data is interpreted. */
    readonly category: EvidenceCategory;

    /** Machine this evidence relates to (if applicable). */
    readonly machine: string | null;

    /** The evidence payload. Shape depends on category. */
    readonly data: EvidenceData;

    /** Optional human-readable annotation. */
    readonly annotation: string | null;
}

/** Evidence categories — open union for extensibility. */
export type EvidenceCategory =
    | 'command'          // shell command executed
    | 'file-access'      // file read/write/exec
    | 'network'          // connection, request, DNS
    | 'auth'             // login, escalation, credential discovery
    | 'detection'        // rule fired, alert generated
    | 'objective'        // objective progress/completion
    | 'process'          // process spawn/kill
    | 'service'          // service interaction
    | 'system'           // simulation events (start, pause, end)
    | (string & {});     // open for extensions

/** Evidence data — discriminated by category in practice. */
export interface EvidenceData {
    /** Short summary of what happened. */
    readonly summary: string;

    /** Structured details — shape varies by category. */
    readonly details: Readonly<Record<string, unknown>>;

    /** Raw input (e.g., the actual command typed). */
    readonly rawInput?: string;

    /** Raw output (e.g., command output, response body). */
    readonly rawOutput?: string;
}

// ── Chain Integrity ─────────────────────────────────────────────

/** Result of verifying the chain's integrity. */
export interface ChainVerification {
    /** Whether the chain is valid (no tampering detected). */
    readonly valid: boolean;

    /** Total number of blocks in the chain. */
    readonly blockCount: number;

    /** Index of the first invalid block, or null if valid. */
    readonly firstInvalidBlock: number | null;

    /** Human-readable error message if invalid. */
    readonly error: string | null;
}

// ── Export Formats ──────────────────────────────────────────────

/** Exported evidence chain — the complete forensic record. */
export interface EvidenceExport {
    /** Format version for forward compatibility. */
    readonly version: '1.0';

    /** Session metadata. */
    readonly session: EvidenceSessionMeta;

    /** The complete block chain. */
    readonly blocks: readonly EvidenceBlock[];

    /** Hash of the entire export (blocks + session). */
    readonly exportHash: string;
}

export interface EvidenceSessionMeta {
    /** Unique session ID. */
    readonly sessionId: string;

    /** Level ID that was played. */
    readonly levelId: string;

    /** When the session started (ISO 8601). */
    readonly startedAt: string;

    /** When the session ended (ISO 8601). */
    readonly endedAt: string;

    /** Total simulation ticks elapsed. */
    readonly totalTicks: number;

    /** Player identifier (opaque). */
    readonly playerId: string;
}

// ── Filter ──────────────────────────────────────────────────────

/** Filter criteria for querying evidence blocks. */
export interface EvidenceFilter {
    /** Only blocks in these categories. */
    readonly categories?: readonly EvidenceCategory[];

    /** Only blocks for this machine. */
    readonly machine?: string;

    /** Only blocks in this tick range (inclusive). */
    readonly tickRange?: readonly [number, number];

    /** Only blocks matching this text in summary or rawInput. */
    readonly search?: string;

    /** Maximum number of results. */
    readonly limit?: number;
}

// ── Evidence Chain Interface ────────────────────────────────────

/**
 * The evidence chain engine.
 *
 * SECURITY: Once a block is appended, it cannot be modified or removed.
 * The chain is append-only. Verification detects any tampering.
 *
 * EXTENSIBILITY: The hash function and export format are configurable.
 * Custom categories can be added without schema changes.
 */
export interface EvidenceChain {
    /** Append a new evidence block to the chain. Returns the block. */
    append(
        tick: number,
        category: EvidenceCategory,
        machine: string | null,
        data: EvidenceData,
        annotation?: string,
    ): EvidenceBlock;

    /** Get a block by sequence number. */
    getBlock(seq: number): EvidenceBlock | null;

    /** Get all blocks, optionally filtered. */
    getBlocks(filter?: EvidenceFilter): readonly EvidenceBlock[];

    /** Get the latest block in the chain. */
    getLatest(): EvidenceBlock | null;

    /** Get the total number of blocks. */
    getLength(): number;

    /** Verify the integrity of the entire chain. */
    verify(): ChainVerification;

    /** Export the chain as a complete forensic record. */
    export(session: EvidenceSessionMeta): EvidenceExport;

    /** Subscribe to new blocks being appended. */
    onBlock(handler: (block: EvidenceBlock) => void): () => void;

    /** Clear the chain (for reset/new session). */
    clear(): void;
}
