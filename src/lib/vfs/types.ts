/**
 * VARIANT — Virtual Filesystem Contract
 *
 * A JSON-backed POSIX-like filesystem for Simulacra.
 * This is the interface. Implementations live separately.
 *
 * DESIGN: Zero dependencies on core/. This is a standalone
 * library that could be extracted into its own package.
 * The engine, backends, and modules all depend on this
 * interface, never on a specific implementation.
 *
 * Replace the implementation in 20 years.
 * This interface stays.
 */

// ── Node types ─────────────────────────────────────────────────

export type VFSNodeType = 'file' | 'dir' | 'symlink';

export interface VFSFile {
    readonly type: 'file';
    readonly content: string;
    readonly mode: number;       // Unix permissions (e.g., 0o644)
    readonly owner: string;
    readonly group: string;
    readonly mtime: number;      // Epoch ms
    readonly size: number;       // Byte count of content
}

export interface VFSDir {
    readonly type: 'dir';
    readonly mode: number;       // e.g., 0o755
    readonly owner: string;
    readonly group: string;
    readonly mtime: number;
    readonly children: ReadonlyMap<string, VFSNode>;
}

export interface VFSSymlink {
    readonly type: 'symlink';
    readonly target: string;     // Absolute or relative path
    readonly owner: string;
    readonly group: string;
}

export type VFSNode = VFSFile | VFSDir | VFSSymlink;

// ── Filesystem interface ───────────────────────────────────────

/**
 * The VFS interface. Implementations must:
 *   1. Maintain a rooted tree of VFSNodes
 *   2. Validate paths (no traversal, no null bytes)
 *   3. Enforce permissions when a 'user' is provided
 *   4. Be deterministic (no randomness, no system calls)
 *   5. Be serializable (JSON round-trip safe)
 */
export interface VirtualFilesystem {
    // ── Read operations ────────────────────────────────────────

    /** Resolve a path to a node. Returns null if not found. */
    stat(path: string): VFSNode | null;

    /** Read file content at path. Returns null if not a file. */
    readFile(path: string): string | null;

    /** List entries in a directory. Returns null if not a dir. */
    readDir(path: string): readonly string[] | null;

    /** Resolve a symlink chain. Returns the final path or null. */
    realpath(path: string): string | null;

    /** Check if a path exists. */
    exists(path: string): boolean;

    // ── Write operations ───────────────────────────────────────

    /** Write content to a file. Creates parent dirs as needed. */
    writeFile(path: string, content: string, opts?: WriteOpts): void;

    /** Create a directory. Creates parents if recursive=true. */
    mkdir(path: string, opts?: MkdirOpts): void;

    /** Remove a file or empty directory. */
    remove(path: string): boolean;

    /** Create a symlink. */
    symlink(target: string, linkPath: string): void;

    /** Change file mode. */
    chmod(path: string, mode: number): void;

    /** Change file owner. */
    chown(path: string, owner: string, group?: string): void;

    // ── Bulk operations ────────────────────────────────────────

    /** Apply a batch of file operations atomically. */
    applyOverlay(overlay: VFSOverlay): void;

    /** Serialize the entire filesystem to a JSON-safe structure. */
    serialize(): VFSSnapshot;

    // ── Queries ────────────────────────────────────────────────

    /** Find files matching a glob pattern (basic implementation). */
    glob(pattern: string): readonly string[];

    /** Get the total size of all files. */
    totalSize(): number;
}

// ── Options ────────────────────────────────────────────────────

export interface WriteOpts {
    readonly mode?: number | undefined;
    readonly owner?: string | undefined;
    readonly group?: string | undefined;
    readonly append?: boolean | undefined;
}

export interface MkdirOpts {
    readonly mode?: number | undefined;
    readonly recursive?: boolean | undefined;
    readonly owner?: string | undefined;
    readonly group?: string | undefined;
}

// ── Overlay (batch filesystem mutation) ────────────────────────

export interface VFSOverlay {
    readonly files: ReadonlyMap<string, VFSOverlayEntry>;
}

export interface VFSOverlayEntry {
    readonly content: string;
    readonly mode?: number | undefined;
    readonly owner?: string | undefined;
    readonly group?: string | undefined;
}

// ── Snapshot (serialization) ───────────────────────────────────

/** JSON-serializable snapshot of the entire filesystem. */
export interface VFSSnapshot {
    readonly version: 1;
    readonly root: VFSSnapshotNode;
}

export type VFSSnapshotNode =
    | VFSSnapshotFile
    | VFSSnapshotDir
    | VFSSnapshotSymlink;

export interface VFSSnapshotFile {
    readonly type: 'file';
    readonly content: string;
    readonly mode: number;
    readonly owner: string;
    readonly group: string;
}

export interface VFSSnapshotDir {
    readonly type: 'dir';
    readonly mode: number;
    readonly owner: string;
    readonly group: string;
    readonly children: Record<string, VFSSnapshotNode>;
}

export interface VFSSnapshotSymlink {
    readonly type: 'symlink';
    readonly target: string;
    readonly owner: string;
    readonly group: string;
}

// ── Path validation ────────────────────────────────────────────

export class VFSPathError extends Error {
    override readonly name = 'VFSPathError' as const;
    readonly path: string;
    constructor(message: string, path: string) {
        super(message);
        this.path = path;
    }
}

export class VFSPermissionError extends Error {
    override readonly name = 'VFSPermissionError' as const;
    readonly path: string;
    readonly user: string;
    constructor(message: string, path: string, user: string) {
        super(message);
        this.path = path;
        this.user = user;
    }
}
