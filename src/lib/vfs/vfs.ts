/**
 * VARIANT — Virtual Filesystem Implementation
 *
 * JSON-backed POSIX-like filesystem for Simulacra.
 * Deterministic. No system calls. Serializable.
 *
 * SECURITY:
 *   - All paths validated (no traversal, no null bytes)
 *   - Symlinks resolve with depth limit (no infinite loops)
 *   - No execution — content is always string data
 *
 * REPLACEABILITY: Implements VirtualFilesystem interface.
 * Swap this file in 20 years. Nothing else changes.
 */

import type {
    VirtualFilesystem,
    VFSNode,
    VFSSnapshot,
    VFSSnapshotNode,
    VFSSnapshotDir,
    VFSOverlay,
    WriteOpts,
    MkdirOpts,
} from './types';
import { VFSPathError } from './types';

// ── Constants ──────────────────────────────────────────────────

const MAX_SYMLINK_DEPTH = 20;
const MAX_PATH_LENGTH = 8192;
const MAX_FILE_SIZE = 5 * 1024 * 1024;
const DEFAULT_FILE_MODE = 0o644;
const DEFAULT_DIR_MODE = 0o755;
const DEFAULT_OWNER = 'root';
const DEFAULT_GROUP = 'root';

// ── Path utilities ─────────────────────────────────────────────

function validatePath(path: string): void {
    if (path.length === 0) {
        throw new VFSPathError('Path cannot be empty', path);
    }
    if (path.length > MAX_PATH_LENGTH) {
        throw new VFSPathError('Path exceeds maximum length', path);
    }
    if (!path.startsWith('/')) {
        throw new VFSPathError('Path must be absolute (start with /)', path);
    }
    if (path.includes('\0')) {
        throw new VFSPathError('Path cannot contain null bytes', path);
    }
}

function splitPath(path: string): string[] {
    validatePath(path);
    if (path === '/') return [];
    return path.split('/').filter(s => s.length > 0);
}

function normalizePath(path: string): string {
    validatePath(path);
    const parts = path.split('/').filter(s => s.length > 0);
    const resolved: string[] = [];

    for (const part of parts) {
        if (part === '.') continue;
        if (part === '..') {
            // Don't traverse above root
            if (resolved.length > 0) resolved.pop();
            continue;
        }
        resolved.push(part);
    }

    return '/' + resolved.join('/');
}

/**
 * Normalize a path (resolve . and ..) without throwing.
 * Returns null if path is invalid (empty, non-absolute, null byte, or too long).
 * Used by HTTP service to enforce path-under-webRoot.
 */
export function normalizePathSafe(path: string): string | null {
    if (path.length === 0 || path.length > MAX_PATH_LENGTH || !path.startsWith('/') || path.includes('\0')) {
        return null;
    }
    const parts = path.split('/').filter(s => s.length > 0);
    const resolved: string[] = [];
    for (const part of parts) {
        if (part === '.') continue;
        if (part === '..') {
            if (resolved.length > 0) resolved.pop();
            continue;
        }
        resolved.push(part);
    }
    return '/' + resolved.join('/');
}

function parentPath(path: string): string {
    const parts = splitPath(path);
    if (parts.length === 0) return '/';
    parts.pop();
    return '/' + parts.join('/');
}

function baseName(path: string): string {
    const parts = splitPath(path);
    if (parts.length === 0) return '/';
    return parts[parts.length - 1]!;
}

// ── Mutable internal node types ────────────────────────────────

interface MutableFile {
    type: 'file';
    content: string;
    mode: number;
    owner: string;
    group: string;
    mtime: number;
}

interface MutableDir {
    type: 'dir';
    mode: number;
    owner: string;
    group: string;
    mtime: number;
    children: Map<string, MutableNode>;
}

interface MutableSymlink {
    type: 'symlink';
    target: string;
    owner: string;
    group: string;
}

type MutableNode = MutableFile | MutableDir | MutableSymlink;

// ── Factory ────────────────────────────────────────────────────

export function createVFS(initial?: VFSSnapshot): VirtualFilesystem {
    let root: MutableDir = {
        type: 'dir',
        mode: DEFAULT_DIR_MODE,
        owner: DEFAULT_OWNER,
        group: DEFAULT_GROUP,
        mtime: Date.now(),
        children: new Map(),
    };

    if (initial !== undefined) {
        root = deserializeDir(initial.root as VFSSnapshotDir);
    }

    // ── Internal tree walker ──────────────────────────────────

    function resolve(path: string, followSymlinks: boolean = true, depth: number = 0): MutableNode | null {
        if (depth > MAX_SYMLINK_DEPTH) return null;

        const normalized = normalizePath(path);
        if (normalized === '/') return root;

        const parts = splitPath(normalized);
        let current: MutableNode = root;

        for (let i = 0; i < parts.length; i++) {
            const part = parts[i]!;

            if (current.type === 'symlink') {
                if (!followSymlinks) return current;
                const resolved = resolve(current.target, true, depth + 1);
                if (resolved === null) return null;
                current = resolved;
            }

            if (current.type !== 'dir') return null;

            const child = current.children.get(part);
            if (child === undefined) return null;

            if (i === parts.length - 1) {
                // Last component
                if (child.type === 'symlink' && followSymlinks) {
                    return resolve(child.target, true, depth + 1);
                }
                return child;
            }

            current = child;
        }

        return current;
    }

    function resolveParent(path: string): MutableDir | null {
        const parent = parentPath(path);
        const node = resolve(parent);
        if (node === null || node.type !== 'dir') return null;
        return node;
    }

    function ensureParentDirs(path: string, owner: string, group: string): void {
        const parts = splitPath(path);
        parts.pop(); // Remove the filename

        let current: MutableDir = root;
        for (const part of parts) {
            let child = current.children.get(part);
            if (child === undefined) {
                const newDir: MutableDir = {
                    type: 'dir',
                    mode: DEFAULT_DIR_MODE,
                    owner,
                    group,
                    mtime: Date.now(),
                    children: new Map(),
                };
                current.children.set(part, newDir);
                child = newDir;
            }
            if (child.type !== 'dir') {
                throw new VFSPathError(
                    `Cannot create directory: '${part}' exists and is not a directory`,
                    path,
                );
            }
            current = child;
        }
    }

    // ── Freeze a mutable node into a readonly VFSNode ─────────

    function freezeNode(node: MutableNode): VFSNode {
        switch (node.type) {
            case 'file':
                return {
                    type: 'file',
                    content: node.content,
                    mode: node.mode,
                    owner: node.owner,
                    group: node.group,
                    mtime: node.mtime,
                    size: new TextEncoder().encode(node.content).byteLength,
                };
            case 'dir': {
                const children = new Map<string, VFSNode>();
                for (const [name, child] of node.children) {
                    children.set(name, freezeNode(child));
                }
                return {
                    type: 'dir',
                    mode: node.mode,
                    owner: node.owner,
                    group: node.group,
                    mtime: node.mtime,
                    children,
                };
            }
            case 'symlink':
                return {
                    type: 'symlink',
                    target: node.target,
                    owner: node.owner,
                    group: node.group,
                };
        }
    }

    // ── Serialization ─────────────────────────────────────────

    function serializeNode(node: MutableNode): VFSSnapshotNode {
        switch (node.type) {
            case 'file':
                return {
                    type: 'file',
                    content: node.content,
                    mode: node.mode,
                    owner: node.owner,
                    group: node.group,
                };
            case 'dir': {
                const children: Record<string, VFSSnapshotNode> = {};
                for (const [name, child] of node.children) {
                    children[name] = serializeNode(child);
                }
                return {
                    type: 'dir',
                    mode: node.mode,
                    owner: node.owner,
                    group: node.group,
                    children,
                };
            }
            case 'symlink':
                return {
                    type: 'symlink',
                    target: node.target,
                    owner: node.owner,
                    group: node.group,
                };
        }
    }

    // ── Glob support (basic) ──────────────────────────────────

    function collectPaths(node: MutableNode, currentPath: string, results: string[]): void {
        if (node.type === 'file') {
            results.push(currentPath);
        } else if (node.type === 'dir') {
            for (const [name, child] of node.children) {
                collectPaths(child, currentPath === '/' ? `/${name}` : `${currentPath}/${name}`, results);
            }
        }
    }

    function matchGlob(path: string, pattern: string): boolean {
        // Simple glob: * matches any non-/ sequence, ** matches anything
        const regexStr = pattern
            .replace(/[.+^${}()|[\]\\]/g, '\\$&')
            .replace(/\*\*/g, '§§')
            .replace(/\*/g, '[^/]*')
            .replace(/§§/g, '.*')
            .replace(/\?/g, '[^/]');
        return new RegExp(`^${regexStr}$`).test(path);
    }

    // ── VFS implementation ────────────────────────────────────

    const vfs: VirtualFilesystem = {
        stat(path: string): VFSNode | null {
            const normalized = normalizePath(path);
            const node = resolve(normalized);
            if (node === null) return null;
            return freezeNode(node);
        },

        readFile(path: string): string | null {
            const normalized = normalizePath(path);
            const node = resolve(normalized);
            if (node === null || node.type !== 'file') return null;
            return node.content;
        },

        readDir(path: string): readonly string[] | null {
            const normalized = normalizePath(path);
            const node = resolve(normalized);
            if (node === null || node.type !== 'dir') return null;
            return [...node.children.keys()].sort();
        },

        realpath(path: string): string | null {
            const normalized = normalizePath(path);
            const node = resolve(normalized, true);
            if (node === null) return null;
            return normalized;
        },

        exists(path: string): boolean {
            const normalized = normalizePath(path);
            return resolve(normalized) !== null;
        },

        writeFile(path: string, content: string, opts?: WriteOpts): void {
            const normalized = normalizePath(path);
            ensureParentDirs(normalized, opts?.owner ?? DEFAULT_OWNER, opts?.group ?? DEFAULT_GROUP);

            const dir = resolveParent(normalized);
            if (dir === null) {
                throw new VFSPathError('Parent directory does not exist', normalized);
            }

            const name = baseName(normalized);
            const existing = dir.children.get(name);

            if (existing !== undefined && existing.type === 'dir') {
                throw new VFSPathError('Cannot write file: path is a directory', normalized);
            }

            const finalContent = (opts?.append === true && existing?.type === 'file')
                ? existing.content + content
                : content;
            const finalBytes = new TextEncoder().encode(finalContent).byteLength;
            if (finalBytes > MAX_FILE_SIZE) {
                throw new VFSPathError('File content exceeds maximum size', path);
            }

            dir.children.set(name, {
                type: 'file',
                content: finalContent,
                mode: opts?.mode ?? DEFAULT_FILE_MODE,
                owner: opts?.owner ?? DEFAULT_OWNER,
                group: opts?.group ?? DEFAULT_GROUP,
                mtime: Date.now(),
            });
        },

        mkdir(path: string, opts?: MkdirOpts): void {
            const normalized = normalizePath(path);

            if (opts?.recursive === true) {
                ensureParentDirs(normalized + '/placeholder', opts.owner ?? DEFAULT_OWNER, opts.group ?? DEFAULT_GROUP);
                // ensureParentDirs creates up to but not including the last component
                // So we need to also create the directory itself
                const dir = resolveParent(normalized);
                if (dir === null) return;
                const name = baseName(normalized);
                if (!dir.children.has(name)) {
                    dir.children.set(name, {
                        type: 'dir',
                        mode: opts.mode ?? DEFAULT_DIR_MODE,
                        owner: opts.owner ?? DEFAULT_OWNER,
                        group: opts.group ?? DEFAULT_GROUP,
                        mtime: Date.now(),
                        children: new Map(),
                    });
                }
                return;
            }

            const dir = resolveParent(normalized);
            if (dir === null) {
                throw new VFSPathError('Parent directory does not exist', normalized);
            }

            const name = baseName(normalized);
            if (dir.children.has(name)) {
                throw new VFSPathError('Directory already exists', normalized);
            }

            dir.children.set(name, {
                type: 'dir',
                mode: opts?.mode ?? DEFAULT_DIR_MODE,
                owner: opts?.owner ?? DEFAULT_OWNER,
                group: opts?.group ?? DEFAULT_GROUP,
                mtime: Date.now(),
                children: new Map(),
            });
        },

        remove(path: string): boolean {
            const normalized = normalizePath(path);
            if (normalized === '/') return false;

            const dir = resolveParent(normalized);
            if (dir === null) return false;

            const name = baseName(normalized);
            const node = dir.children.get(name);
            if (node === undefined) return false;

            if (node.type === 'dir' && node.children.size > 0) {
                return false; // Non-empty directory
            }

            return dir.children.delete(name);
        },

        symlink(target: string, linkPath: string): void {
            const normalized = normalizePath(linkPath);
            const dir = resolveParent(normalized);
            if (dir === null) {
                throw new VFSPathError('Parent directory does not exist', normalized);
            }

            const name = baseName(normalized);
            dir.children.set(name, {
                type: 'symlink',
                target,
                owner: DEFAULT_OWNER,
                group: DEFAULT_GROUP,
            });
        },

        chmod(path: string, mode: number): void {
            const normalized = normalizePath(path);
            const node = resolve(normalized);
            if (node === null) {
                throw new VFSPathError('Path does not exist', normalized);
            }
            if (node.type === 'symlink') return; // Can't chmod symlinks
            const clampedMode = Number.isFinite(mode) ? Math.min(0o7777, Math.max(0, mode)) : DEFAULT_FILE_MODE;
            (node as MutableFile | MutableDir).mode = clampedMode;
        },

        chown(path: string, owner: string, group?: string): void {
            const normalized = normalizePath(path);
            const node = resolve(normalized);
            if (node === null) {
                throw new VFSPathError('Path does not exist', normalized);
            }
            (node as MutableFile | MutableDir | MutableSymlink).owner = owner;
            if (group !== undefined) {
                (node as MutableFile | MutableDir | MutableSymlink).group = group;
            }
        },

        applyOverlay(overlay: VFSOverlay): void {
            for (const [path, entry] of overlay.files) {
                vfs.writeFile(path, entry.content, {
                    mode: entry.mode,
                    owner: entry.owner,
                    group: entry.group,
                });
            }
        },

        serialize(): VFSSnapshot {
            return {
                version: 1,
                root: serializeNode(root) as VFSSnapshotDir,
            };
        },

        glob(pattern: string): readonly string[] {
            const allPaths: string[] = [];
            collectPaths(root, '/', allPaths);
            return allPaths.filter(p => matchGlob(p, pattern));
        },

        totalSize(): number {
            let total = 0;
            const encoder = new TextEncoder();
            function walk(node: MutableNode): void {
                if (node.type === 'file') {
                    total += encoder.encode(node.content).byteLength;
                } else if (node.type === 'dir') {
                    for (const child of node.children.values()) {
                        walk(child);
                    }
                }
            }
            walk(root);
            return total;
        },
    };

    return vfs;
}

// ── Deserialization ────────────────────────────────────────────

function deserializeDir(snap: VFSSnapshotDir): MutableDir {
    const children = new Map<string, MutableNode>();
    for (const [name, child] of Object.entries(snap.children)) {
        children.set(name, deserializeNode(child));
    }
    return {
        type: 'dir',
        mode: snap.mode,
        owner: snap.owner,
        group: snap.group,
        mtime: Date.now(),
        children,
    };
}

function deserializeNode(snap: VFSSnapshotNode): MutableNode {
    switch (snap.type) {
        case 'file':
            return {
                type: 'file',
                content: snap.content,
                mode: snap.mode,
                owner: snap.owner,
                group: snap.group,
                mtime: Date.now(),
            };
        case 'dir':
            return deserializeDir(snap);
        case 'symlink':
            return {
                type: 'symlink',
                target: snap.target,
                owner: snap.owner,
                group: snap.group,
            };
    }
}
