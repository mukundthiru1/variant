/**
 * VARIANT — VFS barrel export.
 */
export type {
    VirtualFilesystem,
    VFSNode,
    VFSFile,
    VFSDir,
    VFSSymlink,
    VFSNodeType,
    VFSSnapshot,
    VFSSnapshotNode,
    VFSSnapshotFile,
    VFSSnapshotDir,
    VFSSnapshotSymlink,
    VFSOverlay,
    VFSOverlayEntry,
    WriteOpts,
    MkdirOpts,
} from './types';
export { VFSPathError, VFSPermissionError } from './types';
export { createVFS, normalizePathSafe } from './vfs';
