/**
 * VARIANT — VM Backend Contract
 *
 * Defines the interface between the engine and the VM runtime.
 * v86 today. Could be anything tomorrow. The rest of the system
 * never imports v86 directly — only this contract.
 *
 * SECURITY INVARIANT: The VM has no direct path to the real network.
 * Frames go through the network fabric, which enforces isolation.
 * There is no method on this interface that could bypass the fabric.
 *
 * SECURITY INVARIANT: Overlays are applied by writing to the VM's
 * filesystem image. They cannot execute arbitrary code on the host.
 * The overlay builder validates all paths and content before injection.
 */

import type { Unsubscribe } from '../events';

// ── Boot configuration ─────────────────────────────────────────

/**
 * Everything needed to boot a VM.
 * All fields are validated before boot (see validator).
 */
export interface VMBootConfig {
    /** CDN URL for the disk image. Must be HTTPS. */
    readonly imageUrl: string;

    /** RAM allocation in MB. Clamped to [16, 256]. */
    readonly memoryMB: number;

    /** MAC address assigned by the fabric. Must be valid format. */
    readonly networkMAC: string;

    /** BIOS URLs. Must be HTTPS. */
    readonly biosUrl: string;
    readonly vgaBiosUrl: string;

    /** Optional kernel command line additions. Validated against allowlist. */
    readonly kernelArgs?: readonly string[];

    /** Whether to enable VGA output (false for headless/background VMs). */
    readonly enableVGA: boolean;

    /** Boot from CD-ROM instead of HDA. */
    readonly bootFromCdrom?: boolean;
}

// ── VM Instance ────────────────────────────────────────────────

/** Opaque VM instance handle. Implementation-specific internals are hidden. */
export interface VMInstance {
    readonly id: string;
    readonly config: VMBootConfig;
    readonly state: VMState;
}

export type VMState =
    | 'booting'
    | 'running'
    | 'paused'
    | 'stopped'
    | 'error';

// ── Filesystem overlay ─────────────────────────────────────────

/**
 * Files/dirs to inject into the VM's filesystem after boot.
 * Used to customize base images per-level without building new images.
 *
 * SECURITY: All paths are validated:
 *   - Must be absolute (start with /)
 *   - No path traversal (no ..)
 *   - No null bytes
 *   - No symlink following outside the overlay
 */
export interface FilesystemOverlay {
    readonly files: ReadonlyMap<string, OverlayFile>;
}

export interface OverlayFile {
    /** File content as UTF-8 string or Uint8Array for binary. */
    readonly content: string | Uint8Array;

    /** Unix permissions. Defaults to 0o644 for files, 0o755 for executables. */
    readonly mode?: number;

    /** Owner user. Defaults to 'root'. */
    readonly owner?: string;

    /** Owner group. Defaults to 'root'. */
    readonly group?: string;
}

// ── Snapshot ────────────────────────────────────────────────────

/** Opaque VM state snapshot. Can be saved to IndexedDB. */
export interface VMSnapshot {
    readonly vmId: string;
    readonly timestamp: number;
    readonly data: ArrayBuffer;
}

// ── Terminal I/O ───────────────────────────────────────────────

/**
 * Bidirectional byte stream for terminal (serial) connection.
 * xterm.js writes to this when the player types.
 * The VM writes to this for terminal output.
 */
export interface TerminalIO {
    /** Send bytes from terminal to VM (player input). */
    sendToVM(data: string | Uint8Array): void;

    /** Subscribe to bytes from VM to terminal (VM output). */
    onOutput(handler: (byte: number) => void): Unsubscribe;
}

// ── Backend contract ───────────────────────────────────────────

/**
 * The VM backend contract.
 *
 * Implementations must guarantee:
 * 1. boot() returns only after the VM reaches 'running' state
 * 2. sendFrame/onFrame interact with the emulated NIC, not the host
 * 3. destroy() fully releases all resources (memory, workers, etc.)
 * 4. All methods reject with typed errors, never throw synchronously
 */
export interface VMBackend {
    /**
     * Boot a VM from the given configuration.
     * The image is streamed from CDN — not downloaded in full.
     * Returns when the VM reaches 'running' state.
     */
    boot(config: VMBootConfig): Promise<VMInstance>;

    /**
     * Connect a terminal (serial port) to the VM.
     * Returns a TerminalIO handle for bidirectional communication.
     */
    attachTerminal(vm: VMInstance): TerminalIO;

    // ── Network (called by fabric, never by user code) ──────────

    /**
     * Send a raw Ethernet frame to the VM's NIC.
     * The frame is a complete Ethernet frame including headers.
     */
    sendFrame(vm: VMInstance, frame: Uint8Array): void;

    /**
     * Subscribe to raw Ethernet frames emitted by the VM's NIC.
     * Every frame emitted by the guest OS is delivered here.
     */
    onFrame(vm: VMInstance, handler: (frame: Uint8Array) => void): Unsubscribe;

    // ── Overlay ─────────────────────────────────────────────────

    /**
     * Apply a filesystem overlay to a running VM.
     * Writes files into the VM's filesystem via the emulated disk.
     */
    applyOverlay(vm: VMInstance, overlay: FilesystemOverlay): Promise<void>;

    // ── State management ────────────────────────────────────────

    /** Capture a snapshot of the VM's entire state (CPU, RAM, disk). */
    snapshot(vm: VMInstance): Promise<VMSnapshot>;

    /** Restore a VM from a previously captured snapshot. */
    restore(vm: VMInstance, snapshot: VMSnapshot): Promise<void>;

    /** Reset the VM to its initial boot state. */
    reset(vm: VMInstance): Promise<void>;

    // ── Lifecycle ───────────────────────────────────────────────

    /** Destroy the VM and release all resources. */
    destroy(vm: VMInstance): void;
}

// ── Errors ─────────────────────────────────────────────────────

export class VMBootError extends Error {
    override readonly name = 'VMBootError' as const;
    readonly vmId: string;
    constructor(message: string, vmId: string, cause?: Error) {
        super(message, { cause });
        this.vmId = vmId;
    }
}

export class VMOverlayError extends Error {
    override readonly name = 'VMOverlayError' as const;
    readonly path: string;
    constructor(message: string, path: string, cause?: Error) {
        super(message, { cause });
        this.path = path;
    }
}

export class VMSnapshotError extends Error {
    override readonly name = 'VMSnapshotError' as const;
    readonly vmId: string;
    constructor(message: string, vmId: string, cause?: Error) {
        super(message, { cause });
        this.vmId = vmId;
    }
}
