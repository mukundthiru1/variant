/**
 * VARIANT — v86 Backend Implementation
 *
 * Implements the VMBackend contract using v86 as the x86 emulator.
 * This is the ONLY file in the codebase that directly references v86.
 * Everything else uses the VMBackend interface.
 *
 * SECURITY: All network frames from the guest go through onFrame callbacks.
 * We never set network_relay_url — there is no WebSocket relay.
 * The guest NIC is connected to our in-memory fabric, not the internet.
 *
 * SECURITY: The 9p filesystem is used for overlay injection only.
 * Files are written into the guest's filesystem — the guest cannot
 * read HOST files through 9p because we don't mount any host directory.
 */

import type {
    VMBackend,
    VMBootConfig,
    VMInstance,
    VMState,
    TerminalIO,
    FilesystemOverlay,
    VMSnapshot,
} from './types';
import type { Unsubscribe } from '../events';
import { VMBootError, VMSnapshotError } from './types';

// ── Constants ──────────────────────────────────────────────────

/** Default CDN for v86 assets. */
const V86_WASM_URL = '/v86/v86.wasm';

/** Boot timeout in milliseconds. */
const BOOT_TIMEOUT_MS = 30_000;

/** Minimum/maximum memory bounds (enforced before passing to v86). */
const MIN_MEMORY_MB = 16;
const MAX_MEMORY_MB = 256;

// ── Internal state per VM ──────────────────────────────────────

interface V86VMState {
    readonly emulator: V86;
    readonly config: VMBootConfig;
    state: VMState;
    readonly frameHandlers: Set<(frame: Uint8Array) => void>;
    readonly outputHandlers: Set<(byte: number) => void>;
}

// ── Helpers (stateless) ────────────────────────────────────────

function clampMemory(mb: number): number {
    return Math.max(MIN_MEMORY_MB, Math.min(MAX_MEMORY_MB, mb));
}

/**
 * Wait for the emulator to emit a specific event, with timeout.
 */
function waitForEvent(
    emulator: V86,
    eventName: string,
    timeoutMs: number,
    vmId: string,
): Promise<void> {
    return new Promise<void>((resolve, reject) => {
        let settled = false;

        const timer = setTimeout(() => {
            if (!settled) {
                settled = true;
                reject(new VMBootError(
                    `Timeout waiting for '${eventName}' after ${timeoutMs}ms`,
                    vmId,
                ));
            }
        }, timeoutMs);

        const handler = () => {
            if (!settled) {
                settled = true;
                clearTimeout(timer);
                emulator.remove_listener(eventName, handler);
                resolve();
            }
        };

        emulator.add_listener(eventName, handler);
    });
}

// ── Backend implementation ─────────────────────────────────────

export function createV86Backend(): VMBackend {
    /**
     * Per-backend state. Each call to createV86Backend() gets its own
     * isolated VM registry. When the backend is GC'd, all unreferenced
     * VM state is collected with it.
     *
     * SECURITY: This prevents cross-simulation state leaks.
     */
    const vms = new Map<string, V86VMState>();
    let nextVmId = 0;

    function generateVmId(): string {
        return `vm-${nextVmId++}-${Date.now().toString(36)}`;
    }

    function getVMState(vm: VMInstance): V86VMState {
        const state = vms.get(vm.id);
        if (state === undefined) {
            throw new VMBootError(`VM '${vm.id}' not found or has been destroyed`, vm.id);
        }
        return state;
    }
    const backend: VMBackend = {
        async boot(config: VMBootConfig): Promise<VMInstance> {
            const vmId = generateVmId();
            const memoryMB = clampMemory(config.memoryMB);

            // Build v86 options
            const options: V86Options = {
                wasm_path: V86_WASM_URL,
                memory_size: memoryMB * 1024 * 1024,
                vga_memory_size: config.enableVGA ? 8 * 1024 * 1024 : 2 * 1024 * 1024,
                autostart: true,

                // SECURITY: No network relay. Frames go through our fabric.
                // network_relay_url is intentionally omitted.

                // SECURITY: No screen/serial containers — we handle I/O ourselves.
                screen_container: null,
                serial_container: null,

                // BIOS
                bios: { url: config.biosUrl },
                vga_bios: { url: config.vgaBiosUrl },

                // Disk image — async loading via HTTP range requests
                hda: {
                    url: config.imageUrl,
                    async: true,
                },

                // Disable keyboard/mouse — all input goes through serial
                disable_keyboard: true,
                disable_mouse: true,

                // ACPI for clean shutdown
                acpi: true,
            };

            // Handle CD-ROM boot
            if (config.bootFromCdrom === true) {
                delete options.hda;
                options.cdrom = { url: config.imageUrl };
                options.boot_order = 0x132; // CD first
            }

            // Create the emulator
            let emulator: V86;
            try {
                emulator = new V86(options);
            } catch (error: unknown) {
                throw new VMBootError(
                    `Failed to create v86 emulator: ${error instanceof Error ? error.message : String(error)}`,
                    vmId,
                    error instanceof Error ? error : undefined,
                );
            }

            // Set up internal state
            const frameHandlers = new Set<(frame: Uint8Array) => void>();
            const outputHandlers = new Set<(byte: number) => void>();

            const vmState: V86VMState = {
                emulator,
                config,
                state: 'booting',
                frameHandlers,
                outputHandlers,
            };

            vms.set(vmId, vmState);

            // Wire up network frame output
            emulator.add_listener('net0-send', (data: unknown) => {
                // v86 emits frames as Uint8Array
                const frame = data instanceof Uint8Array
                    ? data
                    : new Uint8Array(data as ArrayBuffer);

                for (const handler of frameHandlers) {
                    try {
                        handler(frame);
                    } catch {
                        // Handler errors must not crash the VM
                    }
                }
            });

            // Wire up serial output
            emulator.add_listener('serial0-output-byte', (byte: unknown) => {
                const b = typeof byte === 'number' ? byte : Number(byte);
                for (const handler of outputHandlers) {
                    try {
                        handler(b);
                    } catch {
                        // Handler errors must not crash the VM
                    }
                }
            });

            // Wait for boot
            try {
                await waitForEvent(emulator, 'emulator-started', BOOT_TIMEOUT_MS, vmId);
                vmState.state = 'running';
            } catch (error: unknown) {
                vmState.state = 'error';
                throw error instanceof VMBootError
                    ? error
                    : new VMBootError(
                        `Boot failed: ${error instanceof Error ? error.message : String(error)}`,
                        vmId,
                        error instanceof Error ? error : undefined,
                    );
            }

            const instance: VMInstance = {
                id: vmId,
                config,
                state: 'running',
            };

            return instance;
        },

        attachTerminal(vm: VMInstance): TerminalIO {
            const state = getVMState(vm);

            const io: TerminalIO = {
                sendToVM(data: string | Uint8Array): void {
                    if (typeof data === 'string') {
                        // Send each character individually to serial0
                        for (let i = 0; i < data.length; i++) {
                            state.emulator.bus.send('serial0-input', data.charCodeAt(i));
                        }
                    } else {
                        for (let i = 0; i < data.length; i++) {
                            const byte = data[i];
                            if (byte !== undefined) {
                                state.emulator.bus.send('serial0-input', byte);
                            }
                        }
                    }
                },

                onOutput(handler: (byte: number) => void): Unsubscribe {
                    state.outputHandlers.add(handler);
                    let unsubscribed = false;

                    return () => {
                        if (unsubscribed) return;
                        unsubscribed = true;
                        state.outputHandlers.delete(handler);
                    };
                },
            };

            return io;
        },

        sendFrame(vm: VMInstance, frame: Uint8Array): void {
            const state = getVMState(vm);
            // Inject frame into guest NIC
            state.emulator.bus.send('net0-receive', frame);
        },

        onFrame(vm: VMInstance, handler: (frame: Uint8Array) => void): Unsubscribe {
            const state = getVMState(vm);
            state.frameHandlers.add(handler);

            let unsubscribed = false;
            return () => {
                if (unsubscribed) return;
                unsubscribed = true;
                state.frameHandlers.delete(handler);
            };
        },

        async applyOverlay(vm: VMInstance, overlay: FilesystemOverlay): Promise<void> {
            const state = getVMState(vm);

            // Use v86's 9p filesystem to write files into the guest
            for (const [path, file] of overlay.files) {
                const content = typeof file.content === 'string'
                    ? new TextEncoder().encode(file.content)
                    : file.content;

                try {
                    await state.emulator.create_file(path, content);
                } catch (error: unknown) {
                    // Log but continue — partial overlay is better than none
                    console.error(
                        `[v86Backend] Failed to write overlay file '${path}':`,
                        error instanceof Error ? error.message : String(error),
                    );
                }
            }

            // Set permissions and ownership via serial commands
            for (const [path, file] of overlay.files) {
                if (file.mode !== undefined) {
                    const octal = file.mode.toString(8);
                    state.emulator.serial0_send(`chmod ${octal} ${path}\n`);
                }
                if (file.owner !== undefined) {
                    const group = file.owner;
                    state.emulator.serial0_send(`chown ${file.owner}:${group} ${path}\n`);
                }
            }
        },

        async snapshot(vm: VMInstance): Promise<VMSnapshot> {
            const state = getVMState(vm);

            try {
                const data = await state.emulator.save_state();
                return {
                    vmId: vm.id,
                    timestamp: Date.now(),
                    data,
                };
            } catch (error: unknown) {
                throw new VMSnapshotError(
                    `Failed to save snapshot: ${error instanceof Error ? error.message : String(error)}`,
                    vm.id,
                    error instanceof Error ? error : undefined,
                );
            }
        },

        async restore(vm: VMInstance, snapshot: VMSnapshot): Promise<void> {
            const state = getVMState(vm);

            try {
                await state.emulator.restore_state(snapshot.data);
            } catch (error: unknown) {
                throw new VMSnapshotError(
                    `Failed to restore snapshot: ${error instanceof Error ? error.message : String(error)}`,
                    vm.id,
                    error instanceof Error ? error : undefined,
                );
            }
        },

        async reset(vm: VMInstance): Promise<void> {
            const state = getVMState(vm);
            state.emulator.restart();
            state.state = 'booting';

            try {
                await waitForEvent(state.emulator, 'emulator-started', BOOT_TIMEOUT_MS, vm.id);
                state.state = 'running';
            } catch {
                state.state = 'error';
            }
        },

        destroy(vm: VMInstance): void {
            const state = vms.get(vm.id);
            if (state === undefined) return; // Already destroyed — idempotent

            try {
                state.emulator.destroy();
            } catch {
                // Best-effort cleanup
            }

            state.frameHandlers.clear();
            state.outputHandlers.clear();
            state.state = 'stopped';
            vms.delete(vm.id);
        },
    };

    return backend;
}
