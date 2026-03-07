/**
 * VARIANT — v86 Type Declarations
 *
 * v86 is loaded as a global script, not an npm package.
 * These types describe the subset of its API we use.
 *
 * Source: https://github.com/nickelc/nickelc.github.io/tree/master/v86
 * License: BSD-2-Clause
 *
 * SECURITY: v86 runs x86 code in a WebAssembly sandbox.
 * The guest OS has NO access to:
 *   - The host filesystem
 *   - The real network (we intercept all NIC frames)
 *   - Other browser tabs or windows
 *   - Any Web API except what v86 explicitly exposes
 */

declare class V86 {
    constructor(options: V86Options);

    /**
     * Add an event listener.
     *
     * Known events:
     *   'serial0-output-byte' — byte from serial port 0 (terminal output)
     *   'net0-send'           — Ethernet frame from emulated NIC
     *   'emulator-ready'      — emulator has finished initial setup
     *   'emulator-started'    — CPU is running
     *   'emulator-stopped'    — CPU has stopped
     */
    add_listener(event: string, handler: (...args: unknown[]) => void): void;

    /**
     * Remove an event listener.
     */
    remove_listener(event: string, handler: (...args: unknown[]) => void): void;

    /**
     * Internal bus for sending data to the emulator.
     *
     * Known messages:
     *   'serial0-input' — send a character to serial port 0
     *   'net0-receive'  — inject an Ethernet frame into the NIC
     */
    bus: {
        send(event: string, data: unknown): void;
        register(event: string, handler: (...args: unknown[]) => void, context?: unknown): void;
    };

    /** Run the emulator. */
    run(): void;

    /** Stop the emulator. */
    stop(): void;

    /** Restart the emulator. */
    restart(): void;

    /** Destroy the emulator and free all resources. */
    destroy(): void;

    /** Save the emulator state. Returns a promise resolving to an ArrayBuffer. */
    save_state(): Promise<ArrayBuffer>;

    /** Restore a previously saved state. */
    restore_state(state: ArrayBuffer): Promise<void>;

    /** Check if the emulator is running. */
    is_running(): boolean;

    /**
     * Serial port send helpers.
     * Sends a string to serial port 0.
     */
    serial0_send(data: string): void;

    /**
     * Create a file in the 9p filesystem (if configured).
     */
    create_file(path: string, data: Uint8Array): Promise<void>;

    /**
     * Read a file from the 9p filesystem.
     */
    read_file(path: string): Promise<Uint8Array>;
}

interface V86Options {
    /** Path to v86.wasm. Required. */
    wasm_path: string;

    /** Path to v86 worker file. Optional — falls back to inline. */
    wasm_fn?: unknown;

    /** RAM size in bytes. */
    memory_size: number;

    /** VGA memory size in bytes. */
    vga_memory_size: number;

    /** BIOS image. */
    bios?: V86ImageSource;

    /** VGA BIOS image. */
    vga_bios?: V86ImageSource;

    /** Hard drive A image. */
    hda?: V86ImageSource;

    /** Hard drive B image. */
    hdb?: V86ImageSource;

    /** CD-ROM image. */
    cdrom?: V86ImageSource;

    /** Floppy disk image. */
    fda?: V86ImageSource;

    /** Initial filesystem state for 9p. */
    initial_state?: V86ImageSource;

    /** 9p root filesystem URL (for web-based root fs). */
    filesystem?: V86FileSystem;

    /** Whether to start the emulator automatically. */
    autostart: boolean;

    /** Network relay URL (we don't use this — we intercept frames). */
    network_relay_url?: string;

    /** DOM element for VGA screen rendering. Null for headless. */
    screen_container?: HTMLElement | null;

    /** DOM element for serial output. We handle serial ourselves. */
    serial_container?: HTMLElement | null;

    /** Whether to disable keyboard input. */
    disable_keyboard?: boolean;

    /** Whether to disable mouse input. */
    disable_mouse?: boolean;

    /** ACPI support. */
    acpi?: boolean;

    /** Boot order. */
    boot_order?: number;

    /** MAC address for the emulated NIC. */
    mac_address_translation?: boolean;

    /** Preserve MAC addresses in frames. */
    preserve_mac_from_state_image?: boolean;

    /** Kernel command line for direct boot. */
    cmdline?: string;

    /** Kernel image for direct boot. */
    bzimage?: V86ImageSource;

    /** Initial ramdisk for direct boot. */
    initrd?: V86ImageSource;

    /** UART1 (serial port 1). */
    uart1?: boolean;
    uart2?: boolean;
    uart3?: boolean;
}

interface V86ImageSource {
    /** URL to fetch the image from. Supports range requests for async loading. */
    url?: string;

    /** ArrayBuffer containing the image data. */
    buffer?: ArrayBuffer;

    /** Use async loading (range requests). Requires server support. */
    async?: boolean;

    /** Size hint for async images. */
    size?: number;
}

interface V86FileSystem {
    /** Base URL for the 9p filesystem. */
    basefs?: string;

    /** Base URL for individual file fetching. */
    baseurl?: string;
}
