/**
 * VARIANT — Protocol Handler Contract
 *
 * Interface for TCP/IP-level protocol handlers used by Simulacrum+.
 * While regular ServiceHandlers work at the request/response level,
 * ProtocolHandlers work at the raw TCP stream level — they speak
 * real wire protocols (SSH, MySQL, SMTP, DNS).
 *
 * When tcpip.js (lwIP) receives a TCP connection on a registered port,
 * it passes the raw socket to the appropriate ProtocolHandler.
 * The handler speaks the real protocol, enabling real tools (ssh, mysql,
 * nmap) to interact with the Simulacrum as if it were a real server.
 *
 * EXTENSIBILITY: Adding a new protocol = implementing ProtocolHandler
 * and registering it with the ProtocolHandlerRegistry. The Simulacrum+
 * backend discovers handlers by port number. Zero core changes.
 *
 * SECURITY: All protocol handlers run in browser JavaScript.
 * They cannot access the real network. They speak protocols
 * into the lwIP stack, which routes through the fabric.
 */

import type { VirtualFilesystem } from '../vfs/types';
import type { ScriptedShell } from '../shell/types';

// ── Protocol Handler ───────────────────────────────────────────

/**
 * A TCP-level protocol handler for Simulacrum+.
 * Handles raw TCP streams for a specific protocol.
 */
export interface ProtocolHandler {
    /** Protocol name (e.g., 'ssh', 'mysql', 'smtp', 'dns', 'ftp'). */
    readonly name: string;

    /** Default port for this protocol. */
    readonly defaultPort: number;

    /**
     * Handle a new TCP connection.
     * Receives a stream handle for reading/writing raw bytes.
     * The handler must speak the protocol correctly — real tools
     * are on the other end.
     *
     * Returns a cleanup function called when the connection closes.
     */
    handleConnection(conn: ProtocolConnection, ctx: ProtocolContext): (() => void) | void;
}

/**
 * A raw TCP connection handle.
 * Bidirectional byte stream — the protocol handler reads and writes here.
 */
export interface ProtocolConnection {
    /** Unique connection ID. */
    readonly id: string;

    /** Remote IP address. */
    readonly remoteIP: string;

    /** Remote port. */
    readonly remotePort: number;

    /** Local port the connection was accepted on. */
    readonly localPort: number;

    /** Write raw bytes to the connection. */
    write(data: Uint8Array | string): void;

    /** Subscribe to incoming bytes. */
    onData(handler: (data: Uint8Array) => void): () => void;

    /** Subscribe to connection close. */
    onClose(handler: () => void): () => void;

    /** Close the connection from our side. */
    close(): void;
}

/**
 * Context provided to protocol handlers.
 * Access to VFS, shell, credentials, and event emission.
 */
export interface ProtocolContext {
    readonly vfs: VirtualFilesystem;
    readonly shell: ScriptedShell;
    readonly hostname: string;
    readonly ip: string;

    /** Emit an event to the simulation. */
    emit(event: ProtocolEvent): void;

    /**
     * Validate a credential attempt.
     * Returns true if the username/password is valid for this machine/service.
     */
    validateCredential(service: string, username: string, password: string): boolean;

    /**
     * Get a configuration value for this protocol handler.
     * Reads from ServiceConfig.config in the WorldSpec.
     */
    getConfig<T>(key: string, defaultValue: T): T;
}

/**
 * Events emitted by protocol handlers.
 */
export type ProtocolEvent =
    | { readonly type: 'proto:connection-open'; readonly protocol: string; readonly remoteIP: string; readonly remotePort: number }
    | { readonly type: 'proto:connection-close'; readonly protocol: string; readonly remoteIP: string; readonly remotePort: number }
    | { readonly type: 'proto:auth-attempt'; readonly protocol: string; readonly username: string; readonly success: boolean; readonly remoteIP: string }
    | { readonly type: 'proto:command'; readonly protocol: string; readonly command: string; readonly user: string }
    | { readonly type: 'proto:data-transfer'; readonly protocol: string; readonly direction: 'in' | 'out'; readonly bytes: number }
    | { readonly type: 'proto:custom'; readonly protocol: string; readonly action: string; readonly details: Readonly<Record<string, unknown>> };

// ── Protocol Handler Registry ──────────────────────────────────

/**
 * Registry for protocol handlers.
 * The Simulacrum+ backend uses this to route TCP connections
 * to the correct handler based on port number.
 *
 * EXTENSIBILITY: Third-party packages register new protocol handlers.
 * Adding SSH support = implementing ProtocolHandler for SSH and registering it.
 */
export interface ProtocolHandlerRegistry {
    /**
     * Register a protocol handler for a specific port.
     * Throws if a handler is already registered for this port.
     */
    register(handler: ProtocolHandler, port?: number): void;

    /**
     * Get the handler for a given port.
     * Returns null if no handler is registered.
     */
    getHandler(port: number): ProtocolHandler | null;

    /**
     * Get all registered handlers.
     */
    getAll(): readonly ProtocolHandler[];

    /**
     * Get all registered port mappings.
     */
    getPortMap(): ReadonlyMap<number, ProtocolHandler>;

    /**
     * Check if a port has a registered handler.
     */
    hasHandler(port: number): boolean;
}

/**
 * Create a new protocol handler registry.
 */
export function createProtocolHandlerRegistry(): ProtocolHandlerRegistry {
    const handlers = new Map<number, ProtocolHandler>();
    const allHandlers = new Map<string, ProtocolHandler>();

    return {
        register(handler: ProtocolHandler, port?: number): void {
            const targetPort = port ?? handler.defaultPort;

            if (handlers.has(targetPort)) {
                const existing = handlers.get(targetPort);
                throw new Error(
                    `ProtocolHandlerRegistry: port ${targetPort} is already registered ` +
                    `for protocol '${existing?.name}'. Cannot register '${handler.name}'.`,
                );
            }

            handlers.set(targetPort, handler);
            allHandlers.set(handler.name, handler);
        },

        getHandler(port: number): ProtocolHandler | null {
            return handlers.get(port) ?? null;
        },

        getAll(): readonly ProtocolHandler[] {
            return Object.freeze(Array.from(allHandlers.values()));
        },

        getPortMap(): ReadonlyMap<number, ProtocolHandler> {
            return handlers;
        },

        hasHandler(port: number): boolean {
            return handlers.has(port);
        },
    };
}
