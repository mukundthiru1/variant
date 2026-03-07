/**
 * VARIANT — Service Simulacrum Contract
 *
 * Interface for protocol-level service handlers that run
 * inside Simulacra. These handle HTTP, SSH, DNS, etc.
 * without real TCP stacks — they parse frames directly.
 *
 * DESIGN: Zero dependencies on core/. Depends only on
 * VFS and shell types. Each service is a pure plugin:
 *   - Registered by name
 *   - Receives parsed requests
 *   - Returns responses
 *   - Can read/write the VFS
 *   - Can push events (via callback)
 *
 * This is the contract. Implementations (HTTP service,
 * SSH service, DNS service, etc.) live separately.
 * Replace any of them in 20 years.
 */

import type { VirtualFilesystem } from '../vfs/types';
import type { ScriptedShell } from '../shell/types';

// ── Service interface ──────────────────────────────────────────

/**
 * A service handler for a Simulacrum.
 * Each service binds to a port and protocol.
 */
export interface ServiceHandler {
    /** Service name (e.g., 'http', 'ssh', 'dns', 'smtp'). */
    readonly name: string;
    /** Port this service listens on. */
    readonly port: number;
    /** Protocol (tcp or udp). */
    readonly protocol: 'tcp' | 'udp';

    /**
     * Handle an incoming request.
     * Returns a response or null (drop the request).
     */
    handle(request: ServiceRequest, ctx: ServiceContext): ServiceResponse | null;

    /** Optional: called when the service is started. */
    start?(ctx: ServiceContext): void;

    /** Optional: called when the service is stopped. */
    stop?(): void;
}

// ── Request / Response ─────────────────────────────────────────

export interface ServiceRequest {
    /** Source IP address. */
    readonly sourceIP: string;
    /** Source port. */
    readonly sourcePort: number;
    /** Raw payload bytes (above TCP/UDP). */
    readonly payload: Uint8Array;
    /** Parsed payload as string (UTF-8). */
    readonly payloadText: string;
}

export interface ServiceResponse {
    /** Response payload bytes. */
    readonly payload: Uint8Array;
    /** Whether to close the connection after sending. */
    readonly close: boolean;
}

// ── Service context ────────────────────────────────────────────

/**
 * Context provided to service handlers.
 * Gives access to VFS, shell, and event emission.
 */
export interface ServiceContext {
    readonly vfs: VirtualFilesystem;
    readonly shell: ScriptedShell;
    readonly hostname: string;
    readonly ip: string;

    /** Emit an event to the simulation (e.g., for objective detection). */
    emit(event: ServiceEvent): void;
}

// ── Service events ─────────────────────────────────────────────

export type ServiceEvent =
    | HTTPRequestEvent
    | SSHLoginEvent
    | DNSQueryEvent
    | FileAccessEvent
    | CustomServiceEvent;

export interface HTTPRequestEvent {
    readonly type: 'http:request';
    readonly method: string;
    readonly path: string;
    readonly headers: ReadonlyMap<string, string>;
    readonly body: string;
    readonly sourceIP: string;
    readonly responseCode: number;
}

export interface SSHLoginEvent {
    readonly type: 'ssh:login';
    readonly username: string;
    readonly password: string;
    readonly sourceIP: string;
    readonly success: boolean;
}

export interface DNSQueryEvent {
    readonly type: 'dns:query';
    readonly domain: string;
    readonly queryType: string;
    readonly sourceIP: string;
    readonly result: string | null;
}

export interface FileAccessEvent {
    readonly type: 'file:access';
    readonly path: string;
    readonly action: 'read' | 'write' | 'exec';
    readonly user: string;
}

export interface CustomServiceEvent {
    readonly type: 'service:custom';
    readonly service: string;
    readonly action: string;
    readonly details: Record<string, unknown>;
}

// ── Service registry ───────────────────────────────────────────

/**
 * Registry for service handlers.
 * Simulacra use this to dispatch incoming traffic
 * to the correct service handler based on port.
 */
export interface ServiceRegistry {
    /** Register a service handler. */
    register(handler: ServiceHandler): void;

    /** Unregister a service handler by name. */
    unregister(name: string): void;

    /** Get the handler for a given port/protocol. */
    getHandler(port: number, protocol: 'tcp' | 'udp'): ServiceHandler | null;

    /** Get all registered handlers. */
    getAll(): readonly ServiceHandler[];

    /** Start all services. */
    startAll(ctx: ServiceContext): void;

    /** Stop all services. */
    stopAll(): void;
}

// ── Factory ────────────────────────────────────────────────────

export function createServiceRegistry(): ServiceRegistry {
    const handlers = new Map<string, ServiceHandler>();
    const portMap = new Map<string, ServiceHandler>();

    function portKey(port: number, proto: 'tcp' | 'udp'): string {
        return `${proto}:${port}`;
    }

    return {
        register(handler: ServiceHandler): void {
            handlers.set(handler.name, handler);
            portMap.set(portKey(handler.port, handler.protocol), handler);
        },

        unregister(name: string): void {
            const handler = handlers.get(name);
            if (handler !== undefined) {
                portMap.delete(portKey(handler.port, handler.protocol));
                handlers.delete(name);
            }
        },

        getHandler(port: number, protocol: 'tcp' | 'udp'): ServiceHandler | null {
            return portMap.get(portKey(port, protocol)) ?? null;
        },

        getAll(): readonly ServiceHandler[] {
            return [...handlers.values()];
        },

        startAll(ctx: ServiceContext): void {
            for (const handler of handlers.values()) {
                handler.start?.(ctx);
            }
        },

        stopAll(): void {
            for (const handler of handlers.values()) {
                handler.stop?.();
            }
        },
    };
}
