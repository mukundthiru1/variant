/**
 * VARIANT — Network Fabric Contract
 *
 * The air-gapped network that connects all VMs. This is the most
 * security-critical component in the system. It enforces:
 *
 * 1. No frame can reach the real internet
 * 2. VMs can only communicate with VMs on the same network segment
 * 3. DNS resolves only VARIANT-internal names
 * 4. Firewall rules from WorldSpec are enforced at the frame level
 *
 * SECURITY INVARIANT: The fabric has no method, flag, config, or
 * override that allows traffic to reach the real internet. This is
 * enforced by construction — the fabric operates on in-memory
 * Ethernet frames and has no access to any real network interface.
 *
 * The ONE controlled exception: the VARIANT Package Mirror proxies
 * curated package requests to cdn.santh.io. This is mediated by
 * the fabric's mirror proxy, not by the VMs themselves.
 */

import type { Unsubscribe } from '../events';

// ── Network topology ───────────────────────────────────────────

/**
 * Defines how VMs are wired together.
 * Segments are isolated LANs. Edges define which segments can talk.
 */
export interface NetworkTopology {
    /** Named network segments (e.g., 'corporate', 'dmz', 'internet'). */
    readonly segments: readonly NetworkSegment[];

    /** Routing rules between segments. */
    readonly routes: readonly NetworkRoute[];

    /** Firewall rules (applied per-frame). */
    readonly firewallRules: readonly FirewallRule[];
}

export interface NetworkSegment {
    readonly id: string;
    readonly subnet: string;       // e.g., '10.0.1.0/24'
    readonly gateway?: string;     // e.g., '10.0.1.1'
}

export interface NetworkRoute {
    readonly from: string;         // segment ID
    readonly to: string;           // segment ID
    readonly allowedPorts?: readonly number[];  // empty = all ports
    readonly protocol?: 'tcp' | 'udp' | 'any';
}

// ── Firewall ───────────────────────────────────────────────────

export interface FirewallRule {
    readonly action: 'allow' | 'drop' | 'log';
    readonly direction: 'inbound' | 'outbound' | 'both';
    readonly sourceIP?: string;    // CIDR or specific IP
    readonly destIP?: string;
    readonly sourcePort?: number;
    readonly destPort?: number;
    readonly protocol?: 'tcp' | 'udp' | 'icmp' | 'any';
    readonly priority: number;     // lower = higher priority
}

// ── DNS ────────────────────────────────────────────────────────

export interface DNSRecord {
    readonly domain: string;
    readonly ip: string;
    readonly type: 'A' | 'AAAA' | 'CNAME' | 'MX' | 'TXT';
    readonly ttl: number;
}

export interface DNSResponse {
    readonly query: string;
    readonly answers: readonly DNSRecord[];
    readonly authoritative: boolean;
    /** NXDOMAIN if no records found. */
    readonly rcode: 'NOERROR' | 'NXDOMAIN' | 'SERVFAIL' | 'REFUSED';
}

// ── NIC handle ─────────────────────────────────────────────────

/** Represents a VM's network interface connected to a segment. */
export interface NICHandle {
    readonly vmId: string;
    readonly mac: string;
    readonly segment: string;
    readonly ip: string;

    /** Disconnect this NIC from the network. */
    disconnect(): void;
}

// ── Traffic logging ────────────────────────────────────────────

export type FrameDirection = 'inbound' | 'outbound';

export interface TrafficEntry {
    readonly timestamp: number;
    readonly sourceMAC: string;
    readonly destMAC: string;
    readonly sourceIP: string;
    readonly destIP: string;
    readonly protocol: string;
    readonly port: number;
    readonly size: number;
    readonly direction: FrameDirection;
    readonly segment: string;
}

export interface FabricStats {
    readonly totalFrames: number;
    readonly droppedFrames: number;
    readonly bytesRouted: number;
    readonly dnsQueries: number;
    readonly activeConnections: number;
}

// ── VARIANT Internet ───────────────────────────────────────────

/**
 * Handler for simulated external services.
 * Receives an HTTP request (reconstructed from frames) and returns a response.
 *
 * SECURITY: These handlers run in the main thread JS context.
 * They have no access to the real network, real filesystem,
 * or any other browser API. They receive bytes and return bytes.
 */
export interface ExternalServiceHandler {
    readonly domain: string;
    readonly description: string;

    /**
     * Handle an HTTP request to this simulated service.
     * Returns raw HTTP response bytes.
     */
    handleRequest(request: ExternalRequest): ExternalResponse;
}

export interface ExternalRequest {
    readonly method: string;
    readonly path: string;
    readonly headers: ReadonlyMap<string, string>;
    readonly body: Uint8Array | null;
}

export interface ExternalResponse {
    readonly status: number;
    readonly headers: ReadonlyMap<string, string>;
    readonly body: Uint8Array;
}

// ── Package mirror ─────────────────────────────────────────────

/**
 * Configuration for the CDN-backed package mirror.
 * The fabric proxies requests from VMs to our CDN.
 *
 * SECURITY: Only requests matching the configured CDN base URL
 * are proxied. The fabric validates:
 *   - Domain matches mirror.variant.internal (or ecosystem variant)
 *   - Path matches expected package path patterns
 *   - Response is a valid package file
 *   - No redirects to external URLs are followed
 */
export interface PackageMirrorConfig {
    /** CDN base URL for packages. Must be HTTPS. */
    readonly cdnBaseUrl: string;

    /** Supported ecosystem mirrors. */
    readonly ecosystems: readonly PackageEcosystem[];
}

export interface PackageEcosystem {
    /** Internal domain the VM resolves (e.g., 'mirror.variant.internal'). */
    readonly domain: string;

    /** Package manager type (affects path validation). */
    readonly type: 'apk' | 'pip' | 'npm' | 'apt';

    /** CDN path prefix (e.g., 'packages/alpine/'). */
    readonly cdnPrefix: string;
}

// ── Fabric contract ────────────────────────────────────────────

/**
 * The air-gapped network fabric.
 *
 * Implementations must guarantee:
 * 1. No frame ever reaches a real network interface
 * 2. DNS only resolves VARIANT-internal names
 * 3. Firewall rules are checked on every frame
 * 4. Traffic logging does not leak to external systems
 * 5. destroy() fully releases all resources
 */
export interface NetworkFabric {
    /**
     * Initialize the fabric with a network topology.
     * Creates segments, configures routing, loads firewall rules.
     */
    init(topology: NetworkTopology, mirror?: PackageMirrorConfig): void;

    /**
     * Connect a VM's NIC to a network segment.
     * Returns a handle for sending/receiving frames.
     */
    connect(
        vmId: string,
        segment: string,
        mac: string,
        ip: string,
    ): NICHandle;

    /**
     * Register a DNS record in the air-gapped resolver.
     */
    addDNSRecord(record: DNSRecord): void;

    /**
     * Register a simulated external service on the VARIANT Internet.
     */
    registerExternal(handler: ExternalServiceHandler): void;

    /**
     * Tap a network segment for traffic inspection.
     * Used by the traffic inspector lens and by IDS modules.
     */
    tap(
        segment: string,
        handler: (entry: TrafficEntry, frame: Uint8Array) => void,
    ): Unsubscribe;

    /**
     * Route a frame from a VM into the fabric.
     * The fabric parses headers, applies firewall rules,
     * resolves DNS, and delivers to the destination VM.
     */
    routeFrame(sourceVmId: string, frame: Uint8Array): void;

    /**
     * Subscribe to frames destined for a specific VM.
     */
    onFrameForVM(
        vmId: string,
        handler: (frame: Uint8Array) => void,
    ): Unsubscribe;

    // ── Observability ────────────────────────────────────────────

    /** Get all logged traffic entries. */
    getTrafficLog(): readonly TrafficEntry[];

    /** Get aggregate statistics. */
    getStats(): FabricStats;

    /**
     * Look up a registered external service handler by domain.
     * Used by the browser lens to route HTTP requests through
     * the same handlers that serve traffic to VMs.
     */
    getExternalHandler(domain: string): ExternalServiceHandler | undefined;

    /**
     * Get all registered external service domains.
     * Used by the browser lens to show available services.
     */
    getExternalDomains(): readonly string[];

    // ── Lifecycle ────────────────────────────────────────────────

    /** Shut down the fabric and release all resources. */
    destroy(): void;
}

// ── Errors ─────────────────────────────────────────────────────

export class FabricRoutingError extends Error {
    override readonly name = 'FabricRoutingError' as const;
    constructor(
        message: string,
        readonly sourceVM: string,
        readonly frame: Uint8Array,
    ) {
        super(message);
    }
}

export class FabricDNSError extends Error {
    override readonly name = 'FabricDNSError' as const;
    constructor(
        message: string,
        readonly query: string,
    ) {
        super(message);
    }
}
