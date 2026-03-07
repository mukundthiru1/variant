/**
 * VARIANT — Network Topology Engine Types
 *
 * Models network segments, hosts, routes, and connectivity
 * for simulation scenarios. Answers reachability queries,
 * computes shortest paths, and tracks network state changes.
 *
 * FEATURES:
 * - Host registration with interface/IP configuration
 * - Subnet/segment modeling
 * - Route table management
 * - Reachability queries (can host A reach host B on port P?)
 * - Shortest path computation
 * - Firewall rule integration (block/allow between segments)
 * - Network state snapshots
 *
 * SWAPPABILITY: Implements TopologyEngine. Replace this file.
 */

// ── Hosts ───────────────────────────────────────────────────────

/** A network interface on a host. */
export interface NetworkInterface {
    /** Interface name (e.g., 'eth0', 'wlan0'). */
    readonly name: string;
    /** IP address. */
    readonly ip: string;
    /** Subnet mask (CIDR notation, e.g., '24'). */
    readonly cidr: number;
    /** Segment this interface is connected to. */
    readonly segmentId: string;
    /** Whether the interface is up. */
    readonly up: boolean;
}

/** A host in the network topology. */
export interface TopologyHost {
    /** Unique host ID (typically machine name). */
    readonly id: string;
    /** Display name. */
    readonly name: string;
    /** Host type. */
    readonly type: 'server' | 'workstation' | 'router' | 'switch' | 'firewall' | 'iot' | 'other';
    /** Network interfaces. */
    readonly interfaces: readonly NetworkInterface[];
    /** Open ports/services. */
    readonly openPorts: readonly OpenPort[];
}

/** An open port on a host. */
export interface OpenPort {
    /** Port number. */
    readonly port: number;
    /** Protocol. */
    readonly protocol: 'tcp' | 'udp';
    /** Service name (e.g., 'ssh', 'http'). */
    readonly service: string;
}

// ── Segments ────────────────────────────────────────────────────

/** A network segment (subnet, VLAN, etc.). */
export interface NetworkSegment {
    /** Unique segment ID. */
    readonly id: string;
    /** Display name. */
    readonly name: string;
    /** CIDR notation (e.g., '10.0.1.0/24'). */
    readonly cidr: string;
    /** Segment type. */
    readonly type: 'lan' | 'wan' | 'dmz' | 'vpn' | 'management' | 'guest';
}

// ── Routes ──────────────────────────────────────────────────────

/** A link between two segments (routing/connectivity). */
export interface SegmentLink {
    /** Source segment ID. */
    readonly from: string;
    /** Destination segment ID. */
    readonly to: string;
    /** Whether traffic is allowed (false = blocked by firewall). */
    readonly allowed: boolean;
    /** Allowed ports (empty = all). */
    readonly allowedPorts: readonly number[];
    /** Latency in simulated ms. */
    readonly latency: number;
}

// ── Reachability ────────────────────────────────────────────────

/** Result of a reachability query. */
export interface ReachabilityResult {
    /** Whether the target is reachable. */
    readonly reachable: boolean;
    /** The path of segment IDs from source to target. */
    readonly path: readonly string[];
    /** Total latency along the path. */
    readonly totalLatency: number;
    /** Reason for unreachability (if not reachable). */
    readonly reason?: string;
}

// ── Engine ──────────────────────────────────────────────────────

/** The network topology engine. */
export interface TopologyEngine {
    // ── Segments ────────────────────────────────────────────────

    /** Add a network segment. */
    addSegment(segment: NetworkSegment): void;

    /** Get a segment by ID. */
    getSegment(id: string): NetworkSegment | null;

    /** List all segments. */
    listSegments(): readonly NetworkSegment[];

    // ── Hosts ───────────────────────────────────────────────────

    /** Add a host to the topology. */
    addHost(host: TopologyHost): void;

    /** Get a host by ID. */
    getHost(id: string): TopologyHost | null;

    /** List all hosts. */
    listHosts(): readonly TopologyHost[];

    /** List hosts in a specific segment. */
    listHostsInSegment(segmentId: string): readonly TopologyHost[];

    // ── Links ───────────────────────────────────────────────────

    /** Add a link between two segments. */
    addLink(link: SegmentLink): void;

    /** List all links. */
    listLinks(): readonly SegmentLink[];

    // ── Queries ─────────────────────────────────────────────────

    /** Check if host A can reach host B (optionally on a specific port). */
    canReach(fromHostId: string, toHostId: string, port?: number): ReachabilityResult;

    /** Get all hosts reachable from a given host. */
    getReachableHosts(fromHostId: string): readonly string[];

    /** Get hosts that have a specific port open. */
    findHostsByPort(port: number, protocol?: 'tcp' | 'udp'): readonly TopologyHost[];

    /** Get hosts by IP address. */
    findHostByIP(ip: string): TopologyHost | null;

    // ── Reset ───────────────────────────────────────────────────

    /** Clear all state. */
    clear(): void;
}
