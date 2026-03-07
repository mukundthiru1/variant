/**
 * VARIANT — VPN/Tunnel Simulation Types
 *
 * Simulates network tunneling:
 * - VPN connections (IPSec, OpenVPN, WireGuard)
 * - SSH tunnels (local/remote/dynamic forwarding)
 * - SOCKS proxies, HTTP CONNECT
 * - Tor circuits
 * - Tunnel detection and analysis
 *
 * EXTENSIBILITY: Custom tunnel types via open union.
 * SWAPPABILITY: Implements TunnelEngine interface.
 */

// ── Tunnel Types ─────────────────────────────────────────

export type TunnelType =
    | 'ipsec' | 'openvpn' | 'wireguard'
    | 'ssh_local' | 'ssh_remote' | 'ssh_dynamic'
    | 'socks4' | 'socks5' | 'http_connect'
    | 'gre' | 'ipip' | 'vxlan'
    | 'tor' | 'i2p'
    | 'dns_tunnel' | 'icmp_tunnel'
    | (string & {});

export type TunnelStatus = 'connecting' | 'established' | 'degraded' | 'disconnected';

// ── Tunnel ───────────────────────────────────────────────

export interface Tunnel {
    readonly id: string;
    readonly type: TunnelType;
    readonly status: TunnelStatus;
    readonly sourceHost: string;
    readonly sourcePort: number;
    readonly destHost: string;
    readonly destPort: number;
    readonly encrypted: boolean;
    readonly cipher?: string;
    readonly createdAt: number;
    readonly bytesIn: number;
    readonly bytesOut: number;
    readonly latencyMs: number;
    readonly hops: readonly TunnelHop[];
}

export interface TunnelHop {
    readonly host: string;
    readonly ip: string;
    readonly latencyMs: number;
    readonly encrypted: boolean;
}

// ── Tunnel Config ────────────────────────────────────────

export interface TunnelConfig {
    readonly type: TunnelType;
    readonly sourceHost: string;
    readonly sourcePort: number;
    readonly destHost: string;
    readonly destPort: number;
    readonly encrypted?: boolean;
    readonly cipher?: string;
    readonly hops?: readonly TunnelHop[];
}

// ── Tunnel Detection ─────────────────────────────────────

export interface TunnelDetection {
    readonly tunnelId: string;
    readonly type: TunnelDetectionType;
    readonly confidence: number;
    readonly description: string;
    readonly indicators: readonly string[];
    readonly mitre: string;
}

export type TunnelDetectionType =
    | 'known_vpn_protocol' | 'encrypted_tunnel' | 'protocol_anomaly'
    | 'dns_tunnel' | 'icmp_tunnel' | 'tor_exit_node'
    | 'port_forwarding' | 'proxy_detected'
    | (string & {});

// ── Tunnel Engine Interface ──────────────────────────────

export interface TunnelEngine {
    /** Create a tunnel. */
    createTunnel(config: TunnelConfig): Tunnel;
    /** Get tunnel by ID. */
    getTunnel(id: string): Tunnel | null;
    /** List all tunnels. */
    listTunnels(): readonly Tunnel[];
    /** List active tunnels. */
    listActiveTunnels(): readonly Tunnel[];
    /** Close a tunnel. */
    closeTunnel(id: string): boolean;
    /** Transfer data through a tunnel. */
    transferData(tunnelId: string, bytesIn: number, bytesOut: number): boolean;
    /** Detect tunnels from network traffic patterns. */
    detectTunnels(): readonly TunnelDetection[];
    /** Get stats. */
    getStats(): TunnelStats;
}

export interface TunnelStats {
    readonly totalTunnels: number;
    readonly activeTunnels: number;
    readonly closedTunnels: number;
    readonly totalBytesIn: number;
    readonly totalBytesOut: number;
    readonly encryptedTunnels: number;
    readonly tunnelsByType: Readonly<Record<string, number>>;
}
