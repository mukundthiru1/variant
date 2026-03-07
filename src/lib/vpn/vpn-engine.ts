/**
 * VARIANT — VPN/Tunnel Engine
 *
 * Simulates network tunneling with:
 * - Multiple tunnel types (VPN, SSH, SOCKS, Tor, etc.)
 * - Data transfer tracking
 * - Tunnel detection heuristics
 * - Latency simulation
 *
 * All operations are synchronous and pure-data.
 */

import type {
    TunnelEngine,
    Tunnel,
    TunnelConfig,
    TunnelDetection,
} from './types';

// ── Helpers ───────────────────────────────────────────────

let tunnelCounter = 0;

function generateTunnelId(): string {
    return `tun-${++tunnelCounter}`;
}

const DEFAULT_LATENCY: Record<string, number> = {
    ipsec: 5, openvpn: 8, wireguard: 2,
    ssh_local: 3, ssh_remote: 3, ssh_dynamic: 5,
    socks4: 4, socks5: 4, http_connect: 6,
    gre: 2, ipip: 2, vxlan: 3,
    tor: 200, i2p: 500,
    dns_tunnel: 150, icmp_tunnel: 100,
};

const ENCRYPTED_BY_DEFAULT = new Set([
    'ipsec', 'openvpn', 'wireguard', 'ssh_local', 'ssh_remote', 'ssh_dynamic', 'tor', 'i2p',
]);

const TUNNEL_MITRE: Record<string, string> = {
    ipsec: 'T1572', openvpn: 'T1572', wireguard: 'T1572',
    ssh_local: 'T1572', ssh_remote: 'T1572', ssh_dynamic: 'T1572',
    socks4: 'T1090.001', socks5: 'T1090.001', http_connect: 'T1090.002',
    tor: 'T1090.003', i2p: 'T1090.003',
    dns_tunnel: 'T1071.004', icmp_tunnel: 'T1095',
    gre: 'T1572', ipip: 'T1572', vxlan: 'T1572',
};

// ── Factory ──────────────────────────────────────────────

export function createTunnelEngine(): TunnelEngine {
    const tunnels = new Map<string, Tunnel & { _status: string; _bytesIn: number; _bytesOut: number }>();

    function toTunnel(t: Tunnel & { _status: string; _bytesIn: number; _bytesOut: number }): Tunnel {
        const base = {
            id: t.id, type: t.type, status: t._status as Tunnel['status'],
            sourceHost: t.sourceHost, sourcePort: t.sourcePort,
            destHost: t.destHost, destPort: t.destPort,
            encrypted: t.encrypted,
            createdAt: t.createdAt, bytesIn: t._bytesIn, bytesOut: t._bytesOut,
            latencyMs: t.latencyMs, hops: t.hops,
        };
        return Object.freeze(
            t.cipher !== undefined ? { ...base, cipher: t.cipher } : base
        ) as Tunnel;
    }

    const engine: TunnelEngine = {
        createTunnel(config: TunnelConfig) {
            const id = generateTunnelId();
            const encrypted = config.encrypted ?? ENCRYPTED_BY_DEFAULT.has(config.type);
            const latency = DEFAULT_LATENCY[config.type] ?? 10;
            const hopLatency = (config.hops ?? []).reduce((sum, h) => sum + h.latencyMs, 0);

            const cipherValue = config.cipher ?? (encrypted ? 'AES-256-GCM' : undefined);
            const tunnelBase = {
                id,
                type: config.type,
                status: 'established' as const,
                sourceHost: config.sourceHost,
                sourcePort: config.sourcePort,
                destHost: config.destHost,
                destPort: config.destPort,
                encrypted,
                createdAt: Date.now(),
                bytesIn: 0,
                bytesOut: 0,
                latencyMs: latency + hopLatency,
                hops: Object.freeze(config.hops ?? []),
                _status: 'established',
                _bytesIn: 0,
                _bytesOut: 0,
            };
            const tunnel = cipherValue !== undefined
                ? { ...tunnelBase, cipher: cipherValue }
                : tunnelBase;
            const stored = tunnel as Tunnel & { _status: string; _bytesIn: number; _bytesOut: number };
            tunnels.set(id, stored);
            return toTunnel(stored);
        },

        getTunnel(id) {
            const t = tunnels.get(id);
            if (!t) return null;
            return toTunnel(t);
        },

        listTunnels() {
            return Object.freeze(Array.from(tunnels.values()).map(toTunnel));
        },

        listActiveTunnels() {
            return Object.freeze(
                Array.from(tunnels.values())
                    .filter(t => t._status === 'established' || t._status === 'degraded')
                    .map(toTunnel)
            );
        },

        closeTunnel(id) {
            const t = tunnels.get(id);
            if (!t || t._status === 'disconnected') return false;
            t._status = 'disconnected';
            return true;
        },

        transferData(tunnelId, bytesIn, bytesOut) {
            const t = tunnels.get(tunnelId);
            if (!t || t._status === 'disconnected') return false;
            t._bytesIn += bytesIn;
            t._bytesOut += bytesOut;
            return true;
        },

        detectTunnels() {
            const detections: TunnelDetection[] = [];

            for (const t of tunnels.values()) {
                if (t._status === 'disconnected') continue;

                const mitre = TUNNEL_MITRE[t.type] ?? 'T1572';

                // DNS tunnel detection
                if (t.type === 'dns_tunnel') {
                    detections.push(Object.freeze({
                        tunnelId: t.id,
                        type: 'dns_tunnel',
                        confidence: 0.85,
                        description: `DNS tunnel detected: ${t.sourceHost} → ${t.destHost}`,
                        indicators: Object.freeze([
                            'High volume DNS queries',
                            'Unusually long subdomain labels',
                            'High entropy in DNS query names',
                        ]),
                        mitre,
                    }));
                }

                // ICMP tunnel detection
                if (t.type === 'icmp_tunnel') {
                    detections.push(Object.freeze({
                        tunnelId: t.id,
                        type: 'icmp_tunnel',
                        confidence: 0.75,
                        description: `ICMP tunnel detected: ${t.sourceHost} → ${t.destHost}`,
                        indicators: Object.freeze([
                            'ICMP echo with large payloads',
                            'Consistent ICMP traffic pattern',
                        ]),
                        mitre,
                    }));
                }

                // Tor detection
                if (t.type === 'tor') {
                    detections.push(Object.freeze({
                        tunnelId: t.id,
                        type: 'tor_exit_node',
                        confidence: 0.95,
                        description: `Tor circuit detected from ${t.sourceHost}`,
                        indicators: Object.freeze([
                            'Connection to known Tor directory authority',
                            'TLS fingerprint matches Tor relay',
                            'Circuit-based multiplexing pattern',
                        ]),
                        mitre,
                    }));
                }

                // SSH tunnel detection (port forwarding)
                if (t.type === 'ssh_local' || t.type === 'ssh_remote' || t.type === 'ssh_dynamic') {
                    detections.push(Object.freeze({
                        tunnelId: t.id,
                        type: 'port_forwarding',
                        confidence: 0.60,
                        description: `SSH tunnel (${t.type}) detected: ${t.sourceHost}:${t.sourcePort} → ${t.destHost}:${t.destPort}`,
                        indicators: Object.freeze([
                            'Long-lived SSH session with data transfer',
                            'Traffic pattern inconsistent with interactive SSH',
                        ]),
                        mitre,
                    }));
                }

                // Encrypted non-standard port
                if (t.encrypted && ![22, 443, 993, 995, 465, 587].includes(t.destPort) && !['ssh_local', 'ssh_remote', 'ssh_dynamic', 'tor', 'dns_tunnel', 'icmp_tunnel'].includes(t.type)) {
                    detections.push(Object.freeze({
                        tunnelId: t.id,
                        type: 'encrypted_tunnel',
                        confidence: 0.50,
                        description: `Encrypted tunnel on non-standard port ${t.destPort}`,
                        indicators: Object.freeze([
                            `TLS/encrypted traffic on port ${t.destPort}`,
                            'Possible VPN or covert channel',
                        ]),
                        mitre,
                    }));
                }

                // SOCKS/HTTP proxy detection
                if (t.type === 'socks4' || t.type === 'socks5' || t.type === 'http_connect') {
                    detections.push(Object.freeze({
                        tunnelId: t.id,
                        type: 'proxy_detected',
                        confidence: 0.70,
                        description: `Proxy detected: ${t.type} on ${t.sourceHost}:${t.sourcePort}`,
                        indicators: Object.freeze([
                            `${t.type.toUpperCase()} protocol handshake observed`,
                            'Multiple destinations through single connection',
                        ]),
                        mitre,
                    }));
                }
            }

            return Object.freeze(detections);
        },

        getStats() {
            let active = 0;
            let closed = 0;
            let encrypted = 0;
            let totalIn = 0;
            let totalOut = 0;
            const byType: Record<string, number> = {};

            for (const t of tunnels.values()) {
                if (t._status === 'disconnected') closed++;
                else active++;
                if (t.encrypted) encrypted++;
                totalIn += t._bytesIn;
                totalOut += t._bytesOut;
                byType[t.type] = (byType[t.type] ?? 0) + 1;
            }

            return Object.freeze({
                totalTunnels: tunnels.size,
                activeTunnels: active,
                closedTunnels: closed,
                totalBytesIn: totalIn,
                totalBytesOut: totalOut,
                encryptedTunnels: encrypted,
                tunnelsByType: Object.freeze(byType),
            });
        },
    };

    return engine;
}
