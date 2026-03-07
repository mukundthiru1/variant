/**
 * VARIANT — Network Topology Engine Implementation
 *
 * Models network segments, hosts, routes, and connectivity.
 * BFS-based reachability and shortest path computation.
 *
 * SWAPPABILITY: Implements TopologyEngine. Replace this file.
 */

import type {
    TopologyEngine,
    NetworkSegment,
    TopologyHost,
    SegmentLink,
    ReachabilityResult,
} from './types';

export function createTopologyEngine(): TopologyEngine {
    const segments = new Map<string, NetworkSegment>();
    const hosts = new Map<string, TopologyHost>();
    const links: SegmentLink[] = [];

    // Adjacency: segmentId → [{ toSegment, link }]
    function buildAdjacency(): Map<string, { to: string; link: SegmentLink }[]> {
        const adj = new Map<string, { to: string; link: SegmentLink }[]>();
        for (const seg of segments.keys()) {
            adj.set(seg, []);
        }
        for (const link of links) {
            const fromAdj = adj.get(link.from);
            if (fromAdj !== undefined) {
                fromAdj.push({ to: link.to, link });
            }
        }
        return adj;
    }

    function getHostSegments(hostId: string): string[] {
        const host = hosts.get(hostId);
        if (host === undefined) return [];
        return host.interfaces
            .filter(iface => iface.up)
            .map(iface => iface.segmentId);
    }

    /**
     * BFS from source segments to target segments.
     * Returns the path of segment IDs and total latency, or null if unreachable.
     */
    function bfsPath(
        fromSegments: string[],
        toSegments: Set<string>,
        port?: number,
    ): { path: string[]; latency: number } | null {
        const adj = buildAdjacency();
        const visited = new Set<string>();
        // Queue: [currentSegment, path, totalLatency]
        const queue: [string, string[], number][] = [];

        for (const seg of fromSegments) {
            if (toSegments.has(seg)) {
                return { path: [seg], latency: 0 };
            }
            queue.push([seg, [seg], 0]);
            visited.add(seg);
        }

        while (queue.length > 0) {
            const [current, path, latency] = queue.shift()!;
            const neighbors = adj.get(current) ?? [];

            for (const { to, link } of neighbors) {
                if (visited.has(to)) continue;
                if (!link.allowed) continue;

                // If port filter, check allowed ports (empty = all)
                if (port !== undefined && link.allowedPorts.length > 0) {
                    if (!link.allowedPorts.includes(port)) continue;
                }

                const newPath = [...path, to];
                const newLatency = latency + link.latency;

                if (toSegments.has(to)) {
                    return { path: newPath, latency: newLatency };
                }

                visited.add(to);
                queue.push([to, newPath, newLatency]);
            }
        }

        return null;
    }

    return {
        // ── Segments ────────────────────────────────────────────

        addSegment(segment: NetworkSegment): void {
            if (segments.has(segment.id)) {
                throw new Error(`Segment '${segment.id}' already exists`);
            }
            segments.set(segment.id, segment);
        },

        getSegment(id: string): NetworkSegment | null {
            return segments.get(id) ?? null;
        },

        listSegments(): readonly NetworkSegment[] {
            return [...segments.values()];
        },

        // ── Hosts ───────────────────────────────────────────────

        addHost(host: TopologyHost): void {
            if (hosts.has(host.id)) {
                throw new Error(`Host '${host.id}' already exists`);
            }
            hosts.set(host.id, host);
        },

        getHost(id: string): TopologyHost | null {
            return hosts.get(id) ?? null;
        },

        listHosts(): readonly TopologyHost[] {
            return [...hosts.values()];
        },

        listHostsInSegment(segmentId: string): readonly TopologyHost[] {
            return [...hosts.values()].filter(h =>
                h.interfaces.some(iface => iface.segmentId === segmentId),
            );
        },

        // ── Links ───────────────────────────────────────────────

        addLink(link: SegmentLink): void {
            links.push(link);
        },

        listLinks(): readonly SegmentLink[] {
            return [...links];
        },

        // ── Queries ─────────────────────────────────────────────

        canReach(fromHostId: string, toHostId: string, port?: number): ReachabilityResult {
            const fromHost = hosts.get(fromHostId);
            if (fromHost === undefined) {
                return { reachable: false, path: [], totalLatency: 0, reason: `source host '${fromHostId}' not found` };
            }

            const toHost = hosts.get(toHostId);
            if (toHost === undefined) {
                return { reachable: false, path: [], totalLatency: 0, reason: `target host '${toHostId}' not found` };
            }

            // Check port is open on target
            if (port !== undefined) {
                const portOpen = toHost.openPorts.some(p => p.port === port);
                if (!portOpen) {
                    return { reachable: false, path: [], totalLatency: 0, reason: `port ${port} is not open on '${toHostId}'` };
                }
            }

            const fromSegments = getHostSegments(fromHostId);
            const toSegments = new Set(getHostSegments(toHostId));

            if (fromSegments.length === 0) {
                return { reachable: false, path: [], totalLatency: 0, reason: `source host '${fromHostId}' has no active interfaces` };
            }

            if (toSegments.size === 0) {
                return { reachable: false, path: [], totalLatency: 0, reason: `target host '${toHostId}' has no active interfaces` };
            }

            const result = bfsPath(fromSegments, toSegments, port);
            if (result === null) {
                return { reachable: false, path: [], totalLatency: 0, reason: 'no route between hosts' };
            }

            return {
                reachable: true,
                path: result.path,
                totalLatency: result.latency,
            };
        },

        getReachableHosts(fromHostId: string): readonly string[] {
            const reachable: string[] = [];
            for (const hostId of hosts.keys()) {
                if (hostId === fromHostId) continue;
                if (this.canReach(fromHostId, hostId).reachable) {
                    reachable.push(hostId);
                }
            }
            return reachable;
        },

        findHostsByPort(port: number, protocol?: 'tcp' | 'udp'): readonly TopologyHost[] {
            return [...hosts.values()].filter(h =>
                h.openPorts.some(p => p.port === port && (protocol === undefined || p.protocol === protocol)),
            );
        },

        findHostByIP(ip: string): TopologyHost | null {
            for (const host of hosts.values()) {
                if (host.interfaces.some(iface => iface.ip === ip)) {
                    return host;
                }
            }
            return null;
        },

        // ── Reset ───────────────────────────────────────────────

        clear(): void {
            segments.clear();
            hosts.clear();
            links.length = 0;
        },
    };
}
