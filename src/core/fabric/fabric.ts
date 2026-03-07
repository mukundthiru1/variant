/**
 * VARIANT — Network Fabric Implementation
 *
 * The air-gapped network connecting all VMs. This is the most
 * security-critical runtime component.
 *
 * ARCHITECTURE:
 *   VM NIC → fabric.routeFrame() → parse → firewall → route → deliver
 *
 * The fabric has NO access to:
 *   - The real network (no fetch, no WebSocket, no RTCPeerConnection)
 *   - The host filesystem
 *   - Any browser API except what's in this file
 *
 * It operates entirely on in-memory Uint8Array frames.
 *
 * FEATURES:
 *   1. Multi-segment routing with firewall rules
 *   2. Built-in DNS resolver (air-gapped, VARIANT names only)
 *   3. ARP responder (so guest OS can resolve IPs to MACs)
 *   4. Traffic logging with bounded circular buffer
 *   5. Segment tap for IDS/traffic inspection
 *   6. External service handler registration
 */

import type {
    NetworkFabric,
    NetworkTopology,
    NetworkSegment,
    DNSRecord,
    NICHandle,
    TrafficEntry,
    FabricStats,
    ExternalServiceHandler,
    PackageMirrorConfig,
} from './types';
import type { Unsubscribe } from '../events';
import {
    parseFrame,
    buildARPReply,
    buildUDPFrame,
    buildDNSResponse,
    buildDNSNXDomain,
    isBroadcastMAC,
    isInSubnet,
    ETHER_TYPE,
    IP_PROTOCOL,
    ARP_OP,
} from './frames';

// ── Constants ──────────────────────────────────────────────────

/** Maximum traffic log entries before oldest are evicted. */
const MAX_TRAFFIC_LOG = 50_000;

/** The fabric's own MAC address (for ARP/DNS responses). */
const FABRIC_MAC = '02:fa:b1:1c:00:00';

/** The fabric's DNS server IP (gateway IP of each segment). */
const DNS_PORT = 53;

// ── Internal types ─────────────────────────────────────────────

interface ConnectedNIC {
    readonly vmId: string;
    readonly mac: string;
    readonly ip: string;
    readonly segment: string;
    /** Delivery handlers registered by engine and onFrameForVM. */
    readonly deliverHandlers: Set<(frame: Uint8Array) => void>;
    connected: boolean;
}

/** Deliver a frame to all handlers on a NIC. */
function deliverToNIC(nic: ConnectedNIC, frame: Uint8Array): void {
    for (const handler of nic.deliverHandlers) {
        try {
            handler(frame);
        } catch {
            // Delivery errors must not crash the fabric
        }
    }
}

// ── Factory ────────────────────────────────────────────────────

export function createNetworkFabric(): NetworkFabric {
    // ── State ──────────────────────────────────────────────────

    let topology: NetworkTopology | null = null;
    const segments = new Map<string, NetworkSegment>();
    // A VM may have multiple NICs (one per interface).
    // nicsByVM maps vmId → all NICs belonging to that VM.
    const nicsByVM = new Map<string, Set<ConnectedNIC>>();  // vmId → Set<NIC>
    const nicsByMAC = new Map<string, ConnectedNIC>();      // MAC → NIC
    const nicsByIP = new Map<string, ConnectedNIC>();       // IP → NIC
    const dnsRecords = new Map<string, DNSRecord[]>();   // domain → records
    const externalServices = new Map<string, ExternalServiceHandler>();
    const tapHandlers = new Map<string, Set<(entry: TrafficEntry, frame: Uint8Array) => void>>();

    // Traffic log (bounded circular buffer)
    const trafficLog: TrafficEntry[] = [];
    let logHead = 0;
    let logCount = 0;

    // Stats
    let totalFrames = 0;
    let droppedFrames = 0;
    let bytesRouted = 0;
    let dnsQueries = 0;

    // ── Helpers ────────────────────────────────────────────────

    function appendTrafficLog(entry: TrafficEntry): void {
        if (logCount < MAX_TRAFFIC_LOG) {
            trafficLog.push(entry);
            logCount++;
        } else {
            trafficLog[logHead] = entry;
            logHead = (logHead + 1) % MAX_TRAFFIC_LOG;
        }
    }

    // Reserved for cross-segment routing (Phase 2)
    // function findSegmentForIP(ip: string): NetworkSegment | null { ... }

    function getGatewayForSegment(segmentId: string): string | undefined {
        return segments.get(segmentId)?.gateway;
    }

    /** Get a NIC owned by this VM (we pick the first — for routing/ARP). */
    function getPrimaryNIC(vmId: string): ConnectedNIC | undefined {
        const vmNics = nicsByVM.get(vmId);
        if (vmNics === undefined || vmNics.size === 0) return undefined;
        return vmNics.values().next().value;
    }

    function canRoute(fromSegment: string, toSegment: string, destPort?: number, protocol?: string): boolean {
        if (fromSegment === toSegment) return true;
        if (topology === null) return false;

        // Segments are isolated by default. Cross-segment routing
        // requires explicit route edges in the WorldSpec topology.
        for (const route of topology.routes) {
            const matchForward = route.from === fromSegment && route.to === toSegment;
            const matchReverse = route.from === toSegment && route.to === fromSegment;
            if (!matchForward && !matchReverse) continue;

            // Check port restriction if the route has allowedPorts
            if (route.allowedPorts !== undefined && route.allowedPorts.length > 0) {
                if (destPort === undefined || !route.allowedPorts.includes(destPort)) continue;
            }

            // Check protocol restriction
            if (route.protocol !== undefined && route.protocol !== 'any') {
                if (protocol !== undefined && route.protocol !== protocol) continue;
            }

            return true;
        }

        return false;
    }


    function checkFirewall(
        sourceIP: string,
        destIP: string,
        sourcePort: number,
        destPort: number,
        protocol: string,
        direction: 'inbound' | 'outbound',
    ): 'allow' | 'drop' | 'log' {
        if (topology === null) return 'allow';

        // Rules are sorted by priority (lower = higher priority)
        const sorted = [...topology.firewallRules].sort((a, b) => a.priority - b.priority);

        for (const rule of sorted) {
            if (rule.direction !== 'both' && rule.direction !== direction) continue;

            // Source IP match
            if (rule.sourceIP !== undefined && !isInSubnet(sourceIP, rule.sourceIP)) continue;
            if (rule.destIP !== undefined && !isInSubnet(destIP, rule.destIP)) continue;

            // Port match
            if (rule.sourcePort !== undefined && rule.sourcePort !== sourcePort) continue;
            if (rule.destPort !== undefined && rule.destPort !== destPort) continue;

            // Protocol match
            if (rule.protocol !== undefined && rule.protocol !== 'any' && rule.protocol !== protocol) continue;

            return rule.action;
        }

        // Default: allow (no matching rule)
        return 'allow';
    }

    function notifyTap(segment: string, entry: TrafficEntry, frame: Uint8Array): void {
        const handlers = tapHandlers.get(segment);
        if (handlers === undefined) return;

        for (const handler of handlers) {
            try {
                handler(entry, frame);
            } catch {
                // Tap handler errors must not crash the fabric
            }
        }
    }

    function resolveDNS(domain: string): string | null {
        // Check exact match first
        const records = dnsRecords.get(domain);
        if (records !== undefined && records.length > 0) {
            const aRecord = records.find(r => r.type === 'A');
            if (aRecord !== undefined) return aRecord.ip;
        }

        // Check if it's an external service domain
        if (externalServices.has(domain)) {
            // External services resolve to a special IP in 172.16.0.0/12
            // This IP is recognized by the fabric as "handle locally"
            return `172.16.0.${externalServices.size}`;
        }

        return null;
    }

    function handleDNSFrame(
        sourceNIC: ConnectedNIC,
        _rawFrame: Uint8Array,
        parsed: ReturnType<typeof parseFrame>,
    ): void {
        if (parsed === null || parsed.dns === null || parsed.ipv4 === null || parsed.udp === null) return;

        dnsQueries++;
        const query = parsed.dns;
        const resolvedIP = resolveDNS(query.domain);

        let responsePayload: Uint8Array;
        if (resolvedIP !== null) {
            responsePayload = buildDNSResponse(query, resolvedIP);
        } else {
            responsePayload = buildDNSNXDomain(query.id);
        }

        // Build response frame
        const gatewayIP = getGatewayForSegment(sourceNIC.segment);
        if (gatewayIP === undefined) return;

        const responseFrame = buildUDPFrame({
            srcMAC: FABRIC_MAC,
            dstMAC: sourceNIC.mac,
            srcIP: gatewayIP,
            dstIP: sourceNIC.ip,
            srcPort: DNS_PORT,
            dstPort: parsed.udp.sourcePort,
            payload: responsePayload,
        });

        // Deliver directly to the requesting VM
        if (sourceNIC.connected) {
            deliverToNIC(sourceNIC, responseFrame);
        }
    }

    function handleARPFrame(
        sourceNIC: ConnectedNIC,
        rawFrame: Uint8Array,
        parsed: ReturnType<typeof parseFrame>,
    ): void {
        if (parsed === null || parsed.arp === null) return;
        if (parsed.arp.operation !== ARP_OP.REQUEST) return;

        const targetIP = parsed.arp.targetIP;

        // Check if the ARP is for the gateway
        const gatewayIP = getGatewayForSegment(sourceNIC.segment);
        if (targetIP === gatewayIP) {
            const reply = buildARPReply(rawFrame, FABRIC_MAC, targetIP);
            if (sourceNIC.connected) {
                deliverToNIC(sourceNIC, reply);
            }
            return;
        }

        // Check if the ARP is for another VM on the same segment
        const targetNIC = nicsByIP.get(targetIP);
        if (targetNIC !== undefined && targetNIC.segment === sourceNIC.segment && targetNIC.connected) {
            const reply = buildARPReply(rawFrame, targetNIC.mac, targetIP);
            if (sourceNIC.connected) {
                deliverToNIC(sourceNIC, reply);
            }
        }
    }

    // ── Fabric implementation ──────────────────────────────────

    const fabric: NetworkFabric = {
        init(topo: NetworkTopology, _mirrorConfig?: PackageMirrorConfig): void {
            topology = topo;

            segments.clear();
            for (const seg of topo.segments) {
                segments.set(seg.id, seg);
            }
        },

        connect(
            vmId: string,
            segment: string,
            mac: string,
            ip: string,
        ): NICHandle {
            if (!segments.has(segment)) {
                throw new Error(`[Fabric] Segment '${segment}' does not exist`);
            }

            const nic: ConnectedNIC = {
                vmId,
                mac: mac.toLowerCase(),
                ip,
                segment,
                connected: true,
                deliverHandlers: new Set(),
            };

            // Track by VM (multi-NIC safe)
            let vmNics = nicsByVM.get(vmId);
            if (vmNics === undefined) {
                vmNics = new Set();
                nicsByVM.set(vmId, vmNics);
            }
            vmNics.add(nic);

            nicsByMAC.set(mac.toLowerCase(), nic);
            nicsByIP.set(ip, nic);

            const handle: NICHandle = {
                vmId,
                mac,
                segment,
                ip,
                disconnect(): void {
                    nic.connected = false;
                    const vmSet = nicsByVM.get(vmId);
                    if (vmSet !== undefined) {
                        vmSet.delete(nic);
                        if (vmSet.size === 0) nicsByVM.delete(vmId);
                    }
                    nicsByMAC.delete(mac.toLowerCase());
                    nicsByIP.delete(ip);
                },
            };

            return handle;
        },

        addDNSRecord(record: DNSRecord): void {
            let records = dnsRecords.get(record.domain);
            if (records === undefined) {
                records = [];
                dnsRecords.set(record.domain, records);
            }
            records.push(record);
        },

        registerExternal(handler: ExternalServiceHandler): void {
            externalServices.set(handler.domain, handler);
        },

        tap(
            segment: string,
            handler: (entry: TrafficEntry, frame: Uint8Array) => void,
        ): Unsubscribe {
            let handlers = tapHandlers.get(segment);
            if (handlers === undefined) {
                handlers = new Set();
                tapHandlers.set(segment, handlers);
            }
            handlers.add(handler);

            let unsubscribed = false;
            return () => {
                if (unsubscribed) return;
                unsubscribed = true;
                handlers.delete(handler);
                if (handlers.size === 0) {
                    tapHandlers.delete(segment);
                }
            };
        },

        routeFrame(sourceVmId: string, frame: Uint8Array): void {
            totalFrames++;
            bytesRouted += frame.length;

            // Determine source NIC from the frame's source MAC
            // if the VM has multiple NICs. Fallback to primary.
            let sourceNIC: ConnectedNIC | undefined;
            const parsed0 = parseFrame(frame);
            if (parsed0 !== null) {
                sourceNIC = nicsByMAC.get(parsed0.ethernet.sourceMAC.toLowerCase());
            }
            if (sourceNIC === undefined) {
                sourceNIC = getPrimaryNIC(sourceVmId);
            }
            if (sourceNIC === undefined || !sourceNIC.connected) {
                droppedFrames++;
                return;
            }

            // Parse the frame
            // Use already-parsed frame (avoid double-parse)
            const parsed = parsed0;
            if (parsed === null) {
                droppedFrames++;
                return;
            }

            // ── ARP handling ───────────────────────────────────
            if (parsed.ethernet.etherType === ETHER_TYPE.ARP) {
                handleARPFrame(sourceNIC, frame, parsed);
                return;
            }

            // ── IPv4 handling ──────────────────────────────────
            if (parsed.ethernet.etherType !== ETHER_TYPE.IPv4 || parsed.ipv4 === null) {
                droppedFrames++;
                return;
            }

            // ── DNS interception ───────────────────────────────
            if (
                parsed.udp !== null &&
                parsed.udp.destPort === DNS_PORT &&
                parsed.dns !== null
            ) {
                handleDNSFrame(sourceNIC, frame, parsed);
                return;
            }

            // ── Determine protocol string for firewall ─────────
            let protocolStr = 'other';
            let srcPort = 0;
            let dstPort = 0;
            if (parsed.tcp !== null) {
                protocolStr = 'tcp';
                srcPort = parsed.tcp.sourcePort;
                dstPort = parsed.tcp.destPort;
            } else if (parsed.udp !== null) {
                protocolStr = 'udp';
                srcPort = parsed.udp.sourcePort;
                dstPort = parsed.udp.destPort;
            } else if (parsed.ipv4.protocol === IP_PROTOCOL.ICMP) {
                protocolStr = 'icmp';
            }

            // ── Firewall check ─────────────────────────────────
            const firewallResult = checkFirewall(
                parsed.ipv4.sourceIP,
                parsed.ipv4.destIP,
                srcPort,
                dstPort,
                protocolStr,
                'outbound',
            );

            // Log traffic
            const entry: TrafficEntry = {
                timestamp: Date.now(),
                sourceMAC: parsed.ethernet.sourceMAC,
                destMAC: parsed.ethernet.destMAC,
                sourceIP: parsed.ipv4.sourceIP,
                destIP: parsed.ipv4.destIP,
                protocol: protocolStr,
                port: dstPort,
                size: frame.length,
                direction: 'outbound',
                segment: sourceNIC.segment,
            };
            appendTrafficLog(entry);
            notifyTap(sourceNIC.segment, entry, frame);

            if (firewallResult === 'drop') {
                droppedFrames++;
                return;
            }

            // ── Route to destination ───────────────────────────
            const destIP = parsed.ipv4.destIP;

            // Check if destination is on the same segment
            const destNIC = nicsByIP.get(destIP);
            if (destNIC !== undefined) {
                if (destNIC.segment !== sourceNIC.segment) {
                    // Cross-segment — check routing against topology routes
                    if (!canRoute(sourceNIC.segment, destNIC.segment, dstPort, protocolStr)) {
                        droppedFrames++;
                        return;
                    }
                }

                // Inbound firewall check
                const inboundResult = checkFirewall(
                    parsed.ipv4.sourceIP,
                    parsed.ipv4.destIP,
                    srcPort,
                    dstPort,
                    protocolStr,
                    'inbound',
                );

                if (inboundResult === 'drop') {
                    droppedFrames++;
                    return;
                }

                // Deliver
                if (destNIC.connected) {
                    deliverToNIC(destNIC, frame);

                    // Log inbound
                    const inEntry: TrafficEntry = {
                        timestamp: Date.now(),
                        sourceMAC: parsed.ethernet.sourceMAC,
                        destMAC: parsed.ethernet.destMAC,
                        sourceIP: parsed.ipv4.sourceIP,
                        destIP: parsed.ipv4.destIP,
                        protocol: protocolStr,
                        port: dstPort,
                        size: frame.length,
                        direction: 'inbound',
                        segment: destNIC.segment,
                    };
                    appendTrafficLog(inEntry);
                    notifyTap(destNIC.segment, inEntry, frame);
                }
                return;
            }

            // Broadcast
            if (isBroadcastMAC(parsed.ethernet.destMAC)) {
                for (const [, vmNicSet] of nicsByVM) {
                    for (const nic of vmNicSet) {
                        if (nic.vmId !== sourceVmId && nic.segment === sourceNIC.segment && nic.connected) {
                            deliverToNIC(nic, frame);
                        }
                    }
                }
                return;
            }

            // Destination not found — drop
            droppedFrames++;
        },

        onFrameForVM(
            vmId: string,
            handler: (frame: Uint8Array) => void,
        ): Unsubscribe {
            // Register a delivery handler for frames destined to this VM.
            // The engine calls this to wire VM NIC receive to the backend.
            // Multi-NIC: register on ALL NICs belonging to this VM.
            const vmNics = nicsByVM.get(vmId);
            if (vmNics === undefined || vmNics.size === 0) {
                throw new Error(`[Fabric] VM '${vmId}' is not connected`);
            }

            // Add handler to every NIC owned by this VM
            for (const nic of vmNics) {
                nic.deliverHandlers.add(handler);
            }

            let unsubscribed = false;
            return () => {
                if (unsubscribed) return;
                unsubscribed = true;
                // Remove from all NICs (VM may have had NICs added/removed)
                const currentNics = nicsByVM.get(vmId);
                if (currentNics !== undefined) {
                    for (const nic of currentNics) {
                        nic.deliverHandlers.delete(handler);
                    }
                }
            };
        },

        getTrafficLog(): readonly TrafficEntry[] {
            const result: TrafficEntry[] = [];
            for (let i = 0; i < logCount; i++) {
                const idx = (logHead + i) % (logCount < MAX_TRAFFIC_LOG ? logCount : MAX_TRAFFIC_LOG);
                const entry = trafficLog[idx];
                if (entry !== undefined) {
                    result.push(entry);
                }
            }
            return result;
        },

        getStats(): FabricStats {
            let totalNICs = 0;
            for (const vmNicSet of nicsByVM.values()) {
                totalNICs += vmNicSet.size;
            }
            return {
                totalFrames,
                droppedFrames,
                bytesRouted,
                dnsQueries,
                activeConnections: totalNICs,
            };
        },

        getExternalHandler(domain: string): ExternalServiceHandler | undefined {
            return externalServices.get(domain);
        },

        getExternalDomains(): readonly string[] {
            return Array.from(externalServices.keys());
        },

        destroy(): void {
            // Disconnect all NICs
            for (const [, vmNicSet] of nicsByVM) {
                for (const nic of vmNicSet) {
                    nic.connected = false;
                    nic.deliverHandlers.clear();
                }
            }
            nicsByVM.clear();
            nicsByMAC.clear();
            nicsByIP.clear();
            dnsRecords.clear();
            externalServices.clear();
            tapHandlers.clear();
            trafficLog.length = 0;
            logHead = 0;
            logCount = 0;
            topology = null;
        },
    };

    return fabric;
}
