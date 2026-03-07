/**
 * VARIANT — Packet Capture Engine
 *
 * Simulates tcpdump/Wireshark-style packet capture with:
 * - BPF filter parsing (subset)
 * - Display filter evaluation
 * - TCP stream reassembly
 * - DNS record tracking
 * - Protocol statistics
 * - Anomaly detection (port scan, beaconing, tunneling, etc.)
 * - tcpdump/hexdump output formatting
 *
 * All operations are synchronous and pure-data — no real network I/O.
 */

import type {
    PcapEngine,
    CapturedPacket,
    CaptureSession,
    CaptureOptions,
    CaptureFilter,
    NetworkInterface,
    TCPStream,
    TCPState,
    ProtocolStats,
    ConversationEntry,
    DNSRecord,
    PcapAnomaly,
    PcapAnomalyType,
    PcapStats,
} from './types';

// ── Helpers ───────────────────────────────────────────────

let packetCounter = 0;
let sessionCounter = 0;

function generatePacketId(): string {
    return `pkt-${++packetCounter}-${Date.now().toString(36)}`;
}

function generateSessionId(): string {
    return `cap-${++sessionCounter}-${Date.now().toString(36)}`;
}

function getLayerField(packet: CapturedPacket, protocol: string, field: string): string | number | boolean | undefined {
    for (const layer of packet.layers) {
        if (layer.protocol === protocol && field in layer.fields) {
            return layer.fields[field];
        }
    }
    return undefined;
}

function getSourceIP(packet: CapturedPacket): string {
    return (getLayerField(packet, 'ipv4', 'src') ?? getLayerField(packet, 'ipv6', 'src') ?? '') as string;
}

function getDestIP(packet: CapturedPacket): string {
    return (getLayerField(packet, 'ipv4', 'dst') ?? getLayerField(packet, 'ipv6', 'dst') ?? '') as string;
}

function getSourcePort(packet: CapturedPacket): number {
    return (getLayerField(packet, 'tcp', 'srcPort') ?? getLayerField(packet, 'udp', 'srcPort') ?? 0) as number;
}

function getDestPort(packet: CapturedPacket): number {
    return (getLayerField(packet, 'tcp', 'dstPort') ?? getLayerField(packet, 'udp', 'dstPort') ?? 0) as number;
}

function getProtocol(packet: CapturedPacket): string {
    const layers = packet.layers;
    // Return highest-layer protocol
    for (let i = layers.length - 1; i >= 0; i--) {
        const layer = layers[i];
        if (layer !== undefined && layer.protocol !== 'ethernet' && layer.protocol !== 'raw') {
            return layer.protocol;
        }
    }
    const first = layers[0];
    return first !== undefined ? first.protocol : 'unknown';
}

function hasLayer(packet: CapturedPacket, protocol: string): boolean {
    return packet.layers.some(l => l.protocol === protocol);
}

function ipToNumber(ip: string): number {
    const parts = ip.split('.');
    if (parts.length !== 4) return 0;
    return ((parseInt(parts[0] ?? '0') << 24) | (parseInt(parts[1] ?? '0') << 16) |
            (parseInt(parts[2] ?? '0') << 8) | parseInt(parts[3] ?? '0')) >>> 0;
}

function cidrMatch(ip: string, cidr: string): boolean {
    const slashIdx = cidr.indexOf('/');
    const network = slashIdx >= 0 ? cidr.slice(0, slashIdx) : cidr;
    const bitsStr = slashIdx >= 0 ? cidr.slice(slashIdx + 1) : '';
    const mask = bitsStr !== '' ? (~0 << (32 - parseInt(bitsStr))) >>> 0 : 0xFFFFFFFF;
    return (ipToNumber(ip) & mask) === (ipToNumber(network) & mask);
}

function isPrivateIP(ip: string): boolean {
    return cidrMatch(ip, '10.0.0.0/8') ||
           cidrMatch(ip, '172.16.0.0/12') ||
           cidrMatch(ip, '192.168.0.0/16') ||
           ip === '127.0.0.1' || ip === '::1';
}

// ── BPF Filter Parser (subset) ───────────────────────────

interface BPFMatcher {
    match(packet: CapturedPacket): boolean;
}

function parseBPFExpression(expression: string): BPFMatcher {
    const expr = expression.trim().toLowerCase();
    if (!expr) return { match: () => true };

    // Handle 'and' / 'or' / 'not' combinators
    const andParts = splitOutsideParens(expr, ' and ');
    if (andParts.length > 1) {
        const matchers = andParts.map(p => parseBPFExpression(p));
        return { match: (pkt) => matchers.every(m => m.match(pkt)) };
    }

    const orParts = splitOutsideParens(expr, ' or ');
    if (orParts.length > 1) {
        const matchers = orParts.map(p => parseBPFExpression(p));
        return { match: (pkt) => matchers.some(m => m.match(pkt)) };
    }

    if (expr.startsWith('not ')) {
        const inner = parseBPFExpression(expr.slice(4));
        return { match: (pkt) => !inner.match(pkt) };
    }

    if (expr.startsWith('(') && expr.endsWith(')')) {
        return parseBPFExpression(expr.slice(1, -1));
    }

    // Protocol filters
    if (expr === 'tcp') return { match: (pkt) => hasLayer(pkt, 'tcp') };
    if (expr === 'udp') return { match: (pkt) => hasLayer(pkt, 'udp') };
    if (expr === 'icmp') return { match: (pkt) => hasLayer(pkt, 'icmp') };
    if (expr === 'arp') return { match: (pkt) => hasLayer(pkt, 'arp') };
    if (expr === 'ip') return { match: (pkt) => hasLayer(pkt, 'ipv4') };
    if (expr === 'ip6') return { match: (pkt) => hasLayer(pkt, 'ipv6') };
    if (expr === 'dns') return { match: (pkt) => hasLayer(pkt, 'dns') };
    if (expr === 'http') return { match: (pkt) => hasLayer(pkt, 'http') };
    if (expr === 'tls' || expr === 'ssl') return { match: (pkt) => hasLayer(pkt, 'tls') };

    // Host filters
    const hostMatch = expr.match(/^(?:src |dst )?host (.+)$/);
    if (hostMatch) {
        const host = hostMatch[1];
        if (expr.startsWith('src ')) {
            return { match: (pkt) => getSourceIP(pkt) === host };
        }
        if (expr.startsWith('dst ')) {
            return { match: (pkt) => getDestIP(pkt) === host };
        }
        return { match: (pkt) => getSourceIP(pkt) === host || getDestIP(pkt) === host };
    }

    // Net filters
    const netMatch = expr.match(/^(?:src |dst )?net (.+)$/);
    if (netMatch) {
        const net = netMatch[1]!;
        if (expr.startsWith('src ')) {
            return { match: (pkt) => cidrMatch(getSourceIP(pkt), net) };
        }
        if (expr.startsWith('dst ')) {
            return { match: (pkt) => cidrMatch(getDestIP(pkt), net) };
        }
        return { match: (pkt) => cidrMatch(getSourceIP(pkt), net) || cidrMatch(getDestIP(pkt), net) };
    }

    // Port filters
    const portMatch = expr.match(/^(?:src |dst )?port (\d+)$/);
    if (portMatch) {
        const port = parseInt(portMatch[1]!);
        if (expr.startsWith('src ')) {
            return { match: (pkt) => getSourcePort(pkt) === port };
        }
        if (expr.startsWith('dst ')) {
            return { match: (pkt) => getDestPort(pkt) === port };
        }
        return { match: (pkt) => getSourcePort(pkt) === port || getDestPort(pkt) === port };
    }

    // Port range
    const portRangeMatch = expr.match(/^portrange (\d+)-(\d+)$/);
    if (portRangeMatch) {
        const lo = parseInt(portRangeMatch[1]!);
        const hi = parseInt(portRangeMatch[2]!);
        return {
            match: (pkt) => {
                const sp = getSourcePort(pkt);
                const dp = getDestPort(pkt);
                return (sp >= lo && sp <= hi) || (dp >= lo && dp <= hi);
            }
        };
    }

    // Protocol + port combo (e.g., "tcp port 80")
    const protoPortMatch = expr.match(/^(tcp|udp) (?:src |dst )?port (\d+)$/);
    if (protoPortMatch) {
        const proto = protoPortMatch[1]!;
        const port = parseInt(protoPortMatch[2]!);
        const dirPrefix = expr.replace(/^(tcp|udp) /, '');
        return {
            match: (pkt) => {
                if (!hasLayer(pkt, proto)) return false;
                if (dirPrefix.startsWith('src ')) return getSourcePort(pkt) === port;
                if (dirPrefix.startsWith('dst ')) return getDestPort(pkt) === port;
                return getSourcePort(pkt) === port || getDestPort(pkt) === port;
            }
        };
    }

    // Fallback: try as raw protocol name
    return { match: (pkt) => hasLayer(pkt, expr) };
}

function splitOutsideParens(s: string, delimiter: string): string[] {
    const parts: string[] = [];
    let depth = 0;
    let current = '';
    let i = 0;
    while (i < s.length) {
        if (s[i] === '(') depth++;
        else if (s[i] === ')') depth--;

        if (depth === 0 && s.substring(i, i + delimiter.length) === delimiter) {
            parts.push(current.trim());
            current = '';
            i += delimiter.length;
            continue;
        }
        current += s[i];
        i++;
    }
    if (current.trim()) parts.push(current.trim());
    return parts.length > 0 ? parts : [s];
}

// ── Display Filter Evaluator ─────────────────────────────

function evaluateDisplayFilter(packet: CapturedPacket, expression: string): boolean {
    const expr = expression.trim();
    if (!expr) return true;

    // Handle logical operators
    const andParts = splitOutsideParens(expr, ' && ');
    if (andParts.length > 1) {
        return andParts.every(p => evaluateDisplayFilter(packet, p));
    }

    const orParts = splitOutsideParens(expr, ' || ');
    if (orParts.length > 1) {
        return orParts.some(p => evaluateDisplayFilter(packet, p));
    }

    if (expr.startsWith('!')) {
        return !evaluateDisplayFilter(packet, expr.slice(1).trim());
    }

    if (expr.startsWith('(') && expr.endsWith(')')) {
        return evaluateDisplayFilter(packet, expr.slice(1, -1));
    }

    // Protocol existence check (e.g., "tcp", "dns")
    if (/^[a-z][a-z0-9]*$/.test(expr)) {
        return hasLayer(packet, expr);
    }

    // Field comparisons (e.g., "ip.src == 10.0.0.1", "tcp.dstport == 80")
    const cmpMatch = expr.match(/^([a-z][a-z0-9_.]+)\s*(==|!=|>=|<=|>|<|contains|matches)\s*(.+)$/);
    if (cmpMatch) {
        const [, fieldPath, op, rawValue] = cmpMatch as RegExpMatchArray;
        const value = rawValue!.trim().replace(/^["']|["']$/g, '');
        const fieldValue = resolveDisplayField(packet, fieldPath!);

        if (fieldValue === undefined) return false;

        const strVal = String(fieldValue);
        const numVal = typeof fieldValue === 'number' ? fieldValue : parseFloat(strVal);
        const cmpNum = parseFloat(value);

        switch (op) {
            case '==': return strVal === value || (Number.isFinite(numVal) && numVal === cmpNum);
            case '!=': return strVal !== value && (!Number.isFinite(numVal) || numVal !== cmpNum);
            case '>': return Number.isFinite(numVal) && numVal > cmpNum;
            case '<': return Number.isFinite(numVal) && numVal < cmpNum;
            case '>=': return Number.isFinite(numVal) && numVal >= cmpNum;
            case '<=': return Number.isFinite(numVal) && numVal <= cmpNum;
            case 'contains': return strVal.includes(value);
            case 'matches': {
                try { return new RegExp(value).test(strVal); }
                catch { return false; }
            }
            default: return false;
        }
    }

    return false;
}

function resolveDisplayField(packet: CapturedPacket, fieldPath: string): string | number | boolean | undefined {
    // Map Wireshark-style fields to our layer/field structure
    const fieldMap: Record<string, [string, string]> = {
        'ip.src': ['ipv4', 'src'],
        'ip.dst': ['ipv4', 'dst'],
        'ip.ttl': ['ipv4', 'ttl'],
        'ip.proto': ['ipv4', 'proto'],
        'ip.len': ['ipv4', 'totalLength'],
        'ipv6.src': ['ipv6', 'src'],
        'ipv6.dst': ['ipv6', 'dst'],
        'tcp.srcport': ['tcp', 'srcPort'],
        'tcp.dstport': ['tcp', 'dstPort'],
        'tcp.flags': ['tcp', 'flags'],
        'tcp.flags.syn': ['tcp', 'syn'],
        'tcp.flags.ack': ['tcp', 'ack'],
        'tcp.flags.fin': ['tcp', 'fin'],
        'tcp.flags.rst': ['tcp', 'rst'],
        'tcp.flags.psh': ['tcp', 'psh'],
        'tcp.seq': ['tcp', 'seq'],
        'tcp.ack': ['tcp', 'ackNum'],
        'tcp.window': ['tcp', 'window'],
        'udp.srcport': ['udp', 'srcPort'],
        'udp.dstport': ['udp', 'dstPort'],
        'udp.length': ['udp', 'length'],
        'eth.src': ['ethernet', 'src'],
        'eth.dst': ['ethernet', 'dst'],
        'eth.type': ['ethernet', 'type'],
        'dns.qry.name': ['dns', 'queryName'],
        'dns.qry.type': ['dns', 'queryType'],
        'dns.a': ['dns', 'answer'],
        'http.request.method': ['http', 'method'],
        'http.request.uri': ['http', 'uri'],
        'http.response.code': ['http', 'statusCode'],
        'http.host': ['http', 'host'],
        'http.user_agent': ['http', 'userAgent'],
        'http.content_type': ['http', 'contentType'],
        'tls.handshake.type': ['tls', 'handshakeType'],
        'tls.record.version': ['tls', 'version'],
        'tls.handshake.extensions.server_name': ['tls', 'sni'],
        'icmp.type': ['icmp', 'type'],
        'icmp.code': ['icmp', 'code'],
        'arp.opcode': ['arp', 'opcode'],
        'arp.src.proto_ipv4': ['arp', 'senderIP'],
        'arp.dst.proto_ipv4': ['arp', 'targetIP'],
        'frame.len': ['ethernet', 'frameLength'],
    };

    const mapped = fieldMap[fieldPath];
    if (mapped) {
        return getLayerField(packet, mapped[0], mapped[1]);
    }

    // Generic: "protocol.field"
    const dot = fieldPath.indexOf('.');
    if (dot > 0) {
        const proto = fieldPath.substring(0, dot);
        const field = fieldPath.substring(dot + 1);
        return getLayerField(packet, proto, field);
    }

    return undefined;
}

// ── Stream Key ───────────────────────────────────────────

function streamKey(srcIP: string, srcPort: number, dstIP: string, dstPort: number): string {
    // Normalize so both directions map to the same key
    if (srcIP < dstIP || (srcIP === dstIP && srcPort <= dstPort)) {
        return `${srcIP}:${srcPort}-${dstIP}:${dstPort}`;
    }
    return `${dstIP}:${dstPort}-${srcIP}:${srcPort}`;
}

// ── Conversation Key ─────────────────────────────────────

function convKey(srcIP: string, srcPort: number, dstIP: string, dstPort: number, proto: string): string {
    if (srcIP < dstIP || (srcIP === dstIP && srcPort <= dstPort)) {
        return `${proto}:${srcIP}:${srcPort}-${dstIP}:${dstPort}`;
    }
    return `${proto}:${dstIP}:${dstPort}-${srcIP}:${srcPort}`;
}

// ── Factory ──────────────────────────────────────────────

export function createPcapEngine(): PcapEngine {
    const packets: CapturedPacket[] = [];
    const sessions = new Map<string, CaptureSession & { packets: string[]; bpf?: BPFMatcher }>();
    const interfaces = new Map<string, NetworkInterface>();
    const tcpStreams = new Map<string, {
        id: string;
        sourceIP: string; sourcePort: number;
        destIP: string; destPort: number;
        state: TCPState;
        clientData: string; serverData: string;
        packets: number;
        startTick: number; lastTick: number;
    }>();
    const dnsRecords: DNSRecord[] = [];
    const conversations = new Map<string, {
        addressA: string; portA: number;
        addressB: string; portB: number;
        protocol: string;
        packets: number; bytes: number;
        startTick: number; lastTick: number;
    }>();

    // Anomaly detection state
    const portScanTracker = new Map<string, Set<number>>(); // srcIP -> set of dest ports
    const synTracker = new Map<string, number[]>(); // dstIP -> tick array
    const arpMap = new Map<string, string>(); // IP -> MAC
    const beaconTracker = new Map<string, number[]>(); // destIP -> tick intervals
    const transferTracker = new Map<string, number>(); // streamKey -> total bytes

    function matchesBPF(packet: CapturedPacket, bpf?: BPFMatcher): boolean {
        if (!bpf) return true;
        return bpf.match(packet);
    }

    function updateTCPStream(packet: CapturedPacket): void {
        if (!hasLayer(packet, 'tcp')) return;

        const srcIP = getSourceIP(packet);
        const dstIP = getDestIP(packet);
        const srcPort = getSourcePort(packet);
        const dstPort = getDestPort(packet);
        const key = streamKey(srcIP, srcPort, dstIP, dstPort);

        const syn = getLayerField(packet, 'tcp', 'syn') as boolean | undefined;
        const ack = getLayerField(packet, 'tcp', 'ack') as boolean | undefined;
        const fin = getLayerField(packet, 'tcp', 'fin') as boolean | undefined;
        const rst = getLayerField(packet, 'tcp', 'rst') as boolean | undefined;
        const payload = getLayerField(packet, 'tcp', 'payload') as string | undefined;

        let stream = tcpStreams.get(key);
        if (!stream) {
            stream = {
                id: key,
                sourceIP: srcIP, sourcePort: srcPort,
                destIP: dstIP, destPort: dstPort,
                state: 'closed',
                clientData: '', serverData: '',
                packets: 0,
                startTick: packet.tick, lastTick: packet.tick,
            };
            tcpStreams.set(key, stream);
        }

        stream.packets++;
        stream.lastTick = packet.tick;

        // State machine
        if (rst) {
            stream.state = 'closed';
        } else if (syn && !ack) {
            stream.state = 'syn_sent';
        } else if (syn && ack) {
            stream.state = 'syn_received';
        } else if (ack && stream.state === 'syn_received') {
            stream.state = 'established';
        } else if (fin) {
            if (stream.state === 'established') {
                stream.state = 'fin_wait_1';
            } else if (stream.state === 'fin_wait_1') {
                stream.state = 'closing';
            } else if (stream.state === 'close_wait') {
                stream.state = 'last_ack';
            }
        } else if (ack && stream.state === 'fin_wait_1') {
            stream.state = 'fin_wait_2';
        } else if (ack && (stream.state === 'closing' || stream.state === 'last_ack')) {
            stream.state = 'closed';
        }

        // Data reassembly
        if (payload) {
            if (srcIP === stream.sourceIP && srcPort === stream.sourcePort) {
                stream.clientData += payload;
            } else {
                stream.serverData += payload;
            }
        }
    }

    function updateDNS(packet: CapturedPacket): void {
        if (!hasLayer(packet, 'dns')) return;
        const queryName = getLayerField(packet, 'dns', 'queryName') as string | undefined;
        const queryType = getLayerField(packet, 'dns', 'queryType') as string | undefined;
        const answer = getLayerField(packet, 'dns', 'answer') as string | undefined;
        const isResponse = getLayerField(packet, 'dns', 'response') as boolean | undefined;

        if (isResponse && queryName && answer) {
            dnsRecords.push(Object.freeze({
                query: queryName,
                type: (queryType ?? 'A') as any,
                answer,
                ttl: (getLayerField(packet, 'dns', 'ttl') as number) ?? 300,
                tick: packet.tick,
            }));
        }
    }

    function updateConversation(packet: CapturedPacket): void {
        const srcIP = getSourceIP(packet);
        const dstIP = getDestIP(packet);
        if (!srcIP || !dstIP) return;

        const srcPort = getSourcePort(packet);
        const dstPort = getDestPort(packet);
        const proto = hasLayer(packet, 'tcp') ? 'tcp' : hasLayer(packet, 'udp') ? 'udp' : getProtocol(packet);
        const key = convKey(srcIP, srcPort, dstIP, dstPort, proto);

        let conv = conversations.get(key);
        if (!conv) {
            const isFirst = srcIP < dstIP || (srcIP === dstIP && srcPort <= dstPort);
            conv = {
                addressA: isFirst ? srcIP : dstIP,
                portA: isFirst ? srcPort : dstPort,
                addressB: isFirst ? dstIP : srcIP,
                portB: isFirst ? dstPort : srcPort,
                protocol: proto,
                packets: 0, bytes: 0,
                startTick: packet.tick, lastTick: packet.tick,
            };
            conversations.set(key, conv);
        }

        conv.packets++;
        conv.bytes += packet.length;
        conv.lastTick = packet.tick;
    }

    function updateAnomalyTrackers(packet: CapturedPacket): void {
        const srcIP = getSourceIP(packet);
        const dstIP = getDestIP(packet);
        const dstPort = getDestPort(packet);

        // Port scan tracking
        if (srcIP && dstPort > 0) {
            let ports = portScanTracker.get(srcIP);
            if (!ports) { ports = new Set(); portScanTracker.set(srcIP, ports); }
            ports.add(dstPort);
        }

        // SYN flood tracking
        const syn = getLayerField(packet, 'tcp', 'syn') as boolean | undefined;
        const ack = getLayerField(packet, 'tcp', 'ack') as boolean | undefined;
        if (syn && !ack && dstIP) {
            let ticks = synTracker.get(dstIP);
            if (!ticks) { ticks = []; synTracker.set(dstIP, ticks); }
            ticks.push(packet.tick);
        }

        // ARP spoofing detection
        if (hasLayer(packet, 'arp')) {
            const senderIP = getLayerField(packet, 'arp', 'senderIP') as string | undefined;
            const senderMAC = getLayerField(packet, 'arp', 'senderMAC') as string | undefined;
            if (senderIP && senderMAC) {
                arpMap.set(senderIP, senderMAC);
            }
        }

        // Beaconing detection
        if (dstIP && !isPrivateIP(dstIP)) {
            let ticks = beaconTracker.get(dstIP);
            if (!ticks) { ticks = []; beaconTracker.set(dstIP, ticks); }
            ticks.push(packet.tick);
        }

        // Large transfer tracking
        if (srcIP && dstIP) {
            const key = `${srcIP}-${dstIP}`;
            transferTracker.set(key, (transferTracker.get(key) ?? 0) + packet.length);
        }
    }

    function formatMAC(mac: string): string {
        if (mac.includes(':')) return mac;
        return mac.match(/.{2}/g)?.join(':') ?? mac;
    }

    const engine: PcapEngine = {
        startCapture(interfaceName: string, options?: CaptureOptions): CaptureSession {
            const iface = interfaces.get(interfaceName);
            if (!iface) {
                throw new Error(`Interface not found: ${interfaceName}`);
            }

            const sessionId = generateSessionId();
            let bpf: BPFMatcher | undefined;
            let filter: CaptureFilter | undefined;

            if (options?.filter) {
                filter = { expression: options.filter };
                bpf = parseBPFExpression(options.filter);
            }

            const sessionBase = {
                id: sessionId,
                interfaceName,
                startTick: Date.now(),
                snapLength: options?.snapLength ?? 65535,
                promiscuous: options?.promiscuous ?? false,
                packetCount: 0,
                byteCount: 0,
                active: true,
                packets: [] as string[],
            };
            const session = {
                ...sessionBase,
                ...(filter !== undefined ? { filter } : {}),
                ...(bpf !== undefined ? { bpf } : {}),
            } as CaptureSession & { packets: string[]; bpf?: BPFMatcher };

            sessions.set(sessionId, session);

            const resultBase = {
                id: session.id,
                interfaceName: session.interfaceName,
                startTick: session.startTick,
                snapLength: session.snapLength,
                promiscuous: session.promiscuous,
                packetCount: session.packetCount,
                byteCount: session.byteCount,
                active: session.active,
            };
            return Object.freeze(
                filter !== undefined ? { ...resultBase, filter } : resultBase
            ) as CaptureSession;
        },

        stopCapture(sessionId: string): CaptureSession | null {
            const session = sessions.get(sessionId);
            if (!session) return null;

            const endTick = Date.now();
            const stopped = {
                ...session,
                endTick,
                active: false,
            } as CaptureSession & { packets: string[]; bpf?: BPFMatcher };
            sessions.set(sessionId, stopped);

            const base = {
                id: stopped.id,
                interfaceName: stopped.interfaceName,
                startTick: stopped.startTick,
                endTick,
                snapLength: stopped.snapLength,
                promiscuous: stopped.promiscuous,
                packetCount: stopped.packetCount,
                byteCount: stopped.byteCount,
                active: stopped.active,
            };
            return Object.freeze(
                stopped.filter !== undefined ? { ...base, filter: stopped.filter } : base
            ) as CaptureSession;
        },

        injectPacket(input): CapturedPacket {
            const packet: CapturedPacket = Object.freeze({
                ...input,
                id: generatePacketId(),
                matched: true,
            });

            packets.push(packet);

            // Update tracking
            updateTCPStream(packet);
            updateDNS(packet);
            updateConversation(packet);
            updateAnomalyTrackers(packet);

            // Check against active sessions
            for (const session of sessions.values()) {
                if (!session.active) continue;
                if (session.interfaceName !== packet.interfaceName && session.interfaceName !== 'any') continue;
                if (matchesBPF(packet, session.bpf)) {
                    session.packets.push(packet.id);
                    (session as any).packetCount = session.packetCount + 1;
                    (session as any).byteCount = session.byteCount + packet.length;
                }
            }

            return packet;
        },

        applyFilter(filter: string): readonly CapturedPacket[] {
            return Object.freeze(packets.filter(p => evaluateDisplayFilter(p, filter)));
        },

        parseBPF(expression: string): CaptureFilter {
            return Object.freeze({ expression });
        },

        getPackets(): readonly CapturedPacket[] {
            return Object.freeze([...packets]);
        },

        getSessionPackets(sessionId: string): readonly CapturedPacket[] {
            const session = sessions.get(sessionId);
            if (!session) return Object.freeze([]);
            const packetIds = new Set(session.packets);
            return Object.freeze(packets.filter(p => packetIds.has(p.id)));
        },

        followTCPStream(sourceIP: string, sourcePort: number, destIP: string, destPort: number): TCPStream | null {
            const key = streamKey(sourceIP, sourcePort, destIP, destPort);
            const stream = tcpStreams.get(key);
            if (!stream) return null;
            return Object.freeze({ ...stream } as TCPStream);
        },

        getTCPStreams(): readonly TCPStream[] {
            return Object.freeze(
                Array.from(tcpStreams.values()).map(s => Object.freeze({ ...s } as TCPStream))
            );
        },

        getProtocolStats(): readonly ProtocolStats[] {
            const counts = new Map<string, { packets: number; bytes: number }>();
            for (const pkt of packets) {
                const proto = getProtocol(pkt);
                const entry = counts.get(proto) ?? { packets: 0, bytes: 0 };
                entry.packets++;
                entry.bytes += pkt.length;
                counts.set(proto, entry);
            }

            const total = packets.length || 1;
            return Object.freeze(
                Array.from(counts.entries())
                    .map(([protocol, stats]) => Object.freeze({
                        protocol,
                        packetCount: stats.packets,
                        byteCount: stats.bytes,
                        percentage: (stats.packets / total) * 100,
                    }))
                    .sort((a, b) => b.packetCount - a.packetCount)
            );
        },

        getConversations(): readonly ConversationEntry[] {
            return Object.freeze(
                Array.from(conversations.values())
                    .map(c => Object.freeze({ ...c } as ConversationEntry))
                    .sort((a, b) => b.bytes - a.bytes)
            );
        },

        getDNSRecords(): readonly DNSRecord[] {
            return Object.freeze([...dnsRecords]);
        },

        detectAnomalies(): readonly PcapAnomaly[] {
            const anomalies: PcapAnomaly[] = [];
            let anomalyId = 0;

            // Port scan detection (> 20 unique ports from one source)
            for (const [srcIP, ports] of portScanTracker) {
                if (ports.size > 20) {
                    anomalies.push(Object.freeze({
                        id: `anomaly-${++anomalyId}`,
                        type: 'port_scan' as PcapAnomalyType,
                        severity: ports.size > 100 ? 'high' : 'medium',
                        description: `Port scan detected from ${srcIP}: ${ports.size} unique destination ports`,
                        packetIds: [],
                        tick: Date.now(),
                        mitre: 'T1046',
                    }));
                }
            }

            // SYN flood detection (> 50 SYNs to one dest in short window)
            for (const [dstIP, ticks] of synTracker) {
                if (ticks.length > 50) {
                    const window = ticks[ticks.length - 1]! - ticks[0]!;
                    if (window < 10) { // Within 10 ticks
                        anomalies.push(Object.freeze({
                            id: `anomaly-${++anomalyId}`,
                            type: 'syn_flood' as PcapAnomalyType,
                            severity: 'critical',
                            description: `SYN flood detected targeting ${dstIP}: ${ticks.length} SYN packets`,
                            packetIds: [],
                            tick: Date.now(),
                        }));
                    }
                }
            }

            // ARP spoofing (multiple MACs claiming same IP)
            const ipToMacs = new Map<string, Set<string>>();
            for (const pkt of packets) {
                if (hasLayer(pkt, 'arp')) {
                    const ip = getLayerField(pkt, 'arp', 'senderIP') as string;
                    const mac = getLayerField(pkt, 'arp', 'senderMAC') as string;
                    if (ip && mac) {
                        let macs = ipToMacs.get(ip);
                        if (!macs) { macs = new Set(); ipToMacs.set(ip, macs); }
                        macs.add(mac);
                    }
                }
            }
            for (const [ip, macs] of ipToMacs) {
                if (macs.size > 1) {
                    anomalies.push(Object.freeze({
                        id: `anomaly-${++anomalyId}`,
                        type: 'arp_spoof' as PcapAnomalyType,
                        severity: 'high',
                        description: `ARP spoofing detected for ${ip}: ${macs.size} different MAC addresses (${[...macs].join(', ')})`,
                        packetIds: [],
                        tick: Date.now(),
                        mitre: 'T1557.002',
                    }));
                }
            }

            // Beaconing detection (regular intervals to external IP)
            for (const [dstIP, ticks] of beaconTracker) {
                if (ticks.length < 5) continue;
                const intervals: number[] = [];
                for (let i = 1; i < ticks.length; i++) {
                    intervals.push(ticks[i]! - ticks[i - 1]!);
                }
                const avg = intervals.reduce((a, b) => a + b, 0) / intervals.length;
                if (avg === 0) continue;
                const variance = intervals.reduce((sum, v) => sum + (v - avg) ** 2, 0) / intervals.length;
                const cv = Math.sqrt(variance) / avg; // coefficient of variation
                if (cv < 0.15 && intervals.length >= 4) {
                    anomalies.push(Object.freeze({
                        id: `anomaly-${++anomalyId}`,
                        type: 'beaconing' as PcapAnomalyType,
                        severity: 'high',
                        description: `Beaconing detected to ${dstIP}: ${intervals.length + 1} connections at ~${avg.toFixed(1)} tick intervals (CV=${cv.toFixed(3)})`,
                        packetIds: [],
                        tick: Date.now(),
                        mitre: 'T1071',
                    }));
                }
            }

            // Large transfer detection (> 10MB to single destination)
            for (const [key, bytes] of transferTracker) {
                if (bytes > 10_000_000) {
                    const [src, dst] = key.split('-');
                    anomalies.push(Object.freeze({
                        id: `anomaly-${++anomalyId}`,
                        type: 'large_transfer' as PcapAnomalyType,
                        severity: 'medium',
                        description: `Large data transfer: ${src} -> ${dst}: ${(bytes / 1_000_000).toFixed(1)} MB`,
                        packetIds: [],
                        tick: Date.now(),
                        mitre: 'T1048',
                    }));
                }
            }

            // DNS tunnel detection (long query names)
            for (const record of dnsRecords) {
                if (record.query.length > 60) {
                    anomalies.push(Object.freeze({
                        id: `anomaly-${++anomalyId}`,
                        type: 'dns_tunnel' as PcapAnomalyType,
                        severity: 'high',
                        description: `Possible DNS tunnel: query "${record.query.substring(0, 40)}..." (${record.query.length} chars)`,
                        packetIds: [],
                        tick: Date.now(),
                        mitre: 'T1071.004',
                    }));
                }
            }

            // Cleartext credentials (HTTP with auth headers, FTP PASS, etc.)
            for (const pkt of packets) {
                if (hasLayer(pkt, 'http')) {
                    const auth = getLayerField(pkt, 'http', 'authorization') as string | undefined;
                    if (auth && auth.toLowerCase().startsWith('basic ')) {
                        anomalies.push(Object.freeze({
                            id: `anomaly-${++anomalyId}`,
                            type: 'cleartext_credentials' as PcapAnomalyType,
                            severity: 'critical',
                            description: `Cleartext HTTP Basic Auth detected from ${getSourceIP(pkt)}`,
                            packetIds: [pkt.id],
                            tick: pkt.tick,
                            mitre: 'T1552.007',
                        }));
                    }
                }
                if (hasLayer(pkt, 'ftp')) {
                    const cmd = getLayerField(pkt, 'ftp', 'command') as string | undefined;
                    if (cmd && (cmd.toUpperCase().startsWith('PASS ') || cmd.toUpperCase().startsWith('USER '))) {
                        anomalies.push(Object.freeze({
                            id: `anomaly-${++anomalyId}`,
                            type: 'cleartext_credentials' as PcapAnomalyType,
                            severity: 'critical',
                            description: `Cleartext FTP credentials from ${getSourceIP(pkt)}: ${cmd.split(' ')[0]}`,
                            packetIds: [pkt.id],
                            tick: pkt.tick,
                            mitre: 'T1552.007',
                        }));
                    }
                }
            }

            return Object.freeze(anomalies);
        },

        getSessions(): readonly CaptureSession[] {
            return Object.freeze(
                Array.from(sessions.values()).map(s => Object.freeze({
                    id: s.id,
                    interfaceName: s.interfaceName,
                    startTick: s.startTick,
                    endTick: s.endTick,
                    filter: s.filter,
                    snapLength: s.snapLength,
                    promiscuous: s.promiscuous,
                    packetCount: s.packetCount,
                    byteCount: s.byteCount,
                    active: s.active,
                } as CaptureSession))
            );
        },

        getInterfaces(): readonly NetworkInterface[] {
            return Object.freeze(Array.from(interfaces.values()));
        },

        addInterface(iface: NetworkInterface): void {
            interfaces.set(iface.name, Object.freeze(iface));
        },

        formatTcpdump(packet: CapturedPacket): string {
            const srcIP = getSourceIP(packet);
            const dstIP = getDestIP(packet);
            const srcPort = getSourcePort(packet);
            const dstPort = getDestPort(packet);
            const proto = getProtocol(packet);

            const ts = new Date(packet.timestamp).toISOString().slice(11, 23);

            if (proto === 'tcp') {
                const flags: string[] = [];
                if (getLayerField(packet, 'tcp', 'syn')) flags.push('S');
                if (getLayerField(packet, 'tcp', 'ack')) flags.push('.');
                if (getLayerField(packet, 'tcp', 'fin')) flags.push('F');
                if (getLayerField(packet, 'tcp', 'rst')) flags.push('R');
                if (getLayerField(packet, 'tcp', 'psh')) flags.push('P');
                const flagStr = flags.length > 0 ? `[${flags.join('')}]` : '[.]';
                const seq = getLayerField(packet, 'tcp', 'seq') ?? 0;
                const win = getLayerField(packet, 'tcp', 'window') ?? 0;
                return `${ts} IP ${srcIP}.${srcPort} > ${dstIP}.${dstPort}: Flags ${flagStr}, seq ${seq}, win ${win}, length ${packet.length}`;
            }

            if (proto === 'udp') {
                return `${ts} IP ${srcIP}.${srcPort} > ${dstIP}.${dstPort}: UDP, length ${packet.length}`;
            }

            if (proto === 'icmp') {
                const type = getLayerField(packet, 'icmp', 'type') ?? 0;
                const code = getLayerField(packet, 'icmp', 'code') ?? 0;
                return `${ts} IP ${srcIP} > ${dstIP}: ICMP type ${type} code ${code}, length ${packet.length}`;
            }

            if (proto === 'dns') {
                const queryName = getLayerField(packet, 'dns', 'queryName') ?? '';
                const isResponse = getLayerField(packet, 'dns', 'response');
                if (isResponse) {
                    const answer = getLayerField(packet, 'dns', 'answer') ?? '';
                    return `${ts} IP ${srcIP}.${srcPort} > ${dstIP}.${dstPort}: DNS ${queryName} -> ${answer}`;
                }
                return `${ts} IP ${srcIP}.${srcPort} > ${dstIP}.${dstPort}: DNS? ${queryName}`;
            }

            if (proto === 'arp') {
                const opcode = getLayerField(packet, 'arp', 'opcode');
                const senderIP = getLayerField(packet, 'arp', 'senderIP') ?? '';
                const targetIP = getLayerField(packet, 'arp', 'targetIP') ?? '';
                if (opcode === 1 || opcode === 'request') {
                    return `${ts} ARP, Request who-has ${targetIP} tell ${senderIP}, length ${packet.length}`;
                }
                const senderMAC = getLayerField(packet, 'arp', 'senderMAC') ?? '';
                return `${ts} ARP, Reply ${senderIP} is-at ${formatMAC(String(senderMAC))}, length ${packet.length}`;
            }

            return `${ts} IP ${srcIP} > ${dstIP}: ${proto.toUpperCase()}, length ${packet.length}`;
        },

        formatHexDump(packet: CapturedPacket): string {
            const raw = packet.raw;
            const lines: string[] = [];
            const bytesPerLine = 16;

            for (let offset = 0; offset < raw.length; offset += bytesPerLine * 2) {
                const hexChars = raw.slice(offset, offset + bytesPerLine * 2);
                const hexParts: string[] = [];
                const asciiParts: string[] = [];

                for (let i = 0; i < bytesPerLine; i++) {
                    const hex = hexChars.slice(i * 2, i * 2 + 2);
                    if (hex.length === 2) {
                        hexParts.push(hex);
                        const byte = parseInt(hex, 16);
                        asciiParts.push(byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : '.');
                    } else {
                        hexParts.push('  ');
                        asciiParts.push(' ');
                    }
                }

                const hexStr = hexParts.slice(0, 8).join(' ') + '  ' + hexParts.slice(8).join(' ');
                const addr = (offset / 2).toString(16).padStart(8, '0');
                lines.push(`${addr}  ${hexStr.padEnd(49)}  |${asciiParts.join('')}|`);
            }

            return lines.join('\n');
        },

        exportPcapNg(sessionId?: string): string {
            const pkts = sessionId ? engine.getSessionPackets(sessionId) : packets;
            const lines: string[] = [
                '# PCAP-NG Export (VARIANT simulation)',
                `# Packets: ${pkts.length}`,
                `# Exported: ${new Date().toISOString()}`,
                '',
            ];

            for (const pkt of pkts) {
                lines.push(`[${pkt.id}] tick=${pkt.tick} ts=${pkt.timestamp} if=${pkt.interfaceName} len=${pkt.length} cap=${pkt.capturedLength} dir=${pkt.direction}`);
                for (const layer of pkt.layers) {
                    const fields = Object.entries(layer.fields)
                        .map(([k, v]) => `${k}=${v}`)
                        .join(' ');
                    lines.push(`  ${layer.protocol}: ${fields}`);
                }
                lines.push('');
            }

            return lines.join('\n');
        },

        getStats(): PcapStats {
            const protocolBreakdown: Record<string, number> = {};
            let totalBytes = 0;
            for (const pkt of packets) {
                const proto = getProtocol(pkt);
                protocolBreakdown[proto] = (protocolBreakdown[proto] ?? 0) + 1;
                totalBytes += pkt.length;
            }

            let activeSessions = 0;
            for (const s of sessions.values()) {
                if (s.active) activeSessions++;
            }

            return Object.freeze({
                totalPackets: packets.length,
                totalBytes,
                activeSessions,
                totalSessions: sessions.size,
                tcpStreams: tcpStreams.size,
                dnsQueries: dnsRecords.length,
                anomaliesDetected: 0, // Call detectAnomalies() for real count
                protocolBreakdown: Object.freeze({ ...protocolBreakdown }),
            });
        },

        clear(): void {
            packets.length = 0;
            sessions.clear();
            tcpStreams.clear();
            dnsRecords.length = 0;
            conversations.clear();
            portScanTracker.clear();
            synTracker.clear();
            arpMap.clear();
            beaconTracker.clear();
            transferTracker.clear();
        },
    };

    return engine;
}

/** Bootstrap common network interfaces for a simulation. */
export function bootstrapInterfaces(): NetworkInterface[] {
    return [
        Object.freeze({
            name: 'eth0',
            addresses: ['10.0.0.1'],
            mac: '00:11:22:33:44:55',
            mtu: 1500,
            up: true,
            promiscuous: false,
            type: 'ethernet' as const,
        }),
        Object.freeze({
            name: 'lo',
            addresses: ['127.0.0.1'],
            mac: '00:00:00:00:00:00',
            mtu: 65536,
            up: true,
            promiscuous: false,
            type: 'loopback' as const,
        }),
        Object.freeze({
            name: 'docker0',
            addresses: ['172.17.0.1'],
            mac: '02:42:ac:11:00:01',
            mtu: 1500,
            up: true,
            promiscuous: false,
            type: 'bridge' as const,
        }),
    ];
}
