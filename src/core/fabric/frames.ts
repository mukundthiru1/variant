/**
 * VARIANT — Ethernet Frame Parser
 *
 * Parses raw Ethernet frames into structured data.
 * Used by the fabric to route, filter, and log traffic.
 *
 * This is pure parsing — no I/O, no state, no side effects.
 * Every function takes bytes in and returns data out.
 *
 * SECURITY: All parsing is bounds-checked. Malformed frames
 * are rejected, not silently truncated. A guest OS sending
 * garbage frames cannot crash the fabric.
 */

// ── Ethernet ───────────────────────────────────────────────────

export interface EthernetHeader {
    readonly destMAC: string;
    readonly sourceMAC: string;
    readonly etherType: number;
}

/** Minimum Ethernet frame size (header only, no payload). */
const ETHERNET_HEADER_SIZE = 14;

/** EtherType constants. */
export const ETHER_TYPE = {
    IPv4: 0x0800,
    ARP: 0x0806,
    IPv6: 0x86DD,
} as const;

export function parseEthernetHeader(frame: Uint8Array): EthernetHeader | null {
    if (frame.length < ETHERNET_HEADER_SIZE) return null;

    return {
        destMAC: formatMAC(frame, 0),
        sourceMAC: formatMAC(frame, 6),
        etherType: (frame[12]! << 8) | frame[13]!,
    };
}

function formatMAC(data: Uint8Array, offset: number): string {
    const bytes: string[] = [];
    for (let i = 0; i < 6; i++) {
        const b = data[offset + i];
        if (b === undefined) return '00:00:00:00:00:00';
        bytes.push(b.toString(16).padStart(2, '0'));
    }
    return bytes.join(':');
}

export function macToBytes(mac: string): Uint8Array {
    const parts = mac.split(':');
    const bytes = new Uint8Array(6);
    for (let i = 0; i < 6; i++) {
        const part = parts[i];
        if (part === undefined) continue;
        bytes[i] = parseInt(part, 16);
    }
    return bytes;
}

export function isBroadcastMAC(mac: string): boolean {
    return mac === 'ff:ff:ff:ff:ff:ff';
}

// ── IPv4 ───────────────────────────────────────────────────────

export interface IPv4Header {
    readonly version: number;
    readonly headerLength: number;     // in bytes
    readonly totalLength: number;
    readonly protocol: number;
    readonly sourceIP: string;
    readonly destIP: string;
    readonly ttl: number;
}

/** IP protocol numbers. */
export const IP_PROTOCOL = {
    ICMP: 1,
    TCP: 6,
    UDP: 17,
} as const;

const IPV4_MIN_HEADER_SIZE = 20;

export function parseIPv4Header(frame: Uint8Array, offset: number): IPv4Header | null {
    if (frame.length < offset + IPV4_MIN_HEADER_SIZE) return null;

    const versionIHL = frame[offset]!;
    const version = (versionIHL >> 4) & 0x0F;
    if (version !== 4) return null;

    const headerLength = (versionIHL & 0x0F) * 4;
    if (headerLength < IPV4_MIN_HEADER_SIZE) return null;
    if (frame.length < offset + headerLength) return null;

    const totalLength = (frame[offset + 2]! << 8) | frame[offset + 3]!;

    return {
        version,
        headerLength,
        totalLength,
        protocol: frame[offset + 9]!,
        ttl: frame[offset + 8]!,
        sourceIP: formatIPv4(frame, offset + 12),
        destIP: formatIPv4(frame, offset + 16),
    };
}

function formatIPv4(data: Uint8Array, offset: number): string {
    const a = data[offset] ?? 0;
    const b = data[offset + 1] ?? 0;
    const c = data[offset + 2] ?? 0;
    const d = data[offset + 3] ?? 0;
    return `${a}.${b}.${c}.${d}`;
}

export function ipToUint32(ip: string): number {
    const parts = ip.split('.');
    return (
        ((parseInt(parts[0] ?? '0', 10) & 0xFF) << 24) |
        ((parseInt(parts[1] ?? '0', 10) & 0xFF) << 16) |
        ((parseInt(parts[2] ?? '0', 10) & 0xFF) << 8) |
        (parseInt(parts[3] ?? '0', 10) & 0xFF)
    ) >>> 0; // unsigned
}

export function uint32ToIP(n: number): string {
    return [
        (n >>> 24) & 0xFF,
        (n >>> 16) & 0xFF,
        (n >>> 8) & 0xFF,
        n & 0xFF,
    ].join('.');
}

/**
 * Check if an IP is within a CIDR range.
 * e.g., isInSubnet('10.0.1.5', '10.0.1.0/24') → true
 */
export function isInSubnet(ip: string, cidr: string): boolean {
    const slashIdx = cidr.indexOf('/');
    if (slashIdx === -1) return ip === cidr;

    const subnet = cidr.substring(0, slashIdx);
    const prefixLen = parseInt(cidr.substring(slashIdx + 1), 10);
    if (isNaN(prefixLen) || prefixLen < 0 || prefixLen > 32) return false;

    const mask = prefixLen === 0 ? 0 : (~0 << (32 - prefixLen)) >>> 0;
    const ipNum = ipToUint32(ip);
    const subnetNum = ipToUint32(subnet);

    return (ipNum & mask) === (subnetNum & mask);
}

// ── TCP ────────────────────────────────────────────────────────

export interface TCPHeader {
    readonly sourcePort: number;
    readonly destPort: number;
    readonly seqNumber: number;
    readonly ackNumber: number;
    readonly dataOffset: number;    // in bytes
    readonly flags: TCPFlags;
    readonly windowSize: number;
}

export interface TCPFlags {
    readonly fin: boolean;
    readonly syn: boolean;
    readonly rst: boolean;
    readonly psh: boolean;
    readonly ack: boolean;
    readonly urg: boolean;
}

const TCP_MIN_HEADER_SIZE = 20;

export function parseTCPHeader(frame: Uint8Array, offset: number): TCPHeader | null {
    if (frame.length < offset + TCP_MIN_HEADER_SIZE) return null;

    const flagsByte = frame[offset + 13]!;
    const dataOffset = ((frame[offset + 12]! >> 4) & 0x0F) * 4;

    return {
        sourcePort: (frame[offset]! << 8) | frame[offset + 1]!,
        destPort: (frame[offset + 2]! << 8) | frame[offset + 3]!,
        seqNumber: (
            (frame[offset + 4]! << 24) |
            (frame[offset + 5]! << 16) |
            (frame[offset + 6]! << 8) |
            frame[offset + 7]!
        ) >>> 0,
        ackNumber: (
            (frame[offset + 8]! << 24) |
            (frame[offset + 9]! << 16) |
            (frame[offset + 10]! << 8) |
            frame[offset + 11]!
        ) >>> 0,
        dataOffset,
        flags: {
            fin: (flagsByte & 0x01) !== 0,
            syn: (flagsByte & 0x02) !== 0,
            rst: (flagsByte & 0x04) !== 0,
            psh: (flagsByte & 0x08) !== 0,
            ack: (flagsByte & 0x10) !== 0,
            urg: (flagsByte & 0x20) !== 0,
        },
        windowSize: (frame[offset + 14]! << 8) | frame[offset + 15]!,
    };
}

// ── UDP ────────────────────────────────────────────────────────

export interface UDPHeader {
    readonly sourcePort: number;
    readonly destPort: number;
    readonly length: number;
}

const UDP_HEADER_SIZE = 8;

export function parseUDPHeader(frame: Uint8Array, offset: number): UDPHeader | null {
    if (frame.length < offset + UDP_HEADER_SIZE) return null;

    return {
        sourcePort: (frame[offset]! << 8) | frame[offset + 1]!,
        destPort: (frame[offset + 2]! << 8) | frame[offset + 3]!,
        length: (frame[offset + 4]! << 8) | frame[offset + 5]!,
    };
}

// ── ARP ────────────────────────────────────────────────────────

export interface ARPPacket {
    readonly operation: number;        // 1 = request, 2 = reply
    readonly senderMAC: string;
    readonly senderIP: string;
    readonly targetMAC: string;
    readonly targetIP: string;
}

const ARP_HEADER_SIZE = 28;

export const ARP_OP = {
    REQUEST: 1,
    REPLY: 2,
} as const;

export function parseARP(frame: Uint8Array, offset: number): ARPPacket | null {
    if (frame.length < offset + ARP_HEADER_SIZE) return null;

    return {
        operation: (frame[offset + 6]! << 8) | frame[offset + 7]!,
        senderMAC: formatMAC(frame, offset + 8),
        senderIP: formatIPv4(frame, offset + 14),
        targetMAC: formatMAC(frame, offset + 18),
        targetIP: formatIPv4(frame, offset + 24),
    };
}

/**
 * Build an ARP reply frame.
 */
export function buildARPReply(
    requestFrame: Uint8Array,
    replyMAC: string,
    replyIP: string,
): Uint8Array {
    const reply = new Uint8Array(42); // Ethernet(14) + ARP(28)
    const arp = parseARP(requestFrame, ETHERNET_HEADER_SIZE);
    if (arp === null) return reply;

    // Ethernet header
    const senderMACBytes = macToBytes(arp.senderMAC);
    const replyMACBytes = macToBytes(replyMAC);
    reply.set(senderMACBytes, 0);       // dest MAC = original sender
    reply.set(replyMACBytes, 6);        // source MAC = our reply MAC
    reply[12] = 0x08;                    // EtherType ARP
    reply[13] = 0x06;

    // ARP header
    reply[14] = 0x00; reply[15] = 0x01; // hardware type: Ethernet
    reply[16] = 0x08; reply[17] = 0x00; // protocol type: IPv4
    reply[18] = 6;                       // hardware addr length
    reply[19] = 4;                       // protocol addr length
    reply[20] = 0x00; reply[21] = 0x02; // operation: reply

    // Sender (us)
    reply.set(replyMACBytes, 22);
    const replyIPParts = replyIP.split('.');
    for (let i = 0; i < 4; i++) {
        reply[28 + i] = parseInt(replyIPParts[i] ?? '0', 10);
    }

    // Target (original sender)
    reply.set(senderMACBytes, 32);
    const senderIPParts = arp.senderIP.split('.');
    for (let i = 0; i < 4; i++) {
        reply[38 + i] = parseInt(senderIPParts[i] ?? '0', 10);
    }

    return reply;
}

// ── DNS ────────────────────────────────────────────────────────

export interface DNSQuery {
    readonly id: number;
    readonly domain: string;
    readonly queryType: number;
}

/** DNS query types. */
export const DNS_TYPE = {
    A: 1,
    AAAA: 28,
    CNAME: 5,
    MX: 15,
    TXT: 16,
} as const;

/**
 * Parse a DNS query from UDP payload.
 * Returns null for malformed queries.
 */
export function parseDNSQuery(payload: Uint8Array): DNSQuery | null {
    if (payload.length < 12) return null;

    const id = (payload[0]! << 8) | payload[1]!;
    const flags = (payload[2]! << 8) | payload[3]!;

    // Must be a standard query (QR=0, OPCODE=0)
    if ((flags & 0x8000) !== 0) return null; // Response bit set
    if ((flags & 0x7800) !== 0) return null; // Non-standard opcode

    const qdCount = (payload[4]! << 8) | payload[5]!;
    if (qdCount < 1) return null;

    // Parse the domain name from the question section
    let offset = 12;
    const labels: string[] = [];

    while (offset < payload.length) {
        const labelLen = payload[offset]!;
        if (labelLen === 0) {
            offset++;
            break;
        }
        if (labelLen > 63) return null; // Invalid label length
        if (offset + 1 + labelLen > payload.length) return null;

        const label = new TextDecoder().decode(
            payload.slice(offset + 1, offset + 1 + labelLen),
        );
        labels.push(label);
        offset += 1 + labelLen;
    }

    if (labels.length === 0) return null;
    if (offset + 4 > payload.length) return null;

    const queryType = (payload[offset]! << 8) | payload[offset + 1]!;

    return {
        id,
        domain: labels.join('.'),
        queryType,
    };
}

/**
 * Build a DNS response for a given query.
 */
export function buildDNSResponse(
    query: DNSQuery,
    ip: string,
    ttl: number = 300,
): Uint8Array {
    // Build domain labels
    const labels = query.domain.split('.');
    const nameBytes: number[] = [];
    for (const label of labels) {
        nameBytes.push(label.length);
        for (let i = 0; i < label.length; i++) {
            nameBytes.push(label.charCodeAt(i));
        }
    }
    nameBytes.push(0); // null terminator

    const nameLen = nameBytes.length;
    // Header(12) + Question(name + type(2) + class(2)) + Answer(name(2 ptr) + type(2) + class(2) + ttl(4) + rdlen(2) + rdata(4))
    const responseLen = 12 + nameLen + 4 + 2 + 2 + 2 + 4 + 2 + 4;
    const response = new Uint8Array(responseLen);

    // Header
    response[0] = (query.id >> 8) & 0xFF;
    response[1] = query.id & 0xFF;
    response[2] = 0x81;             // QR=1, RD=1
    response[3] = 0x80;             // RA=1
    response[4] = 0x00; response[5] = 0x01;  // QDCOUNT = 1
    response[6] = 0x00; response[7] = 0x01;  // ANCOUNT = 1
    response[8] = 0x00; response[9] = 0x00;  // NSCOUNT = 0
    response[10] = 0x00; response[11] = 0x00; // ARCOUNT = 0

    // Question section
    let offset = 12;
    for (const b of nameBytes) {
        response[offset++] = b;
    }
    response[offset++] = 0x00; response[offset++] = 0x01; // TYPE A
    response[offset++] = 0x00; response[offset++] = 0x01; // CLASS IN

    // Answer section — use pointer to name in question
    response[offset++] = 0xC0; response[offset++] = 0x0C; // Name pointer to offset 12
    response[offset++] = 0x00; response[offset++] = 0x01; // TYPE A
    response[offset++] = 0x00; response[offset++] = 0x01; // CLASS IN
    response[offset++] = (ttl >> 24) & 0xFF;
    response[offset++] = (ttl >> 16) & 0xFF;
    response[offset++] = (ttl >> 8) & 0xFF;
    response[offset++] = ttl & 0xFF;
    response[offset++] = 0x00; response[offset++] = 0x04; // RDLENGTH = 4

    // RDATA — IP address
    const ipParts = ip.split('.');
    for (let i = 0; i < 4; i++) {
        response[offset++] = parseInt(ipParts[i] ?? '0', 10);
    }

    return response;
}

/**
 * Build an NXDOMAIN DNS response.
 */
export function buildDNSNXDomain(queryId: number): Uint8Array {
    const response = new Uint8Array(12);
    response[0] = (queryId >> 8) & 0xFF;
    response[1] = queryId & 0xFF;
    response[2] = 0x81;         // QR=1, RD=1
    response[3] = 0x83;         // RA=1, RCODE=3 (NXDOMAIN)
    // All counts = 0
    return response;
}

// ── UDP Packet Builder ─────────────────────────────────────────

/**
 * Build a complete Ethernet + IPv4 + UDP frame.
 * Used for DNS responses and other fabric-generated traffic.
 */
export function buildUDPFrame(params: {
    readonly srcMAC: string;
    readonly dstMAC: string;
    readonly srcIP: string;
    readonly dstIP: string;
    readonly srcPort: number;
    readonly dstPort: number;
    readonly payload: Uint8Array;
}): Uint8Array {
    const udpLen = 8 + params.payload.length;
    const ipLen = 20 + udpLen;
    const frameLen = 14 + ipLen;
    const frame = new Uint8Array(frameLen);

    // Ethernet header
    frame.set(macToBytes(params.dstMAC), 0);
    frame.set(macToBytes(params.srcMAC), 6);
    frame[12] = 0x08; frame[13] = 0x00; // IPv4

    // IPv4 header
    let off = 14;
    frame[off] = 0x45;                     // Version 4, IHL 5
    frame[off + 1] = 0x00;                 // DSCP/ECN
    frame[off + 2] = (ipLen >> 8) & 0xFF;
    frame[off + 3] = ipLen & 0xFF;
    frame[off + 4] = 0x00; frame[off + 5] = 0x00; // ID
    frame[off + 6] = 0x40; frame[off + 7] = 0x00; // Don't fragment
    frame[off + 8] = 64;                   // TTL
    frame[off + 9] = 17;                   // Protocol: UDP

    // Source IP
    const srcParts = params.srcIP.split('.');
    for (let i = 0; i < 4; i++) {
        frame[off + 12 + i] = parseInt(srcParts[i] ?? '0', 10);
    }
    // Dest IP
    const dstParts = params.dstIP.split('.');
    for (let i = 0; i < 4; i++) {
        frame[off + 16 + i] = parseInt(dstParts[i] ?? '0', 10);
    }

    // IP checksum
    let sum = 0;
    for (let i = 0; i < 20; i += 2) {
        sum += (frame[off + i]! << 8) | frame[off + i + 1]!;
    }
    while (sum > 0xFFFF) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    const checksum = (~sum) & 0xFFFF;
    frame[off + 10] = (checksum >> 8) & 0xFF;
    frame[off + 11] = checksum & 0xFF;

    // UDP header
    off = 34;
    frame[off] = (params.srcPort >> 8) & 0xFF;
    frame[off + 1] = params.srcPort & 0xFF;
    frame[off + 2] = (params.dstPort >> 8) & 0xFF;
    frame[off + 3] = params.dstPort & 0xFF;
    frame[off + 4] = (udpLen >> 8) & 0xFF;
    frame[off + 5] = udpLen & 0xFF;
    // UDP checksum = 0 (optional for IPv4)
    frame[off + 6] = 0x00;
    frame[off + 7] = 0x00;

    // Payload
    frame.set(params.payload, 42);

    return frame;
}

// ── Full Frame Parser ──────────────────────────────────────────

export interface ParsedFrame {
    readonly ethernet: EthernetHeader;
    readonly ipv4: IPv4Header | null;
    readonly tcp: TCPHeader | null;
    readonly udp: UDPHeader | null;
    readonly arp: ARPPacket | null;
    readonly dns: DNSQuery | null;
    readonly payloadOffset: number;
    readonly payloadLength: number;
}

/**
 * Parse a complete Ethernet frame into structured data.
 * Returns null for frames too short to have a valid Ethernet header.
 */
export function parseFrame(frame: Uint8Array): ParsedFrame | null {
    const ethernet = parseEthernetHeader(frame);
    if (ethernet === null) return null;

    let ipv4: IPv4Header | null = null;
    let tcp: TCPHeader | null = null;
    let udp: UDPHeader | null = null;
    let arp: ARPPacket | null = null;
    let dns: DNSQuery | null = null;
    let payloadOffset = ETHERNET_HEADER_SIZE;
    let payloadLength = frame.length - ETHERNET_HEADER_SIZE;

    if (ethernet.etherType === ETHER_TYPE.ARP) {
        arp = parseARP(frame, ETHERNET_HEADER_SIZE);
        payloadOffset = ETHERNET_HEADER_SIZE + ARP_HEADER_SIZE;
        payloadLength = Math.max(0, frame.length - payloadOffset);
    } else if (ethernet.etherType === ETHER_TYPE.IPv4) {
        ipv4 = parseIPv4Header(frame, ETHERNET_HEADER_SIZE);

        if (ipv4 !== null) {
            const transportOffset = ETHERNET_HEADER_SIZE + ipv4.headerLength;

            if (ipv4.protocol === IP_PROTOCOL.TCP) {
                tcp = parseTCPHeader(frame, transportOffset);
                if (tcp !== null) {
                    payloadOffset = transportOffset + tcp.dataOffset;
                    payloadLength = Math.max(0, frame.length - payloadOffset);
                }
            } else if (ipv4.protocol === IP_PROTOCOL.UDP) {
                udp = parseUDPHeader(frame, transportOffset);
                if (udp !== null) {
                    payloadOffset = transportOffset + UDP_HEADER_SIZE;
                    payloadLength = Math.max(0, udp.length - UDP_HEADER_SIZE);

                    // Check for DNS (port 53)
                    if (udp.destPort === 53 || udp.sourcePort === 53) {
                        dns = parseDNSQuery(
                            frame.slice(payloadOffset, payloadOffset + payloadLength),
                        );
                    }
                }
            }
        }
    }

    return {
        ethernet,
        ipv4,
        tcp,
        udp,
        arp,
        dns,
        payloadOffset,
        payloadLength,
    };
}
