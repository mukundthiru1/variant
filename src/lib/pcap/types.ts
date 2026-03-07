/**
 * VARIANT — Packet Capture (PCAP) Types
 *
 * Simulates tcpdump/Wireshark-style packet capture and analysis.
 * Players learn to capture, filter, and analyze network traffic.
 *
 * EXTENSIBILITY: Custom protocol decoders via registry.
 * SWAPPABILITY: Implements PcapEngine interface.
 */

// ── Captured Packet ───────────────────────────────────────

export interface CapturedPacket {
    readonly id: string;
    readonly tick: number;
    readonly timestamp: number;
    readonly interfaceName: string;
    readonly length: number;
    readonly capturedLength: number;
    readonly layers: readonly ProtocolLayer[];
    readonly raw: string;
    readonly direction: 'inbound' | 'outbound' | 'local';
    readonly matched?: boolean;
}

export interface ProtocolLayer {
    readonly protocol: ProtocolType;
    readonly headerLength: number;
    readonly fields: Readonly<Record<string, string | number | boolean>>;
}

export type ProtocolType =
    | 'ethernet' | 'arp'
    | 'ipv4' | 'ipv6'
    | 'tcp' | 'udp' | 'icmp' | 'icmpv6'
    | 'http' | 'https' | 'dns' | 'dhcp'
    | 'tls' | 'ssh' | 'ftp' | 'smtp' | 'pop3' | 'imap'
    | 'ntp' | 'snmp' | 'syslog'
    | 'sip' | 'rtp'
    | 'smb' | 'ldap' | 'kerberos'
    | 'raw'
    | (string & {});

// ── Capture Filter (BPF-style) ────────────────────────────

export interface CaptureFilter {
    readonly expression: string;
    readonly compiled?: BPFProgram;
}

export interface BPFProgram {
    readonly instructions: readonly BPFInstruction[];
}

export interface BPFInstruction {
    readonly op: BPFOpcode;
    readonly jt: number;
    readonly jf: number;
    readonly k: number;
}

export type BPFOpcode =
    | 'ld' | 'ldh' | 'ldb'
    | 'st' | 'stx'
    | 'add' | 'sub' | 'mul' | 'div' | 'mod'
    | 'and' | 'or' | 'xor' | 'lsh' | 'rsh'
    | 'jeq' | 'jgt' | 'jge' | 'jset'
    | 'ret' | 'tax' | 'txa'
    | (string & {});

// ── Display Filter (Wireshark-style) ──────────────────────

export interface DisplayFilter {
    readonly expression: string;
    readonly field: string;
    readonly operator: DisplayFilterOp;
    readonly value: string;
    readonly logic?: 'and' | 'or' | 'not';
    readonly children?: readonly DisplayFilter[];
}

export type DisplayFilterOp =
    | 'eq' | 'ne' | 'gt' | 'lt' | 'ge' | 'le'
    | 'contains' | 'matches'
    | 'bitwise_and'
    | (string & {});

// ── Capture Session ───────────────────────────────────────

export interface CaptureSession {
    readonly id: string;
    readonly interfaceName: string;
    readonly startTick: number;
    readonly endTick?: number;
    readonly filter?: CaptureFilter;
    readonly snapLength: number;
    readonly promiscuous: boolean;
    readonly packetCount: number;
    readonly byteCount: number;
    readonly active: boolean;
}

// ── Network Interface ─────────────────────────────────────

export interface NetworkInterface {
    readonly name: string;
    readonly addresses: readonly string[];
    readonly mac: string;
    readonly mtu: number;
    readonly up: boolean;
    readonly promiscuous: boolean;
    readonly type: 'ethernet' | 'loopback' | 'wireless' | 'tunnel' | 'bridge' | (string & {});
}

// ── Protocol Statistics ───────────────────────────────────

export interface ProtocolStats {
    readonly protocol: string;
    readonly packetCount: number;
    readonly byteCount: number;
    readonly percentage: number;
}

export interface ConversationEntry {
    readonly addressA: string;
    readonly portA: number;
    readonly addressB: string;
    readonly portB: number;
    readonly protocol: string;
    readonly packets: number;
    readonly bytes: number;
    readonly startTick: number;
    readonly lastTick: number;
}

// ── Stream Reassembly ─────────────────────────────────────

export interface TCPStream {
    readonly id: string;
    readonly sourceIP: string;
    readonly sourcePort: number;
    readonly destIP: string;
    readonly destPort: number;
    readonly state: TCPState;
    readonly clientData: string;
    readonly serverData: string;
    readonly packets: number;
    readonly startTick: number;
    readonly lastTick: number;
}

export type TCPState =
    | 'syn_sent' | 'syn_received' | 'established'
    | 'fin_wait_1' | 'fin_wait_2' | 'close_wait'
    | 'closing' | 'last_ack' | 'time_wait' | 'closed'
    | (string & {});

// ── DNS Resolution Cache ──────────────────────────────────

export interface DNSRecord {
    readonly query: string;
    readonly type: DNSRecordType;
    readonly answer: string;
    readonly ttl: number;
    readonly tick: number;
}

export type DNSRecordType =
    | 'A' | 'AAAA' | 'CNAME' | 'MX' | 'NS' | 'PTR'
    | 'SOA' | 'SRV' | 'TXT' | 'CAA'
    | (string & {});

// ── Anomaly Detection ─────────────────────────────────────

export interface PcapAnomaly {
    readonly id: string;
    readonly type: PcapAnomalyType;
    readonly severity: 'low' | 'medium' | 'high' | 'critical';
    readonly description: string;
    readonly packetIds: readonly string[];
    readonly tick: number;
    readonly mitre?: string;
}

export type PcapAnomalyType =
    | 'port_scan' | 'syn_flood' | 'arp_spoof'
    | 'dns_tunnel' | 'dns_exfil'
    | 'large_transfer' | 'beaconing'
    | 'cleartext_credentials' | 'suspicious_tls'
    | 'icmp_tunnel' | 'protocol_anomaly'
    | 'smb_lateral' | 'kerberoasting'
    | (string & {});

// ── Pcap Engine Interface ─────────────────────────────────

export interface PcapEngine {
    /** Start a capture session on an interface. */
    startCapture(interfaceName: string, options?: CaptureOptions): CaptureSession;
    /** Stop a capture session. */
    stopCapture(sessionId: string): CaptureSession | null;
    /** Inject a packet into the capture pipeline. */
    injectPacket(packet: Omit<CapturedPacket, 'id' | 'matched'>): CapturedPacket;
    /** Apply a display filter to captured packets. */
    applyFilter(filter: string): readonly CapturedPacket[];
    /** Parse a BPF filter expression. */
    parseBPF(expression: string): CaptureFilter;
    /** Get all captured packets. */
    getPackets(): readonly CapturedPacket[];
    /** Get packets for a specific session. */
    getSessionPackets(sessionId: string): readonly CapturedPacket[];
    /** Follow a TCP stream. */
    followTCPStream(sourceIP: string, sourcePort: number, destIP: string, destPort: number): TCPStream | null;
    /** Get all TCP streams. */
    getTCPStreams(): readonly TCPStream[];
    /** Get protocol statistics. */
    getProtocolStats(): readonly ProtocolStats[];
    /** Get conversation list. */
    getConversations(): readonly ConversationEntry[];
    /** Get DNS records observed. */
    getDNSRecords(): readonly DNSRecord[];
    /** Detect anomalies in captured traffic. */
    detectAnomalies(): readonly PcapAnomaly[];
    /** Get active sessions. */
    getSessions(): readonly CaptureSession[];
    /** Get interfaces. */
    getInterfaces(): readonly NetworkInterface[];
    /** Add a network interface. */
    addInterface(iface: NetworkInterface): void;
    /** Format packet as tcpdump one-liner. */
    formatTcpdump(packet: CapturedPacket): string;
    /** Format packet as hex dump. */
    formatHexDump(packet: CapturedPacket): string;
    /** Export as pcap-ng (simplified text representation). */
    exportPcapNg(sessionId?: string): string;
    /** Get engine stats. */
    getStats(): PcapStats;
    /** Clear all captured data. */
    clear(): void;
}

export interface CaptureOptions {
    readonly filter?: string;
    readonly snapLength?: number;
    readonly promiscuous?: boolean;
    readonly maxPackets?: number;
}

export interface PcapStats {
    readonly totalPackets: number;
    readonly totalBytes: number;
    readonly activeSessions: number;
    readonly totalSessions: number;
    readonly tcpStreams: number;
    readonly dnsQueries: number;
    readonly anomaliesDetected: number;
    readonly protocolBreakdown: Readonly<Record<string, number>>;
}
