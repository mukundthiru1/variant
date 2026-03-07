/**
 * VARIANT — Packet Capture Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createPcapEngine, bootstrapInterfaces } from '../../../src/lib/pcap/pcap-engine';
import type { CapturedPacket, ProtocolLayer } from '../../../src/lib/pcap/types';

function makeEthLayer(overrides?: Record<string, string | number | boolean>): ProtocolLayer {
    return {
        protocol: 'ethernet',
        headerLength: 14,
        fields: { src: '00:11:22:33:44:55', dst: 'ff:ff:ff:ff:ff:ff', type: '0x0800', ...overrides },
    };
}

function makeIPv4Layer(overrides?: Record<string, string | number | boolean>): ProtocolLayer {
    return {
        protocol: 'ipv4',
        headerLength: 20,
        fields: { src: '192.168.1.100', dst: '10.0.0.1', ttl: 64, proto: 6, ...overrides },
    };
}

function makeTCPLayer(overrides?: Record<string, string | number | boolean>): ProtocolLayer {
    return {
        protocol: 'tcp',
        headerLength: 20,
        fields: { srcPort: 45000, dstPort: 80, seq: 1000, ackNum: 0, syn: false, ack: false, fin: false, rst: false, psh: false, window: 65535, ...overrides },
    };
}

function makeUDPLayer(overrides?: Record<string, string | number | boolean>): ProtocolLayer {
    return {
        protocol: 'udp',
        headerLength: 8,
        fields: { srcPort: 12345, dstPort: 53, length: 64, ...overrides },
    };
}

function makeDNSLayer(overrides?: Record<string, string | number | boolean>): ProtocolLayer {
    return {
        protocol: 'dns',
        headerLength: 12,
        fields: { queryName: 'example.com', queryType: 'A', response: false, ...overrides },
    };
}

function makePacket(layers: ProtocolLayer[], overrides?: Partial<Omit<CapturedPacket, 'id' | 'matched'>>): Omit<CapturedPacket, 'id' | 'matched'> {
    return {
        tick: 1,
        timestamp: Date.now(),
        interfaceName: 'eth0',
        length: 100,
        capturedLength: 100,
        layers,
        raw: '4500003c1c4640004006b1d6c0a80164ac100a01',
        direction: 'inbound',
        ...overrides,
    };
}

function setupEngine() {
    const pcap = createPcapEngine();
    for (const iface of bootstrapInterfaces()) {
        pcap.addInterface(iface);
    }
    return pcap;
}

describe('PcapEngine', () => {
    // ── Creation & Interfaces ─────────────────────────────

    it('creates with empty state', () => {
        const pcap = createPcapEngine();
        expect(pcap.getPackets()).toHaveLength(0);
        expect(pcap.getSessions()).toHaveLength(0);
        expect(pcap.getInterfaces()).toHaveLength(0);
    });

    it('adds interfaces', () => {
        const pcap = setupEngine();
        const ifaces = pcap.getInterfaces();
        expect(ifaces.length).toBeGreaterThanOrEqual(3);
        expect(ifaces.some(i => i.name === 'eth0')).toBe(true);
        expect(ifaces.some(i => i.name === 'lo')).toBe(true);
    });

    it('bootstrap provides standard interfaces', () => {
        const ifaces = bootstrapInterfaces();
        expect(ifaces).toHaveLength(3);
        expect(ifaces[0]!.name).toBe('eth0');
        expect(ifaces[1]!.name).toBe('lo');
        expect(ifaces[2]!.name).toBe('docker0');
    });

    // ── Packet Injection ──────────────────────────────────

    it('injects and retrieves packets', () => {
        const pcap = setupEngine();
        const pkt = pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer(), makeTCPLayer()]));
        expect(pkt.id).toBeTruthy();
        expect(pcap.getPackets()).toHaveLength(1);
    });

    it('assigns unique IDs to packets', () => {
        const pcap = setupEngine();
        const p1 = pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer()]));
        const p2 = pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer()]));
        expect(p1.id).not.toBe(p2.id);
    });

    // ── Capture Sessions ──────────────────────────────────

    it('starts and stops capture sessions', () => {
        const pcap = setupEngine();
        const session = pcap.startCapture('eth0');
        expect(session.active).toBe(true);
        expect(session.interfaceName).toBe('eth0');

        const stopped = pcap.stopCapture(session.id);
        expect(stopped).not.toBeNull();
        expect(stopped!.active).toBe(false);
    });

    it('throws for unknown interface', () => {
        const pcap = setupEngine();
        expect(() => pcap.startCapture('nonexistent')).toThrow();
    });

    it('returns null when stopping unknown session', () => {
        const pcap = setupEngine();
        expect(pcap.stopCapture('nonexistent')).toBeNull();
    });

    it('captures packets matching session interface', () => {
        const pcap = setupEngine();
        const session = pcap.startCapture('eth0');

        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer()], { interfaceName: 'eth0' }));
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer()], { interfaceName: 'lo' }));

        const sessionPkts = pcap.getSessionPackets(session.id);
        expect(sessionPkts).toHaveLength(1);
    });

    it('applies BPF filter to capture sessions', () => {
        const pcap = setupEngine();
        const session = pcap.startCapture('eth0', { filter: 'tcp' });

        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer(), makeTCPLayer()], { interfaceName: 'eth0' }));
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer(), makeUDPLayer()], { interfaceName: 'eth0' }));

        const sessionPkts = pcap.getSessionPackets(session.id);
        expect(sessionPkts).toHaveLength(1);
    });

    // ── BPF Filters ───────────────────────────────────────

    it('parses BPF filter expressions', () => {
        const pcap = createPcapEngine();
        const filter = pcap.parseBPF('tcp and port 80');
        expect(filter.expression).toBe('tcp and port 80');
    });

    // ── Display Filters ───────────────────────────────────

    it('applies protocol display filter', () => {
        const pcap = setupEngine();
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer(), makeTCPLayer()]));
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer(), makeUDPLayer()]));

        const tcpOnly = pcap.applyFilter('tcp');
        expect(tcpOnly).toHaveLength(1);

        const udpOnly = pcap.applyFilter('udp');
        expect(udpOnly).toHaveLength(1);
    });

    it('applies field comparison display filter', () => {
        const pcap = setupEngine();
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer({ src: '192.168.1.100' }), makeTCPLayer()]));
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer({ src: '10.0.0.5' }), makeTCPLayer()]));

        const filtered = pcap.applyFilter('ip.src == 192.168.1.100');
        expect(filtered).toHaveLength(1);
    });

    it('applies port display filter', () => {
        const pcap = setupEngine();
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer(), makeTCPLayer({ dstPort: 80 })]));
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer(), makeTCPLayer({ dstPort: 443 })]));

        const http = pcap.applyFilter('tcp.dstport == 80');
        expect(http).toHaveLength(1);
    });

    it('applies AND display filter', () => {
        const pcap = setupEngine();
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer({ src: '192.168.1.100' }), makeTCPLayer({ dstPort: 80 })]));
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer({ src: '192.168.1.100' }), makeTCPLayer({ dstPort: 443 })]));

        const filtered = pcap.applyFilter('ip.src == 192.168.1.100 && tcp.dstport == 80');
        expect(filtered).toHaveLength(1);
    });

    it('applies NOT display filter', () => {
        const pcap = setupEngine();
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer(), makeTCPLayer()]));
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer(), makeUDPLayer()]));

        const notTcp = pcap.applyFilter('!tcp');
        expect(notTcp).toHaveLength(1);
    });

    it('returns all packets for empty filter', () => {
        const pcap = setupEngine();
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer()]));
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer()]));
        expect(pcap.applyFilter('')).toHaveLength(2);
    });

    // ── TCP Stream Reassembly ─────────────────────────────

    it('tracks TCP streams', () => {
        const pcap = setupEngine();

        // SYN
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer({ src: '192.168.1.100', dst: '10.0.0.1' }), makeTCPLayer({ srcPort: 45000, dstPort: 80, syn: true })]));
        // SYN-ACK
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer({ src: '10.0.0.1', dst: '192.168.1.100' }), makeTCPLayer({ srcPort: 80, dstPort: 45000, syn: true, ack: true })]));
        // ACK
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer({ src: '192.168.1.100', dst: '10.0.0.1' }), makeTCPLayer({ srcPort: 45000, dstPort: 80, ack: true })]));

        const streams = pcap.getTCPStreams();
        expect(streams).toHaveLength(1);
        expect(streams[0]!.state).toBe('established');
    });

    it('reassembles stream data', () => {
        const pcap = setupEngine();

        // Established connection with data
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer({ src: '192.168.1.100', dst: '10.0.0.1' }), makeTCPLayer({ srcPort: 45000, dstPort: 80, syn: true })]));
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer({ src: '10.0.0.1', dst: '192.168.1.100' }), makeTCPLayer({ srcPort: 80, dstPort: 45000, syn: true, ack: true })]));
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer({ src: '192.168.1.100', dst: '10.0.0.1' }), makeTCPLayer({ srcPort: 45000, dstPort: 80, ack: true, payload: 'GET / HTTP/1.1\r\n' })]));
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer({ src: '10.0.0.1', dst: '192.168.1.100' }), makeTCPLayer({ srcPort: 80, dstPort: 45000, ack: true, payload: 'HTTP/1.1 200 OK\r\n' })]));

        const stream = pcap.followTCPStream('192.168.1.100', 45000, '10.0.0.1', 80);
        expect(stream).not.toBeNull();
        expect(stream!.clientData).toContain('GET / HTTP/1.1');
        expect(stream!.serverData).toContain('HTTP/1.1 200 OK');
    });

    it('returns null for nonexistent stream', () => {
        const pcap = setupEngine();
        expect(pcap.followTCPStream('1.2.3.4', 1, '5.6.7.8', 2)).toBeNull();
    });

    // ── DNS Tracking ──────────────────────────────────────

    it('tracks DNS responses', () => {
        const pcap = setupEngine();

        pcap.injectPacket(makePacket([
            makeEthLayer(),
            makeIPv4Layer({ src: '10.0.0.1', dst: '192.168.1.100' }),
            makeUDPLayer({ srcPort: 53, dstPort: 12345 }),
            makeDNSLayer({ queryName: 'example.com', queryType: 'A', answer: '93.184.216.34', response: true, ttl: 300 }),
        ]));

        const records = pcap.getDNSRecords();
        expect(records).toHaveLength(1);
        expect(records[0]!.query).toBe('example.com');
        expect(records[0]!.answer).toBe('93.184.216.34');
    });

    it('does not track DNS queries (only responses)', () => {
        const pcap = setupEngine();

        pcap.injectPacket(makePacket([
            makeEthLayer(),
            makeIPv4Layer(),
            makeUDPLayer({ srcPort: 12345, dstPort: 53 }),
            makeDNSLayer({ queryName: 'example.com', response: false }),
        ]));

        expect(pcap.getDNSRecords()).toHaveLength(0);
    });

    // ── Protocol Statistics ───────────────────────────────

    it('calculates protocol statistics', () => {
        const pcap = setupEngine();

        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer(), makeTCPLayer()]));
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer(), makeTCPLayer()]));
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer(), makeUDPLayer()]));

        const stats = pcap.getProtocolStats();
        const tcpStats = stats.find(s => s.protocol === 'tcp');
        const udpStats = stats.find(s => s.protocol === 'udp');

        expect(tcpStats).toBeTruthy();
        expect(tcpStats!.packetCount).toBe(2);
        expect(udpStats!.packetCount).toBe(1);
        expect(tcpStats!.percentage).toBeCloseTo(66.67, 0);
    });

    // ── Conversations ─────────────────────────────────────

    it('tracks conversations', () => {
        const pcap = setupEngine();

        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer({ src: '192.168.1.100', dst: '10.0.0.1' }), makeTCPLayer({ srcPort: 45000, dstPort: 80 })]));
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer({ src: '10.0.0.1', dst: '192.168.1.100' }), makeTCPLayer({ srcPort: 80, dstPort: 45000 })]));

        const convs = pcap.getConversations();
        expect(convs).toHaveLength(1);
        expect(convs[0]!.packets).toBe(2);
    });

    // ── Anomaly Detection ─────────────────────────────────

    it('detects port scanning', () => {
        const pcap = setupEngine();

        // Inject SYN packets to 25+ different ports from same source
        for (let port = 1; port <= 25; port++) {
            pcap.injectPacket(makePacket([
                makeEthLayer(),
                makeIPv4Layer({ src: '192.168.1.100', dst: '10.0.0.1' }),
                makeTCPLayer({ srcPort: 45000, dstPort: port, syn: true }),
            ]));
        }

        const anomalies = pcap.detectAnomalies();
        const portScan = anomalies.find(a => a.type === 'port_scan');
        expect(portScan).toBeTruthy();
        expect(portScan!.mitre).toBe('T1046');
    });

    it('detects ARP spoofing', () => {
        const pcap = setupEngine();

        const arpLayer1: ProtocolLayer = {
            protocol: 'arp',
            headerLength: 28,
            fields: { opcode: 2, senderIP: '10.0.0.1', senderMAC: '00:11:22:33:44:55', targetIP: '10.0.0.5' },
        };
        const arpLayer2: ProtocolLayer = {
            protocol: 'arp',
            headerLength: 28,
            fields: { opcode: 2, senderIP: '10.0.0.1', senderMAC: 'aa:bb:cc:dd:ee:ff', targetIP: '10.0.0.5' },
        };

        pcap.injectPacket(makePacket([makeEthLayer(), arpLayer1]));
        pcap.injectPacket(makePacket([makeEthLayer(), arpLayer2]));

        const anomalies = pcap.detectAnomalies();
        const arpSpoof = anomalies.find(a => a.type === 'arp_spoof');
        expect(arpSpoof).toBeTruthy();
        expect(arpSpoof!.mitre).toBe('T1557.002');
    });

    it('detects DNS tunneling', () => {
        const pcap = setupEngine();

        const longQueryName = 'a'.repeat(65) + '.tunnel.evil.com';
        pcap.injectPacket(makePacket([
            makeEthLayer(),
            makeIPv4Layer({ src: '10.0.0.1', dst: '192.168.1.100' }),
            makeUDPLayer({ srcPort: 53 }),
            makeDNSLayer({ queryName: longQueryName, answer: '1.2.3.4', response: true }),
        ]));

        const anomalies = pcap.detectAnomalies();
        const dnsTunnel = anomalies.find(a => a.type === 'dns_tunnel');
        expect(dnsTunnel).toBeTruthy();
        expect(dnsTunnel!.mitre).toBe('T1071.004');
    });

    it('detects beaconing behavior', () => {
        const pcap = setupEngine();

        // Regular interval connections to external IP
        for (let i = 0; i < 10; i++) {
            pcap.injectPacket(makePacket([
                makeEthLayer(),
                makeIPv4Layer({ src: '192.168.1.100', dst: '203.0.113.50' }),
                makeTCPLayer({ srcPort: 45000 + i, dstPort: 443 }),
            ], { tick: i * 60 })); // Every 60 ticks
        }

        const anomalies = pcap.detectAnomalies();
        const beacon = anomalies.find(a => a.type === 'beaconing');
        expect(beacon).toBeTruthy();
        expect(beacon!.mitre).toBe('T1071');
    });

    it('detects cleartext HTTP credentials', () => {
        const pcap = setupEngine();

        const httpLayer: ProtocolLayer = {
            protocol: 'http',
            headerLength: 0,
            fields: { method: 'GET', uri: '/admin', authorization: 'Basic YWRtaW46cGFzc3dvcmQ=' },
        };

        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer(), makeTCPLayer({ dstPort: 80 }), httpLayer]));

        const anomalies = pcap.detectAnomalies();
        const creds = anomalies.find(a => a.type === 'cleartext_credentials');
        expect(creds).toBeTruthy();
        expect(creds!.severity).toBe('critical');
    });

    // ── Output Formatting ─────────────────────────────────

    it('formats packets as tcpdump output', () => {
        const pcap = setupEngine();
        const pkt = pcap.injectPacket(makePacket([
            makeEthLayer(),
            makeIPv4Layer({ src: '192.168.1.100', dst: '10.0.0.1' }),
            makeTCPLayer({ srcPort: 45000, dstPort: 80, syn: true }),
        ]));

        const output = pcap.formatTcpdump(pkt);
        expect(output).toContain('192.168.1.100.45000');
        expect(output).toContain('10.0.0.1.80');
        expect(output).toContain('[S');
    });

    it('formats UDP packets as tcpdump output', () => {
        const pcap = setupEngine();
        const pkt = pcap.injectPacket(makePacket([
            makeEthLayer(),
            makeIPv4Layer({ src: '192.168.1.100', dst: '10.0.0.1' }),
            makeUDPLayer({ srcPort: 12345, dstPort: 53 }),
        ]));

        const output = pcap.formatTcpdump(pkt);
        expect(output).toContain('UDP');
    });

    it('formats packets as hex dump', () => {
        const pcap = setupEngine();
        const pkt = pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer()], {
            raw: '4500003c1c4640004006b1d6c0a80164ac100a01',
        }));

        const hex = pcap.formatHexDump(pkt);
        expect(hex).toContain('00000000');
        expect(hex).toContain('45');
    });

    // ── Export ─────────────────────────────────────────────

    it('exports as pcap-ng text format', () => {
        const pcap = setupEngine();
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer(), makeTCPLayer()]));
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer(), makeUDPLayer()]));

        const exported = pcap.exportPcapNg();
        expect(exported).toContain('PCAP-NG Export');
        expect(exported).toContain('Packets: 2');
        expect(exported).toContain('tcp:');
    });

    // ── Stats ─────────────────────────────────────────────

    it('reports engine statistics', () => {
        const pcap = setupEngine();
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer(), makeTCPLayer()], { length: 100 }));
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer(), makeUDPLayer()], { length: 64 }));

        const stats = pcap.getStats();
        expect(stats.totalPackets).toBe(2);
        expect(stats.totalBytes).toBe(164);
        expect(stats.protocolBreakdown['tcp']).toBe(1);
        expect(stats.protocolBreakdown['udp']).toBe(1);
    });

    // ── Clear ─────────────────────────────────────────────

    it('clears all captured data', () => {
        const pcap = setupEngine();
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer()]));
        pcap.injectPacket(makePacket([makeEthLayer(), makeIPv4Layer()]));
        expect(pcap.getPackets()).toHaveLength(2);

        pcap.clear();
        expect(pcap.getPackets()).toHaveLength(0);
        expect(pcap.getTCPStreams()).toHaveLength(0);
        expect(pcap.getDNSRecords()).toHaveLength(0);
        expect(pcap.getConversations()).toHaveLength(0);
        expect(pcap.getStats().totalPackets).toBe(0);
    });
});
