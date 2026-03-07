/**
 * VARIANT — Frame Parser Tests
 *
 * Tests the Ethernet frame parser used by the network fabric.
 * All tests use hand-crafted byte arrays to ensure correctness.
 */

import { describe, it, expect } from 'vitest';
import {
    parseEthernetHeader,
    parseIPv4Header,
    parseTCPHeader,
    parseUDPHeader,
    parseARP,
    parseDNSQuery,
    buildDNSResponse,
    buildDNSNXDomain,
    buildARPReply,
    buildUDPFrame,
    parseFrame,
    isInSubnet,
    ipToUint32,
    uint32ToIP,
    macToBytes,
    isBroadcastMAC,
    ETHER_TYPE,
    ARP_OP,
} from '../../src/core/fabric/frames';

describe('Frame Parser', () => {
    describe('Ethernet', () => {
        it('parses a valid Ethernet header', () => {
            // dst: 02:00:00:00:00:01, src: 02:00:00:00:00:02, type: IPv4
            const frame = new Uint8Array([
                0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // dst MAC
                0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // src MAC
                0x08, 0x00,                           // EtherType IPv4
            ]);

            const header = parseEthernetHeader(frame);
            expect(header).not.toBeNull();
            expect(header!.destMAC).toBe('02:00:00:00:00:01');
            expect(header!.sourceMAC).toBe('02:00:00:00:00:02');
            expect(header!.etherType).toBe(ETHER_TYPE.IPv4);
        });

        it('rejects frames shorter than 14 bytes', () => {
            const frame = new Uint8Array([0x02, 0x00, 0x00]);
            expect(parseEthernetHeader(frame)).toBeNull();
        });
    });

    describe('IPv4', () => {
        it('parses a valid IPv4 header', () => {
            const header = new Uint8Array([
                0x45, 0x00,             // Version 4, IHL 5, DSCP 0
                0x00, 0x28,             // Total length: 40
                0x00, 0x00, 0x40, 0x00, // ID, flags, fragment offset
                0x40,                   // TTL: 64
                0x06,                   // Protocol: TCP
                0x00, 0x00,             // Checksum (0 for test)
                0x0a, 0x00, 0x01, 0x05, // Source: 10.0.1.5
                0x0a, 0x00, 0x01, 0x0a, // Dest: 10.0.1.10
            ]);

            const result = parseIPv4Header(header, 0);
            expect(result).not.toBeNull();
            expect(result!.version).toBe(4);
            expect(result!.headerLength).toBe(20);
            expect(result!.protocol).toBe(6); // TCP
            expect(result!.sourceIP).toBe('10.0.1.5');
            expect(result!.destIP).toBe('10.0.1.10');
            expect(result!.ttl).toBe(64);
        });

        it('rejects non-IPv4 packets', () => {
            const header = new Uint8Array([
                0x60, 0x00, 0x00, 0x00, // IPv6 header
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]);
            expect(parseIPv4Header(header, 0)).toBeNull();
        });
    });

    describe('TCP', () => {
        it('parses TCP header with SYN flag', () => {
            const header = new Uint8Array([
                0x00, 0x50,             // Source port: 80
                0xC0, 0x08,             // Dest port: 49160
                0x00, 0x00, 0x00, 0x01, // Seq number
                0x00, 0x00, 0x00, 0x00, // Ack number
                0x50,                   // Data offset: 5 (20 bytes)
                0x02,                   // Flags: SYN
                0xFF, 0xFF,             // Window size: 65535
                0x00, 0x00, 0x00, 0x00, // Checksum + urgent pointer
            ]);

            const result = parseTCPHeader(header, 0);
            expect(result).not.toBeNull();
            expect(result!.sourcePort).toBe(80);
            expect(result!.destPort).toBe(49160);
            expect(result!.flags.syn).toBe(true);
            expect(result!.flags.ack).toBe(false);
        });
    });

    describe('UDP', () => {
        it('parses a valid UDP header', () => {
            const header = new Uint8Array([
                0x00, 0x35,             // Source port: 53 (DNS)
                0xC0, 0x00,             // Dest port: 49152
                0x00, 0x20,             // Length: 32
                0x00, 0x00,             // Checksum
            ]);

            const result = parseUDPHeader(header, 0);
            expect(result).not.toBeNull();
            expect(result!.sourcePort).toBe(53);
            expect(result!.destPort).toBe(49152);
            expect(result!.length).toBe(32);
        });
    });

    describe('ARP', () => {
        it('parses an ARP request', () => {
            const arp = new Uint8Array([
                0x00, 0x01,             // Hardware type: Ethernet
                0x08, 0x00,             // Protocol type: IPv4
                0x06,                   // Hardware addr length: 6
                0x04,                   // Protocol addr length: 4
                0x00, 0x01,             // Operation: Request
                0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // Sender MAC
                0x0a, 0x00, 0x01, 0x05, // Sender IP: 10.0.1.5
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC (unknown)
                0x0a, 0x00, 0x01, 0x01, // Target IP: 10.0.1.1
            ]);

            const result = parseARP(arp, 0);
            expect(result).not.toBeNull();
            expect(result!.operation).toBe(ARP_OP.REQUEST);
            expect(result!.senderMAC).toBe('02:00:00:00:00:01');
            expect(result!.senderIP).toBe('10.0.1.5');
            expect(result!.targetIP).toBe('10.0.1.1');
        });
    });

    describe('DNS', () => {
        it('parses a DNS query for example.local', () => {
            // Standard DNS query for "example.local"
            const query = new Uint8Array([
                0x12, 0x34,             // ID: 0x1234
                0x01, 0x00,             // Flags: standard query, RD=1
                0x00, 0x01,             // QDCOUNT: 1
                0x00, 0x00,             // ANCOUNT: 0
                0x00, 0x00,             // NSCOUNT: 0
                0x00, 0x00,             // ARCOUNT: 0
                // Question: example.local
                0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
                0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c,               // "local"
                0x00,                   // null terminator
                0x00, 0x01,             // TYPE: A
                0x00, 0x01,             // CLASS: IN
            ]);

            const result = parseDNSQuery(query);
            expect(result).not.toBeNull();
            expect(result!.id).toBe(0x1234);
            expect(result!.domain).toBe('example.local');
            expect(result!.queryType).toBe(1); // A record
        });

        it('builds a DNS response', () => {
            const query = { id: 0x1234, domain: 'test.local', queryType: 1 };
            const response = buildDNSResponse(query, '10.0.1.5');

            // Verify it's a valid response
            expect(response.length).toBeGreaterThan(12);
            expect((response[0]! << 8) | response[1]!).toBe(0x1234); // ID matches
            expect(response[2]! & 0x80).toBe(0x80); // QR bit set (response)
            expect(response[3]! & 0x0F).toBe(0);    // RCODE = 0 (no error)
        });

        it('builds an NXDOMAIN response', () => {
            const response = buildDNSNXDomain(0xABCD);
            expect((response[0]! << 8) | response[1]!).toBe(0xABCD);
            expect(response[3]! & 0x0F).toBe(3); // RCODE = 3 (NXDOMAIN)
        });
    });

    describe('IP utilities', () => {
        it('converts IP to uint32 and back', () => {
            expect(uint32ToIP(ipToUint32('10.0.1.5'))).toBe('10.0.1.5');
            expect(uint32ToIP(ipToUint32('192.168.1.1'))).toBe('192.168.1.1');
            expect(uint32ToIP(ipToUint32('255.255.255.255'))).toBe('255.255.255.255');
            expect(uint32ToIP(ipToUint32('0.0.0.0'))).toBe('0.0.0.0');
        });

        it('checks subnet membership', () => {
            expect(isInSubnet('10.0.1.5', '10.0.1.0/24')).toBe(true);
            expect(isInSubnet('10.0.1.255', '10.0.1.0/24')).toBe(true);
            expect(isInSubnet('10.0.2.1', '10.0.1.0/24')).toBe(false);
            expect(isInSubnet('192.168.1.1', '192.168.0.0/16')).toBe(true);
            expect(isInSubnet('10.0.0.1', '10.0.0.0/8')).toBe(true);
        });

        it('handles /32 and /0', () => {
            expect(isInSubnet('10.0.1.5', '10.0.1.5/32')).toBe(true);
            expect(isInSubnet('10.0.1.6', '10.0.1.5/32')).toBe(false);
            expect(isInSubnet('10.0.1.5', '0.0.0.0/0')).toBe(true);
        });
    });

    describe('MAC utilities', () => {
        it('converts MAC string to bytes', () => {
            const bytes = macToBytes('02:00:00:00:00:01');
            expect(bytes[0]).toBe(2);
            expect(bytes[5]).toBe(1);
        });

        it('detects broadcast MAC', () => {
            expect(isBroadcastMAC('ff:ff:ff:ff:ff:ff')).toBe(true);
            expect(isBroadcastMAC('02:00:00:00:00:01')).toBe(false);
        });
    });

    describe('Frame builders', () => {
        it('builds a valid UDP frame', () => {
            const payload = new TextEncoder().encode('hello');
            const frame = buildUDPFrame({
                srcMAC: '02:00:00:00:00:01',
                dstMAC: '02:00:00:00:00:02',
                srcIP: '10.0.1.5',
                dstIP: '10.0.1.10',
                srcPort: 12345,
                dstPort: 80,
                payload,
            });

            // Parse it back
            const parsed = parseFrame(frame);
            expect(parsed).not.toBeNull();
            expect(parsed!.ethernet.sourceMAC).toBe('02:00:00:00:00:01');
            expect(parsed!.ethernet.destMAC).toBe('02:00:00:00:00:02');
            expect(parsed!.ipv4?.sourceIP).toBe('10.0.1.5');
            expect(parsed!.ipv4?.destIP).toBe('10.0.1.10');
            expect(parsed!.udp?.sourcePort).toBe(12345);
            expect(parsed!.udp?.destPort).toBe(80);
        });

        it('builds a valid ARP reply', () => {
            // Build an ARP request frame first
            const arpRequest = new Uint8Array(42);
            // Ethernet: broadcast dest, sender MAC
            arpRequest.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0);
            arpRequest.set([0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 6);
            arpRequest[12] = 0x08; arpRequest[13] = 0x06; // ARP

            // ARP header
            arpRequest[14] = 0x00; arpRequest[15] = 0x01; // Ethernet
            arpRequest[16] = 0x08; arpRequest[17] = 0x00; // IPv4
            arpRequest[18] = 6; arpRequest[19] = 4;
            arpRequest[20] = 0x00; arpRequest[21] = 0x01; // Request
            arpRequest.set([0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 22); // sender MAC
            arpRequest[28] = 10; arpRequest[29] = 0; arpRequest[30] = 1; arpRequest[31] = 5; // sender IP
            arpRequest.set([0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 32); // target MAC
            arpRequest[38] = 10; arpRequest[39] = 0; arpRequest[40] = 1; arpRequest[41] = 1; // target IP

            const reply = buildARPReply(arpRequest, '02:fa:b1:1c:00:00', '10.0.1.1');
            const parsed = parseARP(reply, 14);
            expect(parsed).not.toBeNull();
            expect(parsed!.operation).toBe(ARP_OP.REPLY);
            expect(parsed!.senderIP).toBe('10.0.1.1');
            expect(parsed!.senderMAC).toBe('02:fa:b1:1c:00:00');
        });
    });

    describe('parseFrame (full frame)', () => {
        it('parses a complete TCP frame', () => {
            // Build: Ethernet(14) + IPv4(20) + TCP(20) = 54 bytes
            const frame = new Uint8Array(54);

            // Ethernet
            frame.set([0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 0);  // dst
            frame.set([0x02, 0x00, 0x00, 0x00, 0x00, 0x02], 6);  // src
            frame[12] = 0x08; frame[13] = 0x00;                    // IPv4

            // IPv4
            frame[14] = 0x45;                    // v4, IHL=5
            frame[16] = 0x00; frame[17] = 40;   // total length
            frame[22] = 0x40;                     // TTL=64
            frame[23] = 0x06;                     // TCP
            frame[26] = 10; frame[27] = 0; frame[28] = 1; frame[29] = 5;  // src
            frame[30] = 10; frame[31] = 0; frame[32] = 1; frame[33] = 10; // dst

            // TCP
            frame[34] = 0x00; frame[35] = 80;   // src port: 80
            frame[36] = 0xC0; frame[37] = 0x00; // dst port: 49152
            frame[46] = 0x50;                     // data offset: 5
            frame[47] = 0x12;                     // SYN+ACK

            const parsed = parseFrame(frame);
            expect(parsed).not.toBeNull();
            expect(parsed!.ethernet.etherType).toBe(ETHER_TYPE.IPv4);
            expect(parsed!.ipv4?.protocol).toBe(6);
            expect(parsed!.tcp?.sourcePort).toBe(80);
            expect(parsed!.tcp?.flags.syn).toBe(true);
            expect(parsed!.tcp?.flags.ack).toBe(true);
            expect(parsed!.udp).toBeNull();
            expect(parsed!.arp).toBeNull();
        });
    });
});
