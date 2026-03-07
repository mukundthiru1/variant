/**
 * VARIANT — Network Fabric Tests
 *
 * Tests the air-gapped network fabric: routing, DNS, ARP, firewall,
 * traffic logging, segment isolation, and cleanup.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createNetworkFabric } from '../../src/core/fabric/fabric';
import type { NetworkFabric, NetworkTopology, TrafficEntry } from '../../src/core/fabric/types';
import { buildUDPFrame } from '../../src/core/fabric/frames';

// ── Helpers ────────────────────────────────────────────────────

function buildSimpleTopology(): NetworkTopology {
    return {
        segments: [
            { id: 'corp', subnet: '10.0.1.0/24', gateway: '10.0.1.1' },
            { id: 'dmz', subnet: '10.0.2.0/24', gateway: '10.0.2.1' },
        ],
        routes: [],
        firewallRules: [],
    };
}

function buildARPRequest(senderMAC: string, senderIP: string, targetIP: string): Uint8Array {
    const frame = new Uint8Array(42);
    // Ethernet: broadcast
    frame.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0);
    const macParts = senderMAC.split(':');
    for (let i = 0; i < 6; i++) {
        frame[6 + i] = parseInt(macParts[i] ?? '0', 16);
    }
    frame[12] = 0x08; frame[13] = 0x06; // ARP

    // ARP
    frame[14] = 0x00; frame[15] = 0x01; // Ethernet
    frame[16] = 0x08; frame[17] = 0x00; // IPv4
    frame[18] = 6; frame[19] = 4;
    frame[20] = 0x00; frame[21] = 0x01; // Request

    for (let i = 0; i < 6; i++) {
        frame[22 + i] = parseInt(macParts[i] ?? '0', 16);
    }

    const senderParts = senderIP.split('.');
    for (let i = 0; i < 4; i++) {
        frame[28 + i] = parseInt(senderParts[i] ?? '0', 10);
    }

    // Target MAC = 0
    frame.set([0, 0, 0, 0, 0, 0], 32);

    const targetParts = targetIP.split('.');
    for (let i = 0; i < 4; i++) {
        frame[38 + i] = parseInt(targetParts[i] ?? '0', 10);
    }

    return frame;
}

function buildDNSQueryFrame(
    srcMAC: string,
    srcIP: string,
    dstIP: string,
    domain: string,
    queryId: number = 0x1234,
): Uint8Array {
    // Build DNS query payload
    const labels = domain.split('.');
    const nameBytes: number[] = [];
    for (const label of labels) {
        nameBytes.push(label.length);
        for (let i = 0; i < label.length; i++) {
            nameBytes.push(label.charCodeAt(i));
        }
    }
    nameBytes.push(0);

    const dnsLen = 12 + nameBytes.length + 4;
    const dnsPayload = new Uint8Array(dnsLen);
    dnsPayload[0] = (queryId >> 8) & 0xFF;
    dnsPayload[1] = queryId & 0xFF;
    dnsPayload[2] = 0x01; dnsPayload[3] = 0x00; // Standard query
    dnsPayload[4] = 0x00; dnsPayload[5] = 0x01; // QDCOUNT=1

    let off = 12;
    for (const b of nameBytes) {
        dnsPayload[off++] = b;
    }
    dnsPayload[off++] = 0x00; dnsPayload[off++] = 0x01; // TYPE A
    dnsPayload[off++] = 0x00; dnsPayload[off] = 0x01;   // CLASS IN

    return buildUDPFrame({
        srcMAC,
        dstMAC: '02:fa:b1:1c:00:00', // fabric MAC
        srcIP,
        dstIP,
        srcPort: 45678,
        dstPort: 53,
        payload: dnsPayload,
    });
}

// ── Tests ──────────────────────────────────────────────────────

describe('Network Fabric', () => {
    let fabric: NetworkFabric;

    beforeEach(() => {
        fabric = createNetworkFabric();
        fabric.init(buildSimpleTopology());
    });

    afterEach(() => {
        fabric.destroy();
    });

    describe('NIC connection', () => {
        it('connects a VM to a segment', () => {
            const handle = fabric.connect('vm-1', 'corp', '02:00:00:00:00:01', '10.0.1.5');
            expect(handle.vmId).toBe('vm-1');
            expect(handle.segment).toBe('corp');
            expect(handle.ip).toBe('10.0.1.5');
        });

        it('throws for unknown segment', () => {
            expect(() => {
                fabric.connect('vm-1', 'nonexistent', '02:00:00:00:00:01', '10.0.1.5');
            }).toThrow("Segment 'nonexistent' does not exist");
        });

        it('disconnects a NIC', () => {
            const handle = fabric.connect('vm-1', 'corp', '02:00:00:00:00:01', '10.0.1.5');
            handle.disconnect();
            expect(fabric.getStats().activeConnections).toBe(0);
        });
    });

    describe('Frame routing', () => {
        it('routes frames between VMs on the same segment', () => {
            fabric.connect('vm-1', 'corp', '02:00:00:00:00:01', '10.0.1.5');
            fabric.connect('vm-2', 'corp', '02:00:00:00:00:02', '10.0.1.10');

            const received: Uint8Array[] = [];
            fabric.onFrameForVM('vm-2', (frame) => {
                received.push(frame);
            });

            // Send a UDP frame from vm-1 to vm-2
            const frame = buildUDPFrame({
                srcMAC: '02:00:00:00:00:01',
                dstMAC: '02:00:00:00:00:02',
                srcIP: '10.0.1.5',
                dstIP: '10.0.1.10',
                srcPort: 12345,
                dstPort: 80,
                payload: new TextEncoder().encode('hello'),
            });

            fabric.routeFrame('vm-1', frame);
            expect(received.length).toBe(1);
        });

        it('drops frames between different segments (no route)', () => {
            fabric.connect('vm-1', 'corp', '02:00:00:00:00:01', '10.0.1.5');
            fabric.connect('vm-2', 'dmz', '02:00:00:00:00:02', '10.0.2.5');

            const received: Uint8Array[] = [];
            fabric.onFrameForVM('vm-2', (frame) => {
                received.push(frame);
            });

            const frame = buildUDPFrame({
                srcMAC: '02:00:00:00:00:01',
                dstMAC: '02:00:00:00:00:02',
                srcIP: '10.0.1.5',
                dstIP: '10.0.2.5',
                srcPort: 12345,
                dstPort: 80,
                payload: new TextEncoder().encode('should not arrive'),
            });

            fabric.routeFrame('vm-1', frame);
            expect(received.length).toBe(0);
            expect(fabric.getStats().droppedFrames).toBeGreaterThan(0);
        });

        it('drops frames from unknown VMs', () => {
            const frame = new Uint8Array(14);
            fabric.routeFrame('nonexistent', frame);
            expect(fabric.getStats().droppedFrames).toBe(1);
        });
    });

    describe('ARP', () => {
        it('responds to ARP for the gateway', () => {
            fabric.connect('vm-1', 'corp', '02:00:00:00:00:01', '10.0.1.5');

            const received: Uint8Array[] = [];
            fabric.onFrameForVM('vm-1', (frame) => {
                received.push(frame);
            });

            // ARP request: who has 10.0.1.1 (gateway)?
            const arpRequest = buildARPRequest('02:00:00:00:00:01', '10.0.1.5', '10.0.1.1');
            fabric.routeFrame('vm-1', arpRequest);

            // Should get an ARP reply
            expect(received.length).toBe(1);
        });

        it('responds to ARP for another VM on the same segment', () => {
            fabric.connect('vm-1', 'corp', '02:00:00:00:00:01', '10.0.1.5');
            fabric.connect('vm-2', 'corp', '02:00:00:00:00:02', '10.0.1.10');

            const received: Uint8Array[] = [];
            fabric.onFrameForVM('vm-1', (frame) => {
                received.push(frame);
            });

            // ARP request: who has 10.0.1.10?
            const arpRequest = buildARPRequest('02:00:00:00:00:01', '10.0.1.5', '10.0.1.10');
            fabric.routeFrame('vm-1', arpRequest);

            expect(received.length).toBe(1);
        });
    });

    describe('DNS', () => {
        it('resolves registered domains', () => {
            fabric.connect('vm-1', 'corp', '02:00:00:00:00:01', '10.0.1.5');

            fabric.addDNSRecord({
                domain: 'target.local',
                ip: '10.0.1.10',
                type: 'A',
                ttl: 300,
            });

            const received: Uint8Array[] = [];
            fabric.onFrameForVM('vm-1', (frame) => {
                received.push(frame);
            });

            // DNS query for target.local
            const dnsFrame = buildDNSQueryFrame(
                '02:00:00:00:00:01',
                '10.0.1.5',
                '10.0.1.1', // gateway as DNS server
                'target.local',
            );

            fabric.routeFrame('vm-1', dnsFrame);

            // Should resolve and send response
            expect(received.length).toBe(1);
            expect(fabric.getStats().dnsQueries).toBe(1);
        });

        it('returns NXDOMAIN for unregistered domains', () => {
            fabric.connect('vm-1', 'corp', '02:00:00:00:00:01', '10.0.1.5');

            const received: Uint8Array[] = [];
            fabric.onFrameForVM('vm-1', (frame) => {
                received.push(frame);
            });

            const dnsFrame = buildDNSQueryFrame(
                '02:00:00:00:00:01',
                '10.0.1.5',
                '10.0.1.1',
                'evil.external.com', // Not registered
            );

            fabric.routeFrame('vm-1', dnsFrame);

            // Should still receive a response (NXDOMAIN)
            expect(received.length).toBe(1);
        });
    });

    describe('Firewall', () => {
        it('drops frames matching a drop rule', () => {
            fabric.destroy();
            fabric = createNetworkFabric();
            fabric.init({
                segments: [
                    { id: 'corp', subnet: '10.0.1.0/24', gateway: '10.0.1.1' },
                ],
                routes: [],
                firewallRules: [
                    {
                        action: 'drop',
                        direction: 'outbound',
                        destPort: 22,
                        protocol: 'tcp',
                        priority: 1,
                    },
                ],
            });

            fabric.connect('vm-1', 'corp', '02:00:00:00:00:01', '10.0.1.5');
            fabric.connect('vm-2', 'corp', '02:00:00:00:00:02', '10.0.1.10');

            const received: Uint8Array[] = [];
            fabric.onFrameForVM('vm-2', (frame) => {
                received.push(frame);
            });

            // Build a TCP SYN to port 22
            const frame = new Uint8Array(54);
            // Ethernet
            frame.set([0x02, 0x00, 0x00, 0x00, 0x00, 0x02], 0);  // dst
            frame.set([0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 6);  // src
            frame[12] = 0x08; frame[13] = 0x00;                    // IPv4
            // IPv4
            frame[14] = 0x45;
            frame[16] = 0x00; frame[17] = 40;
            frame[22] = 0x40; // TTL
            frame[23] = 0x06; // TCP
            frame[26] = 10; frame[27] = 0; frame[28] = 1; frame[29] = 5;
            frame[30] = 10; frame[31] = 0; frame[32] = 1; frame[33] = 10;
            // TCP
            frame[34] = 0xC0; frame[35] = 0x00; // src port: 49152
            frame[36] = 0x00; frame[37] = 22;    // dst port: 22
            frame[46] = 0x50;                     // data offset: 5
            frame[47] = 0x02;                     // SYN

            fabric.routeFrame('vm-1', frame);
            expect(received.length).toBe(0);
        });
    });

    describe('Traffic logging', () => {
        it('logs routed traffic', () => {
            fabric.connect('vm-1', 'corp', '02:00:00:00:00:01', '10.0.1.5');
            fabric.connect('vm-2', 'corp', '02:00:00:00:00:02', '10.0.1.10');

            const frame = buildUDPFrame({
                srcMAC: '02:00:00:00:00:01',
                dstMAC: '02:00:00:00:00:02',
                srcIP: '10.0.1.5',
                dstIP: '10.0.1.10',
                srcPort: 12345,
                dstPort: 80,
                payload: new Uint8Array(0),
            });

            fabric.routeFrame('vm-1', frame);

            const log = fabric.getTrafficLog();
            expect(log.length).toBeGreaterThan(0);

            const outEntry = log.find(e => e.direction === 'outbound');
            expect(outEntry).toBeDefined();
            expect(outEntry!.sourceIP).toBe('10.0.1.5');
            expect(outEntry!.destIP).toBe('10.0.1.10');
        });
    });

    describe('Segment tap', () => {
        it('notifies tap handlers on traffic', () => {
            fabric.connect('vm-1', 'corp', '02:00:00:00:00:01', '10.0.1.5');
            fabric.connect('vm-2', 'corp', '02:00:00:00:00:02', '10.0.1.10');

            const tapped: TrafficEntry[] = [];
            const unsub = fabric.tap('corp', (entry) => {
                tapped.push(entry);
            });

            const frame = buildUDPFrame({
                srcMAC: '02:00:00:00:00:01',
                dstMAC: '02:00:00:00:00:02',
                srcIP: '10.0.1.5',
                dstIP: '10.0.1.10',
                srcPort: 12345,
                dstPort: 80,
                payload: new Uint8Array(0),
            });

            fabric.routeFrame('vm-1', frame);
            expect(tapped.length).toBeGreaterThan(0);

            unsub();
            fabric.routeFrame('vm-1', frame);
            // Should not get more entries after unsubscribe
            const countBefore = tapped.length;
            // The tap was already removed, so no new entries
            expect(tapped.length).toBe(countBefore);
        });
    });

    describe('Stats', () => {
        it('tracks frame counts', () => {
            fabric.connect('vm-1', 'corp', '02:00:00:00:00:01', '10.0.1.5');

            const frame = buildUDPFrame({
                srcMAC: '02:00:00:00:00:01',
                dstMAC: '02:00:00:00:00:02',
                srcIP: '10.0.1.5',
                dstIP: '10.0.1.99', // No VM at this IP
                srcPort: 12345,
                dstPort: 80,
                payload: new Uint8Array(0),
            });

            fabric.routeFrame('vm-1', frame);

            const stats = fabric.getStats();
            expect(stats.totalFrames).toBe(1);
            expect(stats.bytesRouted).toBeGreaterThan(0);
        });
    });

    describe('Cleanup', () => {
        it('cleans up all state on destroy', () => {
            fabric.connect('vm-1', 'corp', '02:00:00:00:00:01', '10.0.1.5');
            fabric.addDNSRecord({ domain: 'test.local', ip: '10.0.1.10', type: 'A', ttl: 300 });

            fabric.destroy();

            expect(fabric.getStats().activeConnections).toBe(0);
            expect(fabric.getTrafficLog().length).toBe(0);
        });
    });
});
