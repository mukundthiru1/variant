/**
 * VARIANT — Topology Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createTopologyEngine } from '../../../src/lib/topology/topology-engine';
import type { TopologyHost, NetworkSegment, SegmentLink } from '../../../src/lib/topology/types';

function seg(id: string, type: NetworkSegment['type'] = 'lan'): NetworkSegment {
    return { id, name: `Segment ${id}`, cidr: `10.0.${id}.0/24`, type };
}

function host(
    id: string,
    segmentId: string,
    ip: string,
    ports: { port: number; protocol: 'tcp' | 'udp'; service: string }[] = [],
    type: TopologyHost['type'] = 'server',
): TopologyHost {
    return {
        id,
        name: `Host ${id}`,
        type,
        interfaces: [{ name: 'eth0', ip, cidr: 24, segmentId, up: true }],
        openPorts: ports,
    };
}

function link(from: string, to: string, allowed: boolean = true, latency: number = 1, allowedPorts: number[] = []): SegmentLink {
    return { from, to, allowed, allowedPorts, latency };
}

describe('TopologyEngine', () => {
    // ── Segments ───────────────────────────────────────────────

    it('adds and retrieves segments', () => {
        const engine = createTopologyEngine();
        engine.addSegment(seg('1'));

        expect(engine.getSegment('1')).not.toBeNull();
        expect(engine.getSegment('nonexistent')).toBeNull();
        expect(engine.listSegments().length).toBe(1);
    });

    it('throws on duplicate segment', () => {
        const engine = createTopologyEngine();
        engine.addSegment(seg('1'));
        expect(() => engine.addSegment(seg('1'))).toThrow();
    });

    // ── Hosts ──────────────────────────────────────────────────

    it('adds and retrieves hosts', () => {
        const engine = createTopologyEngine();
        engine.addSegment(seg('1'));
        engine.addHost(host('web', '1', '10.0.1.10'));

        expect(engine.getHost('web')).not.toBeNull();
        expect(engine.getHost('nonexistent')).toBeNull();
        expect(engine.listHosts().length).toBe(1);
    });

    it('throws on duplicate host', () => {
        const engine = createTopologyEngine();
        engine.addSegment(seg('1'));
        engine.addHost(host('web', '1', '10.0.1.10'));
        expect(() => engine.addHost(host('web', '1', '10.0.1.10'))).toThrow();
    });

    it('lists hosts in segment', () => {
        const engine = createTopologyEngine();
        engine.addSegment(seg('1'));
        engine.addSegment(seg('2'));
        engine.addHost(host('web1', '1', '10.0.1.10'));
        engine.addHost(host('web2', '1', '10.0.1.11'));
        engine.addHost(host('db', '2', '10.0.2.10'));

        expect(engine.listHostsInSegment('1').length).toBe(2);
        expect(engine.listHostsInSegment('2').length).toBe(1);
        expect(engine.listHostsInSegment('3').length).toBe(0);
    });

    // ── Reachability ───────────────────────────────────────────

    it('hosts in same segment can reach each other', () => {
        const engine = createTopologyEngine();
        engine.addSegment(seg('1'));
        engine.addHost(host('a', '1', '10.0.1.10'));
        engine.addHost(host('b', '1', '10.0.1.11'));

        const result = engine.canReach('a', 'b');
        expect(result.reachable).toBe(true);
        expect(result.path).toContain('1');
    });

    it('hosts in different segments need a link', () => {
        const engine = createTopologyEngine();
        engine.addSegment(seg('1'));
        engine.addSegment(seg('2'));
        engine.addHost(host('a', '1', '10.0.1.10'));
        engine.addHost(host('b', '2', '10.0.2.10'));

        // No link → unreachable
        expect(engine.canReach('a', 'b').reachable).toBe(false);

        // Add link → reachable
        engine.addLink(link('1', '2'));
        expect(engine.canReach('a', 'b').reachable).toBe(true);
    });

    it('blocked link prevents reachability', () => {
        const engine = createTopologyEngine();
        engine.addSegment(seg('1'));
        engine.addSegment(seg('2'));
        engine.addHost(host('a', '1', '10.0.1.10'));
        engine.addHost(host('b', '2', '10.0.2.10'));
        engine.addLink(link('1', '2', false));

        expect(engine.canReach('a', 'b').reachable).toBe(false);
    });

    it('multi-hop reachability', () => {
        const engine = createTopologyEngine();
        engine.addSegment(seg('1'));
        engine.addSegment(seg('2'));
        engine.addSegment(seg('3'));
        engine.addHost(host('a', '1', '10.0.1.10'));
        engine.addHost(host('b', '3', '10.0.3.10'));

        engine.addLink(link('1', '2', true, 5));
        engine.addLink(link('2', '3', true, 10));

        const result = engine.canReach('a', 'b');
        expect(result.reachable).toBe(true);
        expect(result.path.length).toBe(3);
        expect(result.totalLatency).toBe(15);
    });

    it('port-specific reachability checks open ports', () => {
        const engine = createTopologyEngine();
        engine.addSegment(seg('1'));
        engine.addHost(host('a', '1', '10.0.1.10'));
        engine.addHost(host('b', '1', '10.0.1.11', [
            { port: 22, protocol: 'tcp', service: 'ssh' },
            { port: 80, protocol: 'tcp', service: 'http' },
        ]));

        expect(engine.canReach('a', 'b', 22).reachable).toBe(true);
        expect(engine.canReach('a', 'b', 80).reachable).toBe(true);
        expect(engine.canReach('a', 'b', 443).reachable).toBe(false);
    });

    it('port filtering on links', () => {
        const engine = createTopologyEngine();
        engine.addSegment(seg('1'));
        engine.addSegment(seg('2'));
        engine.addHost(host('a', '1', '10.0.1.10'));
        engine.addHost(host('b', '2', '10.0.2.10', [
            { port: 80, protocol: 'tcp', service: 'http' },
            { port: 22, protocol: 'tcp', service: 'ssh' },
        ]));
        // Link only allows port 80
        engine.addLink(link('1', '2', true, 1, [80]));

        expect(engine.canReach('a', 'b', 80).reachable).toBe(true);
        expect(engine.canReach('a', 'b', 22).reachable).toBe(false);
    });

    it('returns reason for unknown hosts', () => {
        const engine = createTopologyEngine();
        expect(engine.canReach('x', 'y').reason).toContain('not found');
    });

    // ── Host Discovery ─────────────────────────────────────────

    it('getReachableHosts returns all reachable hosts', () => {
        const engine = createTopologyEngine();
        engine.addSegment(seg('1'));
        engine.addSegment(seg('2'));
        engine.addHost(host('a', '1', '10.0.1.10'));
        engine.addHost(host('b', '1', '10.0.1.11'));
        engine.addHost(host('c', '2', '10.0.2.10'));

        engine.addLink(link('1', '2'));

        const reachable = engine.getReachableHosts('a');
        expect(reachable).toContain('b');
        expect(reachable).toContain('c');
        expect(reachable).not.toContain('a');
    });

    it('findHostsByPort returns hosts with matching port', () => {
        const engine = createTopologyEngine();
        engine.addSegment(seg('1'));
        engine.addHost(host('web', '1', '10.0.1.10', [{ port: 80, protocol: 'tcp', service: 'http' }]));
        engine.addHost(host('db', '1', '10.0.1.11', [{ port: 3306, protocol: 'tcp', service: 'mysql' }]));
        engine.addHost(host('web2', '1', '10.0.1.12', [{ port: 80, protocol: 'tcp', service: 'http' }]));

        expect(engine.findHostsByPort(80).length).toBe(2);
        expect(engine.findHostsByPort(3306).length).toBe(1);
        expect(engine.findHostsByPort(443).length).toBe(0);
    });

    it('findHostByIP returns matching host', () => {
        const engine = createTopologyEngine();
        engine.addSegment(seg('1'));
        engine.addHost(host('web', '1', '10.0.1.10'));

        expect(engine.findHostByIP('10.0.1.10')!.id).toBe('web');
        expect(engine.findHostByIP('192.168.1.1')).toBeNull();
    });

    // ── Host with down interface ───────────────────────────────

    it('host with down interface is unreachable', () => {
        const engine = createTopologyEngine();
        engine.addSegment(seg('1'));
        engine.addHost({
            id: 'down-host',
            name: 'Down Host',
            type: 'server',
            interfaces: [{ name: 'eth0', ip: '10.0.1.99', cidr: 24, segmentId: '1', up: false }],
            openPorts: [],
        });
        engine.addHost(host('a', '1', '10.0.1.10'));

        const result = engine.canReach('a', 'down-host');
        expect(result.reachable).toBe(false);
        expect(result.reason).toContain('no active interfaces');
    });

    // ── Clear ──────────────────────────────────────────────────

    it('clear removes everything', () => {
        const engine = createTopologyEngine();
        engine.addSegment(seg('1'));
        engine.addHost(host('a', '1', '10.0.1.10'));
        engine.addLink(link('1', '1'));

        engine.clear();

        expect(engine.listSegments().length).toBe(0);
        expect(engine.listHosts().length).toBe(0);
        expect(engine.listLinks().length).toBe(0);
    });
});
