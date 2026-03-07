import { describe, it, expect, beforeEach } from 'vitest';
import { createTunnelEngine } from '../../../src/lib/vpn';
import type { TunnelEngine } from '../../../src/lib/vpn';

describe('Tunnel Engine', () => {
    let engine: TunnelEngine;

    beforeEach(() => {
        engine = createTunnelEngine();
    });

    // ── Tunnel Creation ──────────────────────────────────────

    it('creates a tunnel with defaults', () => {
        const t = engine.createTunnel({
            type: 'wireguard', sourceHost: '10.0.0.1', sourcePort: 51820,
            destHost: '10.0.0.2', destPort: 51820,
        });
        expect(t.id).toBeTruthy();
        expect(t.status).toBe('established');
        expect(t.encrypted).toBe(true);
        expect(t.cipher).toBe('AES-256-GCM');
        expect(t.latencyMs).toBe(2); // wireguard default
    });

    it('SSH tunnel is encrypted by default', () => {
        const t = engine.createTunnel({
            type: 'ssh_local', sourceHost: 'attacker', sourcePort: 8080,
            destHost: 'target', destPort: 80,
        });
        expect(t.encrypted).toBe(true);
    });

    it('SOCKS proxy is not encrypted by default', () => {
        const t = engine.createTunnel({
            type: 'socks5', sourceHost: 'attacker', sourcePort: 1080,
            destHost: 'proxy', destPort: 1080,
        });
        expect(t.encrypted).toBe(false);
    });

    it('Tor has high latency', () => {
        const t = engine.createTunnel({
            type: 'tor', sourceHost: 'user', sourcePort: 9050,
            destHost: 'hidden.onion', destPort: 80,
        });
        expect(t.latencyMs).toBeGreaterThanOrEqual(200);
    });

    it('hops add to latency', () => {
        const t = engine.createTunnel({
            type: 'openvpn', sourceHost: 'client', sourcePort: 1194,
            destHost: 'vpn-server', destPort: 1194,
            hops: [
                { host: 'hop1', ip: '10.0.0.5', latencyMs: 50, encrypted: true },
                { host: 'hop2', ip: '10.0.0.6', latencyMs: 30, encrypted: true },
            ],
        });
        expect(t.latencyMs).toBe(8 + 50 + 30); // openvpn default + hops
    });

    // ── Tunnel Retrieval ─────────────────────────────────────

    it('getTunnel retrieves by ID', () => {
        const t = engine.createTunnel({ type: 'ipsec', sourceHost: 'a', sourcePort: 500, destHost: 'b', destPort: 500 });
        expect(engine.getTunnel(t.id)).not.toBeNull();
        expect(engine.getTunnel('nonexistent')).toBeNull();
    });

    it('listTunnels returns all', () => {
        engine.createTunnel({ type: 'wireguard', sourceHost: 'a', sourcePort: 1, destHost: 'b', destPort: 1 });
        engine.createTunnel({ type: 'openvpn', sourceHost: 'a', sourcePort: 2, destHost: 'b', destPort: 2 });
        expect(engine.listTunnels()).toHaveLength(2);
    });

    it('listActiveTunnels excludes disconnected', () => {
        const t1 = engine.createTunnel({ type: 'wireguard', sourceHost: 'a', sourcePort: 1, destHost: 'b', destPort: 1 });
        engine.createTunnel({ type: 'openvpn', sourceHost: 'a', sourcePort: 2, destHost: 'b', destPort: 2 });
        engine.closeTunnel(t1.id);
        expect(engine.listActiveTunnels()).toHaveLength(1);
    });

    // ── Tunnel Lifecycle ─────────────────────────────────────

    it('closeTunnel marks as disconnected', () => {
        const t = engine.createTunnel({ type: 'ssh_local', sourceHost: 'a', sourcePort: 1, destHost: 'b', destPort: 1 });
        expect(engine.closeTunnel(t.id)).toBe(true);
        expect(engine.getTunnel(t.id)!.status).toBe('disconnected');
    });

    it('closeTunnel returns false for already closed', () => {
        const t = engine.createTunnel({ type: 'ssh_local', sourceHost: 'a', sourcePort: 1, destHost: 'b', destPort: 1 });
        engine.closeTunnel(t.id);
        expect(engine.closeTunnel(t.id)).toBe(false);
    });

    it('closeTunnel returns false for unknown', () => {
        expect(engine.closeTunnel('nonexistent')).toBe(false);
    });

    // ── Data Transfer ────────────────────────────────────────

    it('transferData updates byte counters', () => {
        const t = engine.createTunnel({ type: 'wireguard', sourceHost: 'a', sourcePort: 1, destHost: 'b', destPort: 1 });
        expect(engine.transferData(t.id, 1000, 500)).toBe(true);
        expect(engine.transferData(t.id, 2000, 1000)).toBe(true);
        const updated = engine.getTunnel(t.id)!;
        expect(updated.bytesIn).toBe(3000);
        expect(updated.bytesOut).toBe(1500);
    });

    it('transferData fails on disconnected tunnel', () => {
        const t = engine.createTunnel({ type: 'wireguard', sourceHost: 'a', sourcePort: 1, destHost: 'b', destPort: 1 });
        engine.closeTunnel(t.id);
        expect(engine.transferData(t.id, 100, 100)).toBe(false);
    });

    // ── Tunnel Detection ─────────────────────────────────────

    it('detects DNS tunnels', () => {
        engine.createTunnel({ type: 'dns_tunnel', sourceHost: 'victim', sourcePort: 53, destHost: 'c2.evil.com', destPort: 53 });
        const detections = engine.detectTunnels();
        const dns = detections.find(d => d.type === 'dns_tunnel');
        expect(dns).toBeDefined();
        expect(dns!.confidence).toBeGreaterThan(0.5);
        expect(dns!.mitre).toBe('T1071.004');
    });

    it('detects ICMP tunnels', () => {
        engine.createTunnel({ type: 'icmp_tunnel', sourceHost: 'victim', sourcePort: 0, destHost: 'c2.evil.com', destPort: 0 });
        const detections = engine.detectTunnels();
        expect(detections.find(d => d.type === 'icmp_tunnel')).toBeDefined();
    });

    it('detects Tor circuits', () => {
        engine.createTunnel({ type: 'tor', sourceHost: 'user', sourcePort: 9050, destHost: 'hidden.onion', destPort: 80 });
        const detections = engine.detectTunnels();
        const tor = detections.find(d => d.type === 'tor_exit_node');
        expect(tor).toBeDefined();
        expect(tor!.confidence).toBeGreaterThan(0.9);
    });

    it('detects SSH port forwarding', () => {
        engine.createTunnel({ type: 'ssh_dynamic', sourceHost: 'attacker', sourcePort: 1080, destHost: 'pivot', destPort: 22 });
        const detections = engine.detectTunnels();
        expect(detections.find(d => d.type === 'port_forwarding')).toBeDefined();
    });

    it('detects SOCKS proxy', () => {
        engine.createTunnel({ type: 'socks5', sourceHost: 'attacker', sourcePort: 1080, destHost: 'proxy', destPort: 1080 });
        const detections = engine.detectTunnels();
        expect(detections.find(d => d.type === 'proxy_detected')).toBeDefined();
    });

    it('no detections for disconnected tunnels', () => {
        const t = engine.createTunnel({ type: 'dns_tunnel', sourceHost: 'a', sourcePort: 53, destHost: 'b', destPort: 53 });
        engine.closeTunnel(t.id);
        expect(engine.detectTunnels()).toHaveLength(0);
    });

    // ── Stats ────────────────────────────────────────────────

    it('getStats returns accurate counts', () => {
        engine.createTunnel({ type: 'wireguard', sourceHost: 'a', sourcePort: 1, destHost: 'b', destPort: 1 });
        const t2 = engine.createTunnel({ type: 'socks5', sourceHost: 'a', sourcePort: 2, destHost: 'b', destPort: 2 });
        engine.closeTunnel(t2.id);
        engine.transferData(engine.listTunnels()[0]!.id, 1000, 500);

        const stats = engine.getStats();
        expect(stats.totalTunnels).toBe(2);
        expect(stats.activeTunnels).toBe(1);
        expect(stats.closedTunnels).toBe(1);
        expect(stats.totalBytesIn).toBe(1000);
        expect(stats.totalBytesOut).toBe(500);
        expect(stats.encryptedTunnels).toBe(1); // wireguard
        expect(stats.tunnelsByType['wireguard']).toBe(1);
        expect(stats.tunnelsByType['socks5']).toBe(1);
    });
});
