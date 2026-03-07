/**
 * VARIANT — Firewall Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createFirewallEngine } from '../../../src/lib/firewall/firewall-engine';
import type { FirewallPacket, ExtendedFirewallRule, FirewallResult } from '../../../src/lib/firewall/firewall-engine';
import type { MachineFirewallRule } from '../../../src/core/world/types';

function makePacket(overrides?: Partial<FirewallPacket>): FirewallPacket {
    return {
        protocol: 'tcp',
        sourceIP: '10.0.0.5',
        destinationIP: '10.0.0.1',
        sourcePort: 45000,
        destinationPort: 80,
        direction: 'inbound',
        ...overrides,
    };
}

function makeRule(overrides?: Partial<MachineFirewallRule>): MachineFirewallRule {
    return {
        chain: 'INPUT',
        action: 'ACCEPT',
        ...overrides,
    };
}

describe('FirewallEngine', () => {
    it('creates with empty rules and default policies', () => {
        const fw = createFirewallEngine('web-01', []);
        expect(fw.getRules().length).toBe(0);
        const policies = fw.getPolicies();
        expect(policies.INPUT).toBe('ACCEPT');
        expect(policies.OUTPUT).toBe('ACCEPT');
        expect(policies.FORWARD).toBe('DROP');
    });

    it('allows packets by default INPUT policy', () => {
        const fw = createFirewallEngine('web-01', []);
        const result = fw.evaluate(makePacket());
        expect(result.allowed).toBe(true);
        expect(result.action).toBe('ACCEPT');
        expect(result.matchedRuleIndex).toBe(-1);
    });

    it('drops packets by default FORWARD policy', () => {
        const fw = createFirewallEngine('web-01', []);
        const result = fw.evaluate(makePacket({ direction: 'forward' }));
        expect(result.allowed).toBe(false);
        expect(result.action).toBe('DROP');
    });

    it('matches rule by port', () => {
        const fw = createFirewallEngine('web-01', [
            makeRule({ chain: 'INPUT', action: 'DROP', port: 22 }),
        ]);

        const ssh = fw.evaluate(makePacket({ destinationPort: 22 }));
        expect(ssh.allowed).toBe(false);
        expect(ssh.matchedRuleIndex).toBe(0);

        const http = fw.evaluate(makePacket({ destinationPort: 80 }));
        expect(http.allowed).toBe(true); // default policy
    });

    it('matches rule by protocol', () => {
        const fw = createFirewallEngine('web-01', [
            makeRule({ chain: 'INPUT', action: 'DROP', protocol: 'udp' }),
        ]);

        const tcp = fw.evaluate(makePacket({ protocol: 'tcp' }));
        expect(tcp.allowed).toBe(true);

        const udp = fw.evaluate(makePacket({ protocol: 'udp' }));
        expect(udp.allowed).toBe(false);
    });

    it('matches rule by source IP', () => {
        const fw = createFirewallEngine('web-01', [
            makeRule({ chain: 'INPUT', action: 'DROP', source: '10.0.0.5' }),
        ]);

        const blocked = fw.evaluate(makePacket({ sourceIP: '10.0.0.5' }));
        expect(blocked.allowed).toBe(false);

        const allowed = fw.evaluate(makePacket({ sourceIP: '10.0.0.6' }));
        expect(allowed.allowed).toBe(true);
    });

    it('matches rule by destination IP', () => {
        const fw = createFirewallEngine('web-01', [
            makeRule({ chain: 'INPUT', action: 'DROP', destination: '10.0.0.1' }),
        ]);

        const blocked = fw.evaluate(makePacket({ destinationIP: '10.0.0.1' }));
        expect(blocked.allowed).toBe(false);

        const allowed = fw.evaluate(makePacket({ destinationIP: '10.0.0.2' }));
        expect(allowed.allowed).toBe(true);
    });

    it('matches CIDR source', () => {
        const fw = createFirewallEngine('web-01', [
            makeRule({ chain: 'INPUT', action: 'DROP', source: '10.0.0.0/24' }),
        ]);

        const inRange = fw.evaluate(makePacket({ sourceIP: '10.0.0.42' }));
        expect(inRange.allowed).toBe(false);

        const outRange = fw.evaluate(makePacket({ sourceIP: '10.0.1.1' }));
        expect(outRange.allowed).toBe(true);
    });

    it('matches wildcard source 0.0.0.0/0', () => {
        const fw = createFirewallEngine('web-01', [
            makeRule({ chain: 'INPUT', action: 'DROP', source: '0.0.0.0/0' }),
        ]);

        expect(fw.evaluate(makePacket({ sourceIP: '192.168.1.1' })).allowed).toBe(false);
        expect(fw.evaluate(makePacket({ sourceIP: '10.0.0.5' })).allowed).toBe(false);
    });

    it('first matching rule wins', () => {
        const fw = createFirewallEngine('web-01', [
            makeRule({ chain: 'INPUT', action: 'ACCEPT', port: 80 }),
            makeRule({ chain: 'INPUT', action: 'DROP', port: 80 }),
        ]);

        const result = fw.evaluate(makePacket({ destinationPort: 80 }));
        expect(result.allowed).toBe(true);
        expect(result.matchedRuleIndex).toBe(0);
    });

    it('evaluates OUTPUT chain for outbound traffic', () => {
        const fw = createFirewallEngine('web-01', [
            makeRule({ chain: 'OUTPUT', action: 'DROP', port: 443 }),
        ]);

        const result = fw.evaluate(makePacket({ direction: 'outbound', destinationPort: 443 }));
        expect(result.allowed).toBe(false);
        expect(result.chain).toBe('OUTPUT');
    });

    it('changes default policy', () => {
        const fw = createFirewallEngine('web-01', []);
        fw.setPolicy('INPUT', 'DROP');

        const result = fw.evaluate(makePacket());
        expect(result.allowed).toBe(false);
        expect(result.action).toBe('DROP');
    });

    it('adds rules dynamically', () => {
        const fw = createFirewallEngine('web-01', []);
        fw.addRule({ chain: 'INPUT', action: 'DROP', port: 22 });

        expect(fw.getRules().length).toBe(1);
        expect(fw.evaluate(makePacket({ destinationPort: 22 })).allowed).toBe(false);
    });

    it('removes rules by index', () => {
        const fw = createFirewallEngine('web-01', [
            makeRule({ chain: 'INPUT', action: 'DROP', port: 22 }),
            makeRule({ chain: 'INPUT', action: 'DROP', port: 80 }),
        ]);

        expect(fw.removeRule(0)).toBe(true);
        expect(fw.getRules().length).toBe(1);
        expect(fw.evaluate(makePacket({ destinationPort: 22 })).allowed).toBe(true);
    });

    it('removeRule returns false for invalid index', () => {
        const fw = createFirewallEngine('web-01', []);
        expect(fw.removeRule(0)).toBe(false);
        expect(fw.removeRule(-1)).toBe(false);
    });

    it('inserts rule at position', () => {
        const fw = createFirewallEngine('web-01', [
            makeRule({ chain: 'INPUT', action: 'ACCEPT', port: 80 }),
            makeRule({ chain: 'INPUT', action: 'ACCEPT', port: 443 }),
        ]);

        fw.insertRule(1, { chain: 'INPUT', action: 'DROP', port: 22 });
        expect(fw.getRules().length).toBe(3);
        expect(fw.getRules()[1]!.port).toBe(22);
    });

    it('tracks statistics', () => {
        const fw = createFirewallEngine('web-01', [
            makeRule({ chain: 'INPUT', action: 'DROP', port: 22 }),
        ]);

        fw.evaluate(makePacket({ destinationPort: 22 })); // drop
        fw.evaluate(makePacket({ destinationPort: 80 })); // accept (default)
        fw.evaluate(makePacket({ destinationPort: 22 })); // drop

        const stats = fw.getStats();
        expect(stats.packetsEvaluated).toBe(3);
        expect(stats.packetsDropped).toBe(2);
        expect(stats.packetsAllowed).toBe(1);
        expect(stats.ruleHits.get(0)).toBe(2);
    });

    it('resets statistics', () => {
        const fw = createFirewallEngine('web-01', []);
        fw.evaluate(makePacket());
        fw.resetStats();

        const stats = fw.getStats();
        expect(stats.packetsEvaluated).toBe(0);
    });

    it('fires event callback', () => {
        const events: { packet: FirewallPacket; result: FirewallResult }[] = [];
        const fw = createFirewallEngine('web-01', [
            makeRule({ chain: 'INPUT', action: 'DROP', port: 22 }),
        ], (packet, result) => {
            events.push({ packet, result });
        });

        fw.evaluate(makePacket({ destinationPort: 22 }));
        expect(events.length).toBe(1);
        expect(events[0]!.result.allowed).toBe(false);
    });

    it('formats rules as iptables output', () => {
        const fw = createFirewallEngine('web-01', [
            makeRule({ chain: 'INPUT', action: 'DROP', protocol: 'tcp', port: 22, source: '10.0.0.0/24' }),
            makeRule({ chain: 'OUTPUT', action: 'ACCEPT', protocol: 'tcp', port: 443 }),
        ]);

        const output = fw.formatAsIptables();
        expect(output).toContain('Chain INPUT');
        expect(output).toContain('Chain OUTPUT');
        expect(output).toContain('DROP');
        expect(output).toContain('dpt:22');
        expect(output).toContain('10.0.0.0/24');
    });

    it('REJECT counts as dropped', () => {
        const fw = createFirewallEngine('web-01', [
            makeRule({ chain: 'INPUT', action: 'REJECT', port: 80 }),
        ]);

        const result = fw.evaluate(makePacket({ destinationPort: 80 }));
        expect(result.allowed).toBe(false);
        expect(result.action).toBe('REJECT');
        expect(fw.getStats().packetsRejected).toBe(1);
    });

    it('combined protocol + port + source matching', () => {
        const fw = createFirewallEngine('web-01', [
            makeRule({ chain: 'INPUT', action: 'DROP', protocol: 'tcp', port: 3306, source: '0.0.0.0/0' }),
        ]);

        // TCP to 3306 from anywhere: blocked
        expect(fw.evaluate(makePacket({ protocol: 'tcp', destinationPort: 3306 })).allowed).toBe(false);

        // UDP to 3306: not blocked (protocol mismatch)
        expect(fw.evaluate(makePacket({ protocol: 'udp', destinationPort: 3306 })).allowed).toBe(true);

        // TCP to 80: not blocked (port mismatch)
        expect(fw.evaluate(makePacket({ protocol: 'tcp', destinationPort: 80 })).allowed).toBe(true);
    });

    it('extended rule with source port matching', () => {
        const fw = createFirewallEngine('web-01', []);
        fw.addRule({ chain: 'INPUT', action: 'DROP', sourcePort: 31337 } as ExtendedFirewallRule);

        expect(fw.evaluate(makePacket({ sourcePort: 31337 })).allowed).toBe(false);
        expect(fw.evaluate(makePacket({ sourcePort: 45000 })).allowed).toBe(true);
    });

    it('getRules returns frozen copy', () => {
        const fw = createFirewallEngine('web-01', [
            makeRule({ chain: 'INPUT', action: 'DROP', port: 22 }),
        ]);

        const rules = fw.getRules();
        expect(rules.length).toBe(1);
        // Verify it's a copy — modifying shouldn't affect engine
        expect(Object.isFrozen(rules)).toBe(true);
    });
});
