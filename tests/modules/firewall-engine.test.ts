import { describe, it, expect } from 'vitest';
import type { EventBus, EngineEvent } from '../../src/core/events';
import { createEventBus } from '../../src/core/event-bus';
import type { SimulationContext } from '../../src/core/modules';
import { createServiceLocator } from '../../src/core/modules';
import type { MachineFirewallRule, WorldSpec } from '../../src/core/world/types';
import { stubFabric } from '../helpers';
import {
    createFirewallEngine,
    evaluateRule,
    evaluateChain,
    parseIptablesOutput,
    parseIptablesCommand,
    type PacketInfo,
    type RuleHitCounter,
} from '../../src/modules/firewall-engine';

interface FirewallEngineService {
    getRuleCounters(machineId: string): readonly RuleHitCounter[];
}

function createTestEventBus(): EventBus & { emitted: EngineEvent[] } {
    const inner = createEventBus(10_000);
    const emitted: EngineEvent[] = [];

    return {
        emitted,
        emit(event: EngineEvent): void {
            emitted.push(event);
            inner.emit(event);
        },
        on: inner.on.bind(inner),
        once: inner.once.bind(inner),
        waitFor: inner.waitFor.bind(inner),
        onPrefix: inner.onPrefix.bind(inner),
        getLog: inner.getLog.bind(inner),
        clearLog: inner.clearLog.bind(inner),
        removeAllListeners: inner.removeAllListeners.bind(inner),
    };
}

function makePacket(overrides?: Partial<PacketInfo>): PacketInfo {
    return {
        srcIp: '10.0.0.10',
        dstIp: '10.0.0.20',
        srcPort: 43000,
        dstPort: 22,
        protocol: 'tcp',
        direction: 'INPUT',
        bytes: 256,
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

function makeContext(events: EventBus, firewallByMachine: Readonly<Record<string, readonly MachineFirewallRule[]>>): SimulationContext {
    return {
        vms: new Map(),
        fabric: stubFabric(),
        events,
        world: {
            version: '2.0',
            trust: 'community',
            meta: {
                title: 'firewall-test',
                scenario: 'firewall-test',
                briefing: [],
                difficulty: 'easy',
                mode: 'defense',
                vulnClasses: [],
                tags: [],
                estimatedMinutes: 10,
                author: { name: 'test', id: 'test', type: 'santh' },
            },
            machines: {
                attacker: {
                    hostname: 'attacker',
                    image: 'attacker.img',
                    memoryMB: 256,
                    role: 'player',
                    interfaces: [{ ip: '10.0.0.5', segment: 'corp' }],
                    firewall: firewallByMachine['attacker'] ?? [],
                },
                web: {
                    hostname: 'web',
                    image: 'web.img',
                    memoryMB: 256,
                    role: 'target',
                    interfaces: [{ ip: '10.0.0.10', segment: 'corp' }],
                    firewall: firewallByMachine['web'] ?? [],
                },
            },
            startMachine: 'attacker',
            network: { segments: [], edges: [] },
            credentials: [],
            objectives: [],
            modules: [],
            scoring: { maxScore: 1000, timeBonus: false, stealthBonus: false, hintPenalty: 50, tiers: [] },
            hints: [],
        } as unknown as WorldSpec,
        tick: 0,
        services: createServiceLocator(),
    };
}

describe('firewall-engine module', () => {
    it('accept rule matches correctly', () => {
        const result = evaluateRule(
            makeRule({ chain: 'INPUT', action: 'ACCEPT', source: '10.0.0.10', port: 22, protocol: 'tcp' }),
            makePacket(),
        );

        expect(result).toBe('accept');
    });

    it('drop rule blocks traffic', () => {
        const result = evaluateRule(
            makeRule({ chain: 'INPUT', action: 'DROP', port: 22 }),
            makePacket(),
        );

        expect(result).toBe('drop');
    });

    it('CIDR matching works in-subnet', () => {
        const result = evaluateRule(
            makeRule({ action: 'DROP', source: '10.0.0.0/24' }),
            makePacket({ srcIp: '10.0.0.99' }),
        );

        expect(result).toBe('drop');
    });

    it('CIDR matching rejects out-of-subnet packets', () => {
        const result = evaluateRule(
            makeRule({ action: 'DROP', source: '10.0.0.0/24' }),
            makePacket({ srcIp: '10.0.1.10' }),
        );

        expect(result).toBe('no-match');
    });

    it('port range matching supports destination ranges', () => {
        const rule = {
            ...makeRule({ action: 'DROP' }),
            destinationPort: '1024:65535',
        } as MachineFirewallRule;

        const hit = evaluateRule(rule, makePacket({ dstPort: 2048 }));
        const miss = evaluateRule(rule, makePacket({ dstPort: 443 }));

        expect(hit).toBe('drop');
        expect(miss).toBe('no-match');
    });

    it('protocol filtering supports any', () => {
        const result = evaluateRule(
            makeRule({ action: 'DROP', protocol: 'any' }),
            makePacket({ protocol: 'udp' }),
        );

        expect(result).toBe('drop');
    });

    it('protocol mismatch returns no-match', () => {
        const result = evaluateRule(
            makeRule({ action: 'DROP', protocol: 'tcp' }),
            makePacket({ protocol: 'icmp' }),
        );

        expect(result).toBe('no-match');
    });

    it('first-match-wins ordering is enforced', () => {
        const decision = evaluateChain(
            [
                makeRule({ action: 'ACCEPT', port: 22 }),
                makeRule({ action: 'DROP', port: 22 }),
            ],
            makePacket({ dstPort: 22 }),
            'drop',
        );

        expect(decision.decision).toBe('accept');
        expect(decision.ruleIndex).toBe(0);
    });

    it('default policy accept applies when no rule matches', () => {
        const decision = evaluateChain(
            [makeRule({ action: 'DROP', port: 443 })],
            makePacket({ dstPort: 22 }),
            'accept',
        );

        expect(decision.decision).toBe('accept');
        expect(decision.ruleIndex).toBe(-1);
    });

    it('default policy drop applies when no rule matches', () => {
        const decision = evaluateChain(
            [makeRule({ action: 'ACCEPT', port: 443 })],
            makePacket({ dstPort: 22 }),
            'drop',
        );

        expect(decision.decision).toBe('drop');
        expect(decision.ruleIndex).toBe(-1);
    });

    it('iptables output formatting includes expected fields', () => {
        const output = parseIptablesOutput([
            makeRule({ action: 'DROP', protocol: 'tcp', source: '10.0.0.0/24', port: 22 }),
            makeRule({ chain: 'OUTPUT', action: 'ACCEPT', protocol: 'udp', destination: '10.0.0.5', port: 53 }),
        ]);

        expect(output).toContain('Chain INPUT (policy ACCEPT)');
        expect(output).toContain('Chain OUTPUT (policy ACCEPT)');
        expect(output).toContain('DROP');
        expect(output).toContain('dpt:22');
        expect(output).toContain('10.0.0.0/24');
    });

    it('iptables command parsing supports basic command', () => {
        const parsed = parseIptablesCommand('iptables -A INPUT -s 10.0.0.0/24 -p tcp --dport 22 -j ACCEPT');

        expect(parsed).not.toBeNull();
        expect(parsed?.chain).toBe('INPUT');
        expect(parsed?.source).toBe('10.0.0.0/24');
        expect(parsed?.protocol).toBe('tcp');
        expect(parsed?.port).toBe(22);
        expect(parsed?.action).toBe('ACCEPT');
    });

    it('iptables command parsing supports port ranges', () => {
        const parsed = parseIptablesCommand('iptables -A INPUT -p tcp --dport 1024:65535 -j DROP') as (MachineFirewallRule & { destinationPort?: number | string }) | null;

        expect(parsed).not.toBeNull();
        expect(parsed?.port).toBeUndefined();
        expect(parsed?.destinationPort).toBe('1024:65535');
        expect(parsed?.action).toBe('DROP');
    });

    it('event integration emits defense:alert when destination drops request', () => {
        const events = createTestEventBus();
        const module = createFirewallEngine(events);
        const context = makeContext(events, {
            web: [makeRule({ chain: 'INPUT', action: 'DROP', protocol: 'tcp', port: 22 })],
        });

        module.init(context);

        events.emit({
            type: 'net:request',
            method: 'GET',
            url: 'http://web:22/admin',
            source: 'attacker',
            destination: 'web',
            timestamp: Date.now(),
        });

        const alerts = events.emitted.filter((event): event is Extract<EngineEvent, { type: 'defense:alert' }> => event.type === 'defense:alert');

        expect(alerts.length).toBe(1);
        expect(alerts[0]?.machine).toBe('web');
        expect(alerts[0]?.ruleId).toContain('firewall/rule-0');

        module.destroy();
    });

    it('source OUTPUT drop prevents destination INPUT evaluation', () => {
        const events = createTestEventBus();
        const module = createFirewallEngine(events);
        const context = makeContext(events, {
            attacker: [makeRule({ chain: 'OUTPUT', action: 'DROP', protocol: 'tcp', port: 22 })],
            web: [makeRule({ chain: 'INPUT', action: 'DROP', protocol: 'tcp', port: 22 })],
        });

        module.init(context);

        events.emit({
            type: 'net:request',
            method: 'GET',
            url: 'http://web:22/admin',
            source: 'attacker',
            destination: 'web',
            timestamp: Date.now(),
        });

        const alerts = events.emitted.filter((event): event is Extract<EngineEvent, { type: 'defense:alert' }> => event.type === 'defense:alert');
        expect(alerts.length).toBe(1);
        expect(alerts[0]?.machine).toBe('attacker');

        module.destroy();
    });

    it('tracks per-rule packet and byte counters', () => {
        const events = createTestEventBus();
        const module = createFirewallEngine(events);
        const context = makeContext(events, {
            web: [makeRule({ chain: 'INPUT', action: 'DROP', protocol: 'tcp', port: 22 })],
        });

        module.init(context);

        events.emit({
            type: 'net:request',
            method: 'GET',
            url: 'http://web:22/a',
            source: 'attacker',
            destination: 'web',
            timestamp: Date.now(),
        });
        events.emit({
            type: 'net:request',
            method: 'POST',
            url: 'http://web:22/bbbbb',
            source: 'attacker',
            destination: 'web',
            timestamp: Date.now(),
        });

        const service = context.services.get<FirewallEngineService>('firewall-engine');
        expect(service).toBeDefined();

        const counters = service?.getRuleCounters('web') ?? [];
        expect(counters.length).toBe(1);
        expect(counters[0]?.packets).toBe(2);
        expect(counters[0]?.bytes).toBeGreaterThan(0);

        module.destroy();
    });

    it('reject action emits medium severity alert', () => {
        const events = createTestEventBus();
        const module = createFirewallEngine(events);
        const context = makeContext(events, {
            web: [makeRule({ chain: 'INPUT', action: 'REJECT', protocol: 'tcp', port: 22 })],
        });

        module.init(context);

        events.emit({
            type: 'net:request',
            method: 'GET',
            url: 'http://web:22/admin',
            source: 'attacker',
            destination: 'web',
            timestamp: Date.now(),
        });

        const alert = events.emitted.find((event): event is Extract<EngineEvent, { type: 'defense:alert' }> => event.type === 'defense:alert');

        expect(alert).toBeDefined();
        expect(alert?.severity).toBe('medium');

        module.destroy();
    });
});
