/**
 * VARIANT — Firewall Evaluation Module
 *
 * Evaluates per-machine iptables-style rules against network request events.
 */

import type { EventBus, NetRequestEvent, Unsubscribe } from '../core/events';
import type { Capability, Module, SimulationContext } from '../core/modules';
import type { MachineFirewallRule, MachineSpec } from '../core/world/types';
import { isInSubnet } from '../core/fabric/frames';

const MODULE_ID = 'firewall-engine';
const MODULE_VERSION = '1.0.0';

const CAPABILITIES = [
    { name: 'firewall' },
    { name: 'iptables' },
] as const satisfies readonly Capability[];

const EPHEMERAL_SOURCE_PORT = 49152;

type FirewallAction = 'accept' | 'drop' | 'reject';

export interface PacketInfo {
    readonly srcIp: string;
    readonly dstIp: string;
    readonly srcPort: number;
    readonly dstPort: number;
    readonly protocol: 'tcp' | 'udp' | 'icmp' | 'any' | (string & {});
    readonly direction: 'INPUT' | 'OUTPUT' | 'FORWARD';
    readonly bytes?: number;
}

export interface FirewallDecision {
    readonly decision: FirewallAction;
    readonly matchedRule: MachineFirewallRule | null;
    readonly ruleIndex: number;
}

export interface RuleHitCounter {
    readonly packets: number;
    readonly bytes: number;
}

interface MutableRuleHitCounter {
    packets: number;
    bytes: number;
}

interface PortSpecRule extends MachineFirewallRule {
    readonly sourcePort?: number | string;
    readonly destinationPort?: number | string;
    readonly srcPort?: number | string;
    readonly dstPort?: number | string;
}

interface FirewallEngineService {
    evaluateRule: typeof evaluateRule;
    evaluateChain: typeof evaluateChain;
    parseIptablesOutput: typeof parseIptablesOutput;
    parseIptablesCommand: typeof parseIptablesCommand;
    getRuleCounters(machineId: string): readonly RuleHitCounter[];
}

function normalizeChain(chain: string): 'INPUT' | 'OUTPUT' | 'FORWARD' | null {
    const normalized = chain.toUpperCase();
    if (normalized === 'INPUT' || normalized === 'OUTPUT' || normalized === 'FORWARD') {
        return normalized;
    }
    return null;
}

function normalizeAction(action: string): FirewallAction | null {
    const normalized = action.toUpperCase();
    if (normalized === 'ACCEPT') return 'accept';
    if (normalized === 'DROP') return 'drop';
    if (normalized === 'REJECT') return 'reject';
    return null;
}

function normalizeProtocol(protocol: string): string {
    const lowered = protocol.toLowerCase();
    return lowered === 'all' ? 'any' : lowered;
}

function parsePortToken(port: number | string | undefined): { min: number; max: number } | null {
    if (port === undefined) return null;
    if (typeof port === 'number') {
        if (!Number.isInteger(port) || port < 0 || port > 65535) return null;
        return { min: port, max: port };
    }

    const trimmed = port.trim();
    if (trimmed === '' || trimmed === '*' || trimmed.toLowerCase() === 'any') {
        return null;
    }

    if (!trimmed.includes(':')) {
        const exact = Number.parseInt(trimmed, 10);
        if (!Number.isInteger(exact) || exact < 0 || exact > 65535) return null;
        return { min: exact, max: exact };
    }

    const parts = trimmed.split(':', 2);
    const startRaw = parts[0];
    const endRaw = parts[1];
    if (startRaw === undefined || endRaw === undefined) return null;
    const min = startRaw === '' ? 0 : Number.parseInt(startRaw, 10);
    const max = endRaw === '' ? 65535 : Number.parseInt(endRaw, 10);

    if (!Number.isInteger(min) || !Number.isInteger(max) || min < 0 || max > 65535 || min > max) {
        return null;
    }

    return { min, max };
}

function matchesPort(port: number, expected: number | string | undefined): boolean {
    const range = parsePortToken(expected);
    if (range === null) return expected === undefined || expected === '*' || expected === 'any';
    return port >= range.min && port <= range.max;
}

function matchesIp(ip: string, target: string | undefined): boolean {
    if (target === undefined || target === '*' || target === '0.0.0.0/0') return true;
    if (target.includes('/')) return isInSubnet(ip, target);
    return ip === target;
}

function pickSourcePort(rule: MachineFirewallRule): number | string | undefined {
    const extended = rule as PortSpecRule;
    return extended.sourcePort ?? extended.srcPort;
}

function pickDestinationPort(rule: MachineFirewallRule): number | string | undefined {
    const extended = rule as PortSpecRule;
    return extended.destinationPort ?? extended.dstPort ?? rule.port;
}

export function evaluateRule(
    rule: MachineFirewallRule,
    packet: PacketInfo,
): 'accept' | 'drop' | 'reject' | 'no-match' {
    const chain = normalizeChain(rule.chain);
    if (chain === null || chain !== packet.direction) return 'no-match';

    if (!matchesIp(packet.srcIp, rule.source)) return 'no-match';
    if (!matchesIp(packet.dstIp, rule.destination)) return 'no-match';

    const srcPort = pickSourcePort(rule);
    if (srcPort !== undefined && !matchesPort(packet.srcPort, srcPort)) return 'no-match';

    const dstPort = pickDestinationPort(rule);
    if (dstPort !== undefined && !matchesPort(packet.dstPort, dstPort)) return 'no-match';

    if (rule.protocol !== undefined) {
        const expectedProtocol = normalizeProtocol(rule.protocol);
        if (expectedProtocol !== 'any' && expectedProtocol !== packet.protocol.toLowerCase()) {
            return 'no-match';
        }
    }

    return normalizeAction(rule.action) ?? 'no-match';
}

export function evaluateChain(
    rules: readonly MachineFirewallRule[],
    packet: PacketInfo,
    defaultPolicy: 'accept' | 'drop',
): FirewallDecision {
    for (let index = 0; index < rules.length; index++) {
        const rule = rules[index];
        if (rule === undefined) continue;
        const decision = evaluateRule(rule, packet);
        if (decision === 'no-match') continue;

        return {
            decision,
            matchedRule: rule,
            ruleIndex: index,
        };
    }

    return {
        decision: defaultPolicy,
        matchedRule: null,
        ruleIndex: -1,
    };
}

export function parseIptablesOutput(rules: readonly MachineFirewallRule[]): string {
    const lines: string[] = [];

    for (const chain of ['INPUT', 'OUTPUT', 'FORWARD'] as const) {
        lines.push(`Chain ${chain} (policy ACCEPT)`);
        lines.push('target     prot opt source               destination         ports');

        for (const rule of rules) {
            if (normalizeChain(rule.chain) !== chain) continue;

            const target = rule.action.toUpperCase().padEnd(10);
            const protocol = (rule.protocol ?? 'all').padEnd(4);
            const source = (rule.source ?? '0.0.0.0/0').padEnd(20);
            const destination = (rule.destination ?? '0.0.0.0/0').padEnd(20);
            const srcPort = pickSourcePort(rule);
            const dstPort = pickDestinationPort(rule);

            const parts: string[] = [];
            if (srcPort !== undefined) parts.push(`spt:${String(srcPort)}`);
            if (dstPort !== undefined) parts.push(`dpt:${String(dstPort)}`);
            const ports = parts.join(' ');

            lines.push(`${target} ${protocol} --  ${source} ${destination} ${ports}`.trimEnd());
        }

        lines.push('');
    }

    return lines.join('\n').trimEnd();
}

function tokenizeCommand(command: string): readonly string[] {
    const tokens = command.match(/(?:"[^"]*"|'[^']*'|\S+)/g) ?? [];
    return tokens.map((token) => token.replace(/^['"]|['"]$/g, ''));
}

export function parseIptablesCommand(cmd: string): MachineFirewallRule | null {
    const tokens = tokenizeCommand(cmd);
    if (tokens.length < 2) return null;
    if (tokens[0] !== 'iptables') return null;

    const rule: { -readonly [K in keyof PortSpecRule]?: PortSpecRule[K] } = {};

    for (let index = 1; index < tokens.length; index++) {
        const token = tokens[index];
        if (token === undefined) break;

        if ((token === '-A' || token === '--append') && tokens[index + 1] !== undefined) {
            rule.chain = tokens[index + 1]!.toUpperCase() as MachineFirewallRule['chain'];
            index++;
            continue;
        }
        if ((token === '-s' || token === '--source') && tokens[index + 1] !== undefined) {
            rule.source = tokens[index + 1]!;
            index++;
            continue;
        }
        if ((token === '-d' || token === '--destination') && tokens[index + 1] !== undefined) {
            rule.destination = tokens[index + 1]!;
            index++;
            continue;
        }
        if ((token === '-p' || token === '--protocol') && tokens[index + 1] !== undefined) {
            const normalized = normalizeProtocol(tokens[index + 1]!);
            if (normalized === 'tcp' || normalized === 'udp' || normalized === 'icmp') {
                rule.protocol = normalized;
            }
            index++;
            continue;
        }
        if ((token === '--sport' || token === '--source-port') && tokens[index + 1] !== undefined) {
            const parsed = parsePortToken(tokens[index + 1]!);
            rule.sourcePort = parsed !== null && parsed.min === parsed.max ? parsed.min : tokens[index + 1]!;
            index++;
            continue;
        }
        if ((token === '--dport' || token === '--destination-port') && tokens[index + 1] !== undefined) {
            const parsed = parsePortToken(tokens[index + 1]!);
            if (parsed !== null && parsed.min === parsed.max) {
                rule.port = parsed.min;
                rule.destinationPort = parsed.min;
            } else {
                rule.destinationPort = tokens[index + 1]!;
            }
            index++;
            continue;
        }
        if ((token === '-j' || token === '--jump') && tokens[index + 1] !== undefined) {
            rule.action = tokens[index + 1]!.toUpperCase() as MachineFirewallRule['action'];
            index++;
            continue;
        }
    }

    if (rule.chain === undefined || rule.action === undefined) return null;
    if (normalizeChain(rule.chain) === null) return null;
    if (normalizeAction(rule.action) === null) return null;

    return rule as MachineFirewallRule;
}

function resolveMachineIp(machine?: MachineSpec): string {
    return machine?.interfaces[0]?.ip ?? '0.0.0.0';
}

function extractDestinationHost(urlString: string): string | null {
    try {
        return new URL(urlString).hostname;
    } catch {
        return null;
    }
}

function extractDestinationPort(urlString: string): number {
    try {
        const parsed = new URL(urlString);
        if (parsed.port !== '') {
            const direct = Number.parseInt(parsed.port, 10);
            if (Number.isInteger(direct) && direct >= 0 && direct <= 65535) {
                return direct;
            }
        }
        if (parsed.protocol === 'https:') return 443;
        return 80;
    } catch {
        return 80;
    }
}

function extractProtocol(urlString: string): 'tcp' | 'udp' | 'icmp' {
    try {
        const parsed = new URL(urlString);
        if (parsed.protocol === 'icmp:') return 'icmp';
        return 'tcp';
    } catch {
        return 'tcp';
    }
}

function resolveDestinationIp(
    event: NetRequestEvent,
    machines: Readonly<Record<string, MachineSpec>>,
): string {
    const machine = machines[event.destination];
    if (machine !== undefined) return resolveMachineIp(machine);

    const fromUrl = extractDestinationHost(event.url);
    if (fromUrl !== null && /^\d+\.\d+\.\d+\.\d+$/.test(fromUrl)) {
        return fromUrl;
    }
    if (/^\d+\.\d+\.\d+\.\d+$/.test(event.destination)) {
        return event.destination;
    }

    return '0.0.0.0';
}

function makePacketFromEvent(
    event: NetRequestEvent,
    context: SimulationContext,
): PacketInfo {
    const sourceMachine = context.world.machines[event.source];

    return {
        srcIp: resolveMachineIp(sourceMachine),
        dstIp: resolveDestinationIp(event, context.world.machines),
        srcPort: EPHEMERAL_SOURCE_PORT,
        dstPort: extractDestinationPort(event.url),
        protocol: extractProtocol(event.url),
        direction: 'OUTPUT',
        bytes: event.url.length + event.method.length,
    };
}

function getOrCreateCounters(
    countersByMachine: Map<string, MutableRuleHitCounter[]>,
    machineId: string,
    rules: readonly MachineFirewallRule[],
): MutableRuleHitCounter[] {
    let counters = countersByMachine.get(machineId);
    if (counters === undefined) {
        counters = rules.map(() => ({ packets: 0, bytes: 0 }));
        countersByMachine.set(machineId, counters);
    }

    while (counters.length < rules.length) {
        counters.push({ packets: 0, bytes: 0 });
    }

    return counters;
}

function emitBlockAlert(
    bus: EventBus,
    machineId: string,
    event: NetRequestEvent,
    packet: PacketInfo,
    decision: FirewallDecision,
): void {
    const target = decision.matchedRule === null ? 'default-policy' : `rule-${decision.ruleIndex}`;
    bus.emit({
        type: 'defense:alert',
        machine: machineId,
        ruleId: `firewall/${target}`,
        severity: decision.decision === 'reject' ? 'medium' : 'high',
        detail: `${decision.decision.toUpperCase()} ${packet.protocol.toUpperCase()} ${packet.srcIp}:${packet.srcPort} -> ${packet.dstIp}:${packet.dstPort} for ${event.method} ${event.url}`,
        timestamp: Date.now(),
    });
}

function toReadonlyCounters(counters: readonly MutableRuleHitCounter[]): readonly RuleHitCounter[] {
    return counters.map(counter => ({ packets: counter.packets, bytes: counter.bytes }));
}

export function createFirewallEngine(eventBus: EventBus): Module {
    const unsubscribers: Unsubscribe[] = [];
    const rulesByMachine = new Map<string, readonly MachineFirewallRule[]>();
    const countersByMachine = new Map<string, MutableRuleHitCounter[]>();
    const defaultInputPolicy = new Map<string, 'accept' | 'drop'>();
    const defaultOutputPolicy = new Map<string, 'accept' | 'drop'>();

    const module: Module = {
        id: MODULE_ID,
        type: 'defense',
        version: MODULE_VERSION,
        description: 'Evaluates machine firewall rules for network request events',
        provides: CAPABILITIES,
        requires: [] as const,

        init(context: SimulationContext): void {
            rulesByMachine.clear();
            countersByMachine.clear();
            defaultInputPolicy.clear();
            defaultOutputPolicy.clear();

            for (const [machineId, machine] of Object.entries(context.world.machines)) {
                const rules = machine.firewall ?? [];
                if (rules.length === 0) continue;
                rulesByMachine.set(machineId, rules);
                countersByMachine.set(machineId, rules.map(() => ({ packets: 0, bytes: 0 })));
                defaultInputPolicy.set(machineId, 'accept');
                defaultOutputPolicy.set(machineId, 'accept');
            }

            const service: FirewallEngineService = {
                evaluateRule,
                evaluateChain,
                parseIptablesOutput,
                parseIptablesCommand,
                getRuleCounters(machineId: string): readonly RuleHitCounter[] {
                    const counters = countersByMachine.get(machineId) ?? [];
                    return toReadonlyCounters(counters);
                },
            };

            if (!context.services.has(MODULE_ID)) {
                context.services.register(MODULE_ID, service);
            }

            const unsub = eventBus.on('net:request', (event) => {
                const packet = makePacketFromEvent(event, context);
                const sourceRules = rulesByMachine.get(event.source);

                if (sourceRules !== undefined) {
                    const sourceDecision = evaluateChain(
                        sourceRules,
                        { ...packet, direction: 'OUTPUT' },
                        defaultOutputPolicy.get(event.source) ?? 'accept',
                    );

                    if (sourceDecision.ruleIndex >= 0) {
                        const counters = getOrCreateCounters(countersByMachine, event.source, sourceRules);
                        const current = counters[sourceDecision.ruleIndex];
                        if (current !== undefined) {
                            current.packets += 1;
                            current.bytes += packet.bytes ?? 0;
                        }
                    }

                    if (sourceDecision.decision !== 'accept') {
                        emitBlockAlert(eventBus, event.source, event, { ...packet, direction: 'OUTPUT' }, sourceDecision);
                        return;
                    }
                }

                const destinationRules = rulesByMachine.get(event.destination);
                if (destinationRules === undefined) return;

                const destinationDecision = evaluateChain(
                    destinationRules,
                    { ...packet, direction: 'INPUT' },
                    defaultInputPolicy.get(event.destination) ?? 'accept',
                );

                if (destinationDecision.ruleIndex >= 0) {
                    const counters = getOrCreateCounters(countersByMachine, event.destination, destinationRules);
                    const current = counters[destinationDecision.ruleIndex];
                    if (current !== undefined) {
                        current.packets += 1;
                        current.bytes += packet.bytes ?? 0;
                    }
                }

                if (destinationDecision.decision !== 'accept') {
                    emitBlockAlert(eventBus, event.destination, event, { ...packet, direction: 'INPUT' }, destinationDecision);
                }
            });

            unsubscribers.push(unsub);
        },

        destroy(): void {
            for (const unsub of unsubscribers) {
                unsub();
            }
            unsubscribers.length = 0;
            rulesByMachine.clear();
            countersByMachine.clear();
            defaultInputPolicy.clear();
            defaultOutputPolicy.clear();
        },
    };

    return module;
}
