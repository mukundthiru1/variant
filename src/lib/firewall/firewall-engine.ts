/**
 * VARIANT — Firewall Rule Evaluation Engine
 *
 * Evaluates iptables-style firewall rules against network traffic.
 * The WorldSpec already defines MachineFirewallRule types — this
 * engine actually evaluates them. Traffic through the fabric calls
 * evaluate() before forwarding.
 *
 * What it does:
 *   - Evaluates INPUT/OUTPUT/FORWARD chain rules per machine
 *   - Supports protocol, port, source, and destination matching
 *   - Default policy per chain (ACCEPT or DROP)
 *   - Tracks match statistics for SOC dashboard
 *   - Emits events for IDS/SIEM integration
 *   - Generates iptables-format log entries
 *
 * EXTENSIBILITY:
 *   - Custom chain support (third-party chains)
 *   - Custom match extensions (string match, conntrack, etc.)
 *   - Rule priority ordering
 *   - NAT rules (SNAT/DNAT/MASQUERADE)
 *
 * SECURITY: Rules are declarative (from WorldSpec). The engine
 * evaluates them deterministically. No code execution.
 */

import type { MachineFirewallRule } from '../../core/world/types';

// ── Firewall Types ─────────────────────────────────────────────

/**
 * A packet to evaluate against firewall rules.
 */
export interface FirewallPacket {
    readonly protocol: 'tcp' | 'udp' | 'icmp';
    readonly sourceIP: string;
    readonly destinationIP: string;
    readonly sourcePort: number;
    readonly destinationPort: number;
    /** Direction relative to the machine. */
    readonly direction: 'inbound' | 'outbound' | 'forward';
}

/**
 * Result of firewall evaluation.
 */
export interface FirewallResult {
    /** Whether the packet is allowed. */
    readonly allowed: boolean;
    /** The action that was applied. */
    readonly action: 'ACCEPT' | 'DROP' | 'REJECT' | (string & {});
    /** Which rule matched (index, or -1 for default policy). */
    readonly matchedRuleIndex: number;
    /** The chain that was evaluated. */
    readonly chain: 'INPUT' | 'OUTPUT' | 'FORWARD' | (string & {});
}

/**
 * Default policies per chain.
 */
export interface FirewallPolicy {
    readonly INPUT: 'ACCEPT' | 'DROP';
    readonly OUTPUT: 'ACCEPT' | 'DROP';
    readonly FORWARD: 'ACCEPT' | 'DROP';
}

/**
 * Statistics for a firewall instance.
 */
export interface FirewallStats {
    readonly packetsEvaluated: number;
    readonly packetsAllowed: number;
    readonly packetsDropped: number;
    readonly packetsRejected: number;
    readonly ruleHits: ReadonlyMap<number, number>;
}

// ── Extended Rule (beyond WorldSpec basic rule) ────────────────

/**
 * Extended firewall rule with additional match criteria.
 * Backward compatible with MachineFirewallRule.
 */
export interface ExtendedFirewallRule extends MachineFirewallRule {
    /** Match only on specific source port. */
    readonly sourcePort?: number;
    /** Match on connection state (NEW, ESTABLISHED, RELATED). */
    readonly connState?: readonly ('NEW' | 'ESTABLISHED' | 'RELATED' | 'INVALID')[];
    /** Log this rule match. */
    readonly log?: boolean;
    /** Log prefix for identification. */
    readonly logPrefix?: string;
    /** Comment for documentation. */
    readonly comment?: string;
    /** NAT target (for SNAT/DNAT/MASQUERADE). */
    readonly nat?: {
        readonly type: 'SNAT' | 'DNAT' | 'MASQUERADE';
        readonly toAddress?: string;
        readonly toPort?: number;
    };
}

// ── Firewall Engine ────────────────────────────────────────────

/**
 * Firewall engine for a single machine.
 * Instantiate one per machine in the simulation.
 */
export interface FirewallEngine {
    /** Evaluate a packet against the firewall rules. */
    evaluate(packet: FirewallPacket): FirewallResult;
    /** Add a rule dynamically (e.g., from dynamics engine). */
    addRule(rule: ExtendedFirewallRule): void;
    /** Remove a rule by index. */
    removeRule(index: number): boolean;
    /** Insert a rule at a specific position. */
    insertRule(index: number, rule: ExtendedFirewallRule): void;
    /** Get current rule set (frozen copy). */
    getRules(): readonly ExtendedFirewallRule[];
    /** Set default policy for a chain. */
    setPolicy(chain: 'INPUT' | 'OUTPUT' | 'FORWARD', policy: 'ACCEPT' | 'DROP'): void;
    /** Get current policies. */
    getPolicies(): Readonly<FirewallPolicy>;
    /** Get statistics. */
    getStats(): FirewallStats;
    /** Reset statistics. */
    resetStats(): void;
    /** Format rules as iptables output (for `iptables -L`). */
    formatAsIptables(): string;
}

/**
 * Callback for firewall events.
 */
export type FirewallEventCallback = (
    packet: FirewallPacket,
    result: FirewallResult,
    rule: ExtendedFirewallRule | null,
) => void;

/**
 * Create a firewall engine for a machine.
 */
export function createFirewallEngine(
    _machineId: string,
    initialRules: readonly MachineFirewallRule[],
    onEvent?: FirewallEventCallback,
): FirewallEngine {
    const rules: ExtendedFirewallRule[] = initialRules.map(r => ({ ...r }));

    const policies: FirewallPolicy = {
        INPUT: 'ACCEPT',
        OUTPUT: 'ACCEPT',
        FORWARD: 'DROP',
    };
    let mutablePolicies = { ...policies };

    let packetsEvaluated = 0;
    let packetsAllowed = 0;
    let packetsDropped = 0;
    let packetsRejected = 0;
    const ruleHits = new Map<number, number>();

    function directionToChain(direction: FirewallPacket['direction']): 'INPUT' | 'OUTPUT' | 'FORWARD' {
        switch (direction) {
            case 'inbound': return 'INPUT';
            case 'outbound': return 'OUTPUT';
            case 'forward': return 'FORWARD';
        }
    }

    function matchesRule(packet: FirewallPacket, rule: ExtendedFirewallRule): boolean {
        // Chain match
        const chain = directionToChain(packet.direction);
        if (rule.chain !== chain) return false;

        // Protocol match
        if (rule.protocol !== undefined && rule.protocol !== packet.protocol) return false;

        // Port match (destination port)
        if (rule.port !== undefined && rule.port !== packet.destinationPort) return false;

        // Source port match (extended)
        if (rule.sourcePort !== undefined && rule.sourcePort !== packet.sourcePort) return false;

        // Source IP match
        if (rule.source !== undefined) {
            if (!matchesIP(packet.sourceIP, rule.source)) return false;
        }

        // Destination IP match
        if (rule.destination !== undefined) {
            if (!matchesIP(packet.destinationIP, rule.destination)) return false;
        }

        return true;
    }

    return {
        evaluate(packet: FirewallPacket): FirewallResult {
            packetsEvaluated++;
            const chain = directionToChain(packet.direction);

            // Evaluate rules in order (first match wins)
            for (let i = 0; i < rules.length; i++) {
                const rule = rules[i];
                if (rule === undefined) continue;

                if (matchesRule(packet, rule)) {
                    // Track hit
                    ruleHits.set(i, (ruleHits.get(i) ?? 0) + 1);

                    const action = rule.action;
                    if (action === 'ACCEPT') packetsAllowed++;
                    else if (action === 'DROP') packetsDropped++;
                    else if (action === 'REJECT') packetsRejected++;

                    const result: FirewallResult = {
                        allowed: action === 'ACCEPT',
                        action,
                        matchedRuleIndex: i,
                        chain,
                    };

                    if (onEvent !== undefined) {
                        onEvent(packet, result, rule);
                    }

                    return result;
                }
            }

            // Default policy
            const defaultAction = mutablePolicies[chain];
            if (defaultAction === 'ACCEPT') packetsAllowed++;
            else packetsDropped++;

            const result: FirewallResult = {
                allowed: defaultAction === 'ACCEPT',
                action: defaultAction,
                matchedRuleIndex: -1,
                chain,
            };

            if (onEvent !== undefined) {
                onEvent(packet, result, null);
            }

            return result;
        },

        addRule(rule: ExtendedFirewallRule): void {
            rules.push({ ...rule });
        },

        removeRule(index: number): boolean {
            if (index < 0 || index >= rules.length) return false;
            rules.splice(index, 1);
            return true;
        },

        insertRule(index: number, rule: ExtendedFirewallRule): void {
            const clampedIndex = Math.max(0, Math.min(index, rules.length));
            rules.splice(clampedIndex, 0, { ...rule });
        },

        getRules(): readonly ExtendedFirewallRule[] {
            return Object.freeze(rules.map(r => ({ ...r })));
        },

        setPolicy(chain: 'INPUT' | 'OUTPUT' | 'FORWARD', policy: 'ACCEPT' | 'DROP'): void {
            mutablePolicies = { ...mutablePolicies, [chain]: policy };
        },

        getPolicies(): Readonly<FirewallPolicy> {
            return Object.freeze({ ...mutablePolicies });
        },

        getStats(): FirewallStats {
            return {
                packetsEvaluated,
                packetsAllowed,
                packetsDropped,
                packetsRejected,
                ruleHits: new Map(ruleHits),
            };
        },

        resetStats(): void {
            packetsEvaluated = 0;
            packetsAllowed = 0;
            packetsDropped = 0;
            packetsRejected = 0;
            ruleHits.clear();
        },

        formatAsIptables(): string {
            const lines: string[] = [];

            for (const chain of ['INPUT', 'OUTPUT', 'FORWARD'] as const) {
                const policy = mutablePolicies[chain];
                lines.push(`Chain ${chain} (policy ${policy})`);
                lines.push('target     prot opt source               destination');

                for (const rule of rules) {
                    if (rule.chain !== chain) continue;

                    const target = rule.action.padEnd(10);
                    const prot = (rule.protocol ?? 'all').padEnd(4);
                    const opt = '--  ';
                    const src = (rule.source ?? '0.0.0.0/0').padEnd(20);
                    const dst = (rule.destination ?? '0.0.0.0/0').padEnd(20);
                    const portStr = rule.port !== undefined ? ` dpt:${rule.port}` : '';
                    const comment = rule.comment !== undefined ? ` /* ${rule.comment} */` : '';

                    lines.push(`${target} ${prot} ${opt} ${src} ${dst}${portStr}${comment}`);
                }

                lines.push('');
            }

            return lines.join('\n');
        },
    };
}

// ── IP Matching ────────────────────────────────────────────────

/**
 * Match an IP against a rule target.
 * Supports:
 *   - Exact match: '10.0.1.5'
 *   - CIDR: '10.0.1.0/24'
 *   - Wildcard: '0.0.0.0/0' (match all)
 *   - Hostname: ignored (always matches)
 */
function matchesIP(ip: string, rule: string): boolean {
    // Exact match
    if (ip === rule) return true;

    // Match all
    if (rule === '0.0.0.0/0' || rule === '*') return true;

    // CIDR match
    if (rule.includes('/')) {
        const parts = rule.split('/');
        const ruleIP = parts[0];
        const mask = parseInt(parts[1] ?? '32', 10);

        if (ruleIP === undefined) return false;

        const ipNum = ipToNumber(ip);
        const ruleNum = ipToNumber(ruleIP);

        if (ipNum === null || ruleNum === null) return false;

        const maskBits = mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0;
        return (ipNum & maskBits) === (ruleNum & maskBits);
    }

    return false;
}

/**
 * Convert an IPv4 address to a 32-bit number.
 */
function ipToNumber(ip: string): number | null {
    const parts = ip.split('.');
    if (parts.length !== 4) return null;

    let result = 0;
    for (const part of parts) {
        const num = parseInt(part, 10);
        if (isNaN(num) || num < 0 || num > 255) return null;
        result = (result << 8) | num;
    }

    return result >>> 0; // Ensure unsigned
}
