import type { Module, SimulationContext, Capability } from '../core/modules';
import type { EventBus, EngineEvent } from '../core/events';
import type { CredentialEntry, NetworkSpec, MachineSpec } from '../core/world/types';

// ── Types ────────────────────────────────────────────────────────

export interface MachineAccess {
    machine: string;
    user: string;
    shell?: string;
}

export interface MovementResult {
    success: boolean;
    newAccess?: MachineAccess;
    events: EngineEvent[];
    error?: string;
}

export interface PivotChainEntry {
    from: MachineAccess;
    to: MachineAccess;
    technique: string;
    tick: number;
}

export interface LateralMovementTechnique {
    id: string;
    name: string;
    requiresCredType: string;
    sourceProtocol?: string;
    targetProtocol: string;
    execute: (from: string, to: string, credential: CredentialEntry) => MovementResult;
}

export interface NetworkTopology {
    machines: Readonly<Record<string, MachineSpec>>;
    network: NetworkSpec;
}

// ── State ────────────────────────────────────────────────────────

let pivotChain: PivotChainEntry[] = [];

export function recordPivot(from: MachineAccess, to: MachineAccess, technique: string, tick: number): void {
    pivotChain.push({ from, to, technique, tick });
}

export function getPivotChain(): PivotChainEntry[] {
    return [...pivotChain];
}

export function getAccessibleMachines(): string[] {
    const accessible = new Set<string>();
    for (const pivot of pivotChain) {
        accessible.add(pivot.from.machine);
        accessible.add(pivot.to.machine);
    }
    return Array.from(accessible);
}

export function resetLateralMovementState(): void {
    pivotChain = [];
}

// ── Network Reachability ──────────────────────────────────────────

export function canReach(from: string, to: string, port: number, topology: NetworkTopology): boolean {
    if (from === to) return true;

    const graph = new Map<string, Array<{ target: string; ports?: readonly number[] }>>();

    const addEdge = (u: string, v: string, ports?: readonly number[], bidi?: boolean) => {
        if (!graph.has(u)) graph.set(u, []);
        graph.get(u)!.push(ports ? { target: v, ports } : { target: v });
        if (bidi) {
            if (!graph.has(v)) graph.set(v, []);
            graph.get(v)!.push(ports ? { target: u, ports } : { target: u });
        }
    };

    // Add machine <-> segment links
    for (const [machineId, machine] of Object.entries(topology.machines)) {
        if (machine.interfaces) {
            for (const iface of machine.interfaces) {
                addEdge(machineId, iface.segment, undefined, true);
            }
        }
    }

    // Add network edges
    if (topology.network && topology.network.edges) {
        for (const edge of topology.network.edges) {
            addEdge(edge.from, edge.to, edge.ports, edge.bidirectional);
        }
    }

    // BFS
    const visited = new Set<string>();
    const queue: string[] = [from];
    visited.add(from);

    while (queue.length > 0) {
        const curr = queue.shift()!;
        if (curr === to) return true;

        const neighbors = graph.get(curr) || [];
        for (const n of neighbors) {
            if (n.ports !== undefined && n.ports.length > 0) {
                if (!n.ports.includes(port)) continue;
            }
            
            if (!visited.has(n.target)) {
                visited.add(n.target);
                queue.push(n.target);
            }
        }
    }

    return false;
}

// ── Techniques ────────────────────────────────────────────────────

export const techniques: LateralMovementTechnique[] = [
    {
        id: 'ssh-key',
        name: 'SSH Key Authentication',
        requiresCredType: 'ssh-key',
        sourceProtocol: 'ssh',
        targetProtocol: 'ssh',
        execute: (_from, to, cred) => ({
            success: true,
            newAccess: { machine: to, user: cred.validAt.user, shell: '/bin/bash' },
            events: [
                { type: 'auth:login', user: cred.validAt.user, machine: to, service: 'ssh', success: true, timestamp: Date.now() }
            ]
        })
    },
    {
        id: 'ssh-password',
        name: 'SSH Password Authentication',
        requiresCredType: 'password',
        sourceProtocol: 'ssh',
        targetProtocol: 'ssh',
        execute: (_from, to, cred) => ({
            success: true,
            newAccess: { machine: to, user: cred.validAt.user, shell: '/bin/bash' },
            events: [
                { type: 'auth:login', user: cred.validAt.user, machine: to, service: 'ssh', success: true, timestamp: Date.now() }
            ]
        })
    },
    {
        id: 'pass-the-hash',
        name: 'Pass-the-Hash',
        requiresCredType: 'hash',
        targetProtocol: 'smb',
        execute: (_from, to, cred) => ({
            success: true,
            newAccess: { machine: to, user: cred.validAt.user, shell: 'cmd.exe' },
            events: [
                { type: 'auth:login', user: cred.validAt.user, machine: to, service: 'smb', success: true, timestamp: Date.now() }
            ]
        })
    },
    {
        id: 'pass-the-ticket',
        name: 'Pass-the-Ticket',
        requiresCredType: 'kerberos-ticket',
        targetProtocol: 'smb',
        execute: (_from, to, cred) => ({
            success: true,
            newAccess: { machine: to, user: cred.validAt.user, shell: 'cmd.exe' },
            events: [
                { type: 'auth:login', user: cred.validAt.user, machine: to, service: 'kerberos', success: true, timestamp: Date.now() }
            ]
        })
    },
    {
        id: 'port-forwarding',
        name: 'Port Forwarding',
        requiresCredType: 'ssh-key',
        targetProtocol: 'ssh',
        execute: (_from, to, cred) => ({
            success: true,
            newAccess: { machine: to, user: cred.validAt.user, shell: '/bin/bash' },
            events: []
        })
    },
    {
        id: 'socks-proxy',
        name: 'SOCKS Proxy',
        requiresCredType: 'password',
        targetProtocol: 'ssh',
        execute: (_from, to, cred) => ({
            success: true,
            newAccess: { machine: to, user: cred.validAt.user, shell: '/bin/bash' },
            events: []
        })
    },
    {
        id: 'web-shell-pivot',
        name: 'Web Shell Pivot',
        requiresCredType: 'cookie',
        targetProtocol: 'http',
        execute: (_from, to, cred) => ({
            success: true,
            newAccess: { machine: to, user: cred.validAt.user, shell: 'www-data' },
            events: [
                { type: 'auth:login', user: cred.validAt.user, machine: to, service: 'http', success: true, timestamp: Date.now() }
            ]
        })
    },
    {
        id: 'database-link',
        name: 'Database Link',
        requiresCredType: 'database-password',
        targetProtocol: 'mysql',
        execute: (_from, to, cred) => ({
            success: true,
            newAccess: { machine: to, user: cred.validAt.user, shell: 'sql' },
            events: [
                { type: 'auth:login', user: cred.validAt.user, machine: to, service: 'mysql', success: true, timestamp: Date.now() }
            ]
        })
    },
    {
        id: 'cloud-role-chaining',
        name: 'Cloud Role Chaining',
        requiresCredType: 'api-token',
        targetProtocol: 'https',
        execute: (_from, to, cred) => ({
            success: true,
            newAccess: { machine: to, user: cred.validAt.user, shell: 'aws-cli' },
            events: [
                { type: 'auth:escalate', machine: to, from: 'user', to: cred.validAt.user, method: 'assume-role', timestamp: Date.now() }
            ]
        })
    },
    {
        id: 'container-escape',
        name: 'Container Escape',
        requiresCredType: 'jwt-secret',
        targetProtocol: 'docker',
        execute: (_from, to, cred) => ({
            success: true,
            newAccess: { machine: to, user: 'root', shell: '/bin/bash' },
            events: [
                { type: 'auth:escalate', machine: to, from: cred.validAt.user, to: 'root', method: 'container-escape', timestamp: Date.now() }
            ]
        })
    }
];

// ── Validation ────────────────────────────────────────────────────

export function validateMovement(from: string, to: string, credential: CredentialEntry, techniqueId: string, topology: NetworkTopology): MovementResult {
    const technique = techniques.find(t => t.id === techniqueId);
    if (!technique) {
        return { success: false, events: [], error: `Unknown technique: ${techniqueId}` };
    }

    if (credential.type !== technique.requiresCredType) {
        return { success: false, events: [], error: 'Credential type mismatch' };
    }

    if (credential.validAt.machine !== to) {
        return { success: false, events: [], error: 'Credential not valid for target machine' };
    }

    const portMap: Record<string, number> = { ssh: 22, smb: 445, http: 80, https: 443, mysql: 3306, docker: 2375 };
    const port = portMap[technique.targetProtocol] || 0;

    if (port > 0 && !canReach(from, to, port, topology)) {
        return { success: false, events: [], error: 'Network path blocked by firewall or no route' };
    }

    return technique.execute(from, to, credential);
}

// ── Module ────────────────────────────────────────────────────────

const MODULE_ID = 'lateral-movement';
const MODULE_VERSION = '1.0.0';

export function createLateralMovementModule(eventBus?: EventBus): Module {
    return {
        id: MODULE_ID,
        type: 'engine',
        version: MODULE_VERSION,
        description: 'Engine for tracking and validating lateral movement and pivoting across the simulation',
        provides: [{ name: 'lateral-movement' }, { name: 'pivoting' }] as readonly Capability[],
        requires: [] as readonly Capability[],

        init(context: SimulationContext) {
            const bus = eventBus || context.events;
            resetLateralMovementState();

            bus.on('auth:login', (_event) => {
                // Tracking based on general auth events (if user successfully logs in from another machine)
                // The explicit tracking is typically handled directly via validateMovement calling recordPivot.
            });

            bus.on('net:connect', (event) => {
                const topology: NetworkTopology = {
                    machines: context.world.machines,
                    network: context.world.network
                };
                
                // net:connect might not use exact known target ports if custom. We assume port is provided
                const reachable = canReach(event.source, event.host, event.port, topology);
                if (!reachable) {
                    bus.emit({
                        type: 'defense:alert',
                        machine: event.host,
                        ruleId: 'LM-BLOCKED-CONN',
                        severity: 'medium',
                        detail: `Blocked connection from ${event.source} to ${event.host}:${event.port}`,
                        timestamp: Date.now()
                    });
                }
            });

            context.services.register('lateral-movement', {
                validateMovement: (from: string, to: string, cred: CredentialEntry, tech: string) => {
                    const topology = { machines: context.world.machines, network: context.world.network };
                    const result = validateMovement(from, to, cred, tech, topology);
                    
                    if (result.success && result.newAccess) {
                        recordPivot({ machine: from, user: 'system' }, result.newAccess, tech, context.tick);
                        
                        for (const ev of result.events) {
                            bus.emit(ev);
                        }
                        
                        // Emit alert for unusual lateral movements
                        if (!['ssh-key', 'ssh-password', 'web-shell-pivot'].includes(tech)) {
                            bus.emit({
                                type: 'defense:alert',
                                machine: to,
                                ruleId: 'LM-UNUSUAL-TECHNIQUE',
                                severity: 'high',
                                detail: `Unusual lateral movement detected from ${from} via ${tech}`,
                                timestamp: Date.now()
                            });
                        }
                    }
                    return result;
                },
                recordPivot,
                getPivotChain,
                getAccessibleMachines,
                canReach: (from: string, to: string, port: number) => {
                    return canReach(from, to, port, { machines: context.world.machines, network: context.world.network });
                },
            });
        },

        destroy() {
            resetLateralMovementState();
        }
    };
}
