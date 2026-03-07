/**
 * VARIANT — Lateral Movement Engine
 *
 * Simulates attacker lateral movement with:
 * - Multi-technique pivoting (SSH, RDP, PTH, PTT, etc.)
 * - Credential harvesting and reuse
 * - Attack path tracking
 * - Detection risk assessment per technique
 * - Artifact generation for blue-team training
 *
 * All operations are synchronous and pure-data.
 */

import type {
    LateralMovementEngine,
    LateralTechnique,
    NetworkHost,
    HostCredential,
    PivotAttempt,
    PivotResult,
    PivotArtifact,
    AttackPath,
} from './types';

// ── Helpers ───────────────────────────────────────────────

let pivotCounter = 0;

function generatePivotId(): string {
    return `pivot-${++pivotCounter}`;
}

const TECHNIQUE_MITRE: Record<string, string> = {
    ssh: 'T1021.004',
    rdp: 'T1021.001',
    wmi: 'T1047',
    psexec: 'T1021.002',
    smbexec: 'T1021.002',
    dcom: 'T1021.003',
    winrm: 'T1021.006',
    pass_the_hash: 'T1550.002',
    pass_the_ticket: 'T1550.003',
    overpass_the_hash: 'T1550.002',
    golden_ticket: 'T1558.001',
    silver_ticket: 'T1558.002',
    ssh_hijack: 'T1563.001',
    agent_forwarding: 'T1563.001',
    reverse_tunnel: 'T1572',
    scheduled_task_remote: 'T1053.005',
    service_creation: 'T1543.003',
};

const TECHNIQUE_REQUIRED_PORT: Partial<Record<string, number>> = {
    ssh: 22,
    rdp: 3389,
    wmi: 135,
    psexec: 445,
    smbexec: 445,
    winrm: 5985,
    dcom: 135,
};

const TECHNIQUE_DETECTION_RISK: Record<string, 'none' | 'low' | 'medium' | 'high' | 'critical'> = {
    ssh: 'low',
    rdp: 'medium',
    wmi: 'medium',
    psexec: 'high',
    smbexec: 'high',
    dcom: 'medium',
    winrm: 'medium',
    pass_the_hash: 'high',
    pass_the_ticket: 'medium',
    overpass_the_hash: 'medium',
    golden_ticket: 'low',
    silver_ticket: 'low',
    ssh_hijack: 'low',
    agent_forwarding: 'low',
    reverse_tunnel: 'medium',
    scheduled_task_remote: 'high',
    service_creation: 'high',
};

const TECHNIQUE_REQUIRED_CRED: Partial<Record<string, readonly string[]>> = {
    pass_the_hash: ['ntlm_hash'],
    pass_the_ticket: ['kerberos_tgt', 'kerberos_tgs'],
    overpass_the_hash: ['ntlm_hash'],
    golden_ticket: ['kerberos_tgt'],
    silver_ticket: ['kerberos_tgs'],
    ssh: ['password', 'ssh_key'],
    rdp: ['password', 'ntlm_hash'],
    psexec: ['password', 'ntlm_hash'],
    smbexec: ['password', 'ntlm_hash'],
    wmi: ['password', 'ntlm_hash'],
    winrm: ['password', 'ntlm_hash'],
    dcom: ['password', 'ntlm_hash'],
};

function generateArtifacts(technique: LateralTechnique, target: string): PivotArtifact[] {
    const artifacts: PivotArtifact[] = [];

    switch (technique) {
        case 'ssh':
            artifacts.push(
                { type: 'event_log', description: `SSH login accepted on ${target}`, detectable: true },
                { type: 'network_connection', description: `TCP connection to ${target}:22`, detectable: true },
            );
            break;
        case 'rdp':
            artifacts.push(
                { type: 'event_log', description: `RDP session established (Event 4624 Type 10)`, detectable: true },
                { type: 'network_connection', description: `TCP connection to ${target}:3389`, detectable: true },
                { type: 'process', description: 'rdpclip.exe spawned', detectable: true },
            );
            break;
        case 'psexec':
            artifacts.push(
                { type: 'process', description: 'PSEXESVC.exe created as service', detectable: true },
                { type: 'event_log', description: 'Service install event (Event 7045)', detectable: true },
                { type: 'file', description: `PSEXESVC.exe dropped in ADMIN$ share`, detectable: true },
                { type: 'network_connection', description: `SMB connection to ${target}:445`, detectable: true },
            );
            break;
        case 'wmi':
            artifacts.push(
                { type: 'process', description: 'WmiPrvSE.exe spawned child process', detectable: true },
                { type: 'event_log', description: 'WMI activity (Event 5857)', detectable: true },
                { type: 'network_connection', description: `DCOM connection to ${target}:135`, detectable: true },
            );
            break;
        case 'pass_the_hash':
            artifacts.push(
                { type: 'event_log', description: 'Logon with NTLM (Event 4624 Type 3)', detectable: true },
                { type: 'event_log', description: 'Pass-the-Hash detection: NTLM without preceding Type 3 auth', detectable: true },
            );
            break;
        case 'pass_the_ticket':
            artifacts.push(
                { type: 'event_log', description: 'Kerberos TGS request with forged ticket (Event 4769)', detectable: true },
            );
            break;
        case 'golden_ticket':
            artifacts.push(
                { type: 'event_log', description: 'TGT with anomalous lifetime detected', detectable: true },
            );
            break;
        default:
            artifacts.push(
                { type: 'network_connection', description: `Connection to ${target}`, detectable: true },
            );
    }

    return artifacts;
}

// ── Factory ──────────────────────────────────────────────

export function createLateralMovementEngine(): LateralMovementEngine {
    const hosts = new Map<string, NetworkHost & { _creds: HostCredential[] }>();
    const pivotHistory: PivotResult[] = [];
    const techniquesUsed = new Set<string>();
    let initialHost: string | null = null;

    function findHost(hostnameOrIp: string) {
        const direct = hosts.get(hostnameOrIp);
        if (direct) return direct;
        for (const h of hosts.values()) {
            if (h.ip === hostnameOrIp) return h;
        }
        return undefined;
    }

    const engine: LateralMovementEngine = {
        addHost(input) {
            const host: NetworkHost & { _creds: HostCredential[] } = {
                ...input,
                compromised: false,
                adminAccess: false,
                pivot: false,
                _creds: [...input.credentials],
            };
            hosts.set(input.hostname, host);
            return host;
        },

        getHost(hostnameOrIp) {
            return findHost(hostnameOrIp) ?? null;
        },

        listHosts() {
            return Object.freeze(Array.from(hosts.values()).map(h => {
                const base = {
                    hostname: h.hostname,
                    ip: h.ip,
                    os: h.os,
                    openPorts: h.openPorts,
                    services: h.services,
                    credentials: Object.freeze([...h._creds]),
                    compromised: h.compromised,
                    adminAccess: h.adminAccess,
                    pivot: h.pivot,
                };
                return h.domain !== undefined ? { ...base, domain: h.domain } : base;
            })) as readonly NetworkHost[];
        },

        compromiseHost(hostnameOrIp) {
            const host = findHost(hostnameOrIp);
            if (!host) return false;
            (host as any).compromised = true;
            (host as any).pivot = true;
            if (!initialHost) initialHost = host.hostname;
            return true;
        },

        addCredential(hostnameOrIp, credential) {
            const host = findHost(hostnameOrIp);
            if (!host) return false;
            host._creds.push(credential);
            return true;
        },

        pivot(attempt: PivotAttempt): PivotResult {
            const source = findHost(attempt.sourceMachine);
            const target = findHost(attempt.targetMachine);
            const id = generatePivotId();

            // Source must be compromised
            if (!source || !source.compromised) {
                const result: PivotResult = Object.freeze({
                    id, attempt, success: false,
                    reason: `Source ${attempt.sourceMachine} is not compromised`,
                    adminObtained: false,
                    detectionRisk: 'none',
                    mitreTechnique: engine.getMitreMapping(attempt.technique),
                    artifacts: [],
                });
                pivotHistory.push(result);
                return result;
            }

            // Target must exist
            if (!target) {
                const result: PivotResult = Object.freeze({
                    id, attempt, success: false,
                    reason: `Target ${attempt.targetMachine} not found`,
                    adminObtained: false,
                    detectionRisk: 'none',
                    mitreTechnique: engine.getMitreMapping(attempt.technique),
                    artifacts: [],
                });
                pivotHistory.push(result);
                return result;
            }

            // Check required port
            const requiredPort = TECHNIQUE_REQUIRED_PORT[attempt.technique];
            if (requiredPort && !target.openPorts.includes(requiredPort)) {
                const result: PivotResult = Object.freeze({
                    id, attempt, success: false,
                    reason: `Port ${requiredPort} not open on ${target.hostname}`,
                    adminObtained: false,
                    detectionRisk: 'low',
                    mitreTechnique: engine.getMitreMapping(attempt.technique),
                    artifacts: Object.freeze([
                        { type: 'network_connection' as const, description: `Failed connection to ${target.hostname}:${requiredPort}`, detectable: true },
                    ]),
                });
                pivotHistory.push(result);
                return result;
            }

            // Check credential type compatibility
            const allowedCreds = TECHNIQUE_REQUIRED_CRED[attempt.technique];
            if (allowedCreds && !allowedCreds.includes(attempt.credential.credType)) {
                const result: PivotResult = Object.freeze({
                    id, attempt, success: false,
                    reason: `Technique ${attempt.technique} does not accept ${attempt.credential.credType} credentials`,
                    adminObtained: false,
                    detectionRisk: 'low',
                    mitreTechnique: engine.getMitreMapping(attempt.technique),
                    artifacts: [],
                });
                pivotHistory.push(result);
                return result;
            }

            const isAdmin = attempt.credential.username === 'Administrator' ||
                attempt.credential.username === 'root' ||
                attempt.credential.credType === 'kerberos_tgt';

            // Success — mark target compromised
            techniquesUsed.add(attempt.technique);
            (target as any).compromised = true;
            (target as any).pivot = true;
            if (isAdmin) (target as any).adminAccess = true;

            const artifacts = Object.freeze(generateArtifacts(attempt.technique, target.hostname));
            const result: PivotResult = Object.freeze({
                id, attempt, success: true,
                reason: `Lateral movement via ${attempt.technique} successful`,
                adminObtained: isAdmin,
                detectionRisk: TECHNIQUE_DETECTION_RISK[attempt.technique] ?? 'medium',
                mitreTechnique: engine.getMitreMapping(attempt.technique),
                artifacts,
            });
            pivotHistory.push(result);
            return result;
        },

        getAttackPath(): AttackPath {
            const successfulPivots = pivotHistory.filter(p => p.success);
            const lastHop = successfulPivots.length > 0
                ? successfulPivots[successfulPivots.length - 1]!.attempt.targetMachine
                : (initialHost ?? '');

            return Object.freeze({
                id: 'path-1',
                hops: Object.freeze(successfulPivots),
                startHost: initialHost ?? '',
                currentHost: lastHop,
                totalHops: successfulPivots.length,
                detected: successfulPivots.some(p => p.detectionRisk === 'critical' || p.detectionRisk === 'high'),
            });
        },

        getPivotHistory() {
            return Object.freeze([...pivotHistory]);
        },

        getReachableHosts(hostnameOrIp) {
            const source = findHost(hostnameOrIp);
            if (!source || !source.compromised) return [];
            // All hosts except the source itself are potentially reachable
            return Object.freeze(
                Array.from(hosts.values())
                    .filter(h => h.hostname !== source.hostname)
                    .map(h => {
                        const base = {
                            hostname: h.hostname,
                            ip: h.ip,
                            os: h.os,
                            openPorts: h.openPorts,
                            services: h.services,
                            credentials: Object.freeze([...h._creds]),
                            compromised: h.compromised,
                            adminAccess: h.adminAccess,
                            pivot: h.pivot,
                        };
                        return h.domain !== undefined ? { ...base, domain: h.domain } : base;
                    })
            ) as readonly NetworkHost[];
        },

        getMitreMapping(technique) {
            return TECHNIQUE_MITRE[technique] ?? 'T1570';
        },

        getStats() {
            let compromised = 0;
            let admin = 0;
            let totalCreds = 0;
            for (const h of hosts.values()) {
                if (h.compromised) compromised++;
                if (h.adminAccess) admin++;
                totalCreds += h._creds.length;
            }

            return Object.freeze({
                totalHosts: hosts.size,
                compromisedHosts: compromised,
                adminHosts: admin,
                pivotAttempts: pivotHistory.length,
                successfulPivots: pivotHistory.filter(p => p.success).length,
                failedPivots: pivotHistory.filter(p => !p.success).length,
                techniquesUsed: Object.freeze(Array.from(techniquesUsed)),
                credentialsHarvested: totalCreds,
            });
        },
    };

    return engine;
}
