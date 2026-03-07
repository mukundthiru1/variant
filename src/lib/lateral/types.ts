/**
 * VARIANT — Lateral Movement Types
 *
 * Simulates attacker lateral movement across a network:
 * - SSH/RDP/WMI/PSExec/Pass-the-Hash/Pass-the-Ticket pivoting
 * - Credential reuse tracking
 * - Network hop visualization
 * - Detection surface mapping
 *
 * EXTENSIBILITY: Custom technique types via open union.
 * SWAPPABILITY: Implements LateralMovementEngine interface.
 */

// ── Lateral Movement Technique ───────────────────────────

export type LateralTechnique =
    | 'ssh' | 'rdp' | 'wmi' | 'psexec' | 'smbexec'
    | 'dcom' | 'winrm' | 'pass_the_hash' | 'pass_the_ticket'
    | 'overpass_the_hash' | 'golden_ticket' | 'silver_ticket'
    | 'ssh_hijack' | 'agent_forwarding' | 'reverse_tunnel'
    | 'scheduled_task_remote' | 'service_creation'
    | (string & {});

// ── Network Host ─────────────────────────────────────────

export interface NetworkHost {
    readonly hostname: string;
    readonly ip: string;
    readonly os: 'windows' | 'linux' | 'macos' | (string & {});
    readonly domain?: string;
    readonly openPorts: readonly number[];
    readonly services: readonly HostService[];
    readonly credentials: readonly HostCredential[];
    readonly compromised: boolean;
    readonly adminAccess: boolean;
    readonly pivot: boolean;
}

export interface HostService {
    readonly port: number;
    readonly protocol: string;
    readonly name: string;
    readonly version?: string;
    readonly authenticated: boolean;
}

export interface HostCredential {
    readonly username: string;
    readonly credType: CredentialType;
    readonly domain?: string;
    readonly hash?: string;
    readonly ticket?: string;
    readonly key?: string;
}

export type CredentialType =
    | 'password' | 'ntlm_hash' | 'kerberos_tgt' | 'kerberos_tgs'
    | 'ssh_key' | 'certificate' | 'token'
    | (string & {});

// ── Pivot Attempt & Result ───────────────────────────────

export interface PivotAttempt {
    readonly sourceMachine: string;
    readonly targetMachine: string;
    readonly technique: LateralTechnique;
    readonly credential: HostCredential;
    readonly tick: number;
}

export interface PivotResult {
    readonly id: string;
    readonly attempt: PivotAttempt;
    readonly success: boolean;
    readonly reason: string;
    readonly adminObtained: boolean;
    readonly detectionRisk: 'none' | 'low' | 'medium' | 'high' | 'critical';
    readonly mitreTechnique: string;
    readonly artifacts: readonly PivotArtifact[];
}

export interface PivotArtifact {
    readonly type: 'event_log' | 'process' | 'network_connection' | 'file' | 'registry' | (string & {});
    readonly description: string;
    readonly detectable: boolean;
}

// ── Attack Path ──────────────────────────────────────────

export interface AttackPath {
    readonly id: string;
    readonly hops: readonly PivotResult[];
    readonly startHost: string;
    readonly currentHost: string;
    readonly totalHops: number;
    readonly detected: boolean;
}

// ── Lateral Movement Engine Interface ────────────────────

export interface LateralMovementEngine {
    /** Register a network host. */
    addHost(host: Omit<NetworkHost, 'compromised' | 'adminAccess' | 'pivot'>): NetworkHost;
    /** Get a host by hostname or IP. */
    getHost(hostnameOrIp: string): NetworkHost | null;
    /** List all hosts. */
    listHosts(): readonly NetworkHost[];
    /** Mark a host as initially compromised (foothold). */
    compromiseHost(hostnameOrIp: string): boolean;
    /** Add a credential discovered on a host. */
    addCredential(hostnameOrIp: string, credential: HostCredential): boolean;
    /** Attempt lateral movement. */
    pivot(attempt: PivotAttempt): PivotResult;
    /** Get attack path from initial compromise. */
    getAttackPath(): AttackPath;
    /** List all pivot results. */
    getPivotHistory(): readonly PivotResult[];
    /** Get hosts reachable from a given host. */
    getReachableHosts(hostnameOrIp: string): readonly NetworkHost[];
    /** Get technique MITRE mapping. */
    getMitreMapping(technique: LateralTechnique): string;
    /** Get stats. */
    getStats(): LateralStats;
}

export interface LateralStats {
    readonly totalHosts: number;
    readonly compromisedHosts: number;
    readonly adminHosts: number;
    readonly pivotAttempts: number;
    readonly successfulPivots: number;
    readonly failedPivots: number;
    readonly techniquesUsed: readonly string[];
    readonly credentialsHarvested: number;
}
