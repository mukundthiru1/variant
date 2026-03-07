/**
 * VARIANT — Data Exfiltration Types
 *
 * Simulates attacker data exfiltration channels:
 * - DNS tunneling, HTTP/S, ICMP, steganography
 * - Cloud storage, email, USB, covert channels
 * - Bandwidth throttling and chunking
 * - Detection surface per channel
 *
 * EXTENSIBILITY: Custom channel types via open union.
 * SWAPPABILITY: Implements ExfiltrationEngine interface.
 */

// ── Channel Types ────────────────────────────────────────

export type ExfilChannel =
    | 'dns_tunnel' | 'http_post' | 'https_post' | 'http_get_params'
    | 'icmp_tunnel' | 'dns_over_https' | 'custom_protocol'
    | 'cloud_storage' | 'email_attachment' | 'email_body'
    | 'usb' | 'bluetooth' | 'steganography'
    | 'smb_share' | 'ftp' | 'sftp' | 'scp'
    | 'websocket' | 'tor' | 'dead_drop'
    | (string & {});

// ── Sensitive Data ───────────────────────────────────────

export interface SensitiveData {
    readonly id: string;
    readonly name: string;
    readonly classification: DataClassification;
    readonly sizeBytes: number;
    readonly location: string;
    readonly format: string;
    readonly tags: readonly string[];
}

export type DataClassification =
    | 'public' | 'internal' | 'confidential' | 'secret' | 'top_secret'
    | (string & {});

// ── Exfiltration Attempt & Result ────────────────────────

export interface ExfilAttempt {
    readonly dataId: string;
    readonly channel: ExfilChannel;
    readonly sourceMachine: string;
    readonly destination: string;
    readonly tick: number;
    readonly chunkSizeBytes?: number;
    readonly throttleBps?: number;
    readonly encrypted?: boolean;
    readonly encoded?: boolean;
}

export interface ExfilResult {
    readonly id: string;
    readonly attempt: ExfilAttempt;
    readonly success: boolean;
    readonly reason: string;
    readonly bytesTransferred: number;
    readonly chunksUsed: number;
    readonly estimatedDurationTicks: number;
    readonly detectionRisk: 'none' | 'low' | 'medium' | 'high' | 'critical';
    readonly mitreTechnique: string;
    readonly artifacts: readonly ExfilArtifact[];
}

export interface ExfilArtifact {
    readonly type: 'dns_query' | 'http_request' | 'network_flow' | 'file_access' | 'process' | 'email' | (string & {});
    readonly description: string;
    readonly detectable: boolean;
    readonly ioc?: string;
}

// ── Channel Configuration ────────────────────────────────

export interface ChannelConfig {
    readonly channel: ExfilChannel;
    readonly maxBandwidthBps: number;
    readonly maxChunkSize: number;
    readonly encrypted: boolean;
    readonly detectionRisk: 'none' | 'low' | 'medium' | 'high' | 'critical';
    readonly mitreTechnique: string;
    readonly requiresNetwork: boolean;
}

// ── DLP Rule ─────────────────────────────────────────────

export interface DLPRule {
    readonly id: string;
    readonly name: string;
    readonly classification: DataClassification;
    readonly blockedChannels: readonly ExfilChannel[];
    readonly alertChannels: readonly ExfilChannel[];
    readonly enabled: boolean;
}

// ── Exfiltration Engine Interface ────────────────────────

export interface ExfiltrationEngine {
    /** Register sensitive data. */
    addData(data: Omit<SensitiveData, 'id'>): SensitiveData;
    /** Get sensitive data by ID. */
    getData(id: string): SensitiveData | null;
    /** List all sensitive data. */
    listData(): readonly SensitiveData[];
    /** Attempt data exfiltration. */
    exfiltrate(attempt: ExfilAttempt): ExfilResult;
    /** Add a DLP rule. */
    addDLPRule(rule: DLPRule): void;
    /** Remove a DLP rule. */
    removeDLPRule(id: string): boolean;
    /** Get DLP rules. */
    getDLPRules(): readonly DLPRule[];
    /** Get channel configuration. */
    getChannelConfig(channel: ExfilChannel): ChannelConfig;
    /** List all exfiltration results. */
    getExfilHistory(): readonly ExfilResult[];
    /** Get stats. */
    getStats(): ExfilStats;
}

export interface ExfilStats {
    readonly totalDataItems: number;
    readonly totalExfilAttempts: number;
    readonly successfulExfils: number;
    readonly blockedExfils: number;
    readonly totalBytesExfiltrated: number;
    readonly channelsUsed: readonly string[];
    readonly dlpRulesTriggered: number;
}
