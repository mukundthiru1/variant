/**
 * VARIANT — EDR (Endpoint Detection & Response) Types
 *
 * Simulates modern EDR capabilities: process monitoring,
 * behavioral detection, memory scanning, and automated response.
 * Players learn EDR evasion and blue-team response workflows.
 *
 * EXTENSIBILITY: Custom detection rules via open union.
 * SWAPPABILITY: Implements EDREngine interface.
 */

// ── EDR Event ─────────────────────────────────────────────

export interface EDREvent {
    readonly id: string;
    readonly tick: number;
    readonly machine: string;
    readonly type: EDREventType;
    readonly pid: number;
    readonly processName: string;
    readonly parentPid: number;
    readonly parentName: string;
    readonly user: string;
    readonly commandLine: string;
    readonly filePath?: string;
    readonly networkDest?: string;
    readonly networkPort?: number;
    readonly registryKey?: string;
    readonly registryValue?: string;
    readonly dllLoaded?: string;
    readonly hashSha256?: string;
    readonly metadata?: Readonly<Record<string, string>>;
}

export type EDREventType =
    | 'process_create' | 'process_terminate'
    | 'file_create' | 'file_modify' | 'file_delete' | 'file_rename'
    | 'network_connect' | 'network_listen' | 'network_dns'
    | 'registry_set' | 'registry_create' | 'registry_delete'
    | 'dll_load' | 'driver_load'
    | 'pipe_create' | 'pipe_connect'
    | 'wmi_event' | 'powershell_script'
    | 'credential_access' | 'memory_injection'
    | (string & {});

// ── EDR Detection Rule ────────────────────────────────────

export interface EDRDetectionRule {
    readonly id: string;
    readonly name: string;
    readonly description: string;
    readonly severity: EDRSeverity;
    readonly conditions: readonly EDRCondition[];
    readonly logic: 'all' | 'any';
    readonly mitreTechnique: string;
    readonly mitreTactic: string;
    readonly responseActions: readonly EDRResponseAction[];
    readonly enabled: boolean;
    readonly falsePositiveRate: 'none' | 'low' | 'medium' | 'high';
}

export type EDRSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface EDRCondition {
    readonly field: keyof EDREvent | string;
    readonly operator: 'equals' | 'contains' | 'startsWith' | 'endsWith' | 'regex' | 'in' | 'notEquals';
    readonly value: string | readonly string[];
}

export type EDRResponseAction =
    | 'alert' | 'isolate_host' | 'kill_process' | 'quarantine_file'
    | 'block_network' | 'collect_forensics' | 'suspend_user'
    | (string & {});

// ── EDR Alert ─────────────────────────────────────────────

export interface EDRAlert {
    readonly id: string;
    readonly ruleId: string;
    readonly ruleName: string;
    readonly severity: EDRSeverity;
    readonly event: EDREvent;
    readonly tick: number;
    readonly mitreTechnique: string;
    readonly mitreTactic: string;
    readonly responsesTaken: readonly EDRResponseAction[];
    readonly investigated: boolean;
    readonly falsePositive: boolean;
}

// ── EDR Host Status ───────────────────────────────────────

export interface EDRHostStatus {
    readonly machine: string;
    readonly isolated: boolean;
    readonly agentVersion: string;
    readonly lastSeen: number;
    readonly blockedProcesses: readonly string[];
    readonly quarantinedFiles: readonly string[];
    readonly suspendedUsers: readonly string[];
}

// ── EDR Engine Interface ──────────────────────────────────

export interface EDREngine {
    /** Ingest a telemetry event. */
    ingestEvent(event: Omit<EDREvent, 'id'>): EDRAlert[];
    /** Add a detection rule. */
    addRule(rule: EDRDetectionRule): void;
    /** Remove a rule. */
    removeRule(id: string): boolean;
    /** Enable/disable a rule. */
    setRuleEnabled(id: string, enabled: boolean): boolean;
    /** Get all rules. */
    getRules(): readonly EDRDetectionRule[];
    /** Get all alerts. */
    getAlerts(): readonly EDRAlert[];
    /** Get alerts by severity. */
    getAlertsBySeverity(severity: EDRSeverity): readonly EDRAlert[];
    /** Get alerts for a machine. */
    getAlertsByMachine(machine: string): readonly EDRAlert[];
    /** Mark alert as investigated. */
    investigateAlert(alertId: string, falsePositive: boolean): boolean;
    /** Isolate a host. */
    isolateHost(machine: string): void;
    /** Unisolate a host. */
    unisolateHost(machine: string): void;
    /** Get host status. */
    getHostStatus(machine: string): EDRHostStatus;
    /** Get all monitored hosts. */
    getHosts(): readonly EDRHostStatus[];
    /** Reset alerts. */
    resetAlerts(): void;
    /** Get stats. */
    getStats(): EDRStats;
}

export interface EDRStats {
    readonly totalEvents: number;
    readonly totalAlerts: number;
    readonly alertsBySeverity: Readonly<Record<string, number>>;
    readonly totalRules: number;
    readonly enabledRules: number;
    readonly hostsMonitored: number;
    readonly hostsIsolated: number;
    readonly investigatedAlerts: number;
    readonly falsePositives: number;
}
