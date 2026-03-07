/**
 * VARIANT — Audit Log Types
 *
 * Simulates enterprise audit logging:
 * - Authentication, authorization, and access events
 * - Tamper detection and log integrity
 * - Log analysis and anomaly detection
 * - Compliance reporting (SOX, HIPAA, PCI)
 *
 * EXTENSIBILITY: Custom event types via open union.
 * SWAPPABILITY: Implements AuditEngine interface.
 */

// ── Audit Event ──────────────────────────────────────────

export interface AuditEvent {
    readonly id: string;
    readonly tick: number;
    readonly timestamp: number;
    readonly source: string;
    readonly actor: string;
    readonly action: AuditAction;
    readonly target: string;
    readonly result: 'success' | 'failure' | 'denied';
    readonly severity: AuditSeverity;
    readonly details: Readonly<Record<string, string>>;
    readonly sourceIP?: string;
    readonly sessionId?: string;
    readonly hash?: string;
}

export type AuditAction =
    | 'login' | 'logout' | 'login_failed'
    | 'access_granted' | 'access_denied' | 'privilege_escalation'
    | 'file_read' | 'file_write' | 'file_delete' | 'file_permission_change'
    | 'user_create' | 'user_delete' | 'user_modify' | 'group_modify'
    | 'policy_change' | 'config_change'
    | 'service_start' | 'service_stop'
    | 'firewall_rule_change' | 'network_connection'
    | 'audit_log_clear' | 'audit_log_tamper'
    | 'data_export' | 'encryption_change'
    | (string & {});

export type AuditSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

// ── Log Integrity ────────────────────────────────────────

export interface LogIntegrityCheck {
    readonly valid: boolean;
    readonly totalEvents: number;
    readonly missingEvents: number;
    readonly tamperedEvents: readonly string[];
    readonly gaps: readonly LogGap[];
}

export interface LogGap {
    readonly afterId: string;
    readonly beforeId: string;
    readonly missingCount: number;
}

// ── Anomaly Detection ────────────────────────────────────

export interface AuditAnomaly {
    readonly type: AuditAnomalyType;
    readonly severity: AuditSeverity;
    readonly description: string;
    readonly events: readonly string[];
    readonly mitre?: string;
}

export type AuditAnomalyType =
    | 'brute_force' | 'impossible_travel' | 'off_hours_access'
    | 'privilege_abuse' | 'log_tampering' | 'mass_deletion'
    | 'unusual_access_pattern' | 'account_compromise'
    | (string & {});

// ── Compliance ───────────────────────────────────────────

export interface ComplianceReport {
    readonly framework: string;
    readonly generatedAt: number;
    readonly controls: readonly ComplianceControl[];
    readonly overallScore: number;
}

export interface ComplianceControl {
    readonly id: string;
    readonly name: string;
    readonly status: 'pass' | 'fail' | 'partial';
    readonly evidence: readonly string[];
}

// ── Audit Engine Interface ───────────────────────────────

export interface AuditEngine {
    /** Log an audit event. */
    log(event: Omit<AuditEvent, 'id' | 'timestamp' | 'hash'>): AuditEvent;
    /** Get event by ID. */
    getEvent(id: string): AuditEvent | null;
    /** Query events by filter. */
    query(filter: AuditQuery): readonly AuditEvent[];
    /** Get events for a specific actor. */
    getActorEvents(actor: string): readonly AuditEvent[];
    /** Get events by action type. */
    getActionEvents(action: AuditAction): readonly AuditEvent[];
    /** Check log integrity (detect tampering/gaps). */
    checkIntegrity(): LogIntegrityCheck;
    /** Tamper with a log entry (for red-team training). */
    tamperEvent(id: string): boolean;
    /** Delete a log entry (for red-team training). */
    deleteEvent(id: string): boolean;
    /** Clear all logs (simulates log wiping attack). */
    clearLogs(): number;
    /** Detect anomalies in the log. */
    detectAnomalies(): readonly AuditAnomaly[];
    /** Generate compliance report. */
    generateComplianceReport(framework: string): ComplianceReport;
    /** Get stats. */
    getStats(): AuditStats;
}

export interface AuditQuery {
    readonly actor?: string;
    readonly action?: AuditAction;
    readonly target?: string;
    readonly result?: 'success' | 'failure' | 'denied';
    readonly severity?: AuditSeverity;
    readonly sourceIP?: string;
    readonly fromTick?: number;
    readonly toTick?: number;
}

export interface AuditStats {
    readonly totalEvents: number;
    readonly eventsByAction: Readonly<Record<string, number>>;
    readonly eventsBySeverity: Readonly<Record<string, number>>;
    readonly uniqueActors: number;
    readonly failedLogins: number;
    readonly tamperedEvents: number;
    readonly deletedEvents: number;
}
