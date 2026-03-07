/**
 * VARIANT — IDS/IPS Rules Engine Types
 *
 * Simulates Snort/Suricata-style intrusion detection with
 * signature matching, protocol analysis, and evasion detection.
 *
 * EXTENSIBILITY: Custom rule parsers, custom protocol decoders.
 * SWAPPABILITY: Implements IDSEngine interface.
 */

// ── IDS Rule (Snort-compatible) ────────────────────────────

export interface IDSRule {
    readonly sid: number;
    readonly rev: number;
    readonly action: IDSAction;
    readonly protocol: IDSProtocol;
    readonly sourceIP: string;
    readonly sourcePort: string;
    readonly direction: '->' | '<>';
    readonly destIP: string;
    readonly destPort: string;
    readonly options: IDSRuleOptions;
    readonly enabled: boolean;
    readonly raw?: string;
}

export type IDSAction = 'alert' | 'log' | 'pass' | 'drop' | 'reject' | 'sdrop';
export type IDSProtocol = 'tcp' | 'udp' | 'icmp' | 'ip' | 'http' | 'dns' | 'tls' | 'ssh' | 'ftp' | (string & {});

export interface IDSRuleOptions {
    readonly msg?: string;
    readonly content?: readonly IDSContentMatch[];
    readonly pcre?: readonly string[];
    readonly flow?: string;
    readonly flowbits?: string;
    readonly threshold?: IDSThreshold;
    readonly classtype?: string;
    readonly priority?: number;
    readonly reference?: readonly string[];
    readonly metadata?: readonly string[];
    readonly tag?: string;
    readonly detection_filter?: string;
}

export interface IDSContentMatch {
    readonly pattern: string;
    readonly nocase?: boolean;
    readonly offset?: number;
    readonly depth?: number;
    readonly distance?: number;
    readonly within?: number;
    readonly negated?: boolean;
    readonly rawbytes?: boolean;
    readonly http_uri?: boolean;
    readonly http_header?: boolean;
    readonly http_body?: boolean;
    readonly http_method?: boolean;
}

export interface IDSThreshold {
    readonly type: 'limit' | 'threshold' | 'both';
    readonly track: 'by_src' | 'by_dst';
    readonly count: number;
    readonly seconds: number;
}

// ── IDS Alert ──────────────────────────────────────────────

export interface IDSAlert {
    readonly id: string;
    readonly sid: number;
    readonly rev: number;
    readonly message: string;
    readonly severity: IDSSeverity;
    readonly classtype: string;
    readonly timestamp: number;
    readonly tick: number;
    readonly sourceIP: string;
    readonly sourcePort: number;
    readonly destIP: string;
    readonly destPort: number;
    readonly protocol: string;
    readonly payload: string;
    readonly matchedContent: readonly string[];
    readonly action: IDSAction;
    readonly references: readonly string[];
}

export type IDSSeverity = 1 | 2 | 3 | 4;

// ── IDS Packet ─────────────────────────────────────────────

export interface IDSPacket {
    readonly sourceIP: string;
    readonly sourcePort: number;
    readonly destIP: string;
    readonly destPort: number;
    readonly protocol: string;
    readonly payload: string;
    readonly timestamp: number;
    readonly tick: number;
    readonly flow?: 'established' | 'to_server' | 'to_client';
    readonly httpUri?: string;
    readonly httpMethod?: string;
    readonly httpHeaders?: Readonly<Record<string, string>>;
    readonly httpBody?: string;
}

// ── IDS Engine Interface ───────────────────────────────────

export interface IDSEngine {
    /** Load a rule. */
    addRule(rule: IDSRule): void;
    /** Load multiple rules. */
    addRules(rules: readonly IDSRule[]): void;
    /** Parse and load a Snort-format rule string. */
    parseAndAdd(ruleString: string): IDSRule | null;
    /** Remove a rule by SID. */
    removeRule(sid: number): boolean;
    /** Enable/disable a rule. */
    setRuleEnabled(sid: number, enabled: boolean): boolean;
    /** Evaluate a packet against all rules. */
    evaluate(packet: IDSPacket): readonly IDSAlert[];
    /** Get all rules. */
    getRules(): readonly IDSRule[];
    /** Get all alerts. */
    getAlerts(): readonly IDSAlert[];
    /** Get alerts by severity. */
    getAlertsBySeverity(severity: IDSSeverity): readonly IDSAlert[];
    /** Get rule count. */
    ruleCount(): number;
    /** Get alert count. */
    alertCount(): number;
    /** Reset alerts. */
    resetAlerts(): void;
    /** Format a rule as Snort syntax. */
    formatRule(rule: IDSRule): string;
    /** Get stats. */
    getStats(): IDSStats;
}

export interface IDSStats {
    readonly totalRules: number;
    readonly enabledRules: number;
    readonly totalAlerts: number;
    readonly alertsBySeverity: Readonly<Record<number, number>>;
    readonly packetsEvaluated: number;
    readonly ruleHits: Readonly<Record<number, number>>;
}
