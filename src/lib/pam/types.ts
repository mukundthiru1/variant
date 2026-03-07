/**
 * VARIANT — PAM/sudo Policy Engine Types
 *
 * Simulates Pluggable Authentication Modules and sudo policy
 * evaluation for privilege escalation training. Every sudo rule,
 * SUID binary, and Linux capability is evaluable.
 *
 * EXTENSIBILITY: Custom PAM modules via registry.
 * SWAPPABILITY: Implements PamEngine interface. Replace the engine file.
 */

// ── Sudo Rule ──────────────────────────────────────────────

export interface SudoRule {
    readonly user: string;
    readonly host: string;
    readonly runAs: string;
    readonly commands: readonly string[];
    readonly noPasswd: boolean;
    readonly tags?: readonly string[];
}

export interface SudoersConfig {
    readonly defaults: readonly SudoersDefault[];
    readonly rules: readonly SudoRule[];
    readonly aliases?: {
        readonly userAliases?: Readonly<Record<string, readonly string[]>>;
        readonly hostAliases?: Readonly<Record<string, readonly string[]>>;
        readonly cmndAliases?: Readonly<Record<string, readonly string[]>>;
        readonly runasAliases?: Readonly<Record<string, readonly string[]>>;
    };
}

export interface SudoersDefault {
    readonly key: string;
    readonly value: string | boolean | number;
    readonly scope?: 'global' | 'user' | 'host';
    readonly target?: string;
}

// ── SUID/SGID ──────────────────────────────────────────────

export interface SUIDEntry {
    readonly path: string;
    readonly owner: string;
    readonly group: string;
    readonly permissions: number;
    readonly suid: boolean;
    readonly sgid: boolean;
    /** Known GTFOBins exploitation technique (if any). */
    readonly gtfobinsExploit?: string;
    /** Whether this binary can be used for privesc. */
    readonly exploitable: boolean;
}

// ── Linux Capabilities ─────────────────────────────────────

export type LinuxCapability =
    | 'CAP_CHOWN' | 'CAP_DAC_OVERRIDE' | 'CAP_DAC_READ_SEARCH'
    | 'CAP_FOWNER' | 'CAP_FSETID' | 'CAP_KILL' | 'CAP_SETGID'
    | 'CAP_SETUID' | 'CAP_SETPCAP' | 'CAP_LINUX_IMMUTABLE'
    | 'CAP_NET_BIND_SERVICE' | 'CAP_NET_BROADCAST' | 'CAP_NET_ADMIN'
    | 'CAP_NET_RAW' | 'CAP_IPC_LOCK' | 'CAP_IPC_OWNER'
    | 'CAP_SYS_MODULE' | 'CAP_SYS_RAWIO' | 'CAP_SYS_CHROOT'
    | 'CAP_SYS_PTRACE' | 'CAP_SYS_PACCT' | 'CAP_SYS_ADMIN'
    | 'CAP_SYS_BOOT' | 'CAP_SYS_NICE' | 'CAP_SYS_RESOURCE'
    | 'CAP_SYS_TIME' | 'CAP_SYS_TTY_CONFIG' | 'CAP_MKNOD'
    | 'CAP_LEASE' | 'CAP_AUDIT_WRITE' | 'CAP_AUDIT_CONTROL'
    | 'CAP_SETFCAP' | (string & {});

export interface CapabilityEntry {
    readonly path: string;
    readonly capabilities: readonly LinuxCapability[];
    readonly set: 'effective' | 'permitted' | 'inheritable';
    readonly exploitable: boolean;
    readonly exploitDescription?: string;
}

// ── PAM Module ─────────────────────────────────────────────

export type PamControlFlag = 'required' | 'requisite' | 'sufficient' | 'optional' | 'include';

export interface PamModuleConfig {
    readonly type: 'auth' | 'account' | 'password' | 'session';
    readonly control: PamControlFlag;
    readonly module: string;
    readonly args?: readonly string[];
}

export interface PamStackConfig {
    readonly service: string;
    readonly modules: readonly PamModuleConfig[];
}

// ── Evaluation Results ─────────────────────────────────────

export interface SudoEvalResult {
    readonly allowed: boolean;
    readonly matchedRule: SudoRule | null;
    readonly requiresPassword: boolean;
    readonly runAsUser: string;
    readonly reason: string;
}

export interface PrivescVector {
    readonly type: 'sudo' | 'suid' | 'capability' | 'writable-path' | 'cron' | 'service';
    readonly path: string;
    readonly description: string;
    readonly severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
    readonly exploitSteps: readonly string[];
    readonly mitreTechnique: string;
}

// ── PAM Engine Interface ───────────────────────────────────

export interface PamEngine {
    /** Evaluate a sudo command for a user. */
    evaluateSudo(user: string, command: string, runAs?: string): SudoEvalResult;
    /** Get all sudo rules for a user. */
    getUserRules(user: string): readonly SudoRule[];
    /** Get all SUID/SGID binaries. */
    getSUIDEntries(): readonly SUIDEntry[];
    /** Get all capability entries. */
    getCapabilities(): readonly CapabilityEntry[];
    /** Scan for privilege escalation vectors. */
    scanPrivescVectors(currentUser: string): readonly PrivescVector[];
    /** Format as sudoers file output. */
    formatSudoers(): string;
    /** Format SUID listing (like find / -perm -4000). */
    formatSUIDList(): string;
    /** Add a sudo rule dynamically. */
    addSudoRule(rule: SudoRule): void;
    /** Add a SUID entry. */
    addSUIDEntry(entry: SUIDEntry): void;
    /** Add a capability entry. */
    addCapability(entry: CapabilityEntry): void;
    /** Get PAM stack for a service. */
    getPamStack(service: string): readonly PamModuleConfig[];
    /** Set PAM stack for a service. */
    setPamStack(service: string, modules: readonly PamModuleConfig[]): void;
    /** Get stats. */
    getStats(): PamStats;
}

export interface PamStats {
    readonly totalSudoRules: number;
    readonly totalSUIDEntries: number;
    readonly totalCapabilities: number;
    readonly exploitableSUID: number;
    readonly exploitableCapabilities: number;
    readonly noPasswdRules: number;
}
