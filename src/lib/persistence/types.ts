/**
 * VARIANT — Persistence Mechanism Types
 *
 * Catalogs all Linux persistence mechanisms for both offensive
 * (planting persistence) and defensive (detecting persistence) training.
 *
 * EXTENSIBILITY: Custom mechanism types via open union.
 * SWAPPABILITY: Implements PersistenceEngine interface.
 */

// ── Persistence Mechanism ──────────────────────────────────

export type PersistenceMechanismType =
    | 'cron'
    | 'systemd-service'
    | 'systemd-timer'
    | 'init-script'
    | 'rc-local'
    | 'bash-profile'
    | 'bashrc'
    | 'ssh-authorized-key'
    | 'ssh-config'
    | 'web-shell'
    | 'backdoor-binary'
    | 'ld-preload'
    | 'pam-module'
    | 'motd-script'
    | 'at-job'
    | 'kernel-module'
    | 'udev-rule'
    | 'xdg-autostart'
    | 'git-hook'
    | 'docker-entrypoint'
    | (string & {});

export interface PersistenceMechanism {
    readonly id: string;
    readonly type: PersistenceMechanismType;
    readonly name: string;
    readonly description: string;
    readonly machine: string;
    readonly path: string;
    readonly content: string;
    readonly owner: string;
    readonly installedAtTick: number;
    readonly detectable: boolean;
    readonly detectionDifficulty: 'trivial' | 'easy' | 'medium' | 'hard' | 'expert';
    readonly mitreTechnique: string;
    readonly mitreTactic: string;
    readonly surviveReboot: boolean;
    readonly metadata?: Readonly<Record<string, string>>;
}

// ── Detection Signatures ───────────────────────────────────

export interface PersistenceSignature {
    readonly id: string;
    readonly name: string;
    readonly description: string;
    readonly mechanismType: PersistenceMechanismType;
    readonly indicators: readonly PersistenceIndicator[];
    readonly severity: 'low' | 'medium' | 'high' | 'critical';
    readonly mitreTechnique: string;
    readonly falsePositiveRate: 'none' | 'low' | 'medium' | 'high';
}

export type PersistenceIndicator =
    | { readonly type: 'file-exists'; readonly path: string }
    | { readonly type: 'file-contains'; readonly path: string; readonly pattern: string }
    | { readonly type: 'file-modified-after'; readonly path: string; readonly tick: number }
    | { readonly type: 'file-permission'; readonly path: string; readonly permission: string }
    | { readonly type: 'process-running'; readonly name: string }
    | { readonly type: 'cron-entry'; readonly pattern: string }
    | { readonly type: 'service-enabled'; readonly name: string }
    | { readonly type: 'user-shell-changed'; readonly user: string }
    | { readonly type: 'ssh-key-added'; readonly user: string }
    | CustomPersistenceIndicator;

/** Custom indicator for third-party persistence detection. */
export interface CustomPersistenceIndicator {
    readonly type: 'custom';
    /** Handler ID in the indicator registry. */
    readonly handler: string;
    /** Arbitrary parameters. */
    readonly params: Readonly<Record<string, unknown>>;
}

// ── Scan Result ────────────────────────────────────────────

export interface PersistenceScanResult {
    readonly mechanism: PersistenceMechanism;
    readonly matchedSignature: PersistenceSignature;
    readonly confidence: number;
    readonly evidence: readonly string[];
}

// ── Engine Interface ───────────────────────────────────────

export interface PersistenceEngine {
    /** Install a persistence mechanism. */
    install(mechanism: PersistenceMechanism): void;
    /** Remove a persistence mechanism by ID. */
    remove(id: string): boolean;
    /** Get all installed mechanisms. */
    getAll(): readonly PersistenceMechanism[];
    /** Get mechanisms by machine. */
    getByMachine(machine: string): readonly PersistenceMechanism[];
    /** Get mechanisms by type. */
    getByType(type: PersistenceMechanismType): readonly PersistenceMechanism[];
    /** Scan a machine for persistence (blue team). */
    scan(machine: string, vfsReadFile: (path: string) => string | null): readonly PersistenceScanResult[];
    /** Register a custom detection signature. */
    addSignature(signature: PersistenceSignature): void;
    /** Get all registered signatures. */
    getSignatures(): readonly PersistenceSignature[];
    /** Generate a forensic timeline of persistence installations. */
    timeline(): readonly PersistenceMechanism[];
    /** Get statistics. */
    getStats(): PersistenceStats;
    /** Generate VFS overlay for all mechanisms on a machine. */
    generateOverlay(machine: string): Readonly<Record<string, string>>;
}

export interface PersistenceStats {
    readonly totalInstalled: number;
    readonly byType: Readonly<Record<string, number>>;
    readonly byMachine: Readonly<Record<string, number>>;
    readonly detectable: number;
    readonly survivesReboot: number;
}
