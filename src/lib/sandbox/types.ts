/**
 * VARIANT — Sandbox / Isolation Engine
 *
 * Safe execution environment for community-contributed code.
 * Scenarios, plugins, and custom modules run in sandboxes
 * with configurable permissions and resource limits.
 *
 * FEATURES:
 * - Permission-based access control (VFS, network, shell, events)
 * - Resource limits (memory, CPU ticks, file ops)
 * - Audit logging of all sandbox operations
 * - Module isolation (sandboxes can't reach each other)
 * - Capability tokens for fine-grained access
 *
 * SWAPPABILITY: Implements SandboxEngine. Replace this file.
 */

// ── Sandbox Definition ──────────────────────────────────────────

/** Configuration for creating a sandbox. */
export interface SandboxConfig {
    /** Unique sandbox ID. */
    readonly id: string;
    /** Human-readable label. */
    readonly label: string;
    /** Who created this sandbox. */
    readonly owner: string;
    /** Permissions granted to code in this sandbox. */
    readonly permissions: SandboxPermissions;
    /** Resource limits. */
    readonly limits: ResourceLimits;
    /** Time-to-live in ticks. 0 = unlimited. */
    readonly ttlTicks: number;
}

/** Permissions controlling what sandboxed code can do. */
export interface SandboxPermissions {
    /** VFS access. */
    readonly vfs: VFSPermission;
    /** Network access. */
    readonly network: NetworkPermission;
    /** Shell command execution. */
    readonly shell: ShellPermission;
    /** Event bus access. */
    readonly events: EventPermission;
    /** Whether sandboxed code can create child sandboxes. */
    readonly canSpawnChildren: boolean;
}

export interface VFSPermission {
    /** Whether VFS read is allowed. */
    readonly read: boolean;
    /** Whether VFS write is allowed. */
    readonly write: boolean;
    /** Allowed path prefixes (empty = all if read/write is true). */
    readonly allowedPaths: readonly string[];
    /** Blocked path prefixes (takes precedence over allowed). */
    readonly blockedPaths: readonly string[];
}

export interface NetworkPermission {
    /** Whether outbound connections are allowed. */
    readonly outbound: boolean;
    /** Whether inbound listeners are allowed. */
    readonly inbound: boolean;
    /** Allowed destination machines. */
    readonly allowedHosts: readonly string[];
    /** Allowed destination ports. */
    readonly allowedPorts: readonly number[];
}

export interface ShellPermission {
    /** Whether shell execution is allowed. */
    readonly enabled: boolean;
    /** Allowed commands (empty = all if enabled). */
    readonly allowedCommands: readonly string[];
    /** Blocked commands (takes precedence). */
    readonly blockedCommands: readonly string[];
}

export interface EventPermission {
    /** Whether event emission is allowed. */
    readonly emit: boolean;
    /** Whether event listening is allowed. */
    readonly listen: boolean;
    /** Allowed event prefixes. */
    readonly allowedPrefixes: readonly string[];
}

/** Resource limits for a sandbox. */
export interface ResourceLimits {
    /** Max VFS operations per tick. */
    readonly maxFileOpsPerTick: number;
    /** Max shell executions per tick. */
    readonly maxShellOpsPerTick: number;
    /** Max events emitted per tick. */
    readonly maxEventsPerTick: number;
    /** Max total operations across sandbox lifetime. */
    readonly maxTotalOps: number;
}

// ── Sandbox State ───────────────────────────────────────────────

/** Runtime state of a sandbox. */
export interface SandboxState {
    readonly id: string;
    readonly config: SandboxConfig;
    readonly status: SandboxStatus;
    readonly createdAtTick: number;
    readonly currentTick: number;
    readonly usage: ResourceUsage;
    readonly auditLog: readonly AuditEntry[];
    readonly violations: readonly SecurityViolation[];
}

export type SandboxStatus = 'active' | 'suspended' | 'terminated' | 'expired';

/** Current resource usage. */
export interface ResourceUsage {
    readonly fileOpsThisTick: number;
    readonly shellOpsThisTick: number;
    readonly eventsThisTick: number;
    readonly totalOps: number;
}

/** An entry in the sandbox audit log. */
export interface AuditEntry {
    readonly tick: number;
    readonly operation: AuditOperation;
    readonly target: string;
    readonly allowed: boolean;
    readonly reason?: string;
}

export type AuditOperation =
    | 'vfs:read'
    | 'vfs:write'
    | 'shell:exec'
    | 'event:emit'
    | 'event:listen'
    | 'network:connect'
    | 'network:listen'
    | 'spawn:child';

/** A security violation detected by the sandbox. */
export interface SecurityViolation {
    readonly tick: number;
    readonly operation: AuditOperation;
    readonly target: string;
    readonly message: string;
}

// ── Capability Token ────────────────────────────────────────────

/** A capability token granting specific access. */
export interface CapabilityToken {
    /** Token ID. */
    readonly id: string;
    /** Sandbox this token belongs to. */
    readonly sandboxId: string;
    /** Operation this token grants. */
    readonly operation: AuditOperation;
    /** Specific target (path, command, event prefix). */
    readonly target: string;
    /** Expiry tick. 0 = no expiry. */
    readonly expiresAtTick: number;
    /** Whether this token has been revoked. */
    readonly revoked: boolean;
}

// ── Sandbox Engine ──────────────────────────────────────────────

export interface SandboxEngine {
    /** Create a new sandbox. */
    create(config: SandboxConfig, tick: number): SandboxState;

    /** Get sandbox state. */
    get(id: string): SandboxState | null;

    /** List all sandboxes. */
    list(): readonly SandboxState[];

    /** Check if an operation is allowed. Records in audit log. */
    check(sandboxId: string, operation: AuditOperation, target: string, tick: number): boolean;

    /** Tick the sandbox (resets per-tick counters, checks TTL). */
    tick(sandboxId: string, tick: number): void;

    /** Suspend a sandbox. */
    suspend(id: string): boolean;

    /** Resume a suspended sandbox. */
    resume(id: string): boolean;

    /** Terminate a sandbox permanently. */
    terminate(id: string): boolean;

    /** Issue a capability token. */
    issueToken(sandboxId: string, operation: AuditOperation, target: string, expiresAtTick: number): CapabilityToken | null;

    /** Check if a capability token is valid. */
    checkToken(tokenId: string, tick: number): boolean;

    /** Revoke a capability token. */
    revokeToken(tokenId: string): boolean;

    /** Get all violations for a sandbox. */
    getViolations(sandboxId: string): readonly SecurityViolation[];

    /** Get audit log for a sandbox. */
    getAuditLog(sandboxId: string): readonly AuditEntry[];

    /** Subscribe to violations. */
    onViolation(handler: (violation: SecurityViolation, sandboxId: string) => void): () => void;

    /** Clear all sandboxes. */
    clear(): void;
}
