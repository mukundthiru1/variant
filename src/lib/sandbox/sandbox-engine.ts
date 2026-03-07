/**
 * VARIANT — Sandbox Engine Implementation
 *
 * Permission-based isolation with audit logging, resource limits,
 * capability tokens, and violation detection.
 *
 * SWAPPABILITY: Implements SandboxEngine. Replace this file.
 */

import type {
    SandboxEngine,
    SandboxConfig,
    SandboxState,
    SandboxStatus,
    AuditEntry,
    AuditOperation,
    SecurityViolation,
    CapabilityToken,
} from './types';

interface MutableSandbox {
    config: SandboxConfig;
    status: SandboxStatus;
    createdAtTick: number;
    currentTick: number;
    usage: MutableUsage;
    auditLog: AuditEntry[];
    violations: SecurityViolation[];
}

interface MutableUsage {
    fileOpsThisTick: number;
    shellOpsThisTick: number;
    eventsThisTick: number;
    totalOps: number;
}

let nextTokenId = 1;

export function createSandboxEngine(): SandboxEngine {
    const sandboxes = new Map<string, MutableSandbox>();
    const tokens = new Map<string, CapabilityToken & { revoked: boolean }>();
    const violationHandlers: Array<(v: SecurityViolation, id: string) => void> = [];

    function toState(id: string, s: MutableSandbox): SandboxState {
        return {
            id,
            config: s.config,
            status: s.status,
            createdAtTick: s.createdAtTick,
            currentTick: s.currentTick,
            usage: { ...s.usage },
            auditLog: [...s.auditLog],
            violations: [...s.violations],
        };
    }

    function isPathAllowed(path: string, config: SandboxConfig, operation: 'read' | 'write'): boolean {
        const perm = config.permissions.vfs;
        if (operation === 'read' && !perm.read) return false;
        if (operation === 'write' && !perm.write) return false;

        // Check blocked paths first (takes precedence)
        for (const blocked of perm.blockedPaths) {
            if (path.startsWith(blocked)) return false;
        }

        // If allowedPaths is empty, all paths are allowed
        if (perm.allowedPaths.length === 0) return true;

        // Check allowed paths
        for (const allowed of perm.allowedPaths) {
            if (path.startsWith(allowed)) return true;
        }

        return false;
    }

    function isCommandAllowed(command: string, config: SandboxConfig): boolean {
        const perm = config.permissions.shell;
        if (!perm.enabled) return false;

        // Check blocked commands first
        for (const blocked of perm.blockedCommands) {
            if (command === blocked || command.startsWith(blocked + ' ')) return false;
        }

        // If allowedCommands is empty, all commands are allowed
        if (perm.allowedCommands.length === 0) return true;

        for (const allowed of perm.allowedCommands) {
            if (command === allowed || command.startsWith(allowed + ' ')) return true;
        }

        return false;
    }

    function isEventAllowed(prefix: string, config: SandboxConfig, direction: 'emit' | 'listen'): boolean {
        const perm = config.permissions.events;
        if (direction === 'emit' && !perm.emit) return false;
        if (direction === 'listen' && !perm.listen) return false;

        if (perm.allowedPrefixes.length === 0) return true;

        for (const allowed of perm.allowedPrefixes) {
            if (prefix.startsWith(allowed)) return true;
        }

        return false;
    }

    function checkLimits(sandbox: MutableSandbox, operation: AuditOperation): boolean {
        const limits = sandbox.config.limits;

        if (sandbox.usage.totalOps >= limits.maxTotalOps) return false;

        switch (operation) {
            case 'vfs:read':
            case 'vfs:write':
                return sandbox.usage.fileOpsThisTick < limits.maxFileOpsPerTick;
            case 'shell:exec':
                return sandbox.usage.shellOpsThisTick < limits.maxShellOpsPerTick;
            case 'event:emit':
            case 'event:listen':
                return sandbox.usage.eventsThisTick < limits.maxEventsPerTick;
            default:
                return true;
        }
    }

    function incrementUsage(sandbox: MutableSandbox, operation: AuditOperation): void {
        sandbox.usage.totalOps++;
        switch (operation) {
            case 'vfs:read':
            case 'vfs:write':
                sandbox.usage.fileOpsThisTick++;
                break;
            case 'shell:exec':
                sandbox.usage.shellOpsThisTick++;
                break;
            case 'event:emit':
            case 'event:listen':
                sandbox.usage.eventsThisTick++;
                break;
        }
    }

    function recordViolation(
        sandboxId: string,
        sandbox: MutableSandbox,
        operation: AuditOperation,
        target: string,
        message: string,
    ): void {
        const violation: SecurityViolation = {
            tick: sandbox.currentTick,
            operation,
            target,
            message,
        };
        sandbox.violations.push(violation);
        for (const handler of violationHandlers) {
            handler(violation, sandboxId);
        }
    }

    return {
        create(config: SandboxConfig, tick: number): SandboxState {
            if (sandboxes.has(config.id)) {
                throw new Error(`Sandbox '${config.id}' already exists`);
            }

            const sandbox: MutableSandbox = {
                config,
                status: 'active',
                createdAtTick: tick,
                currentTick: tick,
                usage: { fileOpsThisTick: 0, shellOpsThisTick: 0, eventsThisTick: 0, totalOps: 0 },
                auditLog: [],
                violations: [],
            };

            sandboxes.set(config.id, sandbox);
            return toState(config.id, sandbox);
        },

        get(id: string): SandboxState | null {
            const sandbox = sandboxes.get(id);
            if (sandbox === undefined) return null;
            return toState(id, sandbox);
        },

        list(): readonly SandboxState[] {
            return [...sandboxes.entries()].map(([id, s]) => toState(id, s));
        },

        check(sandboxId: string, operation: AuditOperation, target: string, tick: number): boolean {
            const sandbox = sandboxes.get(sandboxId);
            if (sandbox === undefined) return false;

            sandbox.currentTick = tick;

            // Not active
            if (sandbox.status !== 'active') {
                sandbox.auditLog.push({ tick, operation, target, allowed: false, reason: `sandbox is ${sandbox.status}` });
                return false;
            }

            // Check resource limits
            if (!checkLimits(sandbox, operation)) {
                const reason = 'resource limit exceeded';
                sandbox.auditLog.push({ tick, operation, target, allowed: false, reason });
                recordViolation(sandboxId, sandbox, operation, target, reason);
                return false;
            }

            // Check permission by operation type
            let allowed = false;
            let reason: string | undefined;

            switch (operation) {
                case 'vfs:read':
                    allowed = isPathAllowed(target, sandbox.config, 'read');
                    if (!allowed) reason = `read access denied for path '${target}'`;
                    break;
                case 'vfs:write':
                    allowed = isPathAllowed(target, sandbox.config, 'write');
                    if (!allowed) reason = `write access denied for path '${target}'`;
                    break;
                case 'shell:exec':
                    allowed = isCommandAllowed(target, sandbox.config);
                    if (!allowed) reason = `command '${target}' not allowed`;
                    break;
                case 'event:emit':
                    allowed = isEventAllowed(target, sandbox.config, 'emit');
                    if (!allowed) reason = `event emission '${target}' not allowed`;
                    break;
                case 'event:listen':
                    allowed = isEventAllowed(target, sandbox.config, 'listen');
                    if (!allowed) reason = `event listening '${target}' not allowed`;
                    break;
                case 'network:connect':
                    allowed = sandbox.config.permissions.network.outbound;
                    if (!allowed) reason = 'outbound network access denied';
                    break;
                case 'network:listen':
                    allowed = sandbox.config.permissions.network.inbound;
                    if (!allowed) reason = 'inbound network access denied';
                    break;
                case 'spawn:child':
                    allowed = sandbox.config.permissions.canSpawnChildren;
                    if (!allowed) reason = 'child sandbox spawning denied';
                    break;
            }

            const entry: AuditEntry = reason !== undefined
                ? { tick, operation, target, allowed, reason }
                : { tick, operation, target, allowed };
            sandbox.auditLog.push(entry);

            if (allowed) {
                incrementUsage(sandbox, operation);
            } else {
                recordViolation(sandboxId, sandbox, operation, target, reason ?? 'permission denied');
            }

            return allowed;
        },

        tick(sandboxId: string, tick: number): void {
            const sandbox = sandboxes.get(sandboxId);
            if (sandbox === undefined) return;

            sandbox.currentTick = tick;

            // Reset per-tick counters
            sandbox.usage.fileOpsThisTick = 0;
            sandbox.usage.shellOpsThisTick = 0;
            sandbox.usage.eventsThisTick = 0;

            // Check TTL
            if (sandbox.config.ttlTicks > 0 && sandbox.status === 'active') {
                const age = tick - sandbox.createdAtTick;
                if (age >= sandbox.config.ttlTicks) {
                    sandbox.status = 'expired';
                }
            }
        },

        suspend(id: string): boolean {
            const sandbox = sandboxes.get(id);
            if (sandbox === undefined || sandbox.status !== 'active') return false;
            sandbox.status = 'suspended';
            return true;
        },

        resume(id: string): boolean {
            const sandbox = sandboxes.get(id);
            if (sandbox === undefined || sandbox.status !== 'suspended') return false;
            sandbox.status = 'active';
            return true;
        },

        terminate(id: string): boolean {
            const sandbox = sandboxes.get(id);
            if (sandbox === undefined || sandbox.status === 'terminated') return false;
            sandbox.status = 'terminated';
            return true;
        },

        issueToken(
            sandboxId: string,
            operation: AuditOperation,
            target: string,
            expiresAtTick: number,
        ): CapabilityToken | null {
            if (!sandboxes.has(sandboxId)) return null;

            const id = `token-${nextTokenId++}`;
            const token: CapabilityToken & { revoked: boolean } = {
                id,
                sandboxId,
                operation,
                target,
                expiresAtTick,
                revoked: false,
            };

            tokens.set(id, token);
            return token;
        },

        checkToken(tokenId: string, tick: number): boolean {
            const token = tokens.get(tokenId);
            if (token === undefined) return false;
            if (token.revoked) return false;
            if (token.expiresAtTick > 0 && tick >= token.expiresAtTick) return false;
            return true;
        },

        revokeToken(tokenId: string): boolean {
            const token = tokens.get(tokenId);
            if (token === undefined || token.revoked) return false;
            token.revoked = true;
            return true;
        },

        getViolations(sandboxId: string): readonly SecurityViolation[] {
            const sandbox = sandboxes.get(sandboxId);
            if (sandbox === undefined) return [];
            return [...sandbox.violations];
        },

        getAuditLog(sandboxId: string): readonly AuditEntry[] {
            const sandbox = sandboxes.get(sandboxId);
            if (sandbox === undefined) return [];
            return [...sandbox.auditLog];
        },

        onViolation(handler: (v: SecurityViolation, id: string) => void): () => void {
            violationHandlers.push(handler);
            return () => {
                const idx = violationHandlers.indexOf(handler);
                if (idx >= 0) violationHandlers.splice(idx, 1);
            };
        },

        clear(): void {
            sandboxes.clear();
            tokens.clear();
            violationHandlers.length = 0;
            nextTokenId = 1;
        },
    };
}
