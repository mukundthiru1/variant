/**
 * VARIANT — Access Control Engine Implementation
 *
 * RBAC + ABAC with role hierarchy, deny-overrides, and audit.
 *
 * SWAPPABILITY: Implements AccessControlEngine. Replace this file.
 */

import type {
    AccessControlEngine,
    RoleDefinition,
    Principal,
    Permission,
    PermissionAction,
    PermissionCondition,
    AccessDecision,
} from './types';

interface MutablePrincipal {
    id: string;
    type: Principal['type'];
    name: string;
    roles: string[];
    directPermissions: Permission[];
    attributes: Record<string, unknown>;
}

export function createAccessControlEngine(): AccessControlEngine {
    const roles = new Map<string, RoleDefinition>();
    const principals = new Map<string, MutablePrincipal>();
    const auditLog: AccessDecision[] = [];

    function resolveRoleHierarchy(roleId: string, visited: Set<string>): string[] {
        if (visited.has(roleId)) return []; // prevent cycles
        visited.add(roleId);

        const role = roles.get(roleId);
        if (role === undefined) return [];

        const result = [roleId];
        for (const parentId of role.inherits) {
            result.push(...resolveRoleHierarchy(parentId, visited));
        }
        return result;
    }

    function collectPermissions(principal: MutablePrincipal): Permission[] {
        const perms: Permission[] = [...principal.directPermissions];

        for (const roleId of principal.roles) {
            const hierarchy = resolveRoleHierarchy(roleId, new Set());
            for (const rid of hierarchy) {
                const role = roles.get(rid);
                if (role !== undefined) {
                    perms.push(...role.permissions);
                }
            }
        }

        return perms;
    }

    function matchResource(pattern: string, resource: string): boolean {
        if (pattern === '*') return true;
        if (pattern === resource) return true;

        // Glob-style matching: '/etc/*' matches '/etc/passwd'
        if (pattern.endsWith('/*')) {
            const prefix = pattern.slice(0, -1); // '/etc/'
            return resource.startsWith(prefix) || resource === prefix.slice(0, -1);
        }

        if (pattern.endsWith('*')) {
            const prefix = pattern.slice(0, -1);
            return resource.startsWith(prefix);
        }

        return false;
    }

    function matchAction(permAction: PermissionAction, requestedAction: PermissionAction): boolean {
        if (permAction === '*') return true;
        return permAction === requestedAction;
    }

    function evaluateCondition(
        condition: PermissionCondition,
        context: Readonly<Record<string, unknown>>,
    ): boolean {
        switch (condition.kind) {
            case 'time-range': {
                const hour = context['hour'];
                if (typeof hour !== 'number') return false;
                return hour >= condition.startHour && hour < condition.endHour;
            }
            case 'ip-range': {
                const ip = context['ip'];
                if (typeof ip !== 'string') return false;
                // Simple prefix match for CIDR simulation
                const prefix = condition.cidr.split('/')[0]!;
                const parts = prefix.split('.');
                const ipParts = ip.split('.');
                // Match first N octets based on prefix length
                for (let i = 0; i < parts.length; i++) {
                    if (parts[i] === '0') break;
                    if (parts[i] !== ipParts[i]) return false;
                }
                return true;
            }
            case 'attribute': {
                const val = context[condition.key];
                switch (condition.operator) {
                    case '==': return val === condition.value;
                    case '!=': return val !== condition.value;
                    case '>': return typeof val === 'number' && typeof condition.value === 'number' && val > condition.value;
                    case '<': return typeof val === 'number' && typeof condition.value === 'number' && val < condition.value;
                }
                return false;
            }
            case 'and':
                return condition.conditions.every(c => evaluateCondition(c, context));
            case 'or':
                return condition.conditions.some(c => evaluateCondition(c, context));
        }
    }

    function toPrincipal(p: MutablePrincipal): Principal {
        return {
            id: p.id,
            type: p.type,
            name: p.name,
            roles: [...p.roles],
            directPermissions: [...p.directPermissions],
            attributes: { ...p.attributes },
        };
    }

    return {
        addRole(role: RoleDefinition): void {
            if (roles.has(role.id)) {
                throw new Error(`Role '${role.id}' already exists`);
            }
            roles.set(role.id, role);
        },

        getRole(id: string): RoleDefinition | null {
            return roles.get(id) ?? null;
        },

        listRoles(): readonly RoleDefinition[] {
            return [...roles.values()];
        },

        addPrincipal(principal: Principal): void {
            if (principals.has(principal.id)) {
                throw new Error(`Principal '${principal.id}' already exists`);
            }
            principals.set(principal.id, {
                id: principal.id,
                type: principal.type,
                name: principal.name,
                roles: [...principal.roles],
                directPermissions: [...principal.directPermissions],
                attributes: { ...principal.attributes },
            });
        },

        getPrincipal(id: string): Principal | null {
            const p = principals.get(id);
            if (p === undefined) return null;
            return toPrincipal(p);
        },

        listPrincipals(): readonly Principal[] {
            return [...principals.values()].map(toPrincipal);
        },

        assignRole(principalId: string, roleId: string): boolean {
            const principal = principals.get(principalId);
            if (principal === undefined) return false;
            if (!roles.has(roleId)) return false;
            if (principal.roles.includes(roleId)) return false;
            principal.roles.push(roleId);
            return true;
        },

        revokeRole(principalId: string, roleId: string): boolean {
            const principal = principals.get(principalId);
            if (principal === undefined) return false;
            const idx = principal.roles.indexOf(roleId);
            if (idx < 0) return false;
            principal.roles.splice(idx, 1);
            return true;
        },

        check(
            principalId: string,
            resource: string,
            action: PermissionAction,
            context?: Readonly<Record<string, unknown>>,
        ): AccessDecision {
            const trace: string[] = [];
            const ctx = context ?? {};

            const principal = principals.get(principalId);
            if (principal === undefined) {
                const decision: AccessDecision = {
                    allowed: false,
                    principalId,
                    resource,
                    action,
                    reason: 'principal not found',
                    trace: ['Principal not found'],
                };
                auditLog.push(decision);
                return decision;
            }

            const allPerms = collectPermissions(principal);
            trace.push(`Evaluating ${allPerms.length} permissions for ${principalId}`);

            // Deny-overrides: check all denies first
            for (const perm of allPerms) {
                if (perm.effect !== 'deny') continue;
                if (!matchResource(perm.resource, resource)) continue;
                if (!perm.actions.some(a => matchAction(a, action))) continue;

                if (perm.condition !== undefined && !evaluateCondition(perm.condition, ctx)) {
                    trace.push(`Deny on '${perm.resource}' skipped: condition not met`);
                    continue;
                }

                trace.push(`DENIED by explicit deny on '${perm.resource}'`);
                const decision: AccessDecision = {
                    allowed: false,
                    principalId,
                    resource,
                    action,
                    reason: `explicit deny on '${perm.resource}'`,
                    trace,
                };
                auditLog.push(decision);
                return decision;
            }

            // Check allows
            for (const perm of allPerms) {
                if (perm.effect !== 'allow') continue;
                if (!matchResource(perm.resource, resource)) {
                    trace.push(`Allow on '${perm.resource}' skipped: resource mismatch`);
                    continue;
                }
                if (!perm.actions.some(a => matchAction(a, action))) {
                    trace.push(`Allow on '${perm.resource}' skipped: action mismatch`);
                    continue;
                }

                if (perm.condition !== undefined && !evaluateCondition(perm.condition, ctx)) {
                    trace.push(`Allow on '${perm.resource}' skipped: condition not met`);
                    continue;
                }

                trace.push(`ALLOWED by permission on '${perm.resource}'`);
                const decision: AccessDecision = {
                    allowed: true,
                    principalId,
                    resource,
                    action,
                    reason: `allowed by '${perm.resource}'`,
                    trace,
                };
                auditLog.push(decision);
                return decision;
            }

            // Default deny
            trace.push('No matching allow found — default deny');
            const decision: AccessDecision = {
                allowed: false,
                principalId,
                resource,
                action,
                reason: 'no matching permission (default deny)',
                trace,
            };
            auditLog.push(decision);
            return decision;
        },

        getEffectivePermissions(principalId: string): readonly Permission[] {
            const principal = principals.get(principalId);
            if (principal === undefined) return [];
            return collectPermissions(principal);
        },

        getRoleHierarchy(roleId: string): readonly string[] {
            return resolveRoleHierarchy(roleId, new Set());
        },

        getAuditLog(): readonly AccessDecision[] {
            return [...auditLog];
        },

        clear(): void {
            roles.clear();
            principals.clear();
            auditLog.length = 0;
        },
    };
}
