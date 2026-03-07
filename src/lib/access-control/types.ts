/**
 * VARIANT — Access Control / RBAC Engine
 *
 * Role-based and attribute-based access control simulation.
 * Models real permission systems (Unix, RBAC, ABAC, ACLs)
 * so players can exploit misconfigurations, escalate privileges,
 * and understand access control architectures.
 *
 * FEATURES:
 * - Role hierarchy with inheritance
 * - Permission grants and denials
 * - Resource-level ACLs
 * - Attribute-based conditions
 * - Audit trail of access decisions
 * - Policy evaluation with explain
 *
 * SWAPPABILITY: Implements AccessControlEngine. Replace this file.
 */

// ── Principals ──────────────────────────────────────────────────

/** A principal (user, service account, group). */
export interface Principal {
    /** Unique principal ID. */
    readonly id: string;
    /** Principal type. */
    readonly type: PrincipalType;
    /** Display name. */
    readonly name: string;
    /** Roles assigned to this principal. */
    readonly roles: readonly string[];
    /** Direct permissions (not from roles). */
    readonly directPermissions: readonly Permission[];
    /** Attributes for ABAC evaluation. */
    readonly attributes: Readonly<Record<string, unknown>>;
}

export type PrincipalType = 'user' | 'group' | 'service-account' | 'system';

// ── Roles ───────────────────────────────────────────────────────

/** A role definition. */
export interface RoleDefinition {
    /** Unique role ID. */
    readonly id: string;
    /** Display name. */
    readonly name: string;
    /** Parent roles (inherits their permissions). */
    readonly inherits: readonly string[];
    /** Permissions this role grants. */
    readonly permissions: readonly Permission[];
}

// ── Permissions ─────────────────────────────────────────────────

/** A permission entry. */
export interface Permission {
    /** Resource pattern (e.g., '/etc/*', 'service:nginx', '*'). */
    readonly resource: string;
    /** Actions allowed on this resource. */
    readonly actions: readonly PermissionAction[];
    /** Effect: allow or deny. */
    readonly effect: 'allow' | 'deny';
    /** Optional condition for ABAC. */
    readonly condition?: PermissionCondition;
}

export type PermissionAction =
    | 'read'
    | 'write'
    | 'execute'
    | 'delete'
    | 'create'
    | 'admin'
    | 'login'
    | 'sudo'
    | '*'
    | (string & {});

/** Condition for attribute-based access control. */
export type PermissionCondition =
    | { readonly kind: 'time-range'; readonly startHour: number; readonly endHour: number }
    | { readonly kind: 'ip-range'; readonly cidr: string }
    | { readonly kind: 'attribute'; readonly key: string; readonly operator: '==' | '!=' | '>' | '<'; readonly value: unknown }
    | { readonly kind: 'and'; readonly conditions: readonly PermissionCondition[] }
    | { readonly kind: 'or'; readonly conditions: readonly PermissionCondition[] };

// ── Access Decision ─────────────────────────────────────────────

/** Result of an access check. */
export interface AccessDecision {
    /** Whether access is granted. */
    readonly allowed: boolean;
    /** The principal that was checked. */
    readonly principalId: string;
    /** The resource that was checked. */
    readonly resource: string;
    /** The action that was checked. */
    readonly action: PermissionAction;
    /** Which permission/role produced this decision. */
    readonly reason: string;
    /** Full evaluation trace for debugging. */
    readonly trace: readonly string[];
}

// ── Access Control Engine ───────────────────────────────────────

export interface AccessControlEngine {
    /** Register a role definition. */
    addRole(role: RoleDefinition): void;

    /** Get a role by ID. */
    getRole(id: string): RoleDefinition | null;

    /** List all roles. */
    listRoles(): readonly RoleDefinition[];

    /** Register a principal. */
    addPrincipal(principal: Principal): void;

    /** Get a principal by ID. */
    getPrincipal(id: string): Principal | null;

    /** List all principals. */
    listPrincipals(): readonly Principal[];

    /** Assign a role to a principal. */
    assignRole(principalId: string, roleId: string): boolean;

    /** Revoke a role from a principal. */
    revokeRole(principalId: string, roleId: string): boolean;

    /** Check if a principal has access. Returns detailed decision. */
    check(principalId: string, resource: string, action: PermissionAction, context?: Readonly<Record<string, unknown>>): AccessDecision;

    /** Get all effective permissions for a principal (role inheritance resolved). */
    getEffectivePermissions(principalId: string): readonly Permission[];

    /** Get the full role hierarchy for a role (including all ancestors). */
    getRoleHierarchy(roleId: string): readonly string[];

    /** Get audit log of access decisions. */
    getAuditLog(): readonly AccessDecision[];

    /** Clear all state. */
    clear(): void;
}
