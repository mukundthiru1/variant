/**
 * VARIANT — Access Control Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createAccessControlEngine } from '../../../src/lib/access-control/access-control-engine';
import type { RoleDefinition, Principal, Permission } from '../../../src/lib/access-control/types';

function makeRole(id: string, perms: Permission[], inherits: string[] = []): RoleDefinition {
    return { id, name: `Role ${id}`, inherits, permissions: perms };
}

function makePrincipal(id: string, roles: string[] = [], directPerms: Permission[] = []): Principal {
    return {
        id,
        type: 'user',
        name: `User ${id}`,
        roles,
        directPermissions: directPerms,
        attributes: {},
    };
}

function allow(resource: string, actions: string[]): Permission {
    return { resource, actions, effect: 'allow' };
}

function deny(resource: string, actions: string[]): Permission {
    return { resource, actions, effect: 'deny' };
}

describe('AccessControlEngine', () => {
    // ── Roles ─────────────────────────────────────────────────────

    it('adds and retrieves roles', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('admin', [allow('*', ['*'])]));

        expect(engine.getRole('admin')).not.toBeNull();
        expect(engine.getRole('nonexistent')).toBeNull();
        expect(engine.listRoles().length).toBe(1);
    });

    it('throws on duplicate role', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('admin', []));
        expect(() => engine.addRole(makeRole('admin', []))).toThrow();
    });

    // ── Principals ────────────────────────────────────────────────

    it('adds and retrieves principals', () => {
        const engine = createAccessControlEngine();
        engine.addPrincipal(makePrincipal('alice'));

        expect(engine.getPrincipal('alice')).not.toBeNull();
        expect(engine.getPrincipal('nonexistent')).toBeNull();
        expect(engine.listPrincipals().length).toBe(1);
    });

    it('throws on duplicate principal', () => {
        const engine = createAccessControlEngine();
        engine.addPrincipal(makePrincipal('alice'));
        expect(() => engine.addPrincipal(makePrincipal('alice'))).toThrow();
    });

    // ── Role Assignment ───────────────────────────────────────────

    it('assigns and revokes roles', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('viewer', [allow('/public/*', ['read'])]));
        engine.addPrincipal(makePrincipal('alice'));

        expect(engine.assignRole('alice', 'viewer')).toBe(true);
        expect(engine.getPrincipal('alice')!.roles).toContain('viewer');

        expect(engine.revokeRole('alice', 'viewer')).toBe(true);
        expect(engine.getPrincipal('alice')!.roles).not.toContain('viewer');
    });

    it('assignRole returns false for unknown principal or role', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('admin', []));
        engine.addPrincipal(makePrincipal('alice'));

        expect(engine.assignRole('nobody', 'admin')).toBe(false);
        expect(engine.assignRole('alice', 'nonexistent')).toBe(false);
    });

    it('assignRole returns false for duplicate assignment', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('admin', []));
        engine.addPrincipal(makePrincipal('alice', ['admin']));

        expect(engine.assignRole('alice', 'admin')).toBe(false);
    });

    // ── Basic Access Checks ───────────────────────────────────────

    it('allows access via role permission', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('viewer', [allow('/public/*', ['read'])]));
        engine.addPrincipal(makePrincipal('alice', ['viewer']));

        const decision = engine.check('alice', '/public/docs/readme', 'read');
        expect(decision.allowed).toBe(true);
    });

    it('denies access when no matching permission', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('viewer', [allow('/public/*', ['read'])]));
        engine.addPrincipal(makePrincipal('alice', ['viewer']));

        const decision = engine.check('alice', '/etc/shadow', 'read');
        expect(decision.allowed).toBe(false);
        expect(decision.reason).toContain('no matching permission');
    });

    it('denies access for wrong action', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('viewer', [allow('/public/*', ['read'])]));
        engine.addPrincipal(makePrincipal('alice', ['viewer']));

        const decision = engine.check('alice', '/public/docs/readme', 'write');
        expect(decision.allowed).toBe(false);
    });

    it('denies access for unknown principal', () => {
        const engine = createAccessControlEngine();
        const decision = engine.check('nobody', '/etc/passwd', 'read');
        expect(decision.allowed).toBe(false);
        expect(decision.reason).toBe('principal not found');
    });

    // ── Wildcard Permissions ──────────────────────────────────────

    it('wildcard resource matches everything', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('admin', [allow('*', ['*'])]));
        engine.addPrincipal(makePrincipal('root', ['admin']));

        expect(engine.check('root', '/etc/shadow', 'read').allowed).toBe(true);
        expect(engine.check('root', '/var/log/auth.log', 'write').allowed).toBe(true);
        expect(engine.check('root', 'service:nginx', 'admin').allowed).toBe(true);
    });

    it('wildcard action matches any action', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('full-access', [allow('/data/*', ['*'])]));
        engine.addPrincipal(makePrincipal('alice', ['full-access']));

        expect(engine.check('alice', '/data/file.txt', 'read').allowed).toBe(true);
        expect(engine.check('alice', '/data/file.txt', 'write').allowed).toBe(true);
        expect(engine.check('alice', '/data/file.txt', 'delete').allowed).toBe(true);
    });

    // ── Deny Overrides ────────────────────────────────────────────

    it('explicit deny overrides allow', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('mixed', [
            allow('/data/*', ['read', 'write']),
            deny('/data/secret/*', ['read', 'write']),
        ]));
        engine.addPrincipal(makePrincipal('alice', ['mixed']));

        expect(engine.check('alice', '/data/public/file', 'read').allowed).toBe(true);
        expect(engine.check('alice', '/data/secret/keys', 'read').allowed).toBe(false);
    });

    it('deny overrides allow even from different roles', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('reader', [allow('*', ['read'])]));
        engine.addRole(makeRole('restricted', [deny('/etc/shadow', ['read'])]));
        engine.addPrincipal(makePrincipal('alice', ['reader', 'restricted']));

        expect(engine.check('alice', '/etc/passwd', 'read').allowed).toBe(true);
        expect(engine.check('alice', '/etc/shadow', 'read').allowed).toBe(false);
    });

    // ── Role Hierarchy ────────────────────────────────────────────

    it('inherits permissions from parent roles', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('viewer', [allow('/public/*', ['read'])]));
        engine.addRole(makeRole('editor', [allow('/content/*', ['read', 'write'])], ['viewer']));
        engine.addPrincipal(makePrincipal('alice', ['editor']));

        // From editor role
        expect(engine.check('alice', '/content/page', 'write').allowed).toBe(true);
        // From inherited viewer role
        expect(engine.check('alice', '/public/docs', 'read').allowed).toBe(true);
    });

    it('multi-level hierarchy', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('base', [allow('/home/*', ['read'])]));
        engine.addRole(makeRole('mid', [allow('/var/*', ['read'])], ['base']));
        engine.addRole(makeRole('top', [allow('/etc/*', ['read'])], ['mid']));
        engine.addPrincipal(makePrincipal('alice', ['top']));

        expect(engine.check('alice', '/etc/conf', 'read').allowed).toBe(true);
        expect(engine.check('alice', '/var/log', 'read').allowed).toBe(true);
        expect(engine.check('alice', '/home/alice', 'read').allowed).toBe(true);
    });

    it('handles circular role inheritance without infinite loop', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('a', [allow('/a/*', ['read'])], ['b']));
        engine.addRole(makeRole('b', [allow('/b/*', ['read'])], ['a']));
        engine.addPrincipal(makePrincipal('alice', ['a']));

        // Should not hang, should resolve permissions from both
        expect(engine.check('alice', '/a/file', 'read').allowed).toBe(true);
        expect(engine.check('alice', '/b/file', 'read').allowed).toBe(true);
    });

    it('getRoleHierarchy returns full chain', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('base', []));
        engine.addRole(makeRole('mid', [], ['base']));
        engine.addRole(makeRole('top', [], ['mid']));

        const hierarchy = engine.getRoleHierarchy('top');
        expect(hierarchy).toContain('top');
        expect(hierarchy).toContain('mid');
        expect(hierarchy).toContain('base');
    });

    // ── Direct Permissions ────────────────────────────────────────

    it('direct permissions work without roles', () => {
        const engine = createAccessControlEngine();
        engine.addPrincipal(makePrincipal('alice', [], [
            allow('/home/alice/*', ['read', 'write']),
        ]));

        expect(engine.check('alice', '/home/alice/file', 'read').allowed).toBe(true);
        expect(engine.check('alice', '/home/bob/file', 'read').allowed).toBe(false);
    });

    // ── Effective Permissions ─────────────────────────────────────

    it('getEffectivePermissions collects all permissions', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('viewer', [allow('/public/*', ['read'])]));
        engine.addPrincipal(makePrincipal('alice', ['viewer'], [
            allow('/home/alice/*', ['read', 'write']),
        ]));

        const perms = engine.getEffectivePermissions('alice');
        expect(perms.length).toBe(2);
    });

    it('getEffectivePermissions returns empty for unknown principal', () => {
        const engine = createAccessControlEngine();
        expect(engine.getEffectivePermissions('nobody').length).toBe(0);
    });

    // ── Conditional Access (ABAC) ─────────────────────────────────

    it('time-range condition', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('business-hours', [
            { resource: '/sensitive/*', actions: ['read'], effect: 'allow',
              condition: { kind: 'time-range', startHour: 9, endHour: 17 } },
        ]));
        engine.addPrincipal(makePrincipal('alice', ['business-hours']));

        expect(engine.check('alice', '/sensitive/data', 'read', { hour: 10 }).allowed).toBe(true);
        expect(engine.check('alice', '/sensitive/data', 'read', { hour: 22 }).allowed).toBe(false);
    });

    it('attribute condition', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('clearance', [
            { resource: '/classified/*', actions: ['read'], effect: 'allow',
              condition: { kind: 'attribute', key: 'clearance', operator: '==', value: 'top-secret' } },
        ]));
        engine.addPrincipal(makePrincipal('alice', ['clearance']));

        expect(engine.check('alice', '/classified/doc', 'read', { clearance: 'top-secret' }).allowed).toBe(true);
        expect(engine.check('alice', '/classified/doc', 'read', { clearance: 'secret' }).allowed).toBe(false);
    });

    it('compound AND condition', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('strict', [
            { resource: '/admin/*', actions: ['*'], effect: 'allow',
              condition: {
                  kind: 'and',
                  conditions: [
                      { kind: 'time-range', startHour: 9, endHour: 17 },
                      { kind: 'attribute', key: 'mfa', operator: '==', value: true },
                  ],
              } },
        ]));
        engine.addPrincipal(makePrincipal('alice', ['strict']));

        expect(engine.check('alice', '/admin/panel', 'read', { hour: 10, mfa: true }).allowed).toBe(true);
        expect(engine.check('alice', '/admin/panel', 'read', { hour: 10, mfa: false }).allowed).toBe(false);
        expect(engine.check('alice', '/admin/panel', 'read', { hour: 22, mfa: true }).allowed).toBe(false);
    });

    it('conditional deny', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('flexible', [
            allow('/data/*', ['read', 'write']),
            { resource: '/data/*', actions: ['write'], effect: 'deny',
              condition: { kind: 'time-range', startHour: 0, endHour: 6 } },
        ]));
        engine.addPrincipal(makePrincipal('alice', ['flexible']));

        // Write allowed during business hours
        expect(engine.check('alice', '/data/file', 'write', { hour: 10 }).allowed).toBe(true);
        // Write denied late night
        expect(engine.check('alice', '/data/file', 'write', { hour: 3 }).allowed).toBe(false);
        // Read always allowed
        expect(engine.check('alice', '/data/file', 'read', { hour: 3 }).allowed).toBe(true);
    });

    // ── Audit Log ─────────────────────────────────────────────────

    it('records all decisions in audit log', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('viewer', [allow('/public/*', ['read'])]));
        engine.addPrincipal(makePrincipal('alice', ['viewer']));

        engine.check('alice', '/public/doc', 'read');
        engine.check('alice', '/etc/shadow', 'read');

        const log = engine.getAuditLog();
        expect(log.length).toBe(2);
        expect(log[0]!.allowed).toBe(true);
        expect(log[1]!.allowed).toBe(false);
    });

    it('decisions include trace', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('viewer', [allow('/public/*', ['read'])]));
        engine.addPrincipal(makePrincipal('alice', ['viewer']));

        const decision = engine.check('alice', '/public/doc', 'read');
        expect(decision.trace.length).toBeGreaterThan(0);
    });

    // ── Clear ─────────────────────────────────────────────────────

    it('clear removes everything', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('admin', []));
        engine.addPrincipal(makePrincipal('alice', ['admin']));

        engine.clear();

        expect(engine.listRoles().length).toBe(0);
        expect(engine.listPrincipals().length).toBe(0);
        expect(engine.getAuditLog().length).toBe(0);
    });

    // ── Exact Resource Match ──────────────────────────────────────

    it('exact resource match works', () => {
        const engine = createAccessControlEngine();
        engine.addRole(makeRole('specific', [allow('/etc/passwd', ['read'])]));
        engine.addPrincipal(makePrincipal('alice', ['specific']));

        expect(engine.check('alice', '/etc/passwd', 'read').allowed).toBe(true);
        expect(engine.check('alice', '/etc/shadow', 'read').allowed).toBe(false);
    });
});
