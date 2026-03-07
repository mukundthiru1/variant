/**
 * VARIANT — LDAP/Active Directory Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createLDAPEngine, bootstrapADEnvironment } from '../../../src/lib/ldap/ldap-engine';
import type { ADUser, ADGroup, ADComputer } from '../../../src/lib/ldap/types';

const baseDN = 'DC=CORP,DC=LOCAL';

function makeUser(overrides?: Partial<ADUser>): ADUser {
    return {
        dn: `CN=testuser,CN=Users,${baseDN}`,
        sAMAccountName: 'testuser',
        userPrincipalName: 'testuser@CORP.LOCAL',
        displayName: 'Test User',
        memberOf: [],
        enabled: true,
        passwordLastSet: Date.now() - 30 * 86_400_000,
        lastLogon: Date.now() - 3_600_000,
        adminCount: false,
        servicePrincipalNames: [],
        userAccountControl: 512,
        delegationEnabled: false,
        kerberoastable: false,
        asrepRoastable: false,
        ...overrides,
    };
}

function makeGroup(overrides?: Partial<ADGroup>): ADGroup {
    return {
        dn: `CN=TestGroup,CN=Users,${baseDN}`,
        sAMAccountName: 'TestGroup',
        groupType: 'global-security',
        members: [],
        memberOf: [],
        adminCount: false,
        ...overrides,
    };
}

describe('LDAPEngine', () => {
    // ── Domain ────────────────────────────────────────────

    it('sets and gets domain', () => {
        const ldap = createLDAPEngine();
        ldap.setDomain('EVIL.CORP');
        expect(ldap.getDomain()).toBe('EVIL.CORP');
    });

    // ── User Management ───────────────────────────────────

    it('adds and retrieves users', () => {
        const ldap = createLDAPEngine();
        ldap.addUser(makeUser());
        expect(ldap.getUsers()).toHaveLength(1);
        expect(ldap.getUser('testuser')).not.toBeNull();
    });

    it('removes users', () => {
        const ldap = createLDAPEngine();
        ldap.addUser(makeUser());
        expect(ldap.removeUser('testuser')).toBe(true);
        expect(ldap.getUser('testuser')).toBeNull();
    });

    it('returns null for unknown users', () => {
        const ldap = createLDAPEngine();
        expect(ldap.getUser('nobody')).toBeNull();
    });

    // ── Group Management ──────────────────────────────────

    it('adds and retrieves groups', () => {
        const ldap = createLDAPEngine();
        ldap.addGroup(makeGroup());
        expect(ldap.getGroups()).toHaveLength(1);
        expect(ldap.getGroup('TestGroup')).not.toBeNull();
    });

    // ── Computer Management ───────────────────────────────

    it('adds and retrieves computers', () => {
        const ldap = createLDAPEngine();
        const computer: ADComputer = {
            dn: `CN=WS01,OU=Workstations,${baseDN}`,
            sAMAccountName: 'WS01$',
            dnsHostName: 'ws01.corp.local',
            operatingSystem: 'Windows 10',
            enabled: true,
            servicePrincipalNames: ['HOST/ws01.corp.local'],
            delegationEnabled: false,
            constrainedDelegationTargets: [],
            lastLogon: Date.now(),
        };
        ldap.addComputer(computer);
        expect(ldap.getComputers()).toHaveLength(1);
    });

    // ── Group Membership ──────────────────────────────────

    it('checks direct group membership', () => {
        const ldap = createLDAPEngine();
        const userDN = `CN=alice,CN=Users,${baseDN}`;
        ldap.addGroup(makeGroup({
            sAMAccountName: 'Admins',
            dn: `CN=Admins,CN=Users,${baseDN}`,
            members: [userDN],
        }));
        ldap.addUser(makeUser({ dn: userDN, sAMAccountName: 'alice' }));

        expect(ldap.isMemberOf('alice', 'Admins')).toBe(true);
        expect(ldap.isMemberOf('alice', 'NonExistent')).toBe(false);
    });

    it('resolves recursive group membership', () => {
        const ldap = createLDAPEngine();
        const userDN = `CN=bob,CN=Users,${baseDN}`;
        const innerGroupDN = `CN=ITStaff,CN=Users,${baseDN}`;

        ldap.addGroup(makeGroup({
            sAMAccountName: 'ITStaff',
            dn: innerGroupDN,
            members: [userDN],
        }));
        ldap.addGroup(makeGroup({
            sAMAccountName: 'Domain Admins',
            dn: `CN=Domain Admins,CN=Users,${baseDN}`,
            members: [innerGroupDN],
        }));
        ldap.addUser(makeUser({ dn: userDN, sAMAccountName: 'bob' }));

        expect(ldap.isMemberOf('bob', 'ITStaff')).toBe(true);
        expect(ldap.isMemberOf('bob', 'Domain Admins')).toBe(true);
    });

    // ── LDAP Search ───────────────────────────────────────

    it('searches by objectClass', () => {
        const ldap = createLDAPEngine();
        ldap.addUser(makeUser({ sAMAccountName: 'alice', dn: `CN=alice,CN=Users,${baseDN}` }));
        ldap.addGroup(makeGroup());

        const result = ldap.search({
            baseDN,
            scope: 'sub',
            filter: '(objectClass=user)',
        });
        expect(result.count).toBe(1);
        expect(result.entries[0]!.dn).toContain('alice');
    });

    it('searches with AND filter', () => {
        const ldap = createLDAPEngine();
        ldap.addUser(makeUser({ sAMAccountName: 'alice', dn: `CN=alice,CN=Users,${baseDN}`, adminCount: true }));
        ldap.addUser(makeUser({ sAMAccountName: 'bob', dn: `CN=bob,CN=Users,${baseDN}`, adminCount: false }));

        const result = ldap.search({
            baseDN,
            scope: 'sub',
            filter: '(&(objectClass=user)(adminCount=1))',
        });
        expect(result.count).toBe(1);
    });

    it('searches with OR filter', () => {
        const ldap = createLDAPEngine();
        ldap.addUser(makeUser({ sAMAccountName: 'alice', dn: `CN=alice,CN=Users,${baseDN}` }));
        ldap.addGroup(makeGroup({ sAMAccountName: 'TestGroup', dn: `CN=TestGroup,CN=Users,${baseDN}` }));

        const result = ldap.search({
            baseDN,
            scope: 'sub',
            filter: '(|(objectClass=user)(objectClass=group))',
        });
        expect(result.count).toBe(2);
    });

    it('searches with presence filter', () => {
        const ldap = createLDAPEngine();
        ldap.addUser(makeUser({
            sAMAccountName: 'svc',
            dn: `CN=svc,CN=Users,${baseDN}`,
            servicePrincipalNames: ['HTTP/web01.corp.local'],
        }));
        ldap.addUser(makeUser({ sAMAccountName: 'alice', dn: `CN=alice,CN=Users,${baseDN}` }));

        const result = ldap.search({
            baseDN,
            scope: 'sub',
            filter: '(servicePrincipalName=*)',
        });
        expect(result.count).toBe(1);
    });

    it('applies attribute projection', () => {
        const ldap = createLDAPEngine();
        ldap.addUser(makeUser({ sAMAccountName: 'alice', dn: `CN=alice,CN=Users,${baseDN}` }));

        const result = ldap.search({
            baseDN,
            scope: 'sub',
            filter: '(objectClass=user)',
            attributes: ['sAMAccountName', 'displayName'],
        });
        expect(result.count).toBe(1);
        expect(result.entries[0]!.attributes['sAMAccountName']).toBeTruthy();
    });

    it('respects size limit', () => {
        const ldap = createLDAPEngine();
        for (let i = 0; i < 10; i++) {
            ldap.addUser(makeUser({ sAMAccountName: `user${i}`, dn: `CN=user${i},CN=Users,${baseDN}` }));
        }

        const result = ldap.search({
            baseDN,
            scope: 'sub',
            filter: '(objectClass=user)',
            sizeLimit: 3,
        });
        expect(result.count).toBe(3);
        expect(result.truncated).toBe(true);
    });

    // ── Kerberoasting ─────────────────────────────────────

    it('kerberoasts users with SPNs', () => {
        const ldap = createLDAPEngine();
        ldap.addUser(makeUser({
            sAMAccountName: 'svc_sql',
            dn: `CN=svc_sql,CN=Users,${baseDN}`,
            servicePrincipalNames: ['MSSQLSvc/db01:1433'],
            kerberoastable: true,
        }));
        ldap.addUser(makeUser({ sAMAccountName: 'alice', dn: `CN=alice,CN=Users,${baseDN}` }));

        const results = ldap.kerberoast('attacker');
        expect(results).toHaveLength(1);
        expect(results[0]!.targetUser).toBe('svc_sql');
        expect(results[0]!.hashData).toContain('$krb5tgs$');
        expect(results[0]!.mitre).toBe('T1558.003');
    });

    it('skips disabled users for kerberoasting', () => {
        const ldap = createLDAPEngine();
        ldap.addUser(makeUser({
            sAMAccountName: 'svc_disabled',
            dn: `CN=svc_disabled,CN=Users,${baseDN}`,
            servicePrincipalNames: ['HTTP/old:80'],
            kerberoastable: true,
            enabled: false,
        }));

        expect(ldap.kerberoast('attacker')).toHaveLength(0);
    });

    // ── AS-REP Roasting ───────────────────────────────────

    it('AS-REP roasts users without preauth', () => {
        const ldap = createLDAPEngine();
        ldap.addUser(makeUser({
            sAMAccountName: 'legacy',
            dn: `CN=legacy,CN=Users,${baseDN}`,
            asrepRoastable: true,
        }));
        ldap.addUser(makeUser({ sAMAccountName: 'alice', dn: `CN=alice,CN=Users,${baseDN}` }));

        const results = ldap.asrepRoast();
        expect(results).toHaveLength(1);
        expect(results[0]!.hashData).toContain('$krb5asrep$');
        expect(results[0]!.mitre).toBe('T1558.004');
    });

    // ── Domain Enumeration ────────────────────────────────

    it('enumerates domain resources', () => {
        const ldap = createLDAPEngine();
        bootstrapADEnvironment(ldap);

        const result = ldap.enumerate();
        expect(result.domainControllers.length).toBeGreaterThanOrEqual(1);
        expect(result.domainAdmins.length).toBeGreaterThanOrEqual(1);
        expect(result.kerberoastableUsers.length).toBeGreaterThanOrEqual(1);
        expect(result.asrepRoastableUsers.length).toBeGreaterThanOrEqual(1);
        expect(result.unconstrained.length).toBeGreaterThanOrEqual(1);
        expect(result.gpoMisconfigurations.length).toBeGreaterThan(0);
    });

    // ── Kerberos Tickets ──────────────────────────────────

    it('generates TGT', () => {
        const ldap = createLDAPEngine();
        const tgt = ldap.requestTGT('alice');
        expect(tgt.type).toBe('TGT');
        expect(tgt.client).toBe('alice');
        expect(tgt.service).toContain('krbtgt');
        expect(tgt.forwardable).toBe(true);
    });

    it('generates TGS', () => {
        const ldap = createLDAPEngine();
        const tgs = ldap.requestTGS('alice', 'HTTP/web01.corp.local');
        expect(tgs.type).toBe('TGS');
        expect(tgs.service).toBe('HTTP/web01.corp.local');
    });

    // ── GPO ───────────────────────────────────────────────

    it('adds and retrieves GPOs', () => {
        const ldap = createLDAPEngine();
        ldap.addGPO({
            id: 'gpo-1',
            name: 'Test Policy',
            dn: `CN=gpo-1,CN=Policies,${baseDN}`,
            linkedOUs: [baseDN],
            enabled: true,
            settings: {
                passwordPolicy: {
                    minLength: 12,
                    complexityEnabled: true,
                    maxAge: 90,
                    minAge: 1,
                    historyCount: 24,
                    lockoutThreshold: 5,
                    lockoutDuration: 30,
                    lockoutWindow: 30,
                },
            },
        });
        expect(ldap.getGPOs()).toHaveLength(1);
    });

    it('returns password policy from GPO', () => {
        const ldap = createLDAPEngine();
        bootstrapADEnvironment(ldap);
        const policy = ldap.getPasswordPolicy();
        expect(policy).not.toBeNull();
        expect(policy!.minLength).toBeGreaterThan(0);
    });

    // ── Bootstrap ─────────────────────────────────────────

    it('bootstraps AD environment', () => {
        const ldap = createLDAPEngine();
        bootstrapADEnvironment(ldap);

        expect(ldap.getUsers().length).toBeGreaterThanOrEqual(3);
        expect(ldap.getGroups().length).toBeGreaterThanOrEqual(3);
        expect(ldap.getComputers().length).toBeGreaterThanOrEqual(2);
        expect(ldap.getGPOs().length).toBeGreaterThanOrEqual(1);
        expect(ldap.getDomain()).toBe('CORP.LOCAL');
    });

    // ── Stats ─────────────────────────────────────────────

    it('reports statistics', () => {
        const ldap = createLDAPEngine();
        bootstrapADEnvironment(ldap);
        const stats = ldap.getStats();
        expect(stats.totalUsers).toBeGreaterThanOrEqual(3);
        expect(stats.totalGroups).toBeGreaterThanOrEqual(3);
        expect(stats.totalComputers).toBeGreaterThanOrEqual(2);
        expect(stats.kerberoastableCount).toBeGreaterThanOrEqual(1);
        expect(stats.asrepRoastableCount).toBeGreaterThanOrEqual(1);
    });
});
