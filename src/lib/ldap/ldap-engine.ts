/**
 * VARIANT — LDAP/Active Directory Engine
 *
 * Simulates Active Directory with:
 * - User/Group/Computer/GPO management
 * - LDAP search with filter parsing (subset)
 * - Recursive group membership resolution
 * - Kerberoasting attack simulation
 * - AS-REP Roasting attack simulation
 * - Domain enumeration (BloodHound-style)
 * - Kerberos ticket generation
 * - GPO misconfiguration detection
 *
 * All operations are synchronous and pure-data.
 */

import type {
    LDAPEngine,
    ADUser,
    ADGroup,
    ADComputer,
    GroupPolicy,
    PasswordPolicy,
    LDAPEntry,
    LDAPSearchRequest,
    LDAPSearchResult,
    KerberosTicket,
    KerberoastResult,
    ASREPRoastResult,
    DCEnumResult,
    LDAPStats,
} from './types';

// ── Helpers ───────────────────────────────────────────────

function generateHash(prefix: string): string {
    const chars = 'abcdef0123456789';
    let hash = prefix;
    for (let i = 0; i < 32; i++) {
        hash += chars[Math.floor(Math.random() * chars.length)];
    }
    return hash;
}

function userToLDAPEntry(user: ADUser, _domain: string): LDAPEntry {
    const attrs: Record<string, string[]> = {
        objectClass: ['top', 'person', 'organizationalPerson', 'user'],
        sAMAccountName: [user.sAMAccountName],
        userPrincipalName: [user.userPrincipalName],
        displayName: [user.displayName],
        memberOf: [...user.memberOf],
        userAccountControl: [String(user.userAccountControl)],
    };
    if (user.description) attrs['description'] = [user.description];
    if (user.servicePrincipalNames.length > 0) {
        attrs['servicePrincipalName'] = [...user.servicePrincipalNames];
    }
    if (user.adminCount) attrs['adminCount'] = ['1'];

    return {
        dn: user.dn,
        objectClass: ['top', 'person', 'organizationalPerson', 'user'],
        attributes: attrs,
        created: user.passwordLastSet,
        modified: user.lastLogon,
    };
}

function groupToLDAPEntry(group: ADGroup): LDAPEntry {
    return {
        dn: group.dn,
        objectClass: ['top', 'group'],
        attributes: {
            objectClass: ['top', 'group'],
            sAMAccountName: [group.sAMAccountName],
            member: [...group.members],
            memberOf: [...group.memberOf],
            groupType: [group.groupType],
            ...(group.description ? { description: [group.description] } : {}),
            ...(group.adminCount ? { adminCount: ['1'] } : {}),
        },
        created: 0,
        modified: 0,
    };
}

function computerToLDAPEntry(computer: ADComputer): LDAPEntry {
    return {
        dn: computer.dn,
        objectClass: ['top', 'computer'],
        attributes: {
            objectClass: ['top', 'computer'],
            sAMAccountName: [computer.sAMAccountName],
            dNSHostName: [computer.dnsHostName],
            operatingSystem: [computer.operatingSystem],
            ...(computer.operatingSystemVersion ? { operatingSystemVersion: [computer.operatingSystemVersion] } : {}),
            servicePrincipalName: [...computer.servicePrincipalNames],
        },
        created: 0,
        modified: computer.lastLogon,
    };
}

// ── LDAP Filter Parser (subset) ──────────────────────────

interface LDAPFilter {
    match(entry: LDAPEntry): boolean;
}

function parseLDAPFilter(filter: string): LDAPFilter {
    const trimmed = filter.trim();

    if (trimmed.startsWith('(&')) {
        const inner = trimmed.slice(2, -1);
        const parts = splitLDAPFilterParts(inner);
        const filters = parts.map(parseLDAPFilter);
        return { match: (entry) => filters.every(f => f.match(entry)) };
    }

    if (trimmed.startsWith('(|')) {
        const inner = trimmed.slice(2, -1);
        const parts = splitLDAPFilterParts(inner);
        const filters = parts.map(parseLDAPFilter);
        return { match: (entry) => filters.some(f => f.match(entry)) };
    }

    if (trimmed.startsWith('(!')) {
        const inner = trimmed.slice(2, -1);
        const innerFilter = parseLDAPFilter(inner);
        return { match: (entry) => !innerFilter.match(entry) };
    }

    // Strip outer parens
    const expr = trimmed.startsWith('(') ? trimmed.slice(1, -1) : trimmed;

    // Presence: (attribute=*)
    if (expr.endsWith('=*')) {
        const attr = expr.slice(0, -2).toLowerCase();
        return {
            match: (entry) => {
                const key = findAttribute(entry, attr);
                return key !== null && entry.attributes[key] !== undefined && entry.attributes[key]!.length > 0;
            },
        };
    }

    // Substring: (attribute=*value*)
    const subMatch = expr.match(/^([^=]+)=\*(.+)\*$/);
    if (subMatch) {
        const attr = subMatch[1]!.toLowerCase();
        const val = subMatch[2]!.toLowerCase();
        return {
            match: (entry) => {
                const key = findAttribute(entry, attr);
                if (key === null) return false;
                const values = entry.attributes[key];
                return values !== undefined && values.some(v => v.toLowerCase().includes(val));
            },
        };
    }

    // Equality: (attribute=value)
    const eqMatch = expr.match(/^([^=><~!]+)=(.+)$/);
    if (eqMatch) {
        const attr = eqMatch[1]!.toLowerCase();
        const val = eqMatch[2]!.toLowerCase();
        return {
            match: (entry) => {
                // Special case: objectClass
                if (attr === 'objectclass') {
                    return entry.objectClass.some(oc => oc.toLowerCase() === val);
                }
                const key = findAttribute(entry, attr);
                if (key === null) return false;
                const values = entry.attributes[key];
                return values !== undefined && values.some(v => v.toLowerCase() === val);
            },
        };
    }

    // GTE: (attribute>=value)
    const geMatch = expr.match(/^([^=><~!]+)>=(.+)$/);
    if (geMatch) {
        const attr = geMatch[1]!.toLowerCase();
        const val = parseInt(geMatch[2]!, 10);
        return {
            match: (entry) => {
                const key = findAttribute(entry, attr);
                if (key === null) return false;
                const values = entry.attributes[key];
                return values !== undefined && values.some(v => parseInt(v, 10) >= val);
            },
        };
    }

    // Fallback: match nothing
    return { match: () => false };
}

function splitLDAPFilterParts(s: string): string[] {
    const parts: string[] = [];
    let depth = 0;
    let current = '';
    for (const ch of s) {
        if (ch === '(') depth++;
        if (ch === ')') depth--;
        current += ch;
        if (depth === 0 && current.trim()) {
            parts.push(current.trim());
            current = '';
        }
    }
    if (current.trim()) parts.push(current.trim());
    return parts;
}

function findAttribute(entry: LDAPEntry, attrLower: string): string | null {
    for (const key of Object.keys(entry.attributes)) {
        if (key.toLowerCase() === attrLower) return key;
    }
    return null;
}

function dnMatchesBase(dn: string, baseDN: string): boolean {
    return dn.toLowerCase().endsWith(baseDN.toLowerCase());
}

// ── Factory ──────────────────────────────────────────────

export function createLDAPEngine(): LDAPEngine {
    let domain = 'CORP.LOCAL';
    const users = new Map<string, ADUser>();
    const groups = new Map<string, ADGroup>();
    const computers = new Map<string, ADComputer>();
    const gpos = new Map<string, GroupPolicy>();

    function resolveGroupMembership(userDN: string, visited: Set<string>): Set<string> {
        const allGroups = new Set<string>();
        if (visited.has(userDN)) return allGroups;
        visited.add(userDN);

        for (const group of groups.values()) {
            if (group.members.includes(userDN)) {
                allGroups.add(group.sAMAccountName);
                // Recurse into parent groups
                const parentGroups = resolveGroupMembership(group.dn, visited);
                for (const pg of parentGroups) allGroups.add(pg);
            }
        }

        return allGroups;
    }

    function getAllEntries(): LDAPEntry[] {
        const entries: LDAPEntry[] = [];
        for (const user of users.values()) {
            entries.push(userToLDAPEntry(user, domain));
        }
        for (const group of groups.values()) {
            entries.push(groupToLDAPEntry(group));
        }
        for (const computer of computers.values()) {
            entries.push(computerToLDAPEntry(computer));
        }
        return entries;
    }

    const engine: LDAPEngine = {
        setDomain(d: string): void {
            domain = d;
        },

        getDomain(): string {
            return domain;
        },

        addUser(user: ADUser): void {
            users.set(user.sAMAccountName.toLowerCase(), user);
        },

        removeUser(sAMAccountName: string): boolean {
            return users.delete(sAMAccountName.toLowerCase());
        },

        getUser(sAMAccountName: string): ADUser | null {
            return users.get(sAMAccountName.toLowerCase()) ?? null;
        },

        getUsers(): readonly ADUser[] {
            return Object.freeze(Array.from(users.values()));
        },

        addGroup(group: ADGroup): void {
            groups.set(group.sAMAccountName.toLowerCase(), group);
        },

        getGroup(sAMAccountName: string): ADGroup | null {
            return groups.get(sAMAccountName.toLowerCase()) ?? null;
        },

        getGroups(): readonly ADGroup[] {
            return Object.freeze(Array.from(groups.values()));
        },

        addComputer(computer: ADComputer): void {
            computers.set(computer.sAMAccountName.toLowerCase(), computer);
        },

        getComputers(): readonly ADComputer[] {
            return Object.freeze(Array.from(computers.values()));
        },

        addGPO(gpo: GroupPolicy): void {
            gpos.set(gpo.id, gpo);
        },

        getGPOs(): readonly GroupPolicy[] {
            return Object.freeze(Array.from(gpos.values()));
        },

        search(request: LDAPSearchRequest): LDAPSearchResult {
            const filter = parseLDAPFilter(request.filter);
            const allEntries = getAllEntries();
            const limit = request.sizeLimit ?? 1000;

            let matched: LDAPEntry[] = [];

            for (const entry of allEntries) {
                // Scope check
                if (request.scope === 'base' && entry.dn.toLowerCase() !== request.baseDN.toLowerCase()) continue;
                if (request.scope === 'one') {
                    // One level below baseDN
                    const parentDN = entry.dn.split(',').slice(1).join(',');
                    if (parentDN.toLowerCase() !== request.baseDN.toLowerCase()) continue;
                }
                if (request.scope === 'sub') {
                    if (!dnMatchesBase(entry.dn, request.baseDN)) continue;
                }

                if (filter.match(entry)) {
                    // Project attributes if specified
                    if (request.attributes && request.attributes.length > 0) {
                        const projected: Record<string, readonly string[]> = {};
                        for (const attr of request.attributes) {
                            const key = findAttribute(entry, attr.toLowerCase());
                            if (key !== null && entry.attributes[key]) {
                                projected[attr] = entry.attributes[key]!;
                            }
                        }
                        matched.push({ ...entry, attributes: projected });
                    } else {
                        matched.push(entry);
                    }
                }
            }

            const truncated = matched.length > limit;
            if (truncated) matched = matched.slice(0, limit);

            return Object.freeze({
                entries: Object.freeze(matched),
                count: matched.length,
                truncated,
            });
        },

        isMemberOf(userName: string, groupName: string): boolean {
            const user = users.get(userName.toLowerCase());
            if (!user) return false;

            const allMemberships = resolveGroupMembership(user.dn, new Set());
            return allMemberships.has(groupName);
        },

        kerberoast(attackerUser: string): readonly KerberoastResult[] {
            const results: KerberoastResult[] = [];

            for (const user of users.values()) {
                if (!user.kerberoastable) continue;
                if (user.servicePrincipalNames.length === 0) continue;
                if (!user.enabled) continue;

                for (const spn of user.servicePrincipalNames) {
                    const ticket: KerberosTicket = {
                        type: 'TGS',
                        client: attackerUser,
                        service: spn,
                        realm: domain,
                        encryptionType: 'RC4-HMAC',
                        issuedAt: Date.now(),
                        expiresAt: Date.now() + 36_000_000,
                        forwardable: false,
                        renewable: false,
                    };

                    results.push(Object.freeze({
                        targetUser: user.sAMAccountName,
                        spn,
                        ticket,
                        hashData: `$krb5tgs$23$*${user.sAMAccountName}$${domain}$${spn}*$${generateHash('')}`,
                        crackable: true,
                        mitre: 'T1558.003',
                    }));
                }
            }

            return Object.freeze(results);
        },

        asrepRoast(): readonly ASREPRoastResult[] {
            const results: ASREPRoastResult[] = [];

            for (const user of users.values()) {
                if (!user.asrepRoastable) continue;
                if (!user.enabled) continue;

                results.push(Object.freeze({
                    targetUser: user.sAMAccountName,
                    hashData: `$krb5asrep$23$${user.sAMAccountName}@${domain}:${generateHash('')}`,
                    crackable: true,
                    mitre: 'T1558.004',
                }));
            }

            return Object.freeze(results);
        },

        enumerate(): DCEnumResult {
            const domainAdmins: ADUser[] = [];
            const enterpriseAdmins: ADUser[] = [];
            const kerberoastable: ADUser[] = [];
            const asrepRoastable: ADUser[] = [];

            for (const user of users.values()) {
                if (!user.enabled) continue;

                const memberships = resolveGroupMembership(user.dn, new Set());
                if (memberships.has('Domain Admins')) domainAdmins.push(user);
                if (memberships.has('Enterprise Admins')) enterpriseAdmins.push(user);
                if (user.kerberoastable && user.servicePrincipalNames.length > 0) kerberoastable.push(user);
                if (user.asrepRoastable) asrepRoastable.push(user);
            }

            const domainControllers: ADComputer[] = [];
            const unconstrained: ADComputer[] = [];
            const constrainedDelegation: ADComputer[] = [];

            for (const computer of computers.values()) {
                if (computer.servicePrincipalNames.some(spn => spn.includes('GC/'))) {
                    domainControllers.push(computer);
                }
                if (computer.delegationEnabled && computer.constrainedDelegationTargets.length === 0) {
                    unconstrained.push(computer);
                }
                if (computer.constrainedDelegationTargets.length > 0) {
                    constrainedDelegation.push(computer);
                }
            }

            // GPO misconfigurations
            const gpoMisconfigs: string[] = [];
            for (const gpo of gpos.values()) {
                if (gpo.settings.passwordPolicy) {
                    const pp = gpo.settings.passwordPolicy;
                    if (pp.minLength < 8) gpoMisconfigs.push(`${gpo.name}: Password min length ${pp.minLength} < 8`);
                    if (!pp.complexityEnabled) gpoMisconfigs.push(`${gpo.name}: Password complexity disabled`);
                    if (pp.lockoutThreshold === 0) gpoMisconfigs.push(`${gpo.name}: Account lockout disabled`);
                    if (pp.lockoutThreshold > 10) gpoMisconfigs.push(`${gpo.name}: Account lockout threshold too high (${pp.lockoutThreshold})`);
                }
                if (gpo.settings.auditPolicy) {
                    const ap = gpo.settings.auditPolicy;
                    if (!ap.logonEvents) gpoMisconfigs.push(`${gpo.name}: Logon event auditing disabled`);
                    if (!ap.privilegeUse) gpoMisconfigs.push(`${gpo.name}: Privilege use auditing disabled`);
                }
            }

            return Object.freeze({
                domainControllers,
                domainAdmins,
                enterpriseAdmins,
                kerberoastableUsers: kerberoastable,
                asrepRoastableUsers: asrepRoastable,
                unconstrained,
                constrainedDelegation,
                gpoMisconfigurations: gpoMisconfigs,
            });
        },

        requestTGT(user: string, realm?: string): KerberosTicket {
            return Object.freeze({
                type: 'TGT' as const,
                client: user,
                service: `krbtgt/${realm ?? domain}`,
                realm: realm ?? domain,
                encryptionType: 'AES256-CTS-HMAC-SHA1' as const,
                issuedAt: Date.now(),
                expiresAt: Date.now() + 36_000_000,
                renewableUntil: Date.now() + 604_800_000,
                forwardable: true,
                renewable: true,
            });
        },

        requestTGS(user: string, service: string, realm?: string): KerberosTicket {
            return Object.freeze({
                type: 'TGS' as const,
                client: user,
                service,
                realm: realm ?? domain,
                encryptionType: 'AES256-CTS-HMAC-SHA1' as const,
                issuedAt: Date.now(),
                expiresAt: Date.now() + 36_000_000,
                forwardable: false,
                renewable: false,
            });
        },

        getPasswordPolicy(): PasswordPolicy | null {
            for (const gpo of gpos.values()) {
                if (gpo.settings.passwordPolicy) return gpo.settings.passwordPolicy;
            }
            return null;
        },

        getStats(): LDAPStats {
            let domainAdminCount = 0;
            let kerberoastableCount = 0;
            let asrepRoastableCount = 0;
            let disabledCount = 0;
            const staleThreshold = Date.now() - 90 * 86_400_000; // 90 days
            let staleCount = 0;

            for (const user of users.values()) {
                const memberships = resolveGroupMembership(user.dn, new Set());
                if (memberships.has('Domain Admins')) domainAdminCount++;
                if (user.kerberoastable && user.servicePrincipalNames.length > 0) kerberoastableCount++;
                if (user.asrepRoastable) asrepRoastableCount++;
                if (!user.enabled) disabledCount++;
                if (user.lastLogon < staleThreshold && user.enabled) staleCount++;
            }

            return Object.freeze({
                totalUsers: users.size,
                totalGroups: groups.size,
                totalComputers: computers.size,
                totalGPOs: gpos.size,
                domainAdminCount,
                kerberoastableCount,
                asrepRoastableCount,
                disabledAccounts: disabledCount,
                staleAccounts: staleCount,
            });
        },
    };

    return engine;
}

/** Bootstrap a small AD environment for training. */
export function bootstrapADEnvironment(engine: LDAPEngine): void {
    engine.setDomain('CORP.LOCAL');

    const baseDN = 'DC=CORP,DC=LOCAL';

    // Domain Admins group
    engine.addGroup({
        dn: `CN=Domain Admins,CN=Users,${baseDN}`,
        sAMAccountName: 'Domain Admins',
        groupType: 'global-security',
        members: [`CN=Administrator,CN=Users,${baseDN}`],
        memberOf: [],
        description: 'Designated administrators of the domain',
        adminCount: true,
    });

    // Enterprise Admins group
    engine.addGroup({
        dn: `CN=Enterprise Admins,CN=Users,${baseDN}`,
        sAMAccountName: 'Enterprise Admins',
        groupType: 'universal-security',
        members: [`CN=Administrator,CN=Users,${baseDN}`],
        memberOf: [],
        description: 'Designated administrators of the enterprise',
        adminCount: true,
    });

    // Domain Users group
    engine.addGroup({
        dn: `CN=Domain Users,CN=Users,${baseDN}`,
        sAMAccountName: 'Domain Users',
        groupType: 'global-security',
        members: [],
        memberOf: [],
        adminCount: false,
    });

    // Administrator
    engine.addUser({
        dn: `CN=Administrator,CN=Users,${baseDN}`,
        sAMAccountName: 'Administrator',
        userPrincipalName: 'Administrator@CORP.LOCAL',
        displayName: 'Domain Administrator',
        memberOf: [`CN=Domain Admins,CN=Users,${baseDN}`, `CN=Enterprise Admins,CN=Users,${baseDN}`],
        enabled: true,
        passwordLastSet: Date.now() - 30 * 86_400_000,
        lastLogon: Date.now() - 3_600_000,
        adminCount: true,
        servicePrincipalNames: [],
        userAccountControl: 512,
        delegationEnabled: false,
        kerberoastable: false,
        asrepRoastable: false,
    });

    // Service account (kerberoastable)
    engine.addUser({
        dn: `CN=svc_mssql,CN=Users,${baseDN}`,
        sAMAccountName: 'svc_mssql',
        userPrincipalName: 'svc_mssql@CORP.LOCAL',
        displayName: 'MSSQL Service Account',
        memberOf: [`CN=Domain Users,CN=Users,${baseDN}`],
        enabled: true,
        passwordLastSet: Date.now() - 365 * 86_400_000,
        lastLogon: Date.now() - 86_400_000,
        adminCount: false,
        servicePrincipalNames: ['MSSQLSvc/db01.corp.local:1433'],
        description: 'SQL Server service account',
        userAccountControl: 512,
        delegationEnabled: false,
        kerberoastable: true,
        asrepRoastable: false,
    });

    // AS-REP roastable user
    engine.addUser({
        dn: `CN=legacy_app,CN=Users,${baseDN}`,
        sAMAccountName: 'legacy_app',
        userPrincipalName: 'legacy_app@CORP.LOCAL',
        displayName: 'Legacy Application Account',
        memberOf: [`CN=Domain Users,CN=Users,${baseDN}`],
        enabled: true,
        passwordLastSet: Date.now() - 500 * 86_400_000,
        lastLogon: Date.now() - 200 * 86_400_000,
        adminCount: false,
        servicePrincipalNames: [],
        description: 'Do not require Kerberos preauthentication',
        userAccountControl: 4194816, // UF_DONT_REQUIRE_PREAUTH
        delegationEnabled: false,
        kerberoastable: false,
        asrepRoastable: true,
    });

    // Domain controller
    engine.addComputer({
        dn: `CN=DC01,OU=Domain Controllers,${baseDN}`,
        sAMAccountName: 'DC01$',
        dnsHostName: 'dc01.corp.local',
        operatingSystem: 'Windows Server 2019',
        operatingSystemVersion: '10.0 (17763)',
        enabled: true,
        servicePrincipalNames: [
            'GC/dc01.corp.local/CORP.LOCAL',
            'ldap/dc01.corp.local',
            'HOST/dc01.corp.local',
        ],
        delegationEnabled: false,
        constrainedDelegationTargets: [],
        lastLogon: Date.now(),
    });

    // Web server with unconstrained delegation
    engine.addComputer({
        dn: `CN=WEB01,OU=Servers,${baseDN}`,
        sAMAccountName: 'WEB01$',
        dnsHostName: 'web01.corp.local',
        operatingSystem: 'Windows Server 2019',
        enabled: true,
        servicePrincipalNames: ['HTTP/web01.corp.local', 'HOST/web01.corp.local'],
        delegationEnabled: true,
        constrainedDelegationTargets: [],
        lastLogon: Date.now(),
    });

    // Default Domain Policy GPO
    engine.addGPO({
        id: '{31B2F340-016D-11D2-945F-00C04FB984F9}',
        name: 'Default Domain Policy',
        dn: `CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,${baseDN}`,
        linkedOUs: [baseDN],
        enabled: true,
        settings: {
            passwordPolicy: {
                minLength: 7,
                complexityEnabled: true,
                maxAge: 42,
                minAge: 1,
                historyCount: 24,
                lockoutThreshold: 0,
                lockoutDuration: 30,
                lockoutWindow: 30,
            },
            auditPolicy: {
                logonEvents: true,
                objectAccess: false,
                privilegeUse: false,
                processTracking: false,
                policyChange: true,
                accountManagement: true,
                directoryServiceAccess: false,
            },
        },
    });
}
