/**
 * VARIANT — LDAP/Active Directory Types
 *
 * Simulates Active Directory/LDAP for Kerberos attacks,
 * LDAP injection, Group Policy abuse, DCSync, and domain
 * privilege escalation training.
 *
 * EXTENSIBILITY: Custom object classes via open union.
 * SWAPPABILITY: Implements LDAPEngine interface.
 */

// ── LDAP Entry ────────────────────────────────────────────

export interface LDAPEntry {
    readonly dn: string;
    readonly objectClass: readonly LDAPObjectClass[];
    readonly attributes: Readonly<Record<string, readonly string[]>>;
    readonly created: number;
    readonly modified: number;
}

export type LDAPObjectClass =
    | 'top' | 'person' | 'organizationalPerson' | 'user' | 'computer'
    | 'group' | 'organizationalUnit' | 'domain' | 'container'
    | 'groupPolicyContainer' | 'serviceConnectionPoint'
    | 'msDS-ManagedServiceAccount' | 'msDS-GroupManagedServiceAccount'
    | (string & {});

// ── AD User ───────────────────────────────────────────────

export interface ADUser {
    readonly dn: string;
    readonly sAMAccountName: string;
    readonly userPrincipalName: string;
    readonly displayName: string;
    readonly memberOf: readonly string[];
    readonly enabled: boolean;
    readonly passwordLastSet: number;
    readonly lastLogon: number;
    readonly adminCount: boolean;
    readonly servicePrincipalNames: readonly string[];
    readonly description?: string;
    readonly userAccountControl: number;
    readonly delegationEnabled: boolean;
    readonly kerberoastable: boolean;
    readonly asrepRoastable: boolean;
}

// ── AD Group ──────────────────────────────────────────────

export interface ADGroup {
    readonly dn: string;
    readonly sAMAccountName: string;
    readonly groupType: ADGroupType;
    readonly members: readonly string[];
    readonly memberOf: readonly string[];
    readonly description?: string;
    readonly adminCount: boolean;
}

export type ADGroupType =
    | 'global-security' | 'domain-local-security' | 'universal-security'
    | 'global-distribution' | 'domain-local-distribution' | 'universal-distribution'
    | (string & {});

// ── AD Computer ───────────────────────────────────────────

export interface ADComputer {
    readonly dn: string;
    readonly sAMAccountName: string;
    readonly dnsHostName: string;
    readonly operatingSystem: string;
    readonly operatingSystemVersion?: string;
    readonly enabled: boolean;
    readonly servicePrincipalNames: readonly string[];
    readonly delegationEnabled: boolean;
    readonly constrainedDelegationTargets: readonly string[];
    readonly lastLogon: number;
}

// ── Group Policy ──────────────────────────────────────────

export interface GroupPolicy {
    readonly id: string;
    readonly name: string;
    readonly dn: string;
    readonly linkedOUs: readonly string[];
    readonly settings: GPOSettings;
    readonly enabled: boolean;
}

export interface GPOSettings {
    readonly passwordPolicy?: PasswordPolicy;
    readonly auditPolicy?: AuditPolicy;
    readonly restrictedGroups?: readonly RestrictedGroupEntry[];
    readonly userRightsAssignment?: Readonly<Record<string, readonly string[]>>;
    readonly registrySettings?: readonly RegistrySetting[];
    readonly scripts?: readonly GPOScript[];
}

export interface PasswordPolicy {
    readonly minLength: number;
    readonly complexityEnabled: boolean;
    readonly maxAge: number;
    readonly minAge: number;
    readonly historyCount: number;
    readonly lockoutThreshold: number;
    readonly lockoutDuration: number;
    readonly lockoutWindow: number;
}

export interface AuditPolicy {
    readonly logonEvents: boolean;
    readonly objectAccess: boolean;
    readonly privilegeUse: boolean;
    readonly processTracking: boolean;
    readonly policyChange: boolean;
    readonly accountManagement: boolean;
    readonly directoryServiceAccess: boolean;
}

export interface RestrictedGroupEntry {
    readonly groupName: string;
    readonly members: readonly string[];
    readonly memberOf: readonly string[];
}

export interface RegistrySetting {
    readonly hive: 'HKLM' | 'HKCU';
    readonly path: string;
    readonly valueName: string;
    readonly valueType: 'REG_SZ' | 'REG_DWORD' | 'REG_BINARY';
    readonly data: string;
}

export interface GPOScript {
    readonly type: 'startup' | 'shutdown' | 'logon' | 'logoff';
    readonly path: string;
    readonly parameters?: string;
}

// ── Kerberos ──────────────────────────────────────────────

export interface KerberosTicket {
    readonly type: 'TGT' | 'TGS';
    readonly client: string;
    readonly service: string;
    readonly realm: string;
    readonly encryptionType: KerberosEncType;
    readonly issuedAt: number;
    readonly expiresAt: number;
    readonly renewableUntil?: number;
    readonly forwardable: boolean;
    readonly renewable: boolean;
}

export type KerberosEncType =
    | 'AES256-CTS-HMAC-SHA1' | 'AES128-CTS-HMAC-SHA1'
    | 'RC4-HMAC' | 'DES-CBC-MD5'
    | (string & {});

// ── LDAP Query ────────────────────────────────────────────

export interface LDAPSearchRequest {
    readonly baseDN: string;
    readonly scope: 'base' | 'one' | 'sub';
    readonly filter: string;
    readonly attributes?: readonly string[];
    readonly sizeLimit?: number;
}

export interface LDAPSearchResult {
    readonly entries: readonly LDAPEntry[];
    readonly count: number;
    readonly truncated: boolean;
}

// ── Attack Results ────────────────────────────────────────

export interface KerberoastResult {
    readonly targetUser: string;
    readonly spn: string;
    readonly ticket: KerberosTicket;
    readonly hashData: string;
    readonly crackable: boolean;
    readonly mitre: string;
}

export interface ASREPRoastResult {
    readonly targetUser: string;
    readonly hashData: string;
    readonly crackable: boolean;
    readonly mitre: string;
}

export interface DCEnumResult {
    readonly domainControllers: readonly ADComputer[];
    readonly domainAdmins: readonly ADUser[];
    readonly enterpriseAdmins: readonly ADUser[];
    readonly kerberoastableUsers: readonly ADUser[];
    readonly asrepRoastableUsers: readonly ADUser[];
    readonly unconstrained: readonly ADComputer[];
    readonly constrainedDelegation: readonly ADComputer[];
    readonly gpoMisconfigurations: readonly string[];
}

// ── LDAP Engine Interface ─────────────────────────────────

export interface LDAPEngine {
    /** Set the domain name. */
    setDomain(domain: string): void;
    /** Get the domain name. */
    getDomain(): string;
    /** Add a user. */
    addUser(user: ADUser): void;
    /** Remove a user by sAMAccountName. */
    removeUser(sAMAccountName: string): boolean;
    /** Get a user by sAMAccountName. */
    getUser(sAMAccountName: string): ADUser | null;
    /** Get all users. */
    getUsers(): readonly ADUser[];
    /** Add a group. */
    addGroup(group: ADGroup): void;
    /** Get a group by sAMAccountName. */
    getGroup(sAMAccountName: string): ADGroup | null;
    /** Get all groups. */
    getGroups(): readonly ADGroup[];
    /** Add a computer. */
    addComputer(computer: ADComputer): void;
    /** Get all computers. */
    getComputers(): readonly ADComputer[];
    /** Add a group policy. */
    addGPO(gpo: GroupPolicy): void;
    /** Get all GPOs. */
    getGPOs(): readonly GroupPolicy[];
    /** LDAP search with filter. */
    search(request: LDAPSearchRequest): LDAPSearchResult;
    /** Check if user is member of group (recursive). */
    isMemberOf(user: string, group: string): boolean;
    /** Kerberoast attack: extract service ticket hashes. */
    kerberoast(attackerUser: string): readonly KerberoastResult[];
    /** AS-REP Roast attack: extract hashes for users without preauth. */
    asrepRoast(): readonly ASREPRoastResult[];
    /** Enumerate the domain. */
    enumerate(): DCEnumResult;
    /** Request a Kerberos TGT. */
    requestTGT(user: string, realm?: string): KerberosTicket;
    /** Request a Kerberos TGS. */
    requestTGS(user: string, service: string, realm?: string): KerberosTicket;
    /** Get password policy (from Default Domain Policy). */
    getPasswordPolicy(): PasswordPolicy | null;
    /** Get stats. */
    getStats(): LDAPStats;
}

export interface LDAPStats {
    readonly totalUsers: number;
    readonly totalGroups: number;
    readonly totalComputers: number;
    readonly totalGPOs: number;
    readonly domainAdminCount: number;
    readonly kerberoastableCount: number;
    readonly asrepRoastableCount: number;
    readonly disabledAccounts: number;
    readonly staleAccounts: number;
}
