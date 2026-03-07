/**
 * VARIANT — LDAP Service Handler
 *
 * Simulated LDAP directory service for authentication and directory
 * traversal scenarios. Supports bind operations, search queries,
 * and intentional LDAP injection vulnerabilities.
 *
 * What it does:
 *   - Bind (authenticate) with DN and password
 *   - Search with filters (cn=, uid=, memberOf=, etc.)
 *   - LDAP injection vulnerability (unescaped filter params)
 *   - Anonymous bind support
 *   - Returns LDIF-formatted results
 *   - Emits events for objective detection
 *
 * EXTENSIBILITY: Configurable via ServiceConfig.config:
 *   - baseDN: Directory base DN (default: dc=variant,dc=local)
 *   - allowAnonymous: Allow anonymous bind (default: true)
 *   - injectionVulnerable: Enable LDAP injection (default: false)
 *   - directory: Pre-populated directory entries
 */

import type {
    ServiceHandler,
    ServiceRequest,
    ServiceResponse,
    ServiceContext,
} from './types';
import type { ServiceConfig } from '../../core/world/types';

// ── LDAP Config ────────────────────────────────────────────────

interface LDAPConfig {
    readonly baseDN: string;
    readonly allowAnonymous: boolean;
    readonly injectionVulnerable: boolean;
    readonly port: number;
    readonly logFile: string;
    readonly directory: LDAPDirectory;
}

interface LDAPDirectory {
    readonly entries: readonly LDAPEntry[];
}

interface LDAPEntry {
    readonly dn: string;
    readonly attributes: Record<string, string | readonly string[]>;
}

interface LDAPSession {
    authenticated: boolean;
    bindDN: string;
    isAnonymous: boolean;
}

function resolveLDAPConfig(config: ServiceConfig): LDAPConfig {
    const c = config.config ?? {};
    return {
        baseDN: (c['baseDN'] as string) ?? 'dc=variant,dc=local',
        allowAnonymous: (c['allowAnonymous'] as boolean) ?? true,
        injectionVulnerable: (c['injectionVulnerable'] as boolean) ?? false,
        port: config.ports[0] ?? 389,
        logFile: (c['logFile'] as string) ?? '/var/log/slapd.log',
        directory: (c['directory'] as LDAPDirectory) ?? getDefaultDirectory(),
    };
}

function getDefaultDirectory(): LDAPDirectory {
    return {
        entries: [
            {
                dn: 'dc=variant,dc=local',
                attributes: {
                    objectClass: ['dcObject', 'organization'],
                    dc: 'variant',
                    o: 'Variant Corporation',
                },
            },
            {
                dn: 'ou=users,dc=variant,dc=local',
                attributes: {
                    objectClass: ['organizationalUnit'],
                    ou: 'users',
                },
            },
            {
                dn: 'ou=groups,dc=variant,dc=local',
                attributes: {
                    objectClass: ['organizationalUnit'],
                    ou: 'groups',
                },
            },
            {
                dn: 'cn=admin,dc=variant,dc=local',
                attributes: {
                    objectClass: ['inetOrgPerson', 'organizationalPerson', 'person'],
                    cn: 'admin',
                    uid: 'admin',
                    sn: 'Administrator',
                    userPassword: 'admin123',
                    mail: 'admin@variant.local',
                    memberOf: 'cn=admins,ou=groups,dc=variant,dc=local',
                },
            },
            {
                dn: 'cn=john.doe,ou=users,dc=variant,dc=local',
                attributes: {
                    objectClass: ['inetOrgPerson', 'organizationalPerson', 'person'],
                    cn: 'john.doe',
                    uid: 'jdoe',
                    sn: 'Doe',
                    givenName: 'John',
                    userPassword: 'Welcome2024!',
                    mail: 'john.doe@variant.local',
                    telephoneNumber: '+1-555-0101',
                    memberOf: ['cn=users,ou=groups,dc=variant,dc=local', 'cn=engineering,ou=groups,dc=variant,dc=local'],
                },
            },
            {
                dn: 'cn=jane.smith,ou=users,dc=variant,dc=local',
                attributes: {
                    objectClass: ['inetOrgPerson', 'organizationalPerson', 'person'],
                    cn: 'jane.smith',
                    uid: 'jsmith',
                    sn: 'Smith',
                    givenName: 'Jane',
                    userPassword: 'SecurePass99',
                    mail: 'jane.smith@variant.local',
                    telephoneNumber: '+1-555-0102',
                    memberOf: ['cn=users,ou=groups,dc=variant,dc=local', 'cn=admins,ou=groups,dc=variant,dc=local'],
                },
            },
            {
                dn: 'cn=service.account,ou=users,dc=variant,dc=local',
                attributes: {
                    objectClass: ['inetOrgPerson', 'organizationalPerson', 'person', 'simpleSecurityObject'],
                    cn: 'service.account',
                    uid: 'svc_account',
                    sn: 'Service Account',
                    userPassword: 'SvcP@ssw0rd!2024',
                    mail: 'svc@variant.local',
                    memberOf: 'cn=service-accounts,ou=groups,dc=variant,dc=local',
                },
            },
            {
                dn: 'cn=admins,ou=groups,dc=variant,dc=local',
                attributes: {
                    objectClass: ['groupOfNames'],
                    cn: 'admins',
                    member: ['cn=admin,dc=variant,dc=local', 'cn=jane.smith,ou=users,dc=variant,dc=local'],
                },
            },
            {
                dn: 'cn=users,ou=groups,dc=variant,dc=local',
                attributes: {
                    objectClass: ['groupOfNames'],
                    cn: 'users',
                    member: ['cn=john.doe,ou=users,dc=variant,dc=local', 'cn=jane.smith,ou=users,dc=variant,dc=local'],
                },
            },
            {
                dn: 'cn=engineering,ou=groups,dc=variant,dc=local',
                attributes: {
                    objectClass: ['groupOfNames'],
                    cn: 'engineering',
                    member: 'cn=john.doe,ou=users,dc=variant,dc=local',
                },
            },
            {
                dn: 'cn=service-accounts,ou=groups,dc=variant,dc=local',
                attributes: {
                    objectClass: ['groupOfNames'],
                    cn: 'service-accounts',
                    member: 'cn=service.account,ou=users,dc=variant,dc=local',
                },
            },
        ],
    };
}

// ── LDAP Service Handler ───────────────────────────────────────

export function createLDAPService(config: ServiceConfig): ServiceHandler {
    const ldapConfig = resolveLDAPConfig(config);
    const sessions = new Map<string, LDAPSession>();

    function getSession(sourceIP: string): LDAPSession {
        let session = sessions.get(sourceIP);
        if (session === undefined) {
            session = {
                authenticated: false,
                bindDN: '',
                isAnonymous: false,
            };
            sessions.set(sourceIP, session);
        }
        return session;
    }

    function writeLDAPLog(ctx: ServiceContext, message: string): void {
        const timestamp = new Date().toISOString();
        const line = `${timestamp} slapd[${1000 + Math.floor(Math.random() * 9000)}]: ${message}`;
        try {
            const existing = ctx.vfs.readFile(ldapConfig.logFile);
            ctx.vfs.writeFile(ldapConfig.logFile, existing + '\n' + line);
        } catch {
            ctx.vfs.writeFile(ldapConfig.logFile, line);
        }
    }

    function ldapResult(code: number, message: string, close = false): ServiceResponse {
        const resultCodes: Record<number, string> = {
            0: 'success',
            1: 'operationsError',
            2: 'protocolError',
            32: 'noSuchObject',
            48: 'inappropriateAuthentication',
            49: 'invalidCredentials',
            50: 'insufficientAccessRights',
            53: 'unwillingToPerform',
        };
        const codeName = resultCodes[code] ?? 'unknown';
        return {
            payload: new TextEncoder().encode(`RESULT code=${code} ${codeName} message="${message}"\r\n`),
            close,
        };
    }

    return {
        name: 'ldap',
        port: ldapConfig.port,
        protocol: 'tcp',

        start(ctx: ServiceContext): void {
            ctx.emit({
                type: 'service:custom',
                service: 'ldap',
                action: 'started',
                details: {
                    port: ldapConfig.port,
                    baseDN: ldapConfig.baseDN,
                    allowAnonymous: ldapConfig.allowAnonymous,
                },
            });
        },

        handle(request: ServiceRequest, ctx: ServiceContext): ServiceResponse | null {
            const text = request.payloadText.trim();

            // Initial connection - send LDAP notice
            if (text === '') {
                return {
                    payload: new TextEncoder().encode(`# LDAP v3 server ready\r\n`),
                    close: false,
                };
            }

            const session = getSession(request.sourceIP);
            const spaceIdx = text.indexOf(' ');
            const cmd = spaceIdx === -1 ? text.toUpperCase() : text.slice(0, spaceIdx).toUpperCase();
            const arg = spaceIdx === -1 ? '' : text.slice(spaceIdx + 1).trim();

            switch (cmd) {
                case 'BIND': {
                    // Parse: BIND dn=<dn> [password=<password>]
                    const dnMatch = arg.match(/dn=([^\s]+)/i);
                    const passMatch = arg.match(/password=(.+)$/i);
                    const dn = dnMatch?.[1] ?? '';
                    const password = passMatch?.[1] ?? '';

                    // Anonymous bind
                    if (dn === '' || dn.toLowerCase() === 'anonymous') {
                        if (!ldapConfig.allowAnonymous) {
                            writeLDAPLog(ctx, `conn=${request.sourceIP} op=0 BIND dn="${dn}" result=48`);
                            ctx.emit({
                                type: 'service:custom',
                                service: 'ldap',
                                action: 'bind',
                                details: { dn: 'anonymous', sourceIP: request.sourceIP, success: false, reason: 'anonymous disabled' },
                            });
                            return ldapResult(48, 'Anonymous bind not allowed');
                        }
                        session.authenticated = true;
                        session.bindDN = 'anonymous';
                        session.isAnonymous = true;
                        writeLDAPLog(ctx, `conn=${request.sourceIP} op=0 BIND dn="anonymous" method=128 result=0`);
                        ctx.emit({
                            type: 'service:custom',
                            service: 'ldap',
                            action: 'bind',
                            details: { dn: 'anonymous', sourceIP: request.sourceIP, success: true },
                        });
                        return ldapResult(0, 'Bind successful');
                    }

                    // Authenticated bind
                    const entry = ldapConfig.directory.entries.find(e => e.dn.toLowerCase() === dn.toLowerCase());
                    const entryPassword = entry?.attributes['userPassword'];
                    const validPassword = typeof entryPassword === 'string' ? entryPassword : '';

                    if (entry !== undefined && password === validPassword) {
                        session.authenticated = true;
                        session.bindDN = dn;
                        session.isAnonymous = false;
                        writeLDAPLog(ctx, `conn=${request.sourceIP} op=0 BIND dn="${dn}" method=128 result=0`);
                        ctx.emit({
                            type: 'service:custom',
                            service: 'ldap',
                            action: 'bind',
                            details: { dn, sourceIP: request.sourceIP, success: true },
                        });
                        return ldapResult(0, 'Bind successful');
                    }

                    writeLDAPLog(ctx, `conn=${request.sourceIP} op=0 BIND dn="${dn}" result=49`);
                    ctx.emit({
                        type: 'service:custom',
                        service: 'ldap',
                        action: 'bind',
                        details: { dn, sourceIP: request.sourceIP, success: false, reason: 'invalid credentials' },
                    });
                    return ldapResult(49, 'Invalid credentials');
                }

                case 'SEARCH': {
                    // Parse: SEARCH base=<base> filter=<filter>
                    const baseMatch = arg.match(/base=([^\s]+)/i);
                    const filterMatch = arg.match(/filter=\(?([^)]+)\)?/i);
                    const base = baseMatch?.[1] ?? ldapConfig.baseDN;
                    let filter = filterMatch?.[1] ?? '(objectClass=*)';

                    // Remove outer parens if present
                    filter = filter.replace(/^\(/, '').replace(/\)$/, '');

                    if (!session.authenticated && !ldapConfig.allowAnonymous) {
                        return ldapResult(48, 'Authentication required');
                    }

                    // Check for LDAP injection if vulnerable
                    if (ldapConfig.injectionVulnerable) {
                        // In injection mode, we don't properly escape - allowing filter manipulation
                        if (filter.includes('*)(cn=') || filter.includes(')(uid=') || filter.includes('*))(|')) {
                            ctx.emit({
                                type: 'service:custom',
                                service: 'ldap',
                                action: 'injection-attempt',
                                details: { filter, sourceIP: request.sourceIP },
                            });
                        }
                    }

                    const results = performSearch(base, filter, ldapConfig);

                    writeLDAPLog(ctx, `conn=${request.sourceIP} op=1 SEARCH base="${base}" filter="(${filter})" result=0`);
                    ctx.emit({
                        type: 'service:custom',
                        service: 'ldap',
                        action: 'search',
                        details: { base, filter, resultCount: results.length, sourceIP: request.sourceIP },
                    });

                    const ldifOutput = results.map(entryToLDIF).join('\n');
                    const response = ldifOutput !== '' ? ldifOutput + '\n' : '# No entries found\r\n';

                    return {
                        payload: new TextEncoder().encode(response),
                        close: false,
                    };
                }

                case 'UNBIND': {
                    sessions.delete(request.sourceIP);
                    writeLDAPLog(ctx, `conn=${request.sourceIP} op=2 UNBIND result=0`);
                    return {
                        payload: new TextEncoder().encode(''),
                        close: true,
                    };
                }

                case 'WHOAMI': {
                    if (!session.authenticated) {
                        return ldapResult(48, 'Authentication required');
                    }
                    return {
                        payload: new TextEncoder().encode(`dn: ${session.bindDN}\r\n`),
                        close: false,
                    };
                }

                default:
                    return ldapResult(2, `Unknown operation: ${cmd}`);
            }
        },

        stop(): void {
            sessions.clear();
        },
    };
}

// ── LDAP Search Implementation ─────────────────────────────────

function performSearch(base: string, filter: string, config: LDAPConfig): LDAPEntry[] {
    const results: LDAPEntry[] = [];

    for (const entry of config.directory.entries) {
        // Check base DN - entry must be under the base
        if (!entry.dn.toLowerCase().endsWith(base.toLowerCase()) && entry.dn.toLowerCase() !== base.toLowerCase()) {
            continue;
        }

        // Parse and evaluate filter
        if (matchesFilter(entry, filter, config)) {
            results.push(entry);
        }
    }

    return results;
}

function matchesFilter(entry: LDAPEntry, filter: string, config: LDAPConfig): boolean {
    // Handle injection-vulnerable parsing
    if (config.injectionVulnerable) {
        // Allow OR injection: (|(cn=x)(cn=y)) or ** for wildcard abuse
        if (filter.includes(')|(') || filter.includes('|(')) {
            // Simplified injection handling - match if any sub-filter matches
            const parts = filter.split(/\)|\|/);
            for (const part of parts) {
                const cleanPart = part.replace(/^\(?/, '').trim();
                if (cleanPart !== '' && evaluateSimpleFilter(entry, cleanPart)) {
                    return true;
                }
            }
            return false;
        }
    }

    return evaluateSimpleFilter(entry, filter);
}

function evaluateSimpleFilter(entry: LDAPEntry, filter: string): boolean {
    // Simple attribute=value filter
    const eqIdx = filter.indexOf('=');
    if (eqIdx === -1) return false;

    const attr = filter.slice(0, eqIdx).trim().toLowerCase();
    let value = filter.slice(eqIdx + 1).trim();

    // Handle wildcards
    const isWildcard = value === '*' || value.includes('*');
    const cleanValue = value.replace(/\*/g, '').toLowerCase();

    const entryValue = entry.attributes[attr];

    if (entryValue === undefined) {
        // Special case: objectClass=* matches any entry
        return attr === 'objectclass' && value === '*';
    }

    if (Array.isArray(entryValue)) {
        for (const v of entryValue) {
            const vStr = String(v).toLowerCase();
            if (isWildcard) {
                if (cleanValue === '' || vStr.includes(cleanValue)) return true;
            } else {
                if (vStr === cleanValue) return true;
            }
        }
        return false;
    }

    const vStr = String(entryValue).toLowerCase();
    if (isWildcard) {
        return cleanValue === '' || vStr.includes(cleanValue);
    }
    return vStr === cleanValue;
}

function entryToLDIF(entry: LDAPEntry): string {
    let ldif = `dn: ${entry.dn}\n`;
    for (const [attr, value] of Object.entries(entry.attributes)) {
        if (Array.isArray(value)) {
            for (const v of value) {
                ldif += `${attr}: ${v}\n`;
            }
        } else {
            ldif += `${attr}: ${value}\n`;
        }
    }
    return ldif;
}

// ── Export Types ───────────────────────────────────────────────

export type { LDAPConfig, LDAPDirectory, LDAPEntry };
