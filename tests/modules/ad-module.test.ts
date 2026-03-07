import { beforeEach, describe, expect, it } from 'vitest';
import { createADModule } from '../../src/modules/ad-module';
import { createEventBus } from '../../src/core/event-bus';
import type { EventBus, EngineEvent } from '../../src/core/events';
import type { ExternalRequest, ExternalServiceHandler } from '../../src/core/fabric/types';
import type { ActiveDirectorySpec } from '../../src/core/world/types';

const decoder = new TextDecoder();
const encoder = new TextEncoder();

function makeRequest(method: string, path: string, body?: unknown): ExternalRequest {
    const payload = body === undefined ? null : encoder.encode(JSON.stringify(body));
    return {
        method,
        path,
        headers: new Map<string, string>(),
        body: payload,
    };
}

function responseJson(handler: ExternalServiceHandler, request: ExternalRequest): any {
    const response = handler.handleRequest(request);
    return JSON.parse(decoder.decode(response.body));
}

function responseStatus(handler: ExternalServiceHandler, request: ExternalRequest): number {
    return handler.handleRequest(request).status;
}

function findHandler(handlers: readonly ExternalServiceHandler[], domain: string): ExternalServiceHandler {
    const handler = handlers.find(h => h.domain === domain);
    if (handler === undefined) throw new Error(`Missing handler: ${domain}`);
    return handler;
}

function createTestEventBus(): EventBus & { emitted: EngineEvent[] } {
    const inner = createEventBus(10_000);
    const emitted: EngineEvent[] = [];
    return {
        emitted,
        emit(event: EngineEvent): void {
            emitted.push(event);
            inner.emit(event);
        },
        on: inner.on.bind(inner),
        once: inner.once.bind(inner),
        waitFor: inner.waitFor.bind(inner),
        onPrefix: inner.onPrefix.bind(inner),
        getLog: inner.getLog.bind(inner),
        clearLog: inner.clearLog.bind(inner),
        removeAllListeners: inner.removeAllListeners.bind(inner),
    };
}

function makeAdSpec(): ActiveDirectorySpec {
    const spec = {
        domain: 'corp.local',
        domainControllers: ['dc-01'],
        organizationalUnits: [
            { name: 'Users', dn: 'OU=Users,DC=corp,DC=local', children: [] },
            { name: 'Servers', dn: 'OU=Servers,DC=corp,DC=local', children: [] },
        ],
        users: [
            {
                samAccountName: 'alice',
                displayName: 'Alice Smith',
                email: 'alice@corp.local',
                department: 'IT',
                title: 'Administrator',
                memberOf: ['CN=Domain Admins,OU=Users,DC=corp,DC=local'],
                passwordLastSet: '2025-01-01T00:00:00Z',
                lastLogon: '2025-01-02T00:00:00Z',
                enabled: true,
                password: 'alice-pass',
            },
            {
                samAccountName: 'bob',
                displayName: 'Bob Disabled',
                email: 'bob@corp.local',
                department: 'Finance',
                title: 'Analyst',
                memberOf: ['CN=Domain Users,OU=Users,DC=corp,DC=local'],
                passwordLastSet: '2025-01-01T00:00:00Z',
                lastLogon: '2025-01-02T00:00:00Z',
                enabled: false,
                password: 'bob-pass',
            },
            {
                samAccountName: 'svc-web',
                displayName: 'svc-web',
                email: 'svc-web@corp.local',
                department: 'IT',
                title: 'Service Account',
                memberOf: ['CN=Domain Users,OU=Users,DC=corp,DC=local'],
                passwordLastSet: '2025-01-01T00:00:00Z',
                lastLogon: '2025-01-02T00:00:00Z',
                enabled: true,
                password: 'svc-web-pass',
            },
            {
                samAccountName: 'svc-s4u',
                displayName: 'svc-s4u',
                email: 'svc-s4u@corp.local',
                department: 'IT',
                title: 'Service Account',
                memberOf: ['CN=Domain Users,OU=Users,DC=corp,DC=local'],
                passwordLastSet: '2025-01-01T00:00:00Z',
                lastLogon: '2025-01-02T00:00:00Z',
                enabled: true,
                password: 'svc-s4u-pass',
            },
        ],
        groups: [
            {
                name: 'Domain Admins',
                dn: 'CN=Domain Admins,OU=Users,DC=corp,DC=local',
                members: ['CN=Alice Smith,CN=Users,DC=corp,DC=local'],
                isPrivileged: true,
            },
            {
                name: 'Server Admins',
                dn: 'CN=Server Admins,OU=Servers,DC=corp,DC=local',
                members: ['CN=svc-s4u,CN=Users,DC=corp,DC=local'],
                isPrivileged: false,
            },
        ],
        groupPolicies: [
            {
                name: 'Default Domain Policy',
                guid: '{11111111-1111-1111-1111-111111111111}',
                linkedOUs: ['OU=Users,DC=corp,DC=local'],
                settings: {
                    passwordPolicy: { minLength: 8, maxAgeDays: 90 },
                    auditPolicy: { logonEvents: true, objectAccess: true },
                    softwareRestrictions: { allowOnlySigned: false },
                },
            },
        ],
        kerberos: {
            krbtgtHash: 'KRBTGT_HASH_REAL',
            tickets: [],
            servicePrincipalNames: [
                {
                    spn: 'MSSQLSvc/sql01.corp.local:1433',
                    accountDn: 'CN=svc-sql,OU=Users,DC=corp,DC=local',
                    serviceClass: 'MSSQLSvc',
                    host: 'sql01.corp.local',
                },
                {
                    spn: 'HTTP/app.corp.local:443',
                    accountDn: 'CN=svc-web,OU=Users,DC=corp,DC=local',
                    serviceClass: 'HTTP',
                    host: 'app.corp.local',
                },
            ],
            delegationRules: [
                {
                    type: 'unconstrained',
                    sourceDn: 'CN=svc-web,OU=Users,DC=corp,DC=local',
                    targetSpns: [],
                    protocolTransition: true,
                },
                {
                    type: 'constrained',
                    sourceDn: 'CN=svc-s4u,OU=Users,DC=corp,DC=local',
                    targetSpns: ['MSSQLSvc/sql01.corp.local:1433'],
                    protocolTransition: true,
                },
            ],
        },
        serviceAccounts: [
            {
                samAccountName: 'svc-sql',
                dn: 'CN=svc-sql,OU=Users,DC=corp,DC=local',
                spns: ['MSSQLSvc/sql01.corp.local:1433'],
                weakPassword: true,
            },
            {
                samAccountName: 'svc-web',
                dn: 'CN=svc-web,OU=Users,DC=corp,DC=local',
                spns: ['HTTP/app.corp.local:443'],
                weakPassword: false,
            },
            {
                samAccountName: 'svc-s4u',
                dn: 'CN=svc-s4u,OU=Users,DC=corp,DC=local',
                spns: ['HOST/s4u.corp.local'],
                weakPassword: false,
            },
        ],
    };
    return spec as unknown as ActiveDirectorySpec;
}

function setup() {
    const events = createTestEventBus();
    const handlers: ExternalServiceHandler[] = [];
    const dns: Array<{ domain: string; ip: string; type: string; ttl: number }> = [];
    const spec = makeAdSpec();

    const mod = createADModule(spec, events);
    mod.init({
        world: { activeDirectory: spec } as any,
        fabric: {
            addDNSRecord(record: { domain: string; ip: string; type: string; ttl: number }) { dns.push(record); },
            registerExternal(handler: ExternalServiceHandler) { handlers.push(handler); },
        } as any,
        events,
        vms: new Map(),
        tick: 0,
        services: {} as any,
    });

    return { mod, spec, events, handlers, dns };
}

describe('AD module wiring', () => {
    it('registers handlers, DNS, and module metadata', () => {
        const { mod, handlers, dns } = setup();
        expect(mod.id).toBe('active-directory');
        expect(mod.version).toBe('1.0.0');
        expect(mod.provides.map(p => p.name)).toEqual(['active-directory', 'kerberos', 'ldap']);
        expect(handlers.length).toBe(3);
        expect(dns.length).toBe(3);
    });
});

describe('LDAP query handler', () => {
    let ldap: ExternalServiceHandler;

    beforeEach(() => {
        const { handlers, spec } = setup();
        ldap = findHandler(handlers, `ldap.${spec.domain}`);
    });

    it('searches enabled users by objectClass', () => {
        const res = responseJson(ldap, makeRequest('GET', '/query?filter=(objectClass=user)'));
        const usernames = res.map((x: any) => x.attributes.sAMAccountName);
        expect(usernames).toContain('alice');
        expect(usernames).not.toContain('bob');
    });

    it('supports memberOf filter', () => {
        const res = responseJson(
            ldap,
            makeRequest('GET', '/query?filter=(memberOf=CN=Domain Admins,OU=Users,DC=corp,DC=local)'),
        );
        expect(res.length).toBe(1);
        expect(res[0].attributes.sAMAccountName).toBe('alice');
    });

    it('filters disabled users from sAMAccountName queries', () => {
        const res = responseJson(ldap, makeRequest('GET', '/query?filter=(sAMAccountName=bob)'));
        expect(res).toEqual([]);
    });

    it('supports base DN scoping', () => {
        const res = responseJson(
            ldap,
            makeRequest('POST', '/query', {
                filter: '(objectClass=group)',
                baseDN: 'OU=Servers,DC=corp,DC=local',
            }),
        );
        expect(res.length).toBe(1);
        expect(res[0].attributes.cn).toBe('Server Admins');
    });
});

describe('Kerberos handlers', () => {
    let kerberos: ExternalServiceHandler;
    let spec: ActiveDirectorySpec;
    let events: EventBus & { emitted: EngineEvent[] };

    beforeEach(() => {
        const setupResult = setup();
        spec = setupResult.spec;
        events = setupResult.events;
        kerberos = findHandler(setupResult.handlers, `kerberos.${spec.domain}`);
    });

    function getTgt(username: string, password: string, lifetimeSeconds?: number): string {
        const body: Record<string, unknown> = { username, password };
        if (lifetimeSeconds !== undefined) {
            body['lifetimeSeconds'] = lifetimeSeconds;
        }
        const res = responseJson(kerberos, makeRequest('POST', '/as-req', body));
        return res.tgt;
    }

    it('issues TGT for valid credentials and rejects invalid credentials', () => {
        const ok = responseJson(kerberos, makeRequest('POST', '/as-req', { username: 'alice', password: 'alice-pass' }));
        expect(ok.ticketType).toBe('TGT');
        expect(typeof ok.tgt).toBe('string');

        const status = responseStatus(kerberos, makeRequest('POST', '/as-req', { username: 'alice', password: 'wrong' }));
        expect(status).toBe(401);
    });

    it('returns RC4 ticket for Kerberoastable SPN', () => {
        const tgt = getTgt('alice', 'alice-pass');
        const res = responseJson(
            kerberos,
            makeRequest('POST', '/tgs-req', { tgt, spn: 'MSSQLSvc/sql01.corp.local:1433' }),
        );
        expect(res.ticketType).toBe('TGS');
        expect(res.encType).toBe('RC4-HMAC');
        expect(res.kerberoastable).toBe(true);
    });

    it('returns AES ticket for non-Kerberoastable SPN', () => {
        const tgt = getTgt('alice', 'alice-pass');
        const res = responseJson(
            kerberos,
            makeRequest('POST', '/tgs-req', { tgt, spn: 'HTTP/app.corp.local:443' }),
        );
        expect(res.ticketType).toBe('TGS');
        expect(res.encType).toBe('AES256-CTS-HMAC-SHA1');
        expect(res.kerberoastable).toBe(false);
    });

    it('emits golden-ticket detection alert', () => {
        const forged = btoa(JSON.stringify({
            ticketId: 'forged',
            type: 'TGT',
            principal: 'alice',
            realm: 'CORP.LOCAL',
            issuedAt: 111,
            expiresAt: 9999999999,
            encType: 'RC4-HMAC',
            encryptedWith: 'KRBTGT_HASH_REAL',
            signature: 'invalid-signature',
        }));

        const status = responseStatus(
            kerberos,
            makeRequest('POST', '/tgs-req', { tgt: forged, spn: 'HTTP/app.corp.local:443' }),
        );
        expect(status).toBe(401);

        const alerts = events.emitted.filter(
            (e): e is Extract<EngineEvent, { type: 'defense:alert' }> =>
                e.type === 'defense:alert',
        );
        expect(alerts.some(a => a.ruleId === 'golden-ticket-detected' && a.severity === 'critical')).toBe(true);
    });

    it('emits abnormal lifetime alerts for very long TGTs', () => {
        responseJson(
            kerberos,
            makeRequest('POST', '/as-req', {
                username: 'alice',
                password: 'alice-pass',
                lifetimeSeconds: 172800,
            }),
        );

        const alerts = events.emitted.filter(
            (e): e is Extract<EngineEvent, { type: 'defense:alert' }> =>
                e.type === 'defense:alert',
        );
        expect(alerts.some(a => a.ruleId === 'abnormal-ticket-lifetime')).toBe(true);
    });

    it('supports unconstrained and constrained S4U delegation rules', () => {
        const unconstrainedTgt = getTgt('svc-web', 'svc-web-pass');
        const unconstrained = responseJson(
            kerberos,
            makeRequest('POST', '/s4u', {
                tgt: unconstrainedTgt,
                delegatingService: 'svc-web',
                impersonateUser: 'alice',
                targetSpn: 'HTTP/app.corp.local:443',
            }),
        );
        expect(unconstrained.delegationType).toBe('unconstrained');
        expect(unconstrained.principal).toBe('alice');

        const constrainedTgt = getTgt('svc-s4u', 'svc-s4u-pass');
        const constrainedOk = responseJson(
            kerberos,
            makeRequest('POST', '/s4u', {
                tgt: constrainedTgt,
                delegatingService: 'svc-s4u',
                impersonateUser: 'alice',
                targetSpn: 'MSSQLSvc/sql01.corp.local:1433',
            }),
        );
        expect(constrainedOk.delegationType).toBe('constrained');

        const constrainedDeniedStatus = responseStatus(
            kerberos,
            makeRequest('POST', '/s4u', {
                tgt: constrainedTgt,
                delegatingService: 'svc-s4u',
                impersonateUser: 'alice',
                targetSpn: 'HTTP/app.corp.local:443',
            }),
        );
        expect(constrainedDeniedStatus).toBe(403);
    });
});

describe('GPO and SPN handlers', () => {
    let gpo: ExternalServiceHandler;
    let ldap: ExternalServiceHandler;
    let spec: ActiveDirectorySpec;

    beforeEach(() => {
        const setupResult = setup();
        spec = setupResult.spec;
        gpo = findHandler(setupResult.handlers, `gpo.${spec.domain}`);
        ldap = findHandler(setupResult.handlers, `ldap.${spec.domain}`);
    });

    it('lists and retrieves GPO details', () => {
        const list = responseJson(gpo, makeRequest('GET', '/policies'));
        expect(list.length).toBe(1);
        expect(list[0].name).toBe('Default Domain Policy');

        const detail = responseJson(gpo, makeRequest('GET', '/policy/{11111111-1111-1111-1111-111111111111}'));
        expect(detail.settings.passwordPolicy).toBeDefined();
        expect(detail.settings.auditPolicy).toBeDefined();
        expect(detail.settings.softwareRestrictions).toBeDefined();
    });

    it('enumerates SPNs with account mapping', () => {
        const spns = responseJson(ldap, makeRequest('GET', '/spns'));
        expect(spns.length).toBeGreaterThanOrEqual(2);

        const sqlSpn = spns.find((x: any) => x.spn === 'MSSQLSvc/sql01.corp.local:1433');
        expect(sqlSpn).toBeDefined();
        expect(sqlSpn.serviceType).toBe('MSSQLSvc');
        expect(sqlSpn.hostname).toBe('sql01.corp.local');
        expect(sqlSpn.port).toBe(1433);
        expect(sqlSpn.associatedServiceAccount).toBe('svc-sql');
    });
});
