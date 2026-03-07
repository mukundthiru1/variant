/**
 * VARIANT — Active Directory / Kerberos Module
 *
 * Simulates LDAP queries, Kerberos ticket operations, GPO retrieval,
 * and SPN enumeration over VARIANT Internet external handlers.
 */

import type { EventBus } from '../core/events';
import type { ExternalRequest, ExternalResponse, ExternalServiceHandler } from '../core/fabric/types';
import type { Module, SimulationContext, Capability } from '../core/modules';
import type {
    ActiveDirectorySpec,
    ADUserSpec,
    ADGroupSpec,
    ServiceAccountSpec,
    DelegationRuleSpec,
} from '../core/world/types';

const MODULE_ID = 'active-directory';
const MODULE_VERSION = '1.0.0';
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const DEFAULT_TGT_LIFETIME_MS = 10 * 60 * 60 * 1000; // 10h
const DEFAULT_TGS_LIFETIME_MS = 8 * 60 * 60 * 1000; // 8h
const ABNORMAL_TICKET_LIFETIME_MS = 24 * 60 * 60 * 1000; // 24h
const TICKET_EPOCH_MS = 1_893_456_000_000; // 2030-01-01T00:00:00.000Z

interface ADUserWithPassword extends ADUserSpec {
    readonly password?: string;
}

interface ServiceAccountWithWeakPassword extends ServiceAccountSpec {
    readonly weakPassword?: boolean;
}

interface DelegationRuleWithAllowedServices extends DelegationRuleSpec {
    readonly allowedServices?: readonly string[];
}

interface TicketPayload {
    readonly ticketId: string;
    readonly type: 'TGT' | 'TGS';
    readonly principal: string;
    readonly realm: string;
    readonly service?: string;
    readonly issuedAt: number;
    readonly expiresAt: number;
    readonly encType: string;
    readonly encryptedWith: string;
    readonly signature: string;
}

interface ParsedSPN {
    readonly spn: string;
    readonly serviceType: string;
    readonly hostname: string;
    readonly port: number | null;
    readonly accountDn: string;
    readonly accountSam: string | null;
}

interface LdapObject {
    readonly dn: string;
    readonly objectClass: 'user' | 'group';
    readonly attributes: Readonly<Record<string, string | boolean | readonly string[]>>;
}

function parseQuery(path: string): URLSearchParams {
    const query = path.includes('?') ? path.slice(path.indexOf('?') + 1) : '';
    return new URLSearchParams(query);
}

function stripQuery(path: string): string {
    const idx = path.indexOf('?');
    return idx === -1 ? path : path.slice(0, idx);
}

function getRequestJson(request: ExternalRequest): Record<string, unknown> {
    if (request.body === null || request.body.length === 0) return {};
    try {
        const raw = decoder.decode(request.body);
        const parsed = JSON.parse(raw);
        return typeof parsed === 'object' && parsed !== null ? parsed as Record<string, unknown> : {};
    } catch {
        return {};
    }
}

function jsonResponse(status: number, data: unknown): ExternalResponse {
    const headers = new Map<string, string>();
    headers.set('content-type', 'application/json');
    headers.set('server', 'VARIANT-AD/1.0');
    return { status, headers, body: encoder.encode(JSON.stringify(data, null, 2)) };
}

function simpleHash(input: string): string {
    let hash = 5381;
    for (let i = 0; i < input.length; i++) {
        hash = ((hash << 5) + hash + input.charCodeAt(i)) | 0;
    }
    return (hash >>> 0).toString(16).padStart(8, '0');
}

function longHash(input: string, rounds: number = 8): string {
    let out = '';
    let seed = input;
    for (let i = 0; i < rounds; i++) {
        const block = simpleHash(`${seed}|${i}`);
        out += block;
        seed = `${seed}|${block}`;
    }
    return out;
}

function toBase64(input: string): string {
    return btoa(input);
}

function fromBase64(input: string): string {
    return atob(input);
}

function toRealm(domain: string): string {
    return domain.toUpperCase();
}

function domainToBaseDN(domain: string): string {
    return domain
        .split('.')
        .map(part => `DC=${part}`)
        .join(',');
}

function dnWithinBase(dn: string, baseDN: string): boolean {
    return dn.toLowerCase().endsWith(baseDN.toLowerCase());
}

function normalizeSam(name: string): string {
    return name.trim().toLowerCase();
}

function normalizePath(path: string): string {
    const raw = stripQuery(path);
    return raw.length > 1 && raw.endsWith('/') ? raw.slice(0, -1) : raw;
}

function deterministicIssuedAt(seed: string): number {
    const offset = parseInt(simpleHash(seed), 16) % (12 * 60 * 60 * 1000);
    return TICKET_EPOCH_MS + offset;
}

function makeSignature(payload: Omit<TicketPayload, 'signature'>): string {
    const raw = [
        payload.ticketId,
        payload.type,
        payload.principal,
        payload.realm,
        payload.service ?? '',
        String(payload.issuedAt),
        String(payload.expiresAt),
        payload.encType,
        payload.encryptedWith,
    ].join('|');
    return longHash(raw, 4);
}

function encodeTicket(payload: Omit<TicketPayload, 'signature'>): string {
    const signed: TicketPayload = {
        ...payload,
        signature: makeSignature(payload),
    };
    return toBase64(JSON.stringify(signed));
}

function decodeTicket(ticket: string): TicketPayload | null {
    try {
        const raw = fromBase64(ticket);
        const parsed = JSON.parse(raw) as Partial<TicketPayload>;
        if (
            parsed.ticketId === undefined ||
            parsed.type === undefined ||
            parsed.principal === undefined ||
            parsed.realm === undefined ||
            parsed.issuedAt === undefined ||
            parsed.expiresAt === undefined ||
            parsed.encType === undefined ||
            parsed.encryptedWith === undefined ||
            parsed.signature === undefined
        ) {
            return null;
        }
        const reconstructed: Omit<TicketPayload, 'signature'> = {
            ticketId: parsed.ticketId,
            type: parsed.type,
            principal: parsed.principal,
            realm: parsed.realm,
            issuedAt: parsed.issuedAt,
            expiresAt: parsed.expiresAt,
            encType: parsed.encType,
            encryptedWith: parsed.encryptedWith,
            ...(parsed.service !== undefined ? { service: parsed.service } : {}),
        };
        if (makeSignature(reconstructed) !== parsed.signature) return null;
        return parsed as TicketPayload;
    } catch {
        return null;
    }
}

function parseSPNString(spn: string): { serviceType: string; hostname: string; port: number | null } {
    const [serviceTypeRaw, hostRaw] = spn.split('/', 2);
    const serviceType = serviceTypeRaw ?? 'unknown';
    const hostPart = hostRaw ?? '';
    const [host, portRaw] = hostPart.split(':', 2);
    const parsedPort = portRaw !== undefined ? Number(portRaw) : Number.NaN;
    return {
        serviceType,
        hostname: host || '',
        port: Number.isFinite(parsedPort) ? parsedPort : null,
    };
}

function buildParsedSPNs(spec: ActiveDirectorySpec): readonly ParsedSPN[] {
    const accountDnToSam = new Map<string, string>();
    for (const account of spec.serviceAccounts) {
        accountDnToSam.set(account.dn.toLowerCase(), account.samAccountName);
    }

    const all: ParsedSPN[] = [];
    const seen = new Set<string>();

    const append = (spn: string, accountDn: string, serviceClassFromSpec?: string, hostFromSpec?: string): void => {
        const key = `${spn.toLowerCase()}|${accountDn.toLowerCase()}`;
        if (seen.has(key)) return;
        seen.add(key);

        const parsed = parseSPNString(spn);
        const serviceType = serviceClassFromSpec ?? parsed.serviceType;
        const hostname = hostFromSpec ?? parsed.hostname;

        all.push({
            spn,
            serviceType,
            hostname,
            port: parsed.port,
            accountDn,
            accountSam: accountDnToSam.get(accountDn.toLowerCase()) ?? null,
        });
    };

    for (const spn of spec.kerberos.servicePrincipalNames) {
        append(spn.spn, spn.accountDn, spn.serviceClass, spn.host);
    }
    for (const account of spec.serviceAccounts) {
        for (const spn of account.spns) {
            append(spn, account.dn);
        }
    }

    return Object.freeze(all);
}

function findUser(users: readonly ADUserSpec[], username: string): ADUserWithPassword | null {
    const normalized = normalizeSam(username);
    for (const user of users) {
        if (normalizeSam(user.samAccountName) === normalized) {
            return user as ADUserWithPassword;
        }
    }
    return null;
}

function resolveExpectedPassword(user: ADUserWithPassword): string | null {
    return typeof user.password === 'string' ? user.password : null;
}

function buildUserObjects(users: readonly ADUserSpec[], baseDN: string): readonly LdapObject[] {
    const out: LdapObject[] = [];
    for (const user of users) {
        if (!user.enabled) continue;
        out.push({
            dn: `CN=${user.displayName},CN=Users,${baseDN}`,
            objectClass: 'user',
            attributes: {
                objectClass: 'user',
                sAMAccountName: user.samAccountName,
                displayName: user.displayName,
                mail: user.email,
                department: user.department,
                title: user.title,
                memberOf: user.memberOf,
                enabled: user.enabled,
                adminCount: user.adminCount ?? false,
                passwordLastSet: user.passwordLastSet,
                lastLogon: user.lastLogon,
            },
        });
    }
    return Object.freeze(out);
}

function buildGroupObjects(groups: readonly ADGroupSpec[]): readonly LdapObject[] {
    const out: LdapObject[] = [];
    for (const group of groups) {
        out.push({
            dn: group.dn,
            objectClass: 'group',
            attributes: {
                objectClass: 'group',
                cn: group.name,
                dn: group.dn,
                member: group.members,
                isPrivileged: group.isPrivileged,
            },
        });
    }
    return Object.freeze(out);
}

type LdapFilterKind =
    | { kind: 'objectClass'; value: 'user' | 'group' }
    | { kind: 'memberOf'; value: string }
    | { kind: 'sAMAccountName'; value: string };

function parseLdapFilter(filter: string): LdapFilterKind | null {
    const trimmed = filter.trim();
    const objectClassMatch = trimmed.match(/^\(objectClass=(user|group)\)$/i);
    if (objectClassMatch) {
        return { kind: 'objectClass', value: objectClassMatch[1]!.toLowerCase() as 'user' | 'group' };
    }

    const memberOfMatch = trimmed.match(/^\(memberOf=(.+)\)$/i);
    if (memberOfMatch) {
        return { kind: 'memberOf', value: memberOfMatch[1]!.trim() };
    }

    const samMatch = trimmed.match(/^\(sAMAccountName=(.+)\)$/i);
    if (samMatch) {
        return { kind: 'sAMAccountName', value: samMatch[1]!.trim() };
    }

    return null;
}

function getBaseDnFromLdapObject(obj: LdapObject): string {
    return obj.dn;
}

function asString(value: unknown): string | null {
    return typeof value === 'string' ? value : null;
}

function asNumber(value: unknown): number | null {
    return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function extractCnFromDn(dn: string): string | null {
    const match = dn.match(/^CN=([^,]+),/i);
    if (match === null) return null;
    return match[1] ?? null;
}

function isDelegationSourceMatch(ruleSourceDn: string, delegatingService: string, sourceSam: string | null): boolean {
    const d = delegatingService.toLowerCase();
    const sourceDnLower = ruleSourceDn.toLowerCase();
    const sourceCn = extractCnFromDn(ruleSourceDn)?.toLowerCase() ?? null;
    return (
        sourceDnLower === d ||
        (sourceSam !== null && sourceSam.toLowerCase() === d) ||
        (sourceCn !== null && sourceCn === d)
    );
}

function resolveSpnRecord(parsedSpns: readonly ParsedSPN[], targetSpn: string): ParsedSPN | null {
    const target = targetSpn.toLowerCase();
    for (const spn of parsedSpns) {
        if (spn.spn.toLowerCase() === target) return spn;
    }
    return null;
}

function extractGpoSettings(settings: Readonly<Record<string, unknown>>): Readonly<Record<string, unknown>> {
    return {
        passwordPolicy: settings['passwordPolicy'] ?? null,
        auditPolicy: settings['auditPolicy'] ?? null,
        softwareRestrictions: settings['softwareRestrictions'] ?? settings['softwareRestrictionPolicy'] ?? null,
    };
}

export function createADModule(spec: ActiveDirectorySpec, eventBus: EventBus): Module {
    const domain = spec.domain;
    const ldapDomain = `ldap.${domain}`;
    const kerberosDomain = `kerberos.${domain}`;
    const gpoDomain = `gpo.${domain}`;
    const baseDN = domainToBaseDN(domain);
    const parsedSpns = buildParsedSPNs(spec);

    const userObjects = buildUserObjects(spec.users, baseDN);
    const groupObjects = buildGroupObjects(spec.groups);
    const allObjects = Object.freeze([...userObjects, ...groupObjects]);

    const ldapHandler: ExternalServiceHandler = {
        domain: ldapDomain,
        description: `VARIANT AD LDAP service for ${domain}`,
        handleRequest(request: ExternalRequest): ExternalResponse {
            const path = normalizePath(request.path);
            if (path === '/query') {
                return handleLdapQuery(request);
            }
            if (path === '/spns' && request.method === 'GET') {
                return jsonResponse(200, parsedSpns.map(spn => ({
                    spn: spn.spn,
                    serviceType: spn.serviceType,
                    hostname: spn.hostname,
                    port: spn.port,
                    associatedServiceAccount: spn.accountSam ?? spn.accountDn,
                })));
            }
            return jsonResponse(404, { error: 'not-found' });
        },
    };

    const kerberosHandler: ExternalServiceHandler = {
        domain: kerberosDomain,
        description: `VARIANT AD Kerberos service for ${domain}`,
        handleRequest(request: ExternalRequest): ExternalResponse {
            const path = normalizePath(request.path);
            if (request.method !== 'POST') {
                return jsonResponse(405, { error: 'method-not-allowed' });
            }
            if (path === '/as-req') return handleAsReq(request);
            if (path === '/tgs-req') return handleTgsReq(request);
            if (path === '/s4u') return handleS4U(request);
            return jsonResponse(404, { error: 'not-found' });
        },
    };

    const gpoHandler: ExternalServiceHandler = {
        domain: gpoDomain,
        description: `VARIANT AD GPO service for ${domain}`,
        handleRequest(request: ExternalRequest): ExternalResponse {
            const path = normalizePath(request.path);
            if (request.method !== 'GET') return jsonResponse(405, { error: 'method-not-allowed' });
            if (path === '/policies') {
                return jsonResponse(200, spec.groupPolicies.map(gpo => ({
                    id: gpo.guid,
                    name: gpo.name,
                    linkedOUs: gpo.linkedOUs,
                    vulnerabilities: gpo.vulnerabilities ?? [],
                })));
            }
            if (path.startsWith('/policy/')) {
                const id = decodeURIComponent(path.slice('/policy/'.length));
                const gpo = spec.groupPolicies.find(x => x.guid === id || x.name === id);
                if (gpo === undefined) {
                    return jsonResponse(404, { error: 'gpo-not-found' });
                }
                return jsonResponse(200, {
                    id: gpo.guid,
                    name: gpo.name,
                    linkedOUs: gpo.linkedOUs,
                    settings: extractGpoSettings(gpo.settings),
                    vulnerabilities: gpo.vulnerabilities ?? [],
                });
            }
            return jsonResponse(404, { error: 'not-found' });
        },
    };

    function handleLdapQuery(request: ExternalRequest): ExternalResponse {
        let filter = '(objectClass=user)';
        let queryBaseDn = baseDN;

        if (request.method === 'GET') {
            const params = parseQuery(request.path);
            const qFilter = params.get('filter');
            const qBaseDn = params.get('baseDN') ?? params.get('baseDn');
            if (qFilter !== null) filter = qFilter;
            if (qBaseDn !== null && qBaseDn.trim() !== '') queryBaseDn = qBaseDn;
        } else if (request.method === 'POST') {
            const body = getRequestJson(request);
            const bFilter = asString(body['filter']);
            const bBaseDn = asString(body['baseDN']) ?? asString(body['baseDn']);
            if (bFilter !== null) filter = bFilter;
            if (bBaseDn !== null && bBaseDn.trim() !== '') queryBaseDn = bBaseDn;
        } else {
            return jsonResponse(405, { error: 'method-not-allowed' });
        }

        const parsedFilter = parseLdapFilter(filter);
        if (parsedFilter === null) {
            return jsonResponse(400, { error: 'unsupported-filter', supported: ['(objectClass=user)', '(objectClass=group)', '(memberOf=CN=...)', '(sAMAccountName=...)'] });
        }

        const scoped = allObjects.filter(obj => dnWithinBase(getBaseDnFromLdapObject(obj), queryBaseDn));
        let filtered: readonly LdapObject[] = scoped;

        if (parsedFilter.kind === 'objectClass') {
            filtered = scoped.filter(obj => obj.objectClass === parsedFilter.value);
        } else if (parsedFilter.kind === 'memberOf') {
            filtered = userObjects.filter(obj => {
                if (!dnWithinBase(obj.dn, queryBaseDn)) return false;
                const memberOf = obj.attributes['memberOf'];
                if (!Array.isArray(memberOf)) return false;
                return memberOf.some(groupDn => groupDn.toLowerCase() === parsedFilter.value.toLowerCase());
            });
        } else if (parsedFilter.kind === 'sAMAccountName') {
            const target = parsedFilter.value.toLowerCase();
            filtered = scoped.filter(obj => {
                const sam = obj.attributes['sAMAccountName'];
                return typeof sam === 'string' && sam.toLowerCase() === target;
            });
        }

        return jsonResponse(200, filtered);
    }

    function emitDefenseAlert(ruleId: string, severity: 'low' | 'medium' | 'high' | 'critical', detail: string): void {
        eventBus.emit({
            type: 'defense:alert',
            machine: spec.domainControllers[0] ?? 'dc-01',
            ruleId,
            severity,
            detail,
            timestamp: Date.now(),
        });
    }

    function evaluateTicketAnomalies(rawTgt: string, ticket: TicketPayload): void {
        let decodedRaw = '';
        try {
            decodedRaw = fromBase64(rawTgt);
        } catch {
            decodedRaw = '';
        }
        if (
            rawTgt.includes(spec.kerberos.krbtgtHash) ||
            decodedRaw.includes(spec.kerberos.krbtgtHash) ||
            ticket.encryptedWith === spec.kerberos.krbtgtHash
        ) {
            emitDefenseAlert(
                'golden-ticket-detected',
                'critical',
                'Presented TGT contains KRBTGT hash material (tag: golden-ticket-detected).',
            );
        }
        const lifetime = ticket.expiresAt - ticket.issuedAt;
        if (lifetime > ABNORMAL_TICKET_LIFETIME_MS) {
            emitDefenseAlert(
                'abnormal-ticket-lifetime',
                'high',
                `Ticket lifetime ${lifetime}ms exceeds ${ABNORMAL_TICKET_LIFETIME_MS}ms baseline.`,
            );
        }
    }

    function makeTgt(username: string, lifetimeMs: number): string {
        const principal = normalizeSam(username);
        const issuedAt = deterministicIssuedAt(`${principal}|tgt|${domain}`);
        const expiresAt = issuedAt + lifetimeMs;
        const encryptedWith = longHash(`${spec.kerberos.krbtgtHash}|${principal}|${domain}`, 4);
        return encodeTicket({
            ticketId: `tgt-${longHash(`${principal}|${domain}|${lifetimeMs}`, 2).slice(0, 16)}`,
            type: 'TGT',
            principal,
            realm: toRealm(domain),
            issuedAt,
            expiresAt,
            encType: 'AES256-CTS-HMAC-SHA1',
            encryptedWith,
        });
    }

    function makeServiceTicket(principal: string, spn: string, encType: string): string {
        const issuedAt = deterministicIssuedAt(`${principal}|${spn}|${domain}|tgs`);
        const expiresAt = issuedAt + DEFAULT_TGS_LIFETIME_MS;
        return encodeTicket({
            ticketId: `tgs-${longHash(`${principal}|${spn}|${domain}`, 2).slice(0, 16)}`,
            type: 'TGS',
            principal,
            realm: toRealm(domain),
            service: spn,
            issuedAt,
            expiresAt,
            encType,
            encryptedWith: longHash(`${spn}|${encType}|${domain}`, 4),
        });
    }

    function validatePresentedTGT(rawTgt: string): { ok: true; ticket: TicketPayload } | { ok: false; reason: string } {
        try {
            const decoded = fromBase64(rawTgt);
            if (decoded.includes(spec.kerberos.krbtgtHash)) {
                emitDefenseAlert(
                    'golden-ticket-detected',
                    'critical',
                    'Presented TGT contains KRBTGT hash material (tag: golden-ticket-detected).',
                );
            }
        } catch {
            // Ignore decode errors here and continue normal validation.
        }

        const parsed = decodeTicket(rawTgt);
        if (parsed === null) return { ok: false, reason: 'invalid-tgt' };
        if (parsed.type !== 'TGT') return { ok: false, reason: 'not-tgt' };
        if (parsed.realm !== toRealm(domain)) return { ok: false, reason: 'realm-mismatch' };
        evaluateTicketAnomalies(rawTgt, parsed);
        return { ok: true, ticket: parsed };
    }

    function handleAsReq(request: ExternalRequest): ExternalResponse {
        const body = getRequestJson(request);
        const username = asString(body['username']) ?? '';
        const password = asString(body['password']) ?? '';
        const requestedLifetimeSeconds = asNumber(body['lifetimeSeconds']);
        const lifetimeMs = requestedLifetimeSeconds !== null && requestedLifetimeSeconds > 0
            ? requestedLifetimeSeconds * 1000
            : DEFAULT_TGT_LIFETIME_MS;

        if (username === '' || password === '') {
            return jsonResponse(400, { error: 'missing-credentials' });
        }

        const user = findUser(spec.users, username);
        if (user === null || !user.enabled) {
            return jsonResponse(401, { error: 'invalid-credentials' });
        }

        const expectedPassword = resolveExpectedPassword(user);
        if (expectedPassword === null || expectedPassword !== password) {
            return jsonResponse(401, { error: 'invalid-credentials' });
        }

        const tgt = makeTgt(user.samAccountName, lifetimeMs);
        const ticket = decodeTicket(tgt);
        if (ticket !== null) {
            evaluateTicketAnomalies(tgt, ticket);
        }
        return jsonResponse(200, {
            ticketType: 'TGT',
            principal: user.samAccountName,
            realm: toRealm(domain),
            tgt,
            expiresAt: ticket?.expiresAt ?? null,
        });
    }

    function getServiceAccountForSpn(spn: string): ServiceAccountWithWeakPassword | null {
        const match = resolveSpnRecord(parsedSpns, spn);
        if (match === null) return null;

        if (match.accountSam !== null) {
            for (const account of spec.serviceAccounts) {
                if (normalizeSam(account.samAccountName) === normalizeSam(match.accountSam)) {
                    return account as ServiceAccountWithWeakPassword;
                }
            }
        }

        for (const account of spec.serviceAccounts) {
            if (account.dn.toLowerCase() === match.accountDn.toLowerCase()) {
                return account as ServiceAccountWithWeakPassword;
            }
        }
        return null;
    }

    function handleTgsReq(request: ExternalRequest): ExternalResponse {
        const body = getRequestJson(request);
        const tgt = asString(body['tgt']) ?? '';
        const spn = asString(body['spn']) ?? '';

        if (tgt === '' || spn === '') {
            return jsonResponse(400, { error: 'missing-parameters' });
        }

        const validation = validatePresentedTGT(tgt);
        if (!validation.ok) return jsonResponse(401, { error: validation.reason });

        const spnRecord = resolveSpnRecord(parsedSpns, spn);
        if (spnRecord === null) return jsonResponse(404, { error: 'spn-not-found' });

        const serviceAccount = getServiceAccountForSpn(spn);
        const weakPassword = serviceAccount?.weakPassword === true;
        const encType = weakPassword ? 'RC4-HMAC' : 'AES256-CTS-HMAC-SHA1';
        const serviceTicket = makeServiceTicket(validation.ticket.principal, spn, encType);

        return jsonResponse(200, {
            ticketType: 'TGS',
            service: spn,
            principal: validation.ticket.principal,
            encType,
            kerberoastable: weakPassword,
            ticket: serviceTicket,
        });
    }

    function isDelegationAllowed(
        rules: readonly DelegationRuleSpec[],
        sourceSpn: ParsedSPN | null,
        delegatingService: string,
        targetSpn: string,
        protocolTransitionPrincipal: string,
        impersonateUser: string,
    ): { allowed: boolean; matchedType: string | null } {
        for (const rawRule of rules) {
            const rule = rawRule as DelegationRuleWithAllowedServices;
            if (!isDelegationSourceMatch(rule.sourceDn, delegatingService, sourceSpn?.accountSam ?? null)) continue;

            if (rule.protocolTransition === false && normalizeSam(protocolTransitionPrincipal) !== normalizeSam(impersonateUser)) {
                continue;
            }

            if (rule.type === 'unconstrained') {
                return { allowed: true, matchedType: 'unconstrained' };
            }

            const allowed = new Set<string>();
            for (const t of rule.targetSpns) allowed.add(t.toLowerCase());
            if (rule.allowedServices !== undefined) {
                for (const t of rule.allowedServices) allowed.add(t.toLowerCase());
            }

            if (allowed.has(targetSpn.toLowerCase())) {
                return { allowed: true, matchedType: rule.type };
            }
        }
        return { allowed: false, matchedType: null };
    }

    function handleS4U(request: ExternalRequest): ExternalResponse {
        const body = getRequestJson(request);
        const tgt = asString(body['tgt']) ?? '';
        const delegatingService = asString(body['delegatingService']) ?? '';
        const impersonateUser = asString(body['impersonateUser']) ?? '';
        const targetSpn = asString(body['targetSpn']) ?? '';

        if (tgt === '' || delegatingService === '' || impersonateUser === '' || targetSpn === '') {
            return jsonResponse(400, { error: 'missing-parameters' });
        }

        const validation = validatePresentedTGT(tgt);
        if (!validation.ok) return jsonResponse(401, { error: validation.reason });

        const sourceSpn = resolveSpnRecord(parsedSpns, delegatingService);
        const targetRecord = resolveSpnRecord(parsedSpns, targetSpn);
        if (targetRecord === null) {
            return jsonResponse(404, { error: 'target-spn-not-found' });
        }

        const delegation = isDelegationAllowed(
            spec.kerberos.delegationRules,
            sourceSpn,
            delegatingService,
            targetSpn,
            validation.ticket.principal,
            impersonateUser,
        );
        if (!delegation.allowed) {
            return jsonResponse(403, { error: 'delegation-not-allowed' });
        }

        const user = findUser(spec.users, impersonateUser);
        if (user === null || !user.enabled) {
            return jsonResponse(404, { error: 'impersonate-user-not-found' });
        }

        const ticket = makeServiceTicket(user.samAccountName, targetSpn, 'AES256-CTS-HMAC-SHA1');
        return jsonResponse(200, {
            ticketType: 'TGS',
            principal: user.samAccountName,
            service: targetSpn,
            delegationType: delegation.matchedType,
            ticket,
        });
    }

    return {
        id: MODULE_ID,
        type: 'engine',
        version: MODULE_VERSION,
        description: 'Active Directory / Kerberos simulation module with LDAP, ticket operations, GPO, and SPN endpoints',
        provides: [
            { name: 'active-directory' },
            { name: 'kerberos' },
            { name: 'ldap' },
        ] as readonly Capability[],
        requires: [{ name: 'variant-internet' }] as readonly Capability[],
        init(context: SimulationContext): void {
            context.fabric.addDNSRecord({ domain: ldapDomain, ip: '172.16.2.10', type: 'A', ttl: 3600 });
            context.fabric.addDNSRecord({ domain: kerberosDomain, ip: '172.16.2.11', type: 'A', ttl: 3600 });
            context.fabric.addDNSRecord({ domain: gpoDomain, ip: '172.16.2.12', type: 'A', ttl: 3600 });

            context.fabric.registerExternal(ldapHandler);
            context.fabric.registerExternal(kerberosHandler);
            context.fabric.registerExternal(gpoHandler);

            eventBus.emit({
                type: 'sim:alert',
                source: MODULE_ID,
                message: `AD module activated for ${domain}: ${spec.users.length} users, ${spec.groups.length} groups, ${spec.groupPolicies.length} GPOs`,
                timestamp: Date.now(),
            });
        },
        destroy(): void {
            // Handlers are owned by fabric.
        },
    };
}

export type { TicketPayload, ParsedSPN };
