/**
 * VARIANT — VARIANT Internet Module
 *
 * Simulates external internet services within the air-gapped
 * simulation. These services exist as DNS records + HTTP handlers
 * in the fabric, not as real VMs.
 *
 * Service types:
 *   - search:             Simulated search engine with configurable results
 *   - cloud-metadata:     AWS-style metadata endpoint (169.254.169.254)
 *   - package-repo:       APK/apt package mirror
 *   - c2:                 Command & control server
 *   - website:            Static HTML website
 *   - api:                REST API with configurable routes
 *   - git:                Git repository browser (clone via HTTP)
 *   - social-media:       Social media profiles for OSINT
 *   - paste-site:         Pastebin-style content (leaked creds, configs)
 *   - forum:              Forum/discussion board
 *   - whois:              Domain WHOIS lookup
 *   - cert-transparency:  Certificate transparency log search
 *   - dns-lookup:         DNS record lookup service
 *
 * Each service registers:
 *   1. DNS records in the fabric
 *   2. An external service handler for HTTP traffic
 *
 * SECURITY: Services return static or procedurally-generated
 * content. They cannot execute code, access the host, or
 * reach the real internet. All content is defined in the WorldSpec.
 *
 * MODULARITY: Swappable module. Adds DNS + service handlers
 * to the fabric. Removable without affecting core.
 */

import type { Module, SimulationContext, Capability } from '../core/modules';
import type { ExternalRequest, ExternalResponse, ExternalServiceHandler } from '../core/fabric/types';
import type {
    VariantInternetSpec,
    VariantInternetService,
    GitRepoSpec,
    SocialProfileSpec,
    PasteSiteSpec,
} from '../core/world/types';

// ── Module ID ──────────────────────────────────────────────────

const MODULE_ID = 'variant-internet';
const MODULE_VERSION = '2.0.0';

// ── IP allocation ──────────────────────────────────────────────

/** VARIANT Internet services use 172.16.0.0/12 (private range). */
const VNET_BASE_IP = '172.16.0';
let nextServiceOctet = 10;

function allocateServiceIP(): string {
    const ip = `${VNET_BASE_IP}.${nextServiceOctet}`;
    nextServiceOctet++;
    return ip;
}

// ── Response helpers ───────────────────────────────────────────

const encoder = new TextEncoder();

function makeResponse(status: number, contentType: string, body: string): ExternalResponse {
    const headers = new Map<string, string>();
    headers.set('content-type', contentType);
    headers.set('server', 'VARIANT-Internet/2.0');
    return { status, headers, body: encoder.encode(body) };
}

function makeJsonResponse(status: number, data: unknown): ExternalResponse {
    return makeResponse(status, 'application/json', JSON.stringify(data, null, 2));
}

function make404(): ExternalResponse {
    return makeResponse(404, 'text/plain', 'Not Found');
}

// ── HTML templates ──────────────────────────────────────────────

function htmlPage(title: string, bodyHtml: string, css?: string, headHtml?: string): string {
    return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>${escapeHtml(title)}</title>
${headHtml ?? ''}
<style>body{font-family:monospace;background:#0d1117;color:#c9d1d9;margin:2em;line-height:1.6}
a{color:#58a6ff}a:hover{text-decoration:underline}h1,h2,h3{color:#f0f6fc}
pre{background:#161b22;padding:1em;border-radius:6px;overflow-x:auto;border:1px solid #30363d}
code{background:#161b22;padding:2px 6px;border-radius:3px;font-size:0.9em}
.result{margin:1em 0;padding:0.5em 0;border-bottom:1px solid #21262d}
.result-title{font-size:1.1em}.result-url{color:#8b949e;font-size:0.85em}
.result-snippet{color:#8b949e;margin-top:0.3em}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #30363d;padding:8px;text-align:left}
th{background:#161b22}.post{border:1px solid #30363d;padding:1em;margin:1em 0;border-radius:6px}
.meta{color:#8b949e;font-size:0.85em}${css ?? ''}</style></head>
<body>${bodyHtml}</body></html>`;
}

function escapeHtml(s: string): string {
    return s
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function stripQuery(path: string): string {
    const qIdx = path.indexOf('?');
    return qIdx === -1 ? path : path.slice(0, qIdx);
}

function parseJsonSafely(input: string): unknown | null {
    try {
        return JSON.parse(input) as unknown;
    } catch {
        return null;
    }
}

function applyCors(headers: Map<string, string>): void {
    headers.set('access-control-allow-origin', '*');
    headers.set('access-control-allow-methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
    headers.set('access-control-allow-headers', 'authorization,content-type,x-requested-with');
    headers.set('access-control-max-age', '300');
}

function parseRequestBody(request: ExternalRequest): {
    raw: string;
    contentType: string;
    parsed: unknown;
    kind: 'json' | 'form' | 'text' | 'none';
} {
    if (request.body === null) {
        return { raw: '', contentType: '', parsed: null, kind: 'none' };
    }
    const raw = new TextDecoder().decode(request.body);
    const contentType = (request.headers.get('content-type') ?? '').toLowerCase();
    if (contentType.includes('application/json')) {
        const parsed = parseJsonSafely(raw);
        return { raw, contentType, parsed, kind: 'json' };
    }
    if (contentType.includes('application/x-www-form-urlencoded')) {
        const parsed: Record<string, string> = {};
        for (const part of raw.split('&')) {
            const [k, ...v] = part.split('=');
            const key = k ?? '';
            if (key === '') continue;
            parsed[decodeURIComponent(key.replace(/\+/g, ' '))] = decodeURIComponent(v.join('=').replace(/\+/g, ' '));
        }
        return { raw, contentType, parsed, kind: 'form' };
    }
    return { raw, contentType, parsed: raw, kind: 'text' };
}

function wildcardToRegExp(query: string): RegExp {
    const escaped = query.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`^${escaped.replace(/\*/g, '.*')}$`, 'i');
}

// ── Service handler factory ────────────────────────────────────

function createServiceHandler(
    service: VariantInternetService,
    spec: VariantInternetSpec,
): ExternalServiceHandler {
    const staticContent = service.staticContent ?? {};
    const apiRateCounts = new Map<string, number>();

    return {
        domain: service.domain,
        description: `VARIANT Internet: ${service.type} service at ${service.domain}`,

        handleRequest(request: ExternalRequest): ExternalResponse {
            // Check static content first (level designer overrides)
            const staticResponse = staticContent[request.path];
            if (staticResponse !== undefined) {
                return makeResponse(200, 'text/html', staticResponse);
            }

            // Dispatch by service type
            switch (service.type) {
                case 'cloud-metadata':
                    return handleCloudMetadata(request);
                case 'search':
                    return handleSearch(request, service);
                case 'api':
                    return handleApi(request, service, apiRateCounts);
                case 'git':
                    return handleGitRepo(request, spec);
                case 'social-media':
                    return handleSocialMedia(request, spec);
                case 'paste-site':
                    return handlePasteSite(request, spec);
                case 'whois':
                    return handleWhois(request, spec);
                case 'cert-transparency':
                    return handleCertTransparency(request, spec);
                case 'dns-lookup':
                    return handleDnsLookup(request, spec);
                case 'forum':
                    return handleForum(request, service);
                case 'website':
                    return handleWebsite(request, service);
                case 'c2':
                    return handleC2(request, service);
                default:
                    return make404();
            }
        },
    };
}

// ── Factory ────────────────────────────────────────────────────

export function createVariantInternet(): Module {
    const module: Module = {
        id: MODULE_ID,
        type: 'engine',
        version: MODULE_VERSION,
        description: 'Simulates external internet services (search, git repos, social media, paste sites, WHOIS, cert transparency, and more)',

        provides: [{ name: 'variant-internet' }] as readonly Capability[],
        requires: [] as readonly Capability[],

        init(context: SimulationContext): void {
            nextServiceOctet = 10;

            const spec: VariantInternetSpec | undefined = context.world.variantInternet;
            if (spec === undefined) return;

            // Register DNS records from spec
            for (const dnsRecord of spec.dnsRecords) {
                context.fabric.addDNSRecord({
                    domain: dnsRecord.domain,
                    ip: dnsRecord.ip,
                    type: dnsRecord.type === 'MX' ? 'MX' : dnsRecord.type === 'TXT' ? 'TXT' : 'A',
                    ttl: 3600,
                });
            }

            // Register services
            for (const service of spec.services) {
                const ip = allocateServiceIP();
                const handler = createServiceHandler(service, spec);

                context.fabric.addDNSRecord({
                    domain: service.domain,
                    ip,
                    type: 'A',
                    ttl: 3600,
                });

                context.fabric.registerExternal(handler);
            }

            // Auto-register DNS for git repo domains
            if (spec.gitRepos !== undefined) {
                const gitDomains = new Set<string>();
                for (const repo of spec.gitRepos) {
                    if (!gitDomains.has(repo.domain)) {
                        gitDomains.add(repo.domain);
                        const ip = allocateServiceIP();
                        context.fabric.addDNSRecord({
                            domain: repo.domain,
                            ip,
                            type: 'A',
                            ttl: 3600,
                        });
                        context.fabric.registerExternal(
                            createGitDomainHandler(repo.domain, spec),
                        );
                    }
                }
            }

            // Auto-register DNS for social media domains
            if (spec.socialProfiles !== undefined) {
                const socialDomains = new Set<string>();
                for (const profile of spec.socialProfiles) {
                    if (!socialDomains.has(profile.domain)) {
                        socialDomains.add(profile.domain);
                        const ip = allocateServiceIP();
                        context.fabric.addDNSRecord({
                            domain: profile.domain,
                            ip,
                            type: 'A',
                            ttl: 3600,
                        });
                        context.fabric.registerExternal(
                            createSocialDomainHandler(profile.domain, spec),
                        );
                    }
                }
            }

            // Auto-register DNS for paste site domains
            if (spec.pasteSites !== undefined) {
                for (const site of spec.pasteSites) {
                    const ip = allocateServiceIP();
                    context.fabric.addDNSRecord({
                        domain: site.domain,
                        ip,
                        type: 'A',
                        ttl: 3600,
                    });
                    context.fabric.registerExternal(
                        createPasteSiteDomainHandler(site.domain, spec),
                    );
                }
            }

            // Log activation
            const serviceCount = spec.services.length;
            const repoCount = spec.gitRepos?.length ?? 0;
            const profileCount = spec.socialProfiles?.length ?? 0;
            const pasteCount = spec.pasteSites?.length ?? 0;

            context.events.emit({
                type: 'sim:alert',
                source: MODULE_ID,
                message: `VARIANT Internet activated: ${serviceCount} services, ${repoCount} repos, ${profileCount} profiles, ${pasteCount} paste sites`,
                timestamp: Date.now(),
            });
        },

        destroy(): void {
            // DNS records and service handlers are owned by the fabric
        },
    };

    return module;
}

// ── Built-in service handlers ──────────────────────────────────

// ── Cloud Metadata (AWS EC2 style) ─────────────────────────────

function handleCloudMetadata(request: ExternalRequest): ExternalResponse {
    const metadataTree: Record<string, string> = {
        '/latest/meta-data/': 'ami-id\nami-launch-index\nami-manifest-path\nhostname\ninstance-id\ninstance-type\nlocal-ipv4\npublic-ipv4\npublic-hostname\nplacement/\niam/\nsecurity-groups\nnetwork/',
        '/latest/meta-data/instance-id': 'i-0abc123def456789',
        '/latest/meta-data/instance-type': 'm5.large',
        '/latest/meta-data/ami-id': 'ami-0123456789abcdef0',
        '/latest/meta-data/hostname': 'ip-10-0-1-42.internal',
        '/latest/meta-data/local-ipv4': '10.0.1.42',
        '/latest/meta-data/public-ipv4': '203.0.113.42',
        '/latest/meta-data/public-hostname': 'ec2-203-0-113-42.compute-1.amazonaws.com',
        '/latest/meta-data/placement/': 'availability-zone\nregion',
        '/latest/meta-data/placement/availability-zone': 'us-east-1a',
        '/latest/meta-data/placement/region': 'us-east-1',
        '/latest/meta-data/security-groups': 'default\nweb-servers\nadmin-access',
        '/latest/meta-data/network/': 'interfaces/',
        '/latest/meta-data/network/interfaces/': 'macs/',
        '/latest/meta-data/network/interfaces/macs/': '0a:1b:2c:3d:4e:5f/',
        '/latest/meta-data/network/interfaces/macs/0a:1b:2c:3d:4e:5f/': 'vpc-id\nsubnet-id\nsecurity-group-ids',
        '/latest/meta-data/network/interfaces/macs/0a:1b:2c:3d:4e:5f/vpc-id': 'vpc-0abc123',
        '/latest/meta-data/network/interfaces/macs/0a:1b:2c:3d:4e:5f/subnet-id': 'subnet-0def456',
        '/latest/meta-data/network/interfaces/macs/0a:1b:2c:3d:4e:5f/security-group-ids': 'sg-0abc123',
        '/latest/meta-data/iam/': 'info\nsecurity-credentials/',
        '/latest/meta-data/iam/info': JSON.stringify({
            Code: 'Success',
            InstanceProfileArn: 'arn:aws:iam::123456789012:instance-profile/admin-role',
            InstanceProfileId: 'AIPA0ABC123DEF456',
        }, null, 2),
        '/latest/meta-data/iam/security-credentials/': 'admin-role',
        '/latest/meta-data/iam/security-credentials/admin-role': JSON.stringify({
            Code: 'Success',
            Type: 'AWS-HMAC',
            AccessKeyId: 'AKIAIOSFODNN7EXAMPLE',
            SecretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            Token: 'AQoDYXdzEJr...',
            Expiration: '2024-12-31T23:59:59Z',
        }, null, 2),
        '/latest/user-data': '#!/bin/bash\n# User data script\nDB_PASSWORD="s3cret_db_p4ss"\nexport AWS_DEFAULT_REGION=us-east-1\napt-get update && apt-get install -y nginx\necho "Instance initialized"',
        '/latest/dynamic/instance-identity/document': JSON.stringify({
            accountId: '123456789012',
            architecture: 'x86_64',
            availabilityZone: 'us-east-1a',
            imageId: 'ami-0123456789abcdef0',
            instanceId: 'i-0abc123def456789',
            instanceType: 'm5.large',
            privateIp: '10.0.1.42',
            region: 'us-east-1',
        }, null, 2),
    };

    // IMDSv2 token endpoint
    if (request.path === '/latest/api/token' && request.method === 'PUT') {
        return makeResponse(200, 'text/plain', 'AQAAANjUxNjk3NTQ3OA==');
    }

    const response = metadataTree[request.path];
    if (response !== undefined) {
        return makeResponse(200, 'text/plain', response);
    }

    return make404();
}

// ── Search Engine ──────────────────────────────────────────────

function handleSearch(request: ExternalRequest, service: VariantInternetService): ExternalResponse {
    const config = service.searchConfig;
    const engineName = config?.engineName ?? 'VARIANT Search';

    // Root page
    if (request.path === '/' || request.path === '') {
        return makeResponse(200, 'text/html', htmlPage(engineName,
            `<h1>${escapeHtml(engineName)}</h1>
            <form method="GET" action="/search">
                <input type="text" name="q" placeholder="Search..." style="padding:8px;width:400px;background:#161b22;color:#c9d1d9;border:1px solid #30363d;border-radius:4px">
                <button type="submit" style="padding:8px 16px;background:#238636;color:#fff;border:none;border-radius:4px;cursor:pointer">Search</button>
            </form>`,
        ));
    }

    // Search results
    if (request.path === '/search' || request.path.startsWith('/search?')) {
        const query = extractQueryParam(request.path, 'q');
        if (query === null || query === '') {
            return makeResponse(200, 'text/html', htmlPage(engineName,
                `<h1>${escapeHtml(engineName)}</h1><p>Enter a search query.</p>`));
        }

        const searchOperators = parseSearchOperators(query);
        const normalizedQuery = searchOperators.baseQuery;

        // Look up results (case-insensitive)
        const queryLower = normalizedQuery.toLowerCase();
        let results = normalizedQuery === ''
            ? undefined
            : (config?.results?.[queryLower] ?? config?.results?.[normalizedQuery]);

        // Try partial match if exact match fails
        if (results === undefined && config?.results !== undefined) {
            for (const [key, val] of Object.entries(config.results)) {
                if (key.toLowerCase().includes(queryLower) || queryLower.includes(key.toLowerCase())) {
                    results = val;
                    break;
                }
            }
        }

        // Fall back to default results
        if (results === undefined) {
            results = config?.defaultResults ?? [];
        }

        results = applySearchOperators(results, searchOperators);

        if (results.length === 0) {
            return makeResponse(200, 'text/html', htmlPage(
                `${query} - ${engineName}`,
                `<h1>${escapeHtml(engineName)}</h1>
                <p>No results found for <strong>${escapeHtml(query)}</strong></p>`,
            ));
        }

        const resultCountLabel = `${results.length.toLocaleString()} results`;
        const resultsHtml = results.map((r, idx) => renderGoogleLikeSearchResult(r, idx)).join('\n');
        const operatorSummary = [
            searchOperators.site !== null ? `site:${searchOperators.site}` : null,
            searchOperators.filetype !== null ? `filetype:${searchOperators.filetype}` : null,
        ].filter(Boolean).join(' ');

        const searchPageCss = `
.g-shell{max-width:900px;margin:0 auto}
.g-brand{font:600 30px/1.2 Arial,sans-serif;color:#4285f4;margin:0 0 16px}
.g-searchbar{display:flex;gap:8px;margin:12px 0 20px}
.g-input{flex:1;padding:10px 14px;border-radius:24px;border:1px solid #30363d;background:#0d1117;color:#e6edf3}
.g-btn{padding:10px 16px;border:1px solid #30363d;border-radius:4px;background:#21262d;color:#e6edf3;cursor:pointer}
.g-meta{color:#8b949e;font:13px Arial,sans-serif;margin-bottom:18px}
.g-result{margin:0 0 22px}
.g-url{color:#8ab4f8;font:14px Arial,sans-serif}
.g-title a{font:20px Arial,sans-serif;color:#8ab4f8;text-decoration:none}
.g-title a:hover{text-decoration:underline}
.g-snippet{font:14px Arial,sans-serif;color:#bdc1c6}
.g-date{color:#9aa0a6}
.g-cached{margin-left:8px;font-size:12px}
`;

        return makeResponse(200, 'text/html', htmlPage(
            `${query} - ${engineName}`,
            `<div class="g-shell">
                <h1 class="g-brand">${escapeHtml(engineName)}</h1>
                <form method="GET" action="/search" class="g-searchbar">
                    <input class="g-input" type="text" name="q" value="${escapeHtml(query)}" autocomplete="off">
                    <button class="g-btn" type="submit">Search</button>
                </form>
                <div class="g-meta">${escapeHtml(resultCountLabel)} ${operatorSummary !== '' ? `for filters ${escapeHtml(operatorSummary)}` : ''}</div>
                ${resultsHtml}
            </div>`,
            searchPageCss,
        ));
    }

    return make404();
}

function parseSearchOperators(query: string): { baseQuery: string; site: string | null; filetype: string | null } {
    let site: string | null = null;
    let filetype: string | null = null;
    const tokens = query.split(/\s+/).filter(Boolean);
    const baseTokens: string[] = [];
    for (const token of tokens) {
        const siteMatch = token.match(/^site:(.+)$/i);
        if (siteMatch !== null) {
            site = siteMatch[1]?.toLowerCase() ?? null;
            continue;
        }
        const filetypeMatch = token.match(/^filetype:(.+)$/i);
        if (filetypeMatch !== null) {
            filetype = filetypeMatch[1]?.toLowerCase() ?? null;
            continue;
        }
        baseTokens.push(token);
    }
    return { baseQuery: baseTokens.join(' ').trim(), site, filetype };
}

function applySearchOperators(
    results: readonly { title: string; url: string; snippet: string }[],
    operators: { site: string | null; filetype: string | null },
): { title: string; url: string; snippet: string }[] {
    return results.filter(result => {
        if (operators.site !== null) {
            const host = extractHost(result.url);
            if (host === null || (host !== operators.site && !host.endsWith(`.${operators.site}`))) {
                return false;
            }
        }
        if (operators.filetype !== null) {
            const normalizedType = operators.filetype.replace(/^\./, '');
            const urlPath = stripQuery(result.url).toLowerCase();
            if (!urlPath.endsWith(`.${normalizedType}`)) {
                return false;
            }
        }
        return true;
    });
}

function renderGoogleLikeSearchResult(
    result: { title: string; url: string; snippet: string },
    index: number,
): string {
    const timestamp = new Date(Date.now() - (index + 2) * 86400000 * 11).toISOString().slice(0, 10);
    const cachedPath = `/cache?url=${encodeURIComponent(result.url)}`;
    return `<div class="g-result">
        <div class="g-url">${escapeHtml(result.url)}</div>
        <div class="g-title"><a href="${escapeHtml(result.url)}">${escapeHtml(result.title)}</a></div>
        <div class="g-snippet"><span class="g-date">${escapeHtml(timestamp)} - </span>${escapeHtml(result.snippet)} <a class="g-cached" href="${escapeHtml(cachedPath)}">Cached</a></div>
    </div>`;
}

function extractHost(url: string): string | null {
    const match = url.match(/^[a-z]+:\/\/([^/?#]+)/i);
    if (match?.[1] !== undefined) return match[1].toLowerCase();
    return null;
}

// ── API Service ────────────────────────────────────────────────

function handleApi(
    request: ExternalRequest,
    service: VariantInternetService,
    rateCounts: Map<string, number>,
): ExternalResponse {
    const config = service.apiConfig;
    if (config === undefined) return make404();

    const requestPath = stripQuery(request.path);
    if (request.method === 'OPTIONS') {
        const headers = new Map<string, string>();
        headers.set('content-type', 'application/json');
        headers.set('server', 'VARIANT-Internet/2.0');
        applyCors(headers);
        return { status: 204, headers, body: encoder.encode('') };
    }

    const clientKey = request.headers.get('x-forwarded-for') ?? 'global';
    const currentCount = (rateCounts.get(clientKey) ?? 0) + 1;
    rateCounts.set(clientKey, currentCount);
    if (currentCount > 12) {
        const headers = new Map<string, string>();
        headers.set('content-type', 'application/json');
        headers.set('server', 'VARIANT-Internet/2.0');
        headers.set('retry-after', '60');
        applyCors(headers);
        return {
            status: 429,
            headers,
            body: encoder.encode(JSON.stringify({
                error: 'Too Many Requests',
                retryAfterSeconds: 60,
                limit: 12,
                observed: currentCount,
            }, null, 2)),
        };
    }

    // Check auth if required
    if (config.requiresAuth === true) {
        const authHeader = request.headers.get('authorization');
        if (authHeader === undefined || authHeader === null) {
            const headers = new Map<string, string>();
            headers.set('content-type', 'text/plain');
            headers.set('server', 'VARIANT-Internet/2.0');
            applyCors(headers);
            return { status: 401, headers, body: encoder.encode('Unauthorized') };
        }
        if (config.authToken !== undefined && authHeader !== `Bearer ${config.authToken}`) {
            const headers = new Map<string, string>();
            headers.set('content-type', 'text/plain');
            headers.set('server', 'VARIANT-Internet/2.0');
            applyCors(headers);
            return { status: 403, headers, body: encoder.encode('Forbidden') };
        }
    }

    const bodyInfo = parseRequestBody(request);
    const versionlessPath = requestPath.replace(/^\/v[0-9]+(?=\/)/i, '');
    const candidatePaths = Array.from(new Set([request.path, requestPath, versionlessPath]));

    // Match route: "METHOD /path"
    let route: typeof config.routes[string] | undefined;
    for (const candidate of candidatePaths) {
        route = config.routes[`${request.method} ${candidate}`];
        if (route !== undefined) break;
    }

    if (route !== undefined) {
        const headers = new Map<string, string>();
        headers.set('content-type', route.contentType);
        headers.set('server', 'VARIANT-Internet/2.0');
        applyCors(headers);
        if (route.headers !== undefined) {
            for (const [k, v] of Object.entries(route.headers)) {
                headers.set(k, v);
            }
        }
        let responseBody = route.body;
        if (bodyInfo.kind !== 'none') {
            responseBody = responseBody
                .replace(/\{\{request\.body\}\}/g, JSON.stringify(bodyInfo.parsed))
                .replace(/\{\{request\.raw\}\}/g, bodyInfo.raw);
        }
        return { status: route.status, headers, body: encoder.encode(responseBody) };
    }

    // Try without method (fallback)
    let anyRoute: typeof config.routes[string] | undefined;
    for (const candidate of candidatePaths) {
        anyRoute = config.routes[`GET ${candidate}`] ?? config.routes[`* ${candidate}`];
        if (anyRoute !== undefined) break;
    }
    if (anyRoute !== undefined) {
        const headers = new Map<string, string>();
        headers.set('content-type', anyRoute.contentType);
        headers.set('server', 'VARIANT-Internet/2.0');
        applyCors(headers);
        return { status: anyRoute.status, headers, body: encoder.encode(anyRoute.body) };
    }

    const headers = new Map<string, string>();
    headers.set('content-type', 'application/json');
    headers.set('server', 'VARIANT-Internet/2.0');
    applyCors(headers);
    return {
        status: 404,
        headers,
        body: encoder.encode(JSON.stringify({
            error: 'Not Found',
            path: request.path,
            parsedBody: bodyInfo.kind === 'none' ? null : bodyInfo.parsed,
        }, null, 2)),
    };
}

// ── Git Repository Browser ─────────────────────────────────────

function createGitDomainHandler(domain: string, spec: VariantInternetSpec): ExternalServiceHandler {
    return {
        domain,
        description: `VARIANT Internet: git service at ${domain}`,
        handleRequest(request: ExternalRequest): ExternalResponse {
            return handleGitRepo(request, spec);
        },
    };
}

function handleGitRepo(request: ExternalRequest, spec: VariantInternetSpec): ExternalResponse {
    const repos = spec.gitRepos ?? [];
    if (repos.length === 0) return make404();

    // Repository index page
    if (request.path === '/' || request.path === '') {
        const repoListHtml = repos.map(r =>
            `<div class="result">
                <div class="result-title"><a href="${escapeHtml(r.path)}">${escapeHtml(r.name)}</a></div>
                <div class="result-snippet">${escapeHtml(r.description ?? 'No description')}</div>
            </div>`,
        ).join('\n');

        return makeResponse(200, 'text/html', htmlPage('Repositories',
            `<h1>Repositories</h1>${repoListHtml}`));
    }

    // Find matching repo
    const repo = findRepo(repos, request.path);
    if (repo === null) return make404();

    // Git info/refs (for git clone over HTTP)
    if (request.path.endsWith('/info/refs')) {
        return handleGitInfoRefs(repo);
    }

    // File browser
    const relativePath = request.path.replace(repo.path, '').replace(/^\//, '');

    if (relativePath === '' || relativePath === '/') {
        return renderRepoIndex(repo);
    }

    if (relativePath === '.git/config') {
        return makeResponse(200, 'text/plain', renderLeakedGitConfig(repo));
    }

    if (relativePath === 'branches') {
        return renderRepoBranches(repo);
    }

    if (relativePath === 'tags') {
        return renderRepoTags(repo);
    }

    if (relativePath.startsWith('blame/')) {
        const blamePath = relativePath.slice('blame/'.length);
        return renderRepoBlame(repo, blamePath);
    }

    // Browse file tree
    if (relativePath.startsWith('tree/') || relativePath.startsWith('blob/')) {
        const filePath = relativePath.replace(/^(tree|blob)\/[^/]+\//, '');
        return renderRepoFile(repo, filePath);
    }

    // Raw file access
    if (relativePath.startsWith('raw/')) {
        const filePath = relativePath.replace(/^raw\/[^/]+\//, '');
        const file = repo.files[filePath];
        if (file !== undefined) {
            return makeResponse(200, 'text/plain', file.content);
        }
        return make404();
    }

    // Commit log
    if (relativePath === 'commits' || relativePath === 'log') {
        return renderCommitLog(repo);
    }
    if (relativePath.startsWith('commits/')) {
        return renderCommitDetail(repo, relativePath.slice('commits/'.length));
    }

    // Direct file path (for simple access)
    const file = repo.files[relativePath];
    if (file !== undefined) {
        return makeResponse(200, 'text/plain', file.content);
    }

    return make404();
}

function findRepo(repos: readonly GitRepoSpec[], path: string): GitRepoSpec | null {
    for (const repo of repos) {
        if (path === repo.path || path.startsWith(repo.path + '/') || path.startsWith(repo.path.replace('.git', '') + '/')) {
            return repo;
        }
    }
    return null;
}

function handleGitInfoRefs(repo: GitRepoSpec): ExternalResponse {
    const branch = repo.branches?.[0] ?? 'main';
    const hash = repo.commits?.[0]?.hash ?? '0'.repeat(40);
    const body = `${hash}\trefs/heads/${branch}\n`;
    return makeResponse(200, 'application/x-git-upload-pack-advertisement', body);
}

function renderRepoIndex(repo: GitRepoSpec): ExternalResponse {
    const branch = repo.branches?.[0] ?? 'main';
    const fileList = Object.keys(repo.files).sort();

    const filesHtml = fileList.map(f => {
        const isDir = fileList.some(other => other.startsWith(f + '/'));
        const icon = isDir ? '📁' : '📄';
        return `<tr><td>${icon} <a href="${escapeHtml(repo.path)}/blob/${escapeHtml(branch)}/${escapeHtml(f)}">${escapeHtml(f)}</a></td></tr>`;
    }).join('\n');

    const commitsHtml = (repo.commits ?? []).slice(0, 5).map(c =>
        `<div class="meta">${escapeHtml(c.hash.slice(0, 7))} — ${escapeHtml(c.message)} (${escapeHtml(c.author)})</div>`,
    ).join('\n');

    return makeResponse(200, 'text/html', htmlPage(repo.name,
        `<h1>${escapeHtml(repo.name)}</h1>
        <p>${escapeHtml(repo.description ?? '')}</p>
        <p class="meta">Branch: ${escapeHtml(branch)} | ${fileList.length} files</p>
        <h2>Recent commits</h2>${commitsHtml || '<p class="meta">No commits</p>'}
        <h2>Files</h2><table>${filesHtml}</table>`));
}

function renderRepoFile(repo: GitRepoSpec, filePath: string): ExternalResponse {
    const file = repo.files[filePath];
    if (file === undefined) return make404();

    const ext = filePath.split('.').pop() ?? '';
    const lang = ext === 'py' ? 'python' : ext === 'js' ? 'javascript' : ext === 'ts' ? 'typescript' : ext;

    return makeResponse(200, 'text/html', htmlPage(`${filePath} — ${repo.name}`,
        `<h1><a href="${escapeHtml(repo.path)}">${escapeHtml(repo.name)}</a> / ${escapeHtml(filePath)}</h1>
        <pre><code class="language-${escapeHtml(lang)}">${escapeHtml(file.content)}</code></pre>`));
}

function renderCommitLog(repo: GitRepoSpec): ExternalResponse {
    const commits = repo.commits ?? [];
    if (commits.length === 0) {
        return makeResponse(200, 'text/html', htmlPage(`Commits — ${repo.name}`,
            `<h1>${escapeHtml(repo.name)} — Commits</h1><p>No commit history.</p>`));
    }

    const commitsHtml = commits.map(c =>
        `<div class="post">
            <div><strong><a href="${escapeHtml(repo.path)}/commits/${escapeHtml(c.hash)}">${escapeHtml(c.hash.slice(0, 7))}</a></strong> ${escapeHtml(c.message)}</div>
            <div class="meta">${escapeHtml(c.author)} &lt;${escapeHtml(c.email)}&gt; — ${new Date(c.timestamp).toISOString()}</div>
            ${c.changedFiles ? `<div class="meta">Changed: ${c.changedFiles.map(f => escapeHtml(f)).join(', ')}</div>` : ''}
            <pre><code>${escapeHtml(renderCommitDiff(repo, c))}</code></pre>
        </div>`,
    ).join('\n');

    return makeResponse(200, 'text/html', htmlPage(`Commits — ${repo.name}`,
        `<h1><a href="${escapeHtml(repo.path)}">${escapeHtml(repo.name)}</a> — Commits</h1>${commitsHtml}`));
}

function renderCommitDetail(repo: GitRepoSpec, commitRef: string): ExternalResponse {
    const commits = repo.commits ?? [];
    const commit = commits.find(c => c.hash === commitRef || c.hash.startsWith(commitRef));
    if (commit === undefined) return make404();
    return makeResponse(200, 'text/html', htmlPage(
        `${commit.hash.slice(0, 7)} — ${repo.name}`,
        `<h1><a href="${escapeHtml(repo.path)}">${escapeHtml(repo.name)}</a> / Commit ${escapeHtml(commit.hash.slice(0, 7))}</h1>
        <div class="meta">Author: ${escapeHtml(commit.author)} &lt;${escapeHtml(commit.email)}&gt;</div>
        <div class="meta">Date: ${new Date(commit.timestamp).toISOString()}</div>
        <p><strong>${escapeHtml(commit.message)}</strong></p>
        <pre><code>${escapeHtml(renderCommitDiff(repo, commit))}</code></pre>`,
    ));
}

function renderRepoBranches(repo: GitRepoSpec): ExternalResponse {
    const branches = repo.branches ?? ['main'];
    const lastHash = repo.commits?.[0]?.hash ?? '0'.repeat(40);
    const listHtml = branches.map((branch, idx) =>
        `<tr><td>${idx === 0 ? '* ' : ''}${escapeHtml(branch)}</td><td>${escapeHtml(lastHash.slice(0, 7))}</td></tr>`,
    ).join('\n');
    return makeResponse(200, 'text/html', htmlPage(
        `Branches — ${repo.name}`,
        `<h1><a href="${escapeHtml(repo.path)}">${escapeHtml(repo.name)}</a> — Branches</h1>
        <table><thead><tr><th>Branch</th><th>Head</th></tr></thead><tbody>${listHtml}</tbody></table>`,
    ));
}

function renderRepoTags(repo: GitRepoSpec): ExternalResponse {
    const commits = repo.commits ?? [];
    const tags = commits.slice(0, 3).map((commit, idx) => ({
        name: `v${Math.max(1, commits.length - idx)}.${idx}`,
        hash: commit.hash,
        message: commit.message,
    }));
    const tagsHtml = tags.length === 0
        ? '<p class="meta">No tags.</p>'
        : tags.map(t =>
            `<div class="post"><div><strong>${escapeHtml(t.name)}</strong> → ${escapeHtml(t.hash.slice(0, 7))}</div><div class="meta">${escapeHtml(t.message)}</div></div>`,
        ).join('\n');
    return makeResponse(200, 'text/html', htmlPage(
        `Tags — ${repo.name}`,
        `<h1><a href="${escapeHtml(repo.path)}">${escapeHtml(repo.name)}</a> — Tags</h1>${tagsHtml}`,
    ));
}

function renderRepoBlame(repo: GitRepoSpec, filePath: string): ExternalResponse {
    const file = repo.files[filePath];
    if (file === undefined) return make404();
    const commits = repo.commits ?? [];
    const lines = file.content.split('\n');
    const blameLines = lines.map((line, idx) => {
        const commit = commits[idx % Math.max(commits.length, 1)];
        const hash = commit?.hash.slice(0, 8) ?? '00000000';
        const author = commit?.author ?? 'unknown';
        return `${hash} (${author.padEnd(12)} ${String(idx + 1).padStart(4)}) ${line}`;
    });
    return makeResponse(200, 'text/plain', blameLines.join('\n'));
}

function renderLeakedGitConfig(repo: GitRepoSpec): string {
    const emails = Array.from(new Set((repo.commits ?? []).map(c => c.email)));
    const defaultEmail = emails[0] ?? `dev@${repo.domain}`;
    return `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://${repo.domain}${repo.path}
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "${repo.branches?.[0] ?? 'main'}"]
	remote = origin
	merge = refs/heads/${repo.branches?.[0] ?? 'main'}
[user]
	name = ${repo.commits?.[0]?.author ?? 'developer'}
	email = ${defaultEmail}
[credential]
	helper = store`;
}

function renderCommitDiff(repo: GitRepoSpec, commit: NonNullable<GitRepoSpec['commits']>[number]): string {
    const files = commit.changedFiles ?? [];
    if (files.length === 0) return 'diff --git a/README.md b/README.md\n+No file delta metadata available.';
    const chunks: string[] = [];
    for (const filePath of files) {
        const file = repo.files[filePath];
        chunks.push(`diff --git a/${filePath} b/${filePath}`);
        chunks.push(`--- a/${filePath}`);
        chunks.push(`+++ b/${filePath}`);
        if (file === undefined) {
            chunks.push('@@ -0,0 +1,1 @@');
            chunks.push('+[deleted in working tree]');
            continue;
        }
        const lines = file.content.split('\n').slice(0, 12);
        chunks.push(`@@ -0,0 +1,${lines.length} @@`);
        for (const line of lines) {
            chunks.push(`+${line}`);
        }
    }
    return chunks.join('\n');
}

// ── Social Media ───────────────────────────────────────────────

function createSocialDomainHandler(domain: string, spec: VariantInternetSpec): ExternalServiceHandler {
    return {
        domain,
        description: `VARIANT Internet: social-media service at ${domain}`,
        handleRequest(request: ExternalRequest): ExternalResponse {
            return handleSocialMedia(request, spec);
        },
    };
}

function handleSocialMedia(request: ExternalRequest, spec: VariantInternetSpec): ExternalResponse {
    const profiles = spec.socialProfiles ?? [];
    if (profiles.length === 0) return make404();
    const cleanPath = stripQuery(request.path);

    const messagesMatch = cleanPath.match(/^\/api\/messages\/([^/?#]+)$/);
    if (messagesMatch?.[1] !== undefined) {
        const userId = decodeURIComponent(messagesMatch[1]);
        const profile = profiles.find(p => p.username === userId);
        if (profile === undefined) return makeJsonResponse(404, { error: 'User not found', userId });
        return makeJsonResponse(200, {
            userId,
            directMessages: buildDirectMessages(profile),
        });
    }

    const connectionsMatch = cleanPath.match(/^\/api\/connections\/([^/?#]+)$/);
    if (connectionsMatch?.[1] !== undefined) {
        const userId = decodeURIComponent(connectionsMatch[1]);
        const profile = profiles.find(p => p.username === userId);
        if (profile === undefined) return makeJsonResponse(404, { error: 'User not found', userId });
        return makeJsonResponse(200, {
            userId,
            connections: buildSocialConnections(profile, profiles),
        });
    }

    // Profile pages
    for (const profile of profiles) {
        if (cleanPath === profile.profilePath || cleanPath === profile.profilePath + '/') {
            return renderSocialProfile(profile);
        }

        // Individual post
        if (profile.posts !== undefined) {
            for (const post of profile.posts) {
                if (cleanPath === `${profile.profilePath}/post/${post.id}`) {
                    return renderSocialPost(profile, post);
                }
            }
        }
    }

    // User search (API endpoint)
    if (request.path === '/api/users/search' || request.path.startsWith('/api/users/search?')) {
        const query = extractQueryParam(request.path, 'q');
        if (query === null) return makeJsonResponse(400, { error: 'Missing query' });

        const queryLower = query.toLowerCase();
        const matches = profiles.filter(p =>
            p.username.toLowerCase().includes(queryLower) ||
            p.displayName.toLowerCase().includes(queryLower) ||
            (p.bio?.toLowerCase().includes(queryLower) ?? false),
        );

        return makeJsonResponse(200, {
            results: matches.map(p => ({
                username: p.username,
                displayName: p.displayName,
                bio: p.bio ?? '',
                profileUrl: p.profilePath,
            })),
        });
    }

    // Feed / index
    if (request.path === '/' || request.path === '') {
        const allPosts: Array<{ profile: SocialProfileSpec; post: typeof profiles[0]['posts'] extends readonly (infer P)[] | undefined ? P : never }> = [];
        for (const profile of profiles) {
            if (profile.posts !== undefined) {
                for (const post of profile.posts) {
                    allPosts.push({ profile, post });
                }
            }
        }
        allPosts.sort((a, b) => b.post.timestamp - a.post.timestamp);

        const feedHtml = allPosts.slice(0, 50).map(({ profile, post }) =>
            `<div class="post">
                <div><strong><a href="${escapeHtml(profile.profilePath)}">${escapeHtml(profile.displayName)}</a></strong> <span class="meta">@${escapeHtml(profile.username)}</span></div>
                <div>${escapeHtml(post.content)}</div>
                <div class="meta">${new Date(post.timestamp).toISOString()}</div>
            </div>`,
        ).join('\n');

        return makeResponse(200, 'text/html', htmlPage('Social Feed',
            `<h1>Social Feed</h1>${feedHtml || '<p>No posts yet.</p>'}`));
    }

    return make404();
}

function renderSocialProfile(profile: SocialProfileSpec): ExternalResponse {
    const postsHtml = (profile.posts ?? []).map(post =>
        `<div class="post">
            <div>${escapeHtml(post.content)}</div>
            <div class="meta">${new Date(post.timestamp).toISOString()}${post.mentions ? ` | Mentions: ${post.mentions.map(m => '@' + escapeHtml(m)).join(', ')}` : ''}</div>
        </div>`,
    ).join('\n');

    const linksHtml = (profile.links ?? []).map(link =>
        `<li><a href="${escapeHtml(link)}">${escapeHtml(link)}</a></li>`,
    ).join('\n');

    const metaHtml = profile.metadata !== undefined
        ? Object.entries(profile.metadata).map(([k, v]) =>
            `<li><strong>${escapeHtml(k)}:</strong> ${escapeHtml(v)}</li>`).join('\n')
        : '';

    const profileSchema = {
        '@context': 'https://schema.org',
        '@type': 'Person',
        name: profile.displayName,
        alternateName: profile.username,
        description: profile.bio ?? '',
        url: profile.profilePath,
    };
    const headHtml = [
        `<meta property="og:type" content="profile">`,
        `<meta property="og:title" content="${escapeHtml(profile.displayName)}">`,
        `<meta property="profile:username" content="${escapeHtml(profile.username)}">`,
        `<meta name="description" content="${escapeHtml(profile.bio ?? `${profile.displayName} profile`)}">`,
        `<script type="application/ld+json">${escapeHtml(JSON.stringify(profileSchema))}</script>`,
    ].join('\n');

    return makeResponse(200, 'text/html', htmlPage(`${profile.displayName} (@${profile.username})`,
        `<h1>${escapeHtml(profile.displayName)}</h1>
        <p class="meta">@${escapeHtml(profile.username)}</p>
        ${profile.bio ? `<p>${escapeHtml(profile.bio)}</p>` : ''}
        ${metaHtml ? `<h3>Info</h3><ul>${metaHtml}</ul>` : ''}
        ${linksHtml ? `<h3>Links</h3><ul>${linksHtml}</ul>` : ''}
        <h2>Posts</h2>${postsHtml || '<p>No posts.</p>'}`,
    undefined, headHtml));
}

function renderSocialPost(profile: SocialProfileSpec, post: NonNullable<SocialProfileSpec['posts']>[number]): ExternalResponse {
    return makeResponse(200, 'text/html', htmlPage(`Post by @${profile.username}`,
        `<div class="post">
            <div><strong><a href="${escapeHtml(profile.profilePath)}">${escapeHtml(profile.displayName)}</a></strong> <span class="meta">@${escapeHtml(profile.username)}</span></div>
            <div>${escapeHtml(post.content)}</div>
            <div class="meta">${new Date(post.timestamp).toISOString()}</div>
        </div>`));
}

function buildDirectMessages(profile: SocialProfileSpec): Array<{ id: string; from: string; to: string; timestamp: number; message: string }> {
    const latestTimestamp = (profile.posts ?? [])[0]?.timestamp ?? Date.now();
    const sensitivePost = (profile.posts ?? []).find(p => p.sensitive === true);
    const sensitiveExtract = sensitivePost?.content.match(/[A-Za-z0-9!@#$%^&*()_+\-=]{8,}/)?.[0] ?? null;
    const inferredContact = (profile.links ?? []).find(link => link.includes('@')) ?? `${profile.username}@corp.local`;
    const messages = [
        {
            id: `${profile.username}-dm-1`,
            from: 'helpdesk-bot',
            to: profile.username,
            timestamp: latestTimestamp - 7200000,
            message: `Ticket #${profile.username.toUpperCase()}-4821: VPN recovery code is 992741.`,
        },
        {
            id: `${profile.username}-dm-2`,
            from: 'ops-manager',
            to: profile.username,
            timestamp: latestTimestamp - 3600000,
            message: `Send production access details to ${inferredContact} before standup.`,
        },
    ];
    if (sensitiveExtract !== null) {
        messages.push({
            id: `${profile.username}-dm-3`,
            from: 'teammate',
            to: profile.username,
            timestamp: latestTimestamp - 1800000,
            message: `Saw your post mentioning "${sensitiveExtract}". Please rotate it after deployment.`,
        });
    }
    return messages;
}

function buildSocialConnections(
    profile: SocialProfileSpec,
    allProfiles: readonly SocialProfileSpec[],
): Array<{ target: string; relation: 'mentions' | 'linked' | 'same-domain'; strength: number }> {
    const relationships: Array<{ target: string; relation: 'mentions' | 'linked' | 'same-domain'; strength: number }> = [];
    const mentionTargets = new Set<string>();
    for (const post of profile.posts ?? []) {
        for (const mention of post.mentions ?? []) {
            mentionTargets.add(mention.replace(/^@/, ''));
        }
    }
    for (const target of mentionTargets) {
        if (target === profile.username) continue;
        relationships.push({ target, relation: 'mentions', strength: 0.7 });
    }
    for (const link of profile.links ?? []) {
        const match = link.match(/@([a-z0-9_.-]+)/i);
        if (match?.[1] !== undefined && match[1] !== profile.username) {
            relationships.push({ target: match[1], relation: 'linked', strength: 0.6 });
        }
    }
    for (const other of allProfiles) {
        if (other.username !== profile.username && other.domain === profile.domain) {
            relationships.push({ target: other.username, relation: 'same-domain', strength: 0.5 });
        }
    }
    return relationships;
}

// ── Paste Site ─────────────────────────────────────────────────

function createPasteSiteDomainHandler(domain: string, spec: VariantInternetSpec): ExternalServiceHandler {
    return {
        domain,
        description: `VARIANT Internet: paste-site service at ${domain}`,
        handleRequest(request: ExternalRequest): ExternalResponse {
            return handlePasteSite(request, spec);
        },
    };
}

function handlePasteSite(request: ExternalRequest, spec: VariantInternetSpec): ExternalResponse {
    const sites = spec.pasteSites ?? [];
    if (sites.length === 0) return make404();

    // Find all pastes across all sites
    const allPastes: Array<{ site: PasteSiteSpec; paste: PasteSiteSpec['pastes'][number] }> = [];
    for (const site of sites) {
        for (const paste of site.pastes) {
            allPastes.push({ site, paste });
        }
    }

    // Individual paste
    for (const { paste } of allPastes) {
        if (request.path === `/${paste.id}` || request.path === `/paste/${paste.id}`) {
            const lang = paste.language ?? 'text';
            return makeResponse(200, 'text/html', htmlPage(
                paste.title ?? `Paste ${paste.id}`,
                `<h1>${escapeHtml(paste.title ?? `Paste ${paste.id}`)}</h1>
                <div class="meta">Author: ${escapeHtml(paste.author ?? 'anonymous')} | Language: ${escapeHtml(lang)} | ${new Date(paste.timestamp).toISOString()}</div>
                <pre><code class="language-${escapeHtml(lang)}">${escapeHtml(paste.content)}</code></pre>`,
            ));
        }

        // Raw paste content
        if (request.path === `/raw/${paste.id}`) {
            return makeResponse(200, 'text/plain', paste.content);
        }
    }

    // Paste API
    if (request.path === '/api/pastes' || request.path === '/api/recent') {
        return makeJsonResponse(200, allPastes.map(({ paste }) => ({
            id: paste.id,
            title: paste.title ?? null,
            author: paste.author ?? 'anonymous',
            language: paste.language ?? 'text',
            timestamp: paste.timestamp,
            size: paste.content.length,
        })));
    }

    // Index
    if (request.path === '/' || request.path === '') {
        const pastesHtml = allPastes
            .sort((a, b) => b.paste.timestamp - a.paste.timestamp)
            .slice(0, 50)
            .map(({ paste }) =>
                `<div class="result">
                    <div class="result-title"><a href="/${escapeHtml(paste.id)}">${escapeHtml(paste.title ?? `Paste ${paste.id}`)}</a></div>
                    <div class="meta">${escapeHtml(paste.author ?? 'anonymous')} | ${escapeHtml(paste.language ?? 'text')} | ${new Date(paste.timestamp).toISOString()}</div>
                </div>`,
            ).join('\n');

        return makeResponse(200, 'text/html', htmlPage('Paste Site',
            `<h1>Recent Pastes</h1>${pastesHtml || '<p>No pastes.</p>'}`));
    }

    return make404();
}

// ── WHOIS ──────────────────────────────────────────────────────

function handleWhois(request: ExternalRequest, spec: VariantInternetSpec): ExternalResponse {
    const records = spec.whoisRecords ?? [];

    // Query via path or query param
    const queryDomain = extractQueryParam(request.path, 'domain')
        ?? request.path.replace(/^\/lookup\//, '').replace(/^\//, '').replace(/\/$/, '');

    if (queryDomain === '' || request.path === '/') {
        return makeResponse(200, 'text/html', htmlPage('WHOIS Lookup',
            `<h1>WHOIS Lookup</h1>
            <form method="GET" action="/lookup/">
                <input type="text" name="domain" placeholder="example.com" style="padding:8px;width:300px;background:#161b22;color:#c9d1d9;border:1px solid #30363d;border-radius:4px">
                <button type="submit" style="padding:8px 16px;background:#238636;color:#fff;border:none;border-radius:4px;cursor:pointer">Lookup</button>
            </form>`));
    }

    const record = records.find(r => r.domain === queryDomain);
    if (record === undefined) {
        return makeResponse(200, 'text/plain',
            `% WHOIS query for ${queryDomain}\n% No match for "${queryDomain}"\n`);
    }

    const whoisText = [
        `% WHOIS query for ${record.domain}`,
        ``,
        `Domain Name: ${record.domain.toUpperCase()}`,
        `Registrar: ${record.registrar}`,
        `Registrant: ${record.registrant}`,
        record.registrantEmail ? `Registrant Email: ${record.registrantEmail}` : null,
        `Creation Date: ${record.createdDate}`,
        `Updated Date: ${record.updatedDate}`,
        `Expiration Date: ${record.expiresDate}`,
        `Status: ${record.status}`,
        `Name Servers:`,
        ...record.nameservers.map(ns => `  ${ns}`),
    ].filter(Boolean).join('\n');

    // JSON API
    if (request.headers.get('accept')?.includes('application/json')) {
        return makeJsonResponse(200, record);
    }

    return makeResponse(200, 'text/plain', whoisText);
}

// ── Certificate Transparency ───────────────────────────────────

function handleCertTransparency(request: ExternalRequest, spec: VariantInternetSpec): ExternalResponse {
    const records = spec.certRecords ?? [];

    const query = extractQueryParam(request.path, 'domain')
        ?? extractQueryParam(request.path, 'q')
        ?? request.path.replace(/^\/search\//, '').replace(/^\//, '').replace(/\/$/, '');

    if (query === '' || request.path === '/') {
        return makeResponse(200, 'text/html', htmlPage('Certificate Transparency Search',
            `<h1>Certificate Transparency Search</h1>
            <form method="GET" action="/search/">
                <input type="text" name="domain" placeholder="example.com" style="padding:8px;width:300px;background:#161b22;color:#c9d1d9;border:1px solid #30363d;border-radius:4px">
                <button type="submit" style="padding:8px 16px;background:#238636;color:#fff;border:none;border-radius:4px;cursor:pointer">Search</button>
            </form>`));
    }

    const queryLower = query.toLowerCase();
    const wildcardRegex = query.includes('*') ? wildcardToRegExp(queryLower) : null;
    const matches = records.filter(r => {
        const fields = [r.domain, ...r.subjectAltNames].map(v => v.toLowerCase());
        if (wildcardRegex !== null) return fields.some(v => wildcardRegex.test(v));
        return fields.some(v => v.includes(queryLower));
    });

    // JSON API
    if (request.path.startsWith('/api/domains')) {
        const domains = matches.flatMap(m => [m.domain, ...m.subjectAltNames]);
        return makeJsonResponse(200, {
            query,
            domains: Array.from(new Set(domains)).sort(),
            certificates: matches.map(m => ({
                domain: m.domain,
                chain: buildCertificateChainDetails(m),
            })),
        });
    }
    if (request.path.startsWith('/api/') || request.headers.get('accept')?.includes('application/json')) {
        return makeJsonResponse(200, {
            query,
            results: matches.map(m => ({ ...m, chain: buildCertificateChainDetails(m) })),
        });
    }

    if (matches.length === 0) {
        return makeResponse(200, 'text/html', htmlPage(`CT Search: ${query}`,
            `<h1>Certificate Transparency Search</h1>
            <p>No certificates found for <strong>${escapeHtml(query)}</strong></p>`));
    }

    const resultsHtml = matches.map(r => {
        const sansHtml = r.subjectAltNames.map(san => `<code>${escapeHtml(san)}</code>`).join(', ');
        const chainHtml = buildCertificateChainDetails(r).map(c =>
            `<li>${escapeHtml(c.subject)} | Issuer: ${escapeHtml(c.issuer)} | Valid: ${escapeHtml(c.validFrom)} → ${escapeHtml(c.validTo)}</li>`,
        ).join('');
        return `<div class="result">
            <div class="result-title">${escapeHtml(r.domain)}</div>
            <div class="meta">Issuer: ${escapeHtml(r.issuer)} | Serial: ${escapeHtml(r.serialNumber)}</div>
            <div class="meta">Valid: ${escapeHtml(r.validFrom)} → ${escapeHtml(r.validTo)}</div>
            <div class="meta">SANs: ${sansHtml}</div>
            <div class="meta">Chain:</div><ul>${chainHtml}</ul>
        </div>`;
    }).join('\n');

    return makeResponse(200, 'text/html', htmlPage(`CT Search: ${query}`,
        `<h1>Certificate Transparency Search</h1>
        <p>${matches.length} certificates found for <strong>${escapeHtml(query)}</strong></p>
        ${resultsHtml}`));
}

function buildCertificateChainDetails(record: NonNullable<VariantInternetSpec['certRecords']>[number]): Array<{
    subject: string;
    issuer: string;
    validFrom: string;
    validTo: string;
    sans: readonly string[];
}> {
    return [
        {
            subject: record.domain,
            issuer: record.issuer,
            validFrom: record.validFrom,
            validTo: record.validTo,
            sans: record.subjectAltNames,
        },
        {
            subject: `${record.issuer} Intermediate`,
            issuer: `${record.issuer} Root`,
            validFrom: '2019-01-01',
            validTo: '2034-01-01',
            sans: [],
        },
        {
            subject: `${record.issuer} Root`,
            issuer: `${record.issuer} Root`,
            validFrom: '2010-01-01',
            validTo: '2040-01-01',
            sans: [],
        },
    ];
}

// ── DNS Lookup ─────────────────────────────────────────────────

function handleDnsLookup(request: ExternalRequest, spec: VariantInternetSpec): ExternalResponse {
    const dnsRecords = spec.dnsRecords;

    const query = extractQueryParam(request.path, 'domain')
        ?? request.path.replace(/^\/lookup\//, '').replace(/^\//, '').replace(/\/$/, '');

    if (query === '' || request.path === '/') {
        return makeResponse(200, 'text/html', htmlPage('DNS Lookup',
            `<h1>DNS Lookup</h1>
            <form method="GET" action="/lookup/">
                <input type="text" name="domain" placeholder="example.com" style="padding:8px;width:300px;background:#161b22;color:#c9d1d9;border:1px solid #30363d;border-radius:4px">
                <button type="submit" style="padding:8px 16px;background:#238636;color:#fff;border:none;border-radius:4px;cursor:pointer">Lookup</button>
            </form>`));
    }

    const matches = dnsRecords.filter(r => r.domain === query || r.domain.endsWith('.' + query));

    // JSON API
    if (request.headers.get('accept')?.includes('application/json')) {
        return makeJsonResponse(200, { query, records: matches });
    }

    if (matches.length === 0) {
        return makeResponse(200, 'text/plain', `; DNS lookup for ${query}\n; NXDOMAIN — no records found\n`);
    }

    const lines = [
        `; DNS lookup for ${query}`,
        `;; ANSWER SECTION:`,
        ...matches.map(r => `${r.domain}.\t3600\tIN\t${r.type ?? 'A'}\t${r.value ?? r.ip}`),
    ];

    return makeResponse(200, 'text/plain', lines.join('\n'));
}

// ── Forum ──────────────────────────────────────────────────────

function handleForum(request: ExternalRequest, service: VariantInternetService): ExternalResponse {
    const staticContent = service.staticContent ?? {};

    // Forums are primarily staticContent-driven
    if (request.path === '/' || request.path === '') {
        const rootContent = staticContent['/'];
        if (rootContent !== undefined) {
            return makeResponse(200, 'text/html', rootContent);
        }

        // Generate index from available pages
        const pages = Object.keys(staticContent).sort();
        const linksHtml = pages.map(p =>
            `<li><a href="${escapeHtml(p)}">${escapeHtml(p)}</a></li>`,
        ).join('\n');

        return makeResponse(200, 'text/html', htmlPage(`Forum — ${service.domain}`,
            `<h1>${escapeHtml(service.domain)} Forum</h1>
            <ul>${linksHtml || '<li>No threads.</li>'}</ul>`));
    }

    return make404();
}

// ── Website (enhanced) ─────────────────────────────────────────

function handleWebsite(request: ExternalRequest, service: VariantInternetService): ExternalResponse {
    const staticContent = service.staticContent ?? {};

    // Try exact path match
    const content = staticContent[request.path];
    if (content !== undefined) {
        return makeResponse(200, 'text/html', content);
    }

    // Try with trailing slash
    const withSlash = staticContent[request.path + '/'];
    if (withSlash !== undefined) {
        return makeResponse(200, 'text/html', withSlash);
    }

    // Try index.html under the path
    const indexContent = staticContent[request.path + '/index.html']
        ?? staticContent[request.path + 'index.html'];
    if (indexContent !== undefined) {
        return makeResponse(200, 'text/html', indexContent);
    }

    // Root fallback
    if (request.path === '/' || request.path === '') {
        const rootContent = staticContent['/'] ?? staticContent['/index.html'];
        if (rootContent !== undefined) {
            return makeResponse(200, 'text/html', rootContent);
        }
    }

    return make404();
}

// ── C2 Server ──────────────────────────────────────────────────

function handleC2(request: ExternalRequest, service: VariantInternetService): ExternalResponse {
    const staticContent = service.staticContent ?? {};

    // C2 registration endpoint
    if (request.path === '/register' && request.method === 'POST') {
        return makeJsonResponse(200, {
            status: 'registered',
            id: 'agent-' + Math.random().toString(36).slice(2, 10),
            interval: 60,
            commands: [],
        });
    }

    // C2 beacon/check-in
    if (request.path === '/beacon' || request.path === '/checkin') {
        return makeJsonResponse(200, {
            status: 'ok',
            commands: [],
            nextCheckin: 60,
        });
    }

    // C2 command result upload
    if (request.path === '/result' && request.method === 'POST') {
        return makeJsonResponse(200, { status: 'received' });
    }

    // C2 payload download
    if (request.path.startsWith('/payload/') || request.path.startsWith('/download/')) {
        const content = staticContent[request.path];
        if (content !== undefined) {
            return makeResponse(200, 'application/octet-stream', content);
        }
        return make404();
    }

    // Static content fallback
    const content = staticContent[request.path];
    if (content !== undefined) {
        return makeResponse(200, 'text/html', content);
    }

    // Intentionally vague 200 response (realistic C2 behavior — blend in)
    return makeResponse(200, 'text/html', '<html><body></body></html>');
}

// ── Utility ────────────────────────────────────────────────────

function extractQueryParam(path: string, param: string): string | null {
    const qIdx = path.indexOf('?');
    if (qIdx === -1) return null;
    const queryString = path.slice(qIdx + 1);
    const parts = queryString.split('&');
    for (const part of parts) {
        const eqIdx = part.indexOf('=');
        if (eqIdx === -1) continue;
        const key = decodeURIComponent(part.slice(0, eqIdx).replace(/\+/g, ' '));
        if (key === param) {
            return decodeURIComponent(part.slice(eqIdx + 1).replace(/\+/g, ' '));
        }
    }
    return null;
}
