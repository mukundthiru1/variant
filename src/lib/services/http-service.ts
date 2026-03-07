/**
 * VARIANT — HTTP Service Handler
 *
 * Simulated HTTP server for Simulacra.
 * Serves files from the VFS, handles routes, and emits
 * events for objective detection.
 *
 * DESIGN: Implements ServiceHandler interface.
 * Replace this file. Nothing else changes.
 */

import { normalizePathSafe } from '../vfs';
import type {
    ServiceHandler,
    ServiceRequest,
    ServiceResponse,
    ServiceContext,
} from './types';

// ── Types ──────────────────────────────────────────────────────

export interface HTTPRoute {
    /** HTTP method (GET, POST, etc.). '*' matches any. */
    readonly method: string;
    /** URL path pattern. Supports :param and * wildcard. */
    readonly path: string;
    /** Response status code. */
    readonly status: number;
    /** Response headers. */
    readonly headers?: ReadonlyMap<string, string>;
    /** Response body (string). */
    readonly body: string;
    /** Content-Type header. Default: 'text/html'. */
    readonly contentType?: string;
    /**
     * If true, serve a file from VFS at this path.
     * The 'body' field is ignored; VFS content is used.
     */
    readonly serveFromVFS?: boolean;
    /**
     * If set, this route is a vulnerability.
     * The vuln ID is emitted as part of the service event.
     */
    readonly vulnId?: string;
}

export interface HTTPServiceConfig {
    /** Port to listen on. Default: 80. */
    readonly port?: number;
    /** Server name for headers. Default: hostname. */
    readonly serverName?: string;
    /** Routes in priority order. First match wins. */
    readonly routes: readonly HTTPRoute[];
    /** Default 404 response body. */
    readonly notFoundBody?: string;
    /** Web root in VFS for static file serving. Default: '/var/www'. */
    readonly webRoot?: string;
}

// ── Factory ────────────────────────────────────────────────────

export function createHTTPService(config: HTTPServiceConfig): ServiceHandler {
    const port = config.port ?? 80;
    const webRoot = config.webRoot ?? '/var/www';
    let ctx: ServiceContext | null = null;

    const MAX_REQUEST_SIZE = 2 * 1024 * 1024;
    const MAX_HEADER_LINES = 500;
    const MAX_LINE_LENGTH = 8192;

    function parseHTTPRequest(text: string): ParsedHTTPRequest | null {
        if (text.length > MAX_REQUEST_SIZE) return null;
        const lines = text.split('\r\n');
        if (lines.length === 0) return null;
        if (lines.length > MAX_HEADER_LINES) return null;

        const requestLine = lines[0]!;
        if (requestLine.length > MAX_LINE_LENGTH) return null;
        const parts = requestLine.split(' ');
        if (parts.length < 2) return null;

        const method = parts[0]!;
        const fullPath = parts[1]!;

        // Parse query string (decodeURIComponent can throw on malformed %)
        const [path, queryString] = fullPath.split('?');
        const query = new Map<string, string>();
        if (queryString !== undefined) {
            for (const pair of queryString.split('&')) {
                const eqIdx = pair.indexOf('=');
                const key = eqIdx >= 0 ? pair.slice(0, eqIdx) : pair;
                const value = eqIdx >= 0 ? pair.slice(eqIdx + 1) : '';
                if (key === undefined) continue;
                try {
                    query.set(decodeURIComponent(key), decodeURIComponent(value ?? ''));
                } catch {
                    query.set(key, value ?? '');
                }
            }
        }

        // Parse headers
        const headers = new Map<string, string>();
        let bodyStart = -1;
        for (let i = 1; i < lines.length; i++) {
            const line = lines[i]!;
            if (line.length > MAX_LINE_LENGTH) return null;
            if (line === '') {
                bodyStart = i + 1;
                break;
            }
            const colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                headers.set(
                    line.slice(0, colonIdx).trim().toLowerCase(),
                    line.slice(colonIdx + 1).trim(),
                );
            }
        }

        const body = bodyStart >= 0 ? lines.slice(bodyStart).join('\r\n') : '';

        return { method, path: path ?? '/', query, headers, body };
    }

    function matchRoute(method: string, path: string): HTTPRoute | null {
        for (const route of config.routes) {
            if (route.method !== '*' && route.method.toUpperCase() !== method.toUpperCase()) continue;

            if (route.path === path) return route;

            // Wildcard match
            if (route.path.endsWith('*')) {
                const prefix = route.path.slice(0, -1);
                if (path.startsWith(prefix)) return route;
            }

            // Param match (basic: /users/:id)
            const routeParts = route.path.split('/');
            const pathParts = path.split('/');
            if (routeParts.length !== pathParts.length) continue;

            let match = true;
            for (let i = 0; i < routeParts.length; i++) {
                if (routeParts[i]!.startsWith(':')) continue; // Param — matches anything
                if (routeParts[i] !== pathParts[i]) { match = false; break; }
            }
            if (match) return route;
        }
        return null;
    }

    function buildHTTPResponse(status: number, headers: Map<string, string>, body: string): Uint8Array {
        const statusText = HTTP_STATUS_TEXT.get(status) ?? 'OK';
        const responseHeaders = new Map(headers);

        if (!responseHeaders.has('content-type')) {
            responseHeaders.set('content-type', 'text/html; charset=utf-8');
        }
        responseHeaders.set('content-length', String(new TextEncoder().encode(body).byteLength));
        responseHeaders.set('connection', 'close');

        if (ctx !== null) {
            responseHeaders.set('server', config.serverName ?? ctx.hostname);
        }

        let response = `HTTP/1.1 ${status} ${statusText}\r\n`;
        for (const [key, value] of responseHeaders) {
            response += `${key}: ${value}\r\n`;
        }
        response += '\r\n';
        response += body;

        return new TextEncoder().encode(response);
    }

    return {
        name: 'http',
        port,
        protocol: 'tcp',

        start(serviceCtx: ServiceContext): void {
            ctx = serviceCtx;
        },

        stop(): void {
            ctx = null;
        },

        handle(request: ServiceRequest, serviceCtx: ServiceContext): ServiceResponse | null {
            const parsed = parseHTTPRequest(request.payloadText);
            if (parsed === null) return null;

            // Find matching route
            const route = matchRoute(parsed.method, parsed.path);

            let status: number;
            let body: string;
            let contentType: string;

            if (route !== null) {
                status = route.status;
                contentType = route.contentType ?? 'text/html';

                if (route.serveFromVFS === true) {
                    const rawPath = `${webRoot}${parsed.path}`;
                    const safePath = pathUnderWebRoot(rawPath, webRoot);
                    const content = safePath !== null ? serviceCtx.vfs.readFile(safePath) : null;
                    body = content ?? config.notFoundBody ?? '<html><body><h1>404 Not Found</h1></body></html>';
                    if (content === null) status = 404;
                } else {
                    body = route.body;
                }
            } else {
                // Try static file serving from web root (enforce path under webRoot)
                const rawPath = `${webRoot}${parsed.path === '/' ? '/index.html' : parsed.path}`;
                const safePath = pathUnderWebRoot(rawPath, webRoot);
                const content = safePath !== null ? serviceCtx.vfs.readFile(safePath) : null;

                if (content !== null) {
                    status = 200;
                    body = content;
                    contentType = guessContentType(parsed.path);
                } else {
                    status = 404;
                    body = config.notFoundBody ?? '<html><body><h1>404 Not Found</h1></body></html>';
                    contentType = 'text/html';
                }
            }

            const responseHeaders = new Map<string, string>();
            responseHeaders.set('content-type', contentType);

            // Merge route-specific headers
            if (route?.headers !== undefined) {
                for (const [k, v] of route.headers) {
                    responseHeaders.set(k, v);
                }
            }

            // Emit HTTP request event
            serviceCtx.emit({
                type: 'http:request',
                method: parsed.method,
                path: parsed.path,
                headers: parsed.headers,
                body: parsed.body,
                sourceIP: request.sourceIP,
                responseCode: status,
            });

            return {
                payload: buildHTTPResponse(status, responseHeaders, body),
                close: true,
            };
        },
    };
}

// ── Helpers ────────────────────────────────────────────────────

/** Resolve path and ensure it stays under webRoot (prevents path traversal). Returns null if invalid or escape. */
function pathUnderWebRoot(requestedPath: string, webRoot: string): string | null {
    const normalized = normalizePathSafe(requestedPath);
    const rootNorm = normalizePathSafe(webRoot);
    if (normalized === null || rootNorm === null) return null;
    if (normalized === rootNorm) return normalized;
    const prefix = rootNorm.endsWith('/') ? rootNorm : rootNorm + '/';
    if (!normalized.startsWith(prefix)) return null;
    return normalized;
}

interface ParsedHTTPRequest {
    readonly method: string;
    readonly path: string;
    readonly query: ReadonlyMap<string, string>;
    readonly headers: ReadonlyMap<string, string>;
    readonly body: string;
}

function guessContentType(path: string): string {
    if (path.endsWith('.html') || path.endsWith('.htm')) return 'text/html';
    if (path.endsWith('.css')) return 'text/css';
    if (path.endsWith('.js')) return 'application/javascript';
    if (path.endsWith('.json')) return 'application/json';
    if (path.endsWith('.xml')) return 'application/xml';
    if (path.endsWith('.txt')) return 'text/plain';
    if (path.endsWith('.png')) return 'image/png';
    if (path.endsWith('.jpg') || path.endsWith('.jpeg')) return 'image/jpeg';
    if (path.endsWith('.svg')) return 'image/svg+xml';
    if (path.endsWith('.ico')) return 'image/x-icon';
    return 'application/octet-stream';
}

const HTTP_STATUS_TEXT = new Map<number, string>([
    [200, 'OK'],
    [201, 'Created'],
    [301, 'Moved Permanently'],
    [302, 'Found'],
    [304, 'Not Modified'],
    [400, 'Bad Request'],
    [401, 'Unauthorized'],
    [403, 'Forbidden'],
    [404, 'Not Found'],
    [405, 'Method Not Allowed'],
    [500, 'Internal Server Error'],
    [502, 'Bad Gateway'],
    [503, 'Service Unavailable'],
]);
