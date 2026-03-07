/**
 * VARIANT — HTTP Service + Search Engine tests
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createHTTPService } from '../../../src/lib/services/http-service';
import { createSearchEngine } from '../../../src/lib/services/search-engine';
import { createServiceRegistry } from '../../../src/lib/services/types';
import { createVFS } from '../../../src/lib/vfs/vfs';
import { createShell } from '../../../src/lib/shell/shell';
import type { ServiceContext, ServiceRequest } from '../../../src/lib/services/types';

function makeRequest(text: string, sourceIP: string = '10.0.0.10'): ServiceRequest {
    return {
        sourceIP,
        sourcePort: 12345,
        payload: new TextEncoder().encode(text),
        payloadText: text,
    };
}

function makeContext(): ServiceContext {
    const vfs = createVFS();
    vfs.writeFile('/var/www/index.html', '<html><body>Hello</body></html>');
    vfs.writeFile('/var/www/style.css', 'body { color: red; }');
    vfs.writeFile('/var/www/api/users.json', '{"users":[]}');

    const shell = createShell({ vfs, hostname: 'web-01' });

    return {
        vfs,
        shell,
        hostname: 'web-01',
        ip: '10.0.1.10',
        emit: vi.fn(),
    };
}

describe('HTTPService', () => {
    let ctx: ServiceContext;

    beforeEach(() => {
        ctx = makeContext();
    });

    it('serves static file from VFS', () => {
        const service = createHTTPService({ routes: [] });
        service.start?.(ctx);

        const response = service.handle(
            makeRequest('GET /index.html HTTP/1.1\r\nHost: web-01\r\n\r\n'),
            ctx,
        );

        expect(response).not.toBeNull();
        const text = new TextDecoder().decode(response!.payload);
        expect(text).toContain('200 OK');
        expect(text).toContain('<html><body>Hello</body></html>');
    });

    it('returns 404 for missing file', () => {
        const service = createHTTPService({ routes: [] });
        service.start?.(ctx);

        const response = service.handle(
            makeRequest('GET /nonexistent.html HTTP/1.1\r\nHost: web-01\r\n\r\n'),
            ctx,
        );

        const text = new TextDecoder().decode(response!.payload);
        expect(text).toContain('404');
    });

    it('matches configured routes', () => {
        const service = createHTTPService({
            routes: [
                { method: 'GET', path: '/api/status', status: 200, body: '{"status":"ok"}', contentType: 'application/json' },
                { method: 'POST', path: '/api/login', status: 200, body: '{"token":"abc123"}', contentType: 'application/json' },
            ],
        });
        service.start?.(ctx);

        const response = service.handle(
            makeRequest('GET /api/status HTTP/1.1\r\nHost: web-01\r\n\r\n'),
            ctx,
        );

        const text = new TextDecoder().decode(response!.payload);
        expect(text).toContain('200 OK');
        expect(text).toContain('{"status":"ok"}');
    });

    it('serves index.html for root path', () => {
        const service = createHTTPService({ routes: [] });
        service.start?.(ctx);

        const response = service.handle(
            makeRequest('GET / HTTP/1.1\r\nHost: web-01\r\n\r\n'),
            ctx,
        );

        const text = new TextDecoder().decode(response!.payload);
        expect(text).toContain('200 OK');
        expect(text).toContain('Hello');
    });

    it('emits HTTP request event', () => {
        const service = createHTTPService({ routes: [] });
        service.start?.(ctx);

        service.handle(
            makeRequest('GET / HTTP/1.1\r\nHost: web-01\r\n\r\n'),
            ctx,
        );

        expect(ctx.emit).toHaveBeenCalledWith(expect.objectContaining({
            type: 'http:request',
            method: 'GET',
            responseCode: 200,
        }));
    });

    it('matches wildcard routes', () => {
        const service = createHTTPService({
            routes: [
                { method: '*', path: '/api/*', status: 200, body: '{"caught":true}' },
            ],
        });
        service.start?.(ctx);

        const response = service.handle(
            makeRequest('POST /api/anything/here HTTP/1.1\r\nHost: web-01\r\n\r\n'),
            ctx,
        );

        const text = new TextDecoder().decode(response!.payload);
        expect(text).toContain('{"caught":true}');
    });
});

describe('SearchEngine', () => {
    it('returns results matching query keywords', () => {
        const engine = createSearchEngine({
            entries: [
                {
                    keywords: ['nginx', 'vulnerability'],
                    results: [
                        { title: 'Nginx CVE-2024-XXXX', url: 'https://security.variant/cve', snippet: 'Critical nginx vuln...' },
                    ],
                },
                {
                    keywords: ['python', 'tutorial'],
                    results: [
                        { title: 'Python 101', url: 'https://learn.variant/python', snippet: 'Learn Python...' },
                    ],
                },
            ],
        });

        const ctx = makeContext();
        const response = engine.handle(
            makeRequest('GET /search?q=nginx+vulnerability HTTP/1.1\r\nHost: search.variant\r\n\r\n'),
            ctx,
        );

        expect(response).not.toBeNull();
        const text = new TextDecoder().decode(response!.payload);
        expect(text).toContain('Nginx CVE-2024-XXXX');
        expect(text).not.toContain('Python 101');
    });

    it('returns home page for root path', () => {
        const engine = createSearchEngine({
            engineName: 'TestSearch',
            entries: [],
        });

        const ctx = makeContext();
        const response = engine.handle(
            makeRequest('GET / HTTP/1.1\r\nHost: search.variant\r\n\r\n'),
            ctx,
        );

        const text = new TextDecoder().decode(response!.payload);
        expect(text).toContain('TestSearch');
    });

    it('emits search event', () => {
        const engine = createSearchEngine({ entries: [] });
        const ctx = makeContext();

        engine.handle(
            makeRequest('GET /search?q=test+query HTTP/1.1\r\nHost: search.variant\r\n\r\n'),
            ctx,
        );

        expect(ctx.emit).toHaveBeenCalledWith(expect.objectContaining({
            type: 'service:custom',
            service: 'search-engine',
            action: 'search',
        }));
    });

    it('mixes noise with planted results', () => {
        const engine = createSearchEngine({
            entries: [
                { keywords: ['hack'], results: [{ title: 'Planted Result', url: 'https://planted.variant', snippet: 'Planted' }] },
            ],
            noise: [
                { keywords: ['hack'], results: [{ title: 'Noise Result', url: 'https://noise.variant', snippet: 'Background noise' }] },
            ],
        });

        const ctx = makeContext();
        const response = engine.handle(
            makeRequest('GET /search?q=hack HTTP/1.1\r\nHost: search.variant\r\n\r\n'),
            ctx,
        );

        const text = new TextDecoder().decode(response!.payload);
        expect(text).toContain('Planted Result');
        expect(text).toContain('Noise Result');
    });

    it('serves page content for clickable search results', () => {
        const engine = createSearchEngine({
            entries: [
                {
                    keywords: ['example'],
                    results: [{
                        title: 'Example Page',
                        url: 'https://example.variant/page',
                        snippet: 'Click me',
                        pageContent: '<html><body>Full page content here</body></html>',
                    }],
                },
            ],
        });

        const ctx = makeContext();
        const response = engine.handle(
            makeRequest('GET /page HTTP/1.1\r\nHost: example.variant\r\n\r\n'),
            ctx,
        );

        const text = new TextDecoder().decode(response!.payload);
        expect(text).toContain('Full page content here');
    });
});

describe('ServiceRegistry', () => {
    it('registers and retrieves handlers', () => {
        const registry = createServiceRegistry();
        const handler = createHTTPService({ routes: [] });
        registry.register(handler);

        expect(registry.getHandler(80, 'tcp')).toBe(handler);
        expect(registry.getHandler(443, 'tcp')).toBeNull();
    });

    it('unregisters handlers', () => {
        const registry = createServiceRegistry();
        const handler = createHTTPService({ routes: [] });
        registry.register(handler);
        registry.unregister('http');

        expect(registry.getHandler(80, 'tcp')).toBeNull();
    });

    it('lists all handlers', () => {
        const registry = createServiceRegistry();
        registry.register(createHTTPService({ routes: [] }));
        registry.register(createSearchEngine({ port: 8080, entries: [] }));

        expect(registry.getAll()).toHaveLength(2);
    });
});
