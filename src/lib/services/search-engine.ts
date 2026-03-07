/**
 * VARIANT — Search Engine Simulacrum
 *
 * Designer-controlled search engine for the VARIANT Internet.
 * Returns results based on keyword matching against
 * configured entries. Includes noise templates for realism.
 *
 * DESIGN: Implements ServiceHandler interface.
 * The search engine is a special HTTP service that:
 *   1. Matches query keywords against configured entries
 *   2. Mixes in noise results from templates
 *   3. Returns a realistic search results page
 *   4. Emits events for what the player searched
 *
 * Level designers configure:
 *   - Planted results (level-specific)
 *   - Noise template IDs (background realism)
 *   - Result count limits
 *   - Custom search page branding
 */

import type {
    ServiceHandler,
    ServiceRequest,
    ServiceResponse,
    ServiceContext,
} from './types';

// ── Types ──────────────────────────────────────────────────────

export interface SearchEntry {
    /** Keywords that trigger this result (any match). */
    readonly keywords: readonly string[];
    /** Search results to show when keywords match. */
    readonly results: readonly SearchResult[];
    /** Priority (higher = shown first). Default: 0. */
    readonly priority?: number;
}

export interface SearchResult {
    readonly title: string;
    readonly url: string;
    readonly snippet: string;
    /** Full page content served if the player clicks the URL. */
    readonly pageContent?: string;
}

export interface SearchEngineConfig {
    /** Port. Default: 80. */
    readonly port?: number;
    /** Search engine name shown in the UI. Default: 'SearchNet'. */
    readonly engineName?: string;
    /** Level-specific search entries. */
    readonly entries: readonly SearchEntry[];
    /** Noise template entries (mixed in for realism). */
    readonly noise?: readonly SearchEntry[];
    /** Max results per query. Default: 10. */
    readonly maxResults?: number;
    /** Brand color (hex). Default: '#4285f4'. */
    readonly brandColor?: string;
}

// ── Factory ────────────────────────────────────────────────────

export function createSearchEngine(config: SearchEngineConfig): ServiceHandler {
    const port = config.port ?? 80;
    const engineName = config.engineName ?? 'SearchNet';
    const maxResults = config.maxResults ?? 10;
    const brandColor = config.brandColor ?? '#4285f4';

    // Merge all entries
    const allEntries: SearchEntry[] = [...config.entries];
    if (config.noise !== undefined) {
        allEntries.push(...config.noise);
    }

    // Pre-index clickable pages
    const pageMap = new Map<string, string>();
    for (const entry of allEntries) {
        for (const result of entry.results) {
            if (result.pageContent !== undefined) {
                // Map URL path to content
                try {
                    const url = new URL(result.url);
                    pageMap.set(url.pathname, result.pageContent);
                } catch {
                    // If URL is relative or invalid, use as-is
                    pageMap.set(result.url, result.pageContent);
                }
            }
        }
    }

    function search(query: string): SearchResult[] {
        const queryLower = query.toLowerCase();
        const queryWords = queryLower.split(/\s+/).filter(w => w.length > 0);

        // Score each entry by keyword match count
        const scored: Array<{ entry: SearchEntry; score: number }> = [];

        for (const entry of allEntries) {
            let score = 0;
            for (const keyword of entry.keywords) {
                const keyLower = keyword.toLowerCase();
                for (const word of queryWords) {
                    if (keyLower.includes(word) || word.includes(keyLower)) {
                        score += 1;
                    }
                }
                // Exact phrase match bonus
                if (queryLower.includes(keyLower)) {
                    score += 2;
                }
            }
            if (score > 0) {
                scored.push({ entry, score: score + (entry.priority ?? 0) });
            }
        }

        // Sort by score descending
        scored.sort((a, b) => b.score - a.score);

        // Collect results
        const results: SearchResult[] = [];
        for (const { entry } of scored) {
            for (const result of entry.results) {
                if (results.length >= maxResults) break;
                // Deduplicate by URL
                if (!results.some(r => r.url === result.url)) {
                    results.push(result);
                }
            }
            if (results.length >= maxResults) break;
        }

        return results;
    }

    function renderSearchPage(query: string, results: SearchResult[]): string {
        const escapedQuery = escapeHTML(query);
        const resultHTML = results.map(r => `
        <div class="result">
            <a href="${escapeHTML(r.url)}" class="result-url">${escapeHTML(r.url)}</a>
            <h3><a href="${escapeHTML(r.url)}">${escapeHTML(r.title)}</a></h3>
            <p class="snippet">${escapeHTML(r.snippet)}</p>
        </div>`).join('\n');

        return `<!DOCTYPE html>
<html>
<head>
    <title>${escapedQuery} - ${escapeHTML(engineName)}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #fff; }
        .header { background: #f1f3f4; padding: 20px; border-bottom: 1px solid #dfe1e5; }
        .logo { color: ${brandColor}; font-size: 24px; font-weight: bold; text-decoration: none; }
        .search-box { margin-top: 12px; }
        .search-box input { width: 500px; padding: 10px 16px; border: 1px solid #dfe1e5; border-radius: 24px; font-size: 14px; outline: none; }
        .search-box input:focus { border-color: ${brandColor}; box-shadow: 0 1px 6px rgba(32,33,36,.28); }
        .results { padding: 20px 40px; max-width: 700px; }
        .result { margin-bottom: 24px; }
        .result-url { color: #202124; font-size: 12px; text-decoration: none; }
        .result h3 { margin: 4px 0; }
        .result h3 a { color: #1a0dab; text-decoration: none; font-size: 18px; }
        .result h3 a:hover { text-decoration: underline; }
        .snippet { color: #4d5156; font-size: 14px; line-height: 1.4; }
        .stats { color: #70757a; font-size: 12px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <a href="/" class="logo">${escapeHTML(engineName)}</a>
        <div class="search-box">
            <form action="/search" method="GET">
                <input type="text" name="q" value="${escapedQuery}" autofocus>
            </form>
        </div>
    </div>
    <div class="results">
        <p class="stats">About ${results.length} results</p>
        ${resultHTML}
    </div>
</body>
</html>`;
    }

    function renderHomePage(): string {
        return `<!DOCTYPE html>
<html>
<head>
    <title>${escapeHTML(engineName)}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 100vh; }
        .logo { color: ${brandColor}; font-size: 64px; font-weight: bold; margin-bottom: 24px; }
        .search-box input { width: 500px; padding: 14px 20px; border: 1px solid #dfe1e5; border-radius: 24px; font-size: 16px; outline: none; }
        .search-box input:focus { border-color: ${brandColor}; box-shadow: 0 1px 6px rgba(32,33,36,.28); }
    </style>
</head>
<body>
    <div class="logo">${escapeHTML(engineName)}</div>
    <div class="search-box">
        <form action="/search" method="GET">
            <input type="text" name="q" placeholder="Search the web..." autofocus>
        </form>
    </div>
</body>
</html>`;
    }

    return {
        name: 'search-engine',
        port,
        protocol: 'tcp',

        handle(request: ServiceRequest, serviceCtx: ServiceContext): ServiceResponse | null {
            const text = request.payloadText;
            const firstLine = text.split('\r\n')[0] ?? '';
            const parts = firstLine.split(' ');
            if (parts.length < 2) return null;

            const method = parts[0]!;
            const fullPath = parts[1]!;

            if (method !== 'GET') {
                return {
                    payload: new TextEncoder().encode(
                        'HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n'
                    ),
                    close: true,
                };
            }

            const [path, queryString] = fullPath.split('?');

            // Search page
            if (path === '/search') {
                const params = new URLSearchParams(queryString ?? '');
                const query = params.get('q') ?? '';

                // Emit search event
                serviceCtx.emit({
                    type: 'service:custom',
                    service: 'search-engine',
                    action: 'search',
                    details: { query },
                });

                const results = search(query);
                const html = renderSearchPage(query, results);
                const body = new TextEncoder().encode(html);
                const response = `HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`;
                const header = new TextEncoder().encode(response);
                const full = new Uint8Array(header.length + body.length);
                full.set(header);
                full.set(body, header.length);
                return { payload: full, close: true };
            }

            // Check if this is a page associated with a search result
            const pageContent = pageMap.get(path ?? '/');
            if (pageContent !== undefined) {
                const body = new TextEncoder().encode(pageContent);
                const response = `HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`;
                const header = new TextEncoder().encode(response);
                const full = new Uint8Array(header.length + body.length);
                full.set(header);
                full.set(body, header.length);

                serviceCtx.emit({
                    type: 'http:request',
                    method: 'GET',
                    path: path ?? '/',
                    headers: new Map(),
                    body: '',
                    sourceIP: request.sourceIP,
                    responseCode: 200,
                });

                return { payload: full, close: true };
            }

            // Home page
            if (path === '/' || path === '') {
                const html = renderHomePage();
                const body = new TextEncoder().encode(html);
                const response = `HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`;
                const header = new TextEncoder().encode(response);
                const full = new Uint8Array(header.length + body.length);
                full.set(header);
                full.set(body, header.length);
                return { payload: full, close: true };
            }

            // 404
            const notFound = new TextEncoder().encode(
                'HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found'
            );
            return { payload: notFound, close: true };
        },
    };
}

// ── Helpers ────────────────────────────────────────────────────

function escapeHTML(text: string): string {
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
