/**
 * VARIANT API — Cloudflare Worker
 *
 * Marketplace backend for variant.santh.io
 * Handles: auth, level CRUD, ratings, leaderboards, analytics
 *
 * Database: variant-db (Neon PostgreSQL via Hyperdrive)
 * Separate from santh-intel database.
 */

export interface Env {
    HYPERDRIVE: Hyperdrive;
    JWT_SECRET: string;
    ADMIN_API_KEY: string;
    DATABASE_URL: string;
    CORS_ORIGIN: string;
    ENVIRONMENT: string;
}

export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        const url = new URL(request.url);
        const path = url.pathname;

        // CORS preflight
        if (request.method === 'OPTIONS') {
            return corsResponse(env, new Response(null, { status: 204 }));
        }

        try {
            const response = await route(request, env, path);
            return corsResponse(env, response);
        } catch (error: unknown) {
            const message = error instanceof Error ? error.message : 'Internal server error';
            return corsResponse(env, jsonResponse({ error: message }, 500));
        }
    },
};

// ── Router ────────────────────────────────────────────────────────

async function route(request: Request, env: Env, path: string): Promise<Response> {
    const method = request.method;

    // Health check
    if (path === '/health') {
        return jsonResponse({ status: 'ok', service: 'variant-api', version: '0.1.0' });
    }

    // ── Auth ──────────────────────────────────────────────────────
    if (path === '/api/auth/register' && method === 'POST') {
        return jsonResponse({ error: 'Not yet implemented — waiting for Neon connection' }, 501);
    }
    if (path === '/api/auth/login' && method === 'POST') {
        return jsonResponse({ error: 'Not yet implemented — waiting for Neon connection' }, 501);
    }

    // ── Levels ────────────────────────────────────────────────────
    if (path === '/api/levels' && method === 'GET') {
        return jsonResponse({ error: 'Not yet implemented — waiting for Neon connection' }, 501);
    }
    if (path.startsWith('/api/levels/') && method === 'GET') {
        return jsonResponse({ error: 'Not yet implemented — waiting for Neon connection' }, 501);
    }
    if (path === '/api/levels' && method === 'POST') {
        return jsonResponse({ error: 'Not yet implemented — waiting for Neon connection' }, 501);
    }

    // ── Leaderboards ──────────────────────────────────────────────
    if (path.startsWith('/api/leaderboard/') && method === 'GET') {
        return jsonResponse({ error: 'Not yet implemented — waiting for Neon connection' }, 501);
    }

    // ── 404 ───────────────────────────────────────────────────────
    return jsonResponse({ error: 'Not found', path }, 404);
}

// ── Helpers ───────────────────────────────────────────────────────

function jsonResponse(data: unknown, status = 200): Response {
    return new Response(JSON.stringify(data), {
        status,
        headers: { 'Content-Type': 'application/json' },
    });
}

function corsResponse(env: Env, response: Response): Response {
    const headers = new Headers(response.headers);
    headers.set('Access-Control-Allow-Origin', env.CORS_ORIGIN ?? '*');
    headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    headers.set('Access-Control-Max-Age', '86400');
    return new Response(response.body, {
        status: response.status,
        headers,
    });
}
