/**
 * VARIANT API — Cloudflare Worker
 *
 * Marketplace backend for variant.santh.io
 * Handles: auth, level CRUD, ratings, leaderboards, analytics
 *
 * Database: variant-db (Neon PostgreSQL via Hyperdrive)
 * Separate from santh-intel database.
 *
 * Crypto: Web Crypto API (PBKDF2 for passwords, HMAC-SHA256 for JWT)
 * No external dependencies for crypto — runs on CF Workers edge.
 */

import pg from 'pg';

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
            return corsResponse(env, new Response(null, { status: 204 }), request);
        }

        try {
            // Request size limit: 10MB (protects against payload DoS)
            const contentLength = request.headers.get('Content-Length');
            if (contentLength !== null && parseInt(contentLength, 10) > 10_485_760) {
                return corsResponse(env, jsonResponse({ error: 'Request too large' }, 413), request);
            }

            const response = await route(request, env, path, url);
            return corsResponse(env, response, request);
        } catch (error: unknown) {
            // Never leak internal error details to clients
            console.error('[VARIANT API] Unhandled error:', error instanceof Error ? error.message : String(error));

            if (error instanceof SyntaxError) {
                return corsResponse(env, jsonResponse({ error: 'Invalid JSON in request body' }, 400), request);
            }

            return corsResponse(env, jsonResponse({ error: 'Internal server error' }, 500), request);
        }
    },
};

// ── Router ────────────────────────────────────────────────────────

async function route(request: Request, env: Env, path: string, url: URL): Promise<Response> {
    const method = request.method;

    // Health check
    if (path === '/health') {
        return jsonResponse({ status: 'ok', service: 'variant-api', version: '0.1.0' });
    }

    // Health check with DB ping
    if (path === '/health/db') {
        return handleDBHealth(env);
    }

    // ── Auth ──────────────────────────────────────────────────────
    if (path === '/api/auth/register' && method === 'POST') {
        return handleRegister(request, env);
    }
    if (path === '/api/auth/login' && method === 'POST') {
        return handleLogin(request, env);
    }
    if (path === '/api/auth/me' && method === 'GET') {
        return handleMe(request, env);
    }

    // ── Levels ────────────────────────────────────────────────────
    if (path === '/api/levels' && method === 'GET') {
        return handleListLevels(env, url);
    }
    if (path === '/api/levels' && method === 'POST') {
        return handleCreateLevel(request, env);
    }
    // /api/levels/:slug
    const levelMatch = path.match(/^\/api\/levels\/([a-z0-9-]+)$/);
    if (levelMatch !== null && method === 'GET') {
        return handleGetLevel(env, levelMatch[1]!);
    }

    // ── Ratings ───────────────────────────────────────────────────
    const ratingMatch = path.match(/^\/api\/levels\/([a-z0-9-]+)\/rate$/);
    if (ratingMatch !== null && method === 'POST') {
        return handleRateLevel(request, env, ratingMatch[1]!);
    }

    // ── Leaderboards ──────────────────────────────────────────────
    const leaderboardMatch = path.match(/^\/api\/leaderboard\/([a-z0-9-]+)$/);
    if (leaderboardMatch !== null && method === 'GET') {
        return handleGetLeaderboard(env, leaderboardMatch[1]!, url);
    }

    // ── 404 ───────────────────────────────────────────────────────
    return jsonResponse({ error: 'Not found', path }, 404);
}

// ── Database ─────────────────────────────────────────────────────

function getConnectionString(env: Env): string {
    // Prefer Hyperdrive (connection pooling at the edge)
    // Fall back to direct DATABASE_URL for development
    try {
        if (env.HYPERDRIVE !== undefined) {
            return env.HYPERDRIVE.connectionString;
        }
    } catch {
        // Hyperdrive not configured
    }
    return env.DATABASE_URL;
}

async function withDB<T>(env: Env, fn: (client: pg.Client) => Promise<T>): Promise<T> {
    const client = new pg.Client({ connectionString: getConnectionString(env) });
    await client.connect();
    try {
        return await fn(client);
    } finally {
        await client.end();
    }
}

// ── Crypto ───────────────────────────────────────────────────────

const PBKDF2_ITERATIONS = 100_000;
const SALT_BYTES = 16;
const HASH_BYTES = 32;

async function hashPassword(password: string): Promise<string> {
    const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(password),
        'PBKDF2',
        false,
        ['deriveBits'],
    );
    const derived = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
        key,
        HASH_BYTES * 8,
    );
    const saltHex = bufToHex(salt);
    const hashHex = bufToHex(new Uint8Array(derived));
    return `pbkdf2:sha256:${PBKDF2_ITERATIONS}:${saltHex}:${hashHex}`;
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
    const parts = stored.split(':');
    if (parts.length !== 5 || parts[0] !== 'pbkdf2') return false;
    const iterations = parseInt(parts[2]!, 10);
    const salt = hexToBuf(parts[3]!);
    const expectedHash = parts[4]!;

    const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(password),
        'PBKDF2',
        false,
        ['deriveBits'],
    );
    const derived = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
        key,
        HASH_BYTES * 8,
    );
    return bufToHex(new Uint8Array(derived)) === expectedHash;
}

function bufToHex(buf: Uint8Array): string {
    return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBuf(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    }
    return bytes;
}

// ── JWT ──────────────────────────────────────────────────────────

interface JWTPayload {
    readonly sub: string;      // user ID
    readonly username: string;
    readonly role: string;
    readonly iat: number;
    readonly exp: number;
}

const JWT_EXPIRY_SECS = 7 * 24 * 60 * 60; // 7 days

async function signJWT(payload: JWTPayload, secret: string): Promise<string> {
    const header = { alg: 'HS256', typ: 'JWT' };
    const headerB64 = base64url(JSON.stringify(header));
    const payloadB64 = base64url(JSON.stringify(payload));
    const message = `${headerB64}.${payloadB64}`;

    const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign'],
    );
    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
    const sigB64 = base64url(new Uint8Array(sig));
    return `${message}.${sigB64}`;
}

async function verifyJWT(token: string, secret: string): Promise<JWTPayload | null> {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;

        // Reject "none" algorithm attacks
        const headerJSON = atob(parts[0]!.replace(/-/g, '+').replace(/_/g, '/'));
        const header = JSON.parse(headerJSON) as { alg?: string };
        if (header.alg !== 'HS256') return null;

        const message = `${parts[0]}.${parts[1]}`;
        const sig = base64urlDecode(parts[2]!);

        const key = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(secret),
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['verify'],
        );

        const valid = await crypto.subtle.verify('HMAC', key, sig, new TextEncoder().encode(message));
        if (!valid) return null;

        const payload = JSON.parse(atob(parts[1]!.replace(/-/g, '+').replace(/_/g, '/'))) as JWTPayload;

        // Check expiry
        if (payload.exp < Math.floor(Date.now() / 1000)) return null;

        // Validate payload shape
        if (typeof payload.sub !== 'string' || typeof payload.username !== 'string') return null;

        return payload;
    } catch {
        // Malformed token — reject silently (no error leakage)
        return null;
    }
}

function base64url(input: string | Uint8Array): string {
    let b64: string;
    if (typeof input === 'string') {
        b64 = btoa(input);
    } else {
        b64 = btoa(String.fromCharCode(...input));
    }
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(input: string): Uint8Array {
    const b64 = input.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

// ── Input Sanitization ───────────────────────────────────────

/** Strip HTML tags and limit length. Prevents stored XSS. */
function sanitizeText(input: string, maxLength: number): string {
    return input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .slice(0, maxLength)
        .trim();
}

/** Validate email format. */
function isValidEmail(email: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

async function authenticateRequest(request: Request, env: Env): Promise<JWTPayload | null> {
    const authHeader = request.headers.get('Authorization');
    if (authHeader === null || !authHeader.startsWith('Bearer ')) return null;
    const token = authHeader.slice(7);
    return verifyJWT(token, env.JWT_SECRET);
}

// ── Route Handlers ───────────────────────────────────────────────

async function handleDBHealth(env: Env): Promise<Response> {
    try {
        await withDB(env, async (client) => {
            await client.query('SELECT 1');
        });
        return jsonResponse({ status: 'ok', database: 'connected' });
    } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : 'Unknown error';
        return jsonResponse({ status: 'error', database: 'disconnected', error: msg }, 503);
    }
}

// ── Auth: Register ───────────────────────────────────────────────

interface RegisterBody {
    readonly username: string;
    readonly password: string;
    readonly display_name?: string;
    readonly email?: string;
}

async function handleRegister(request: Request, env: Env): Promise<Response> {
    const body = await request.json() as RegisterBody;

    // Validate
    if (!body.username || typeof body.username !== 'string' || body.username.length < 3 || body.username.length > 30) {
        return jsonResponse({ error: 'Username must be 3-30 characters' }, 400);
    }
    if (!body.password || typeof body.password !== 'string' || body.password.length < 8) {
        return jsonResponse({ error: 'Password must be at least 8 characters' }, 400);
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(body.username)) {
        return jsonResponse({ error: 'Username can only contain letters, numbers, hyphens, and underscores' }, 400);
    }

    // Validate email if provided
    if (body.email !== undefined && body.email !== null && !isValidEmail(body.email)) {
        return jsonResponse({ error: 'Invalid email format' }, 400);
    }

    const passwordHash = await hashPassword(body.password);
    const displayName = sanitizeText(body.display_name ?? body.username, 100);

    try {
        const result = await withDB(env, async (client) => {
            const res = await client.query(
                `INSERT INTO users (username, display_name, email, password_hash)
                 VALUES ($1, $2, $3, $4)
                 RETURNING id, username, display_name, role, reputation, created_at`,
                [body.username.toLowerCase(), displayName, body.email ?? null, passwordHash],
            );
            return res.rows[0] as { id: string; username: string; display_name: string; role: string; reputation: number; created_at: string };
        });

        // Issue JWT
        const now = Math.floor(Date.now() / 1000);
        const token = await signJWT({
            sub: result.id,
            username: result.username,
            role: result.role,
            iat: now,
            exp: now + JWT_EXPIRY_SECS,
        }, env.JWT_SECRET);

        return jsonResponse({
            user: {
                id: result.id,
                username: result.username,
                display_name: result.display_name,
                role: result.role,
                reputation: result.reputation,
            },
            token,
        }, 201);
    } catch (error: unknown) {
        if (error instanceof Error && error.message.includes('unique')) {
            return jsonResponse({ error: 'Username or email already taken' }, 409);
        }
        throw error;
    }
}

// ── Auth: Login ──────────────────────────────────────────────────

interface LoginBody {
    readonly username: string;
    readonly password: string;
}

async function handleLogin(request: Request, env: Env): Promise<Response> {
    const body = await request.json() as LoginBody;

    if (!body.username || !body.password) {
        return jsonResponse({ error: 'Username and password required' }, 400);
    }

    const user = await withDB(env, async (client) => {
        const res = await client.query(
            `SELECT id, username, display_name, password_hash, role, reputation, banned, ban_reason
             FROM users WHERE username = $1`,
            [body.username.toLowerCase()],
        );
        return res.rows[0] as { id: string; username: string; display_name: string; password_hash: string; role: string; reputation: number; banned: boolean; ban_reason: string | null } | undefined;
    });

    if (user === undefined) {
        return jsonResponse({ error: 'Invalid credentials' }, 401);
    }

    if (user.banned) {
        return jsonResponse({ error: 'Account suspended', reason: user.ban_reason }, 403);
    }

    if (user.password_hash === null) {
        return jsonResponse({ error: 'No password set for this account' }, 401);
    }

    const valid = await verifyPassword(body.password, user.password_hash);
    if (!valid) {
        return jsonResponse({ error: 'Invalid credentials' }, 401);
    }

    // Update last_active_at
    await withDB(env, async (client) => {
        await client.query('UPDATE users SET last_active_at = NOW() WHERE id = $1', [user.id]);
    });

    const now = Math.floor(Date.now() / 1000);
    const token = await signJWT({
        sub: user.id,
        username: user.username,
        role: user.role,
        iat: now,
        exp: now + JWT_EXPIRY_SECS,
    }, env.JWT_SECRET);

    return jsonResponse({
        user: {
            id: user.id,
            username: user.username,
            display_name: user.display_name,
            role: user.role,
            reputation: user.reputation,
        },
        token,
    });
}

// ── Auth: Me ─────────────────────────────────────────────────────

async function handleMe(request: Request, env: Env): Promise<Response> {
    const auth = await authenticateRequest(request, env);
    if (auth === null) {
        return jsonResponse({ error: 'Unauthorized' }, 401);
    }

    const user = await withDB(env, async (client) => {
        const res = await client.query(
            `SELECT id, username, display_name, email, avatar_url, bio, role, reputation,
                    levels_created, levels_played, total_score, created_at, last_active_at
             FROM users WHERE id = $1`,
            [auth.sub],
        );
        return res.rows[0];
    });

    if (user === undefined) {
        return jsonResponse({ error: 'User not found' }, 404);
    }

    return jsonResponse({ user });
}

// ── Levels: List ─────────────────────────────────────────────────

async function handleListLevels(env: Env, url: URL): Promise<Response> {
    const page = Math.max(1, parseInt(url.searchParams.get('page') ?? '1', 10));
    const limit = Math.min(50, Math.max(1, parseInt(url.searchParams.get('limit') ?? '20', 10)));
    const offset = (page - 1) * limit;
    const sort = url.searchParams.get('sort') ?? 'newest';
    const difficulty = url.searchParams.get('difficulty');
    const mode = url.searchParams.get('mode');
    const search = url.searchParams.get('q');

    let orderBy: string;
    switch (sort) {
        case 'popular': orderBy = 'l.downloads DESC'; break;
        case 'top-rated': orderBy = 'l.avg_rating DESC'; break;
        case 'plays': orderBy = 'l.plays DESC'; break;
        default: orderBy = 'l.published_at DESC NULLS LAST, l.created_at DESC';
    }

    const conditions: string[] = ["l.status IN ('published', 'featured')"];
    const params: unknown[] = [];
    let paramIdx = 1;

    if (difficulty !== null) {
        conditions.push(`l.difficulty = $${paramIdx++}`);
        params.push(difficulty);
    }
    if (mode !== null) {
        conditions.push(`l.mode = $${paramIdx++}`);
        params.push(mode);
    }
    if (search !== null && search.length > 0) {
        conditions.push(`to_tsvector('english', l.title || ' ' || l.description || ' ' || l.briefing) @@ plainto_tsquery('english', $${paramIdx++})`);
        params.push(search);
    }

    const where = conditions.join(' AND ');

    const result = await withDB(env, async (client) => {
        const countRes = await client.query(
            `SELECT COUNT(*)::int as total FROM levels l WHERE ${where}`,
            params,
        );
        const total = (countRes.rows[0] as { total: number }).total;

        const levelsRes = await client.query(
            `SELECT l.id, l.slug, l.title, l.description, l.briefing, l.difficulty, l.mode,
                    l.tags, l.vuln_classes, l.estimated_mins, l.version, l.status, l.featured,
                    l.downloads, l.plays, l.completions, l.avg_rating, l.rating_count,
                    l.created_at, l.published_at,
                    u.username as author_username, u.display_name as author_display_name
             FROM levels l
             JOIN users u ON l.author_id = u.id
             WHERE ${where}
             ORDER BY ${orderBy}
             LIMIT $${paramIdx++} OFFSET $${paramIdx++}`,
            [...params, limit, offset],
        );

        return { total, levels: levelsRes.rows };
    });

    return jsonResponse({
        levels: result.levels,
        pagination: {
            page,
            limit,
            total: result.total,
            pages: Math.ceil(result.total / limit),
        },
    });
}

// ── Levels: Get by slug ──────────────────────────────────────────

async function handleGetLevel(env: Env, slug: string): Promise<Response> {
    const level = await withDB(env, async (client) => {
        const res = await client.query(
            `SELECT l.id, l.slug, l.title, l.description, l.briefing, l.difficulty, l.mode,
                    l.tags, l.vuln_classes, l.estimated_mins, l.worldspec, l.worldspec_hash,
                    l.version, l.status, l.featured, l.downloads, l.plays, l.completions,
                    l.avg_rating, l.rating_count, l.avg_completion_mins,
                    l.created_at, l.published_at,
                    u.id as author_id, u.username as author_username,
                    u.display_name as author_display_name, u.avatar_url as author_avatar
             FROM levels l
             JOIN users u ON l.author_id = u.id
             WHERE l.slug = $1 AND l.status IN ('published', 'featured')`,
            [slug],
        );
        return res.rows[0];
    });

    if (level === undefined) {
        return jsonResponse({ error: 'Level not found' }, 404);
    }

    // Increment downloads count
    await withDB(env, async (client) => {
        await client.query('UPDATE levels SET downloads = downloads + 1 WHERE slug = $1', [slug]);
    });

    return jsonResponse({ level });
}

// ── Levels: Create ───────────────────────────────────────────────

interface CreateLevelBody {
    readonly title: string;
    readonly slug: string;
    readonly description: string;
    readonly briefing: string;
    readonly difficulty: string;
    readonly mode: string;
    readonly tags: string[];
    readonly vuln_classes: string[];
    readonly estimated_mins: number;
    readonly worldspec: Record<string, unknown>;
}

async function handleCreateLevel(request: Request, env: Env): Promise<Response> {
    const auth = await authenticateRequest(request, env);
    if (auth === null) {
        return jsonResponse({ error: 'Unauthorized' }, 401);
    }

    const body = await request.json() as CreateLevelBody;

    // Validate required fields
    if (!body.title || !body.slug || !body.worldspec) {
        return jsonResponse({ error: 'title, slug, and worldspec are required' }, 400);
    }

    if (!/^[a-z0-9-]+$/.test(body.slug)) {
        return jsonResponse({ error: 'Slug must be lowercase alphanumeric with hyphens' }, 400);
    }

    // Hash the worldspec for integrity
    const worldspecJSON = JSON.stringify(body.worldspec);
    const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(worldspecJSON));
    const worldspecHash = bufToHex(new Uint8Array(hashBuffer));

    // Validate difficulty and mode against allowed values
    const VALID_DIFFICULTIES = ['beginner', 'easy', 'medium', 'hard', 'expert'];
    const VALID_MODES = ['attack', 'defense', 'mixed'];
    const difficulty = body.difficulty ?? 'medium';
    const mode = body.mode ?? 'attack';
    if (!VALID_DIFFICULTIES.includes(difficulty)) {
        return jsonResponse({ error: 'Invalid difficulty. Must be: ' + VALID_DIFFICULTIES.join(', ') }, 400);
    }
    if (!VALID_MODES.includes(mode)) {
        return jsonResponse({ error: 'Invalid mode. Must be: ' + VALID_MODES.join(', ') }, 400);
    }

    try {
        const result = await withDB(env, async (client) => {
            const res = await client.query(
                `INSERT INTO levels (author_id, slug, title, description, briefing, difficulty, mode,
                                     tags, vuln_classes, estimated_mins, worldspec, worldspec_hash)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                 RETURNING id, slug, title, status, created_at`,
                [
                    auth.sub,
                    body.slug,
                    sanitizeText(body.title, 200),
                    sanitizeText(body.description ?? '', 5000),
                    sanitizeText(body.briefing ?? '', 5000),
                    difficulty,
                    mode,
                    (body.tags ?? []).map(t => sanitizeText(t, 50)),
                    (body.vuln_classes ?? []).map(v => sanitizeText(v, 50)),
                    Math.min(Math.max(1, body.estimated_mins ?? 30), 480),
                    body.worldspec,
                    worldspecHash,
                ],
            );
            return res.rows[0];
        });

        // Increment author's levels_created
        await withDB(env, async (client) => {
            await client.query('UPDATE users SET levels_created = levels_created + 1 WHERE id = $1', [auth.sub]);
        });

        return jsonResponse({ level: result }, 201);
    } catch (error: unknown) {
        if (error instanceof Error && error.message.includes('unique')) {
            return jsonResponse({ error: 'A level with this slug already exists' }, 409);
        }
        throw error;
    }
}

// ── Ratings ──────────────────────────────────────────────────────

interface RateLevelBody {
    readonly score: number;
    readonly review?: string;
    readonly difficulty_felt?: string;
    readonly completed: boolean;
    readonly completion_mins?: number;
}

async function handleRateLevel(request: Request, env: Env, slug: string): Promise<Response> {
    const auth = await authenticateRequest(request, env);
    if (auth === null) {
        return jsonResponse({ error: 'Unauthorized' }, 401);
    }

    const body = await request.json() as RateLevelBody;

    if (!body.score || body.score < 1 || body.score > 5) {
        return jsonResponse({ error: 'Score must be 1-5' }, 400);
    }

    const result = await withDB(env, async (client) => {
        // Get level ID from slug
        const levelRes = await client.query('SELECT id FROM levels WHERE slug = $1', [slug]);
        const level = levelRes.rows[0] as { id: string } | undefined;
        if (level === undefined) {
            return { error: 'Level not found' };
        }

        // Validate difficulty_felt
        const VALID_DIFFICULTY_FELT = ['too-easy', 'just-right', 'too-hard'];
        if (body.difficulty_felt !== undefined && !VALID_DIFFICULTY_FELT.includes(body.difficulty_felt)) {
            return { error: 'Invalid difficulty_felt' };
        }

        // Upsert rating
        await client.query(
            `INSERT INTO ratings (level_id, user_id, score, review, difficulty_felt, completed, completion_mins)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (level_id, user_id) DO UPDATE SET
                score = EXCLUDED.score,
                review = EXCLUDED.review,
                difficulty_felt = EXCLUDED.difficulty_felt,
                completed = EXCLUDED.completed,
                completion_mins = EXCLUDED.completion_mins`,
            [level.id, auth.sub, body.score, body.review !== undefined ? sanitizeText(body.review, 2000) : null, body.difficulty_felt ?? null, body.completed ?? false, body.completion_mins ?? null],
        );

        // Update aggregate on levels table
        await client.query(
            `UPDATE levels SET
                avg_rating = (SELECT AVG(score)::real FROM ratings WHERE level_id = $1),
                rating_count = (SELECT COUNT(*)::int FROM ratings WHERE level_id = $1),
                completions = (SELECT COUNT(*)::int FROM ratings WHERE level_id = $1 AND completed = true)
             WHERE id = $1`,
            [level.id],
        );

        return { success: true };
    });

    if ('error' in result) {
        return jsonResponse({ error: result.error }, 404);
    }

    return jsonResponse({ status: 'ok' });
}

// ── Leaderboards ─────────────────────────────────────────────────

async function handleGetLeaderboard(env: Env, slug: string, url: URL): Promise<Response> {
    const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get('limit') ?? '25', 10)));

    const result = await withDB(env, async (client) => {
        const res = await client.query(
            `SELECT le.score, le.time_secs, le.hints_used, le.achieved_at,
                    u.username, u.display_name, u.avatar_url
             FROM leaderboard_entries le
             JOIN levels l ON le.level_id = l.id
             JOIN users u ON le.user_id = u.id
             WHERE l.slug = $1
             ORDER BY le.score DESC, le.time_secs ASC
             LIMIT $2`,
            [slug, limit],
        );
        return res.rows;
    });

    return jsonResponse({ leaderboard: result });
}

// ── Helpers ───────────────────────────────────────────────────────

function jsonResponse(data: unknown, status = 200): Response {
    return new Response(JSON.stringify(data), {
        status,
        headers: { 'Content-Type': 'application/json' },
    });
}

function corsResponse(env: Env, response: Response, request?: Request): Response {
    const headers = new Headers(response.headers);

    // Dynamic CORS: allow known origins only
    // env.CORS_ORIGIN reserved for override when Hyperdrive is configured
    const configuredOrigin = env.CORS_ORIGIN;
    const allowedOrigins = configuredOrigin === '*' ? null : [
        'https://variant.santh.io',
        'https://santh-variant.pages.dev',
        'http://localhost:5173',  // Vite dev server
    ];
    const requestOrigin = request?.headers.get('Origin') ?? '';
    if (allowedOrigins === null) {
        headers.set('Access-Control-Allow-Origin', '*');
    } else {
        const origin = allowedOrigins.includes(requestOrigin) ? requestOrigin : allowedOrigins[0]!;
        headers.set('Access-Control-Allow-Origin', origin);
        headers.set('Vary', 'Origin');
    }
    headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    headers.set('Access-Control-Max-Age', '86400');

    // Security headers
    headers.set('X-Content-Type-Options', 'nosniff');
    headers.set('X-Frame-Options', 'DENY');
    headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    headers.set('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

    // Remove server identification
    headers.delete('Server');

    return new Response(response.body, {
        status: response.status,
        headers,
    });
}
