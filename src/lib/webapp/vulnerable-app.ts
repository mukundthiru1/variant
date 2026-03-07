/// <reference lib="es2015" />
/// <reference lib="es2016.array.include" />

/**
 * VARIANT — Vulnerable Web Application Template
 *
 * A configurable, realistic vulnerable web application for
 * security training scenarios. Level designers can embed this
 * in their scenarios with specific vulnerabilities enabled.
 *
 * FEATURES:
 *   - Realistic HTML/CSS interface
 *   - Session management with cookies
 *   - Multiple vulnerability types (configurable)
 *   - REST API endpoints
 *   - File upload handling
 *   - Error pages (404, 403, 500)
 *
 * VULNERABILITIES:
 *   - sqli: SQL Injection in login
 *   - xss: Reflected XSS in search
 *   - idor: Insecure Direct Object Reference in profile
 *   - mass_assignment: Mass assignment in registration
 *   - broken_auth: Broken authentication in admin panel
 *   - unrestricted_upload: Unrestricted file upload
 *   - ssrf: Server-Side Request Forgery in export
 *   - bola: Broken Object Level Authorization in API
 *   - info_disclosure: Information disclosure in config
 *   - exposed_git: Exposed .git directory
 *   - exposed_backup: Exposed backup files
 *   - info_leak: PHP info / server status pages
 *
 * DESIGN: Implements ServiceHandler interface. Integrates
 * with the HTTP service and request pipeline.
 */

import type {
    ServiceHandler,
    ServiceRequest,
    ServiceResponse,
    ServiceContext,
} from '../services/types';

// ── Types ──────────────────────────────────────────────────────

/** Vulnerability identifiers */
export type VulnerabilityId =
    | 'sqli'
    | 'xss'
    | 'idor'
    | 'mass_assignment'
    | 'broken_auth'
    | 'unrestricted_upload'
    | 'ssrf'
    | 'bola'
    | 'info_disclosure'
    | 'exposed_git'
    | 'exposed_backup'
    | 'info_leak';

/** Vulnerable web application configuration */
export interface VulnerableWebAppConfig {
    /** Port to listen on. Default: 80. */
    readonly port?: number;
    /** Server name for headers. Default: 'Apache/2.4.41'. */
    readonly serverName?: string;
    /** Web root in VFS. Default: '/var/www'. */
    readonly webRoot?: string;
    /** Active vulnerabilities. Default: all enabled. */
    readonly vulns?: readonly VulnerabilityId[];
    /** Application name. Default: 'CyberShop'. */
    readonly appName?: string;
    /** Session secret (for cookie signing simulation). */
    readonly sessionSecret?: string;
}

/** Parsed HTTP request */
interface ParsedRequest {
    readonly method: string;
    readonly path: string;
    readonly query: Map<string, string>;
    readonly headers: Map<string, string>;
    readonly body: string;
    readonly cookies: Map<string, string>;
    readonly params: Map<string, string>;
}

/** Route handler function */
type RouteHandler = (
    req: ParsedRequest,
    ctx: ServiceContext,
    session: SessionData,
) => ResponseData;

/** Route definition */
interface Route {
    readonly method: string;
    readonly path: string;
    readonly handler: RouteHandler;
    readonly requireAuth?: boolean;
}

/** Session data */
export interface SessionData {
    userId: string | null;
    username: string | null;
    isAdmin: boolean;
    flashMessage: string | null;
}

/** Response data */
interface ResponseData {
    readonly status: number;
    readonly body: string;
    readonly contentType?: string;
    readonly headers?: Map<string, string>;
    readonly setCookie?: string[];
}

/** Simulated database user */
export interface User {
    readonly id: number;
    readonly username: string;
    readonly password: string;
    readonly email: string;
    readonly role: 'user' | 'admin';
    readonly profile: {
        readonly fullName: string;
        readonly bio: string;
        readonly avatar: string;
    };
}

// ── Factory ────────────────────────────────────────────────────

export function createVulnerableWebApp(
    config: VulnerableWebAppConfig,
): ServiceHandler {
    const port = config.port ?? 80;
    const webRoot = config.webRoot ?? '/var/www';
    const serverName = config.serverName ?? 'Apache/2.4.41 (Ubuntu)';
    const appName = config.appName ?? 'CyberShop';
    const allVulns: VulnerabilityId[] = [
        'sqli', 'xss', 'idor', 'mass_assignment', 'broken_auth',
        'unrestricted_upload', 'ssrf', 'bola', 'info_disclosure',
        'exposed_git', 'exposed_backup', 'info_leak',
    ];
    const activeVulns = new Set<VulnerabilityId>(config.vulns ?? allVulns);

    // Simulated database
    const users: User[] = [
        {
            id: 1,
            username: 'admin',
            password: 'admin123',
            email: 'admin@cybershop.local',
            role: 'admin',
            profile: {
                fullName: 'System Administrator',
                bio: 'Managing the CyberShop platform since 2020.',
                avatar: '/static/admin.png',
            },
        },
        {
            id: 2,
            username: 'john_doe',
            password: 'password123',
            email: 'john@example.com',
            role: 'user',
            profile: {
                fullName: 'John Doe',
                bio: 'Cyber security enthusiast and shopper.',
                avatar: '/static/user1.png',
            },
        },
        {
            id: 3,
            username: 'jane_smith',
            password: 'qwerty123',
            email: 'jane@example.com',
            role: 'user',
            profile: {
                fullName: 'Jane Smith',
                bio: 'Tech blogger and reviewer.',
                avatar: '/static/user2.png',
            },
        },
    ];

    const products = [
        { id: 1, name: 'USB Rubber Ducky', price: 49.99, category: 'hacking' },
        { id: 2, name: 'WiFi Pineapple', price: 99.99, category: 'hacking' },
        { id: 3, name: 'HackRF One', price: 299.99, category: 'sdr' },
        { id: 4, name: 'Proxmark3', price: 159.99, category: 'rfid' },
        { id: 5, name: 'Bus Pirate', price: 39.99, category: 'hardware' },
    ];

    // Session store (in-memory, per instance)
    const sessions = new Map<string, SessionData>();

    // Routes registry
    const routes: Route[] = [];

    function registerRoute(route: Route): void {
        routes.push(route);
    }

    function isVulnActive(id: VulnerabilityId): boolean {
        return activeVulns.has(id);
    }

    // ── Request Parsing ─────────────────────────────────────────

    function parseRequest(
        text: string,
        routeMatch?: { params: Map<string, string> },
    ): ParsedRequest | null {
        const lines = text.split('\r\n');
        if (lines.length === 0) return null;

        const requestLine = lines[0]!;
        const parts = requestLine.split(' ');
        if (parts.length < 2) return null;

        const method = parts[0]!;
        const fullPath = parts[1]!;

        // Parse query string
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

        // Parse cookies
        const cookies = new Map<string, string>();
        const cookieHeader = headers.get('cookie');
        if (cookieHeader !== undefined) {
            for (const pair of cookieHeader.split(';')) {
                const eqIdx = pair.indexOf('=');
                if (eqIdx > 0) {
                    const key = pair.slice(0, eqIdx).trim();
                    const value = pair.slice(eqIdx + 1).trim();
                    cookies.set(key, value);
                }
            }
        }

        // Parse body
        let body = '';
        if (bodyStart >= 0) {
            body = lines.slice(bodyStart).join('\r\n');
        }

        return {
            method,
            path: path ?? '/',
            query,
            headers,
            body,
            cookies,
            params: routeMatch?.params ?? new Map(),
        };
    }

    function parseFormBody(body: string): Map<string, string> {
        const form = new Map<string, string>();
        for (const pair of body.split('&')) {
            const eqIdx = pair.indexOf('=');
            const key = eqIdx >= 0 ? pair.slice(0, eqIdx) : pair;
            const value = eqIdx >= 0 ? pair.slice(eqIdx + 1) : '';
            if (key !== undefined) {
                try {
                    form.set(decodeURIComponent(key), decodeURIComponent(value ?? ''));
                } catch {
                    form.set(key, value ?? '');
                }
            }
        }
        return form;
    }

    // ── Session Management ──────────────────────────────────────

    function getSession(req: ParsedRequest): SessionData {
        const sessionId = req.cookies.get('session_id');
        if (sessionId !== undefined && sessions.has(sessionId)) {
            const session = sessions.get(sessionId)!;
            // Clear flash message after reading
            const data = { ...session };
            sessions.set(sessionId, { ...session, flashMessage: null });
            return data;
        }
        return { userId: null, username: null, isAdmin: false, flashMessage: null };
    }

    function createSession(user: User): { sessionId: string; data: SessionData } {
        const sessionId = `sess_${Math.random().toString(36).slice(2)}_${Date.now()}`;
        const data: SessionData = {
            userId: String(user.id),
            username: user.username,
            isAdmin: user.role === 'admin',
            flashMessage: null,
        };
        sessions.set(sessionId, data);
        return { sessionId, data };
    }

    function destroySession(sessionId: string): void {
        sessions.delete(sessionId);
    }

    // ── Route Matching ──────────────────────────────────────────

    function matchRoute(
        method: string,
        path: string,
    ): { route: Route; params: Map<string, string> } | null {
        for (const route of routes) {
            if (route.method !== '*' && route.method.toUpperCase() !== method.toUpperCase()) {
                continue;
            }

            // Exact match
            if (route.path === path) {
                return { route, params: new Map() };
            }

            // Wildcard match
            if (route.path.endsWith('*')) {
                const prefix = route.path.slice(0, -1);
                if (path.startsWith(prefix)) {
                    return { route, params: new Map() };
                }
            }

            // Parameter match
            const routeParts = route.path.split('/');
            const pathParts = path.split('/');
            if (routeParts.length !== pathParts.length) continue;

            const params = new Map<string, string>();
            let match = true;

            for (let i = 0; i < routeParts.length; i++) {
                const routePart = routeParts[i]!;
                const pathPart = pathParts[i]!;

                if (routePart.startsWith(':')) {
                    params.set(routePart.slice(1), decodeURIComponent(pathPart));
                } else if (routePart !== pathPart) {
                    match = false;
                    break;
                }
            }

            if (match) {
                return { route, params };
            }
        }
        return null;
    }

    // ── HTML Templates ──────────────────────────────────────────

    function renderPage(
        title: string,
        content: string,
        session: SessionData,
        options?: { noContainer?: boolean },
    ): string {
        const flashHtml = session.flashMessage
            ? `<div class="alert alert-info">${escapeHtml(session.flashMessage)}</div>`
            : '';

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${escapeHtml(title)} - ${escapeHtml(appName)}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: #eaeaea;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 0 20px; }
        header {
            background: rgba(0,0,0,0.3);
            backdrop-filter: blur(10px);
            border-bottom: 1px solid rgba(255,255,255,0.1);
            padding: 1rem 0;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        nav { display: flex; justify-content: space-between; align-items: center; }
        .logo {
            font-size: 1.5rem;
            font-weight: bold;
            background: linear-gradient(90deg, #00d4ff, #7b2cbf);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-decoration: none;
        }
        .nav-links { display: flex; gap: 2rem; align-items: center; }
        .nav-links a {
            color: #eaeaea;
            text-decoration: none;
            transition: color 0.3s;
        }
        .nav-links a:hover { color: #00d4ff; }
        .btn {
            display: inline-block;
            padding: 0.5rem 1.5rem;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 500;
            transition: all 0.3s;
            border: none;
            cursor: pointer;
            font-size: 1rem;
        }
        .btn-primary {
            background: linear-gradient(90deg, #00d4ff, #7b2cbf);
            color: white;
        }
        .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(0,212,255,0.3); }
        .btn-secondary {
            background: rgba(255,255,255,0.1);
            color: #eaeaea;
            border: 1px solid rgba(255,255,255,0.2);
        }
        .btn-secondary:hover { background: rgba(255,255,255,0.2); }
        main { padding: 2rem 0; }
        .card {
            background: rgba(255,255,255,0.05);
            border-radius: 16px;
            padding: 2rem;
            border: 1px solid rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            margin-bottom: 1.5rem;
        }
        .card h2 { margin-bottom: 1rem; color: #00d4ff; }
        .card h3 { margin: 1rem 0 0.5rem; color: #eaeaea; }
        .form-group { margin-bottom: 1.5rem; }
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: #b0b0b0;
        }
        .form-group input,
        .form-group textarea,
        .form-group select {
            width: 100%;
            padding: 0.75rem 1rem;
            border-radius: 8px;
            border: 1px solid rgba(255,255,255,0.2);
            background: rgba(0,0,0,0.2);
            color: #eaeaea;
            font-size: 1rem;
        }
        .form-group input:focus,
        .form-group textarea:focus {
            outline: none;
            border-color: #00d4ff;
        }
        .alert {
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1rem;
        }
        .alert-info { background: rgba(0,212,255,0.1); border: 1px solid rgba(0,212,255,0.3); color: #00d4ff; }
        .alert-error { background: rgba(255,71,87,0.1); border: 1px solid rgba(255,71,87,0.3); color: #ff4757; }
        .alert-success { background: rgba(46,213,115,0.1); border: 1px solid rgba(46,213,115,0.3); color: #2ed573; }
        .product-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 1.5rem;
        }
        .product-card {
            background: rgba(255,255,255,0.03);
            border-radius: 12px;
            padding: 1.5rem;
            border: 1px solid rgba(255,255,255,0.1);
            transition: transform 0.3s;
        }
        .product-card:hover { transform: translateY(-5px); }
        .product-card h3 { color: #00d4ff; margin-bottom: 0.5rem; }
        .price { font-size: 1.25rem; color: #2ed573; font-weight: bold; }
        .category { color: #b0b0b0; font-size: 0.875rem; }
        .search-box {
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .search-box input { flex: 1; }
        footer {
            text-align: center;
            padding: 2rem 0;
            color: #666;
            border-top: 1px solid rgba(255,255,255,0.1);
            margin-top: 2rem;
        }
        .user-menu { display: flex; align-items: center; gap: 1rem; }
        .badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: bold;
        }
        .badge-admin { background: #ff4757; color: white; }
        .badge-user { background: #2ed573; color: white; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }
        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        th { color: #00d4ff; font-weight: 600; }
        .code-block {
            background: rgba(0,0,0,0.3);
            padding: 1rem;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
            margin: 1rem 0;
        }
        .upload-area {
            border: 2px dashed rgba(0,212,255,0.3);
            border-radius: 12px;
            padding: 3rem;
            text-align: center;
            background: rgba(0,212,255,0.02);
        }
        .upload-area:hover { border-color: #00d4ff; }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <nav>
                <a href="/" class="logo">${escapeHtml(appName)}</a>
                <div class="nav-links">
                    <a href="/">Home</a>
                    <a href="/search">Search</a>
                    ${session.isAdmin ? '<a href="/admin">Admin</a>' : ''}
                    ${session.username
                        ? `<div class="user-menu">
                            <a href="/profile/${session.userId}">${escapeHtml(session.username)}</a>
                            <span class="badge badge-${session.isAdmin ? 'admin' : 'user'}">${session.isAdmin ? 'Admin' : 'User'}</span>
                            <a href="/logout" class="btn btn-secondary">Logout</a>
                           </div>`
                        : '<a href="/login" class="btn btn-primary">Login</a>'}
                </div>
            </nav>
        </div>
    </header>
    <main>
        <div class="container">
            ${flashHtml}
            ${options?.noContainer ? content : `<div class="card">${content}</div>`}
        </div>
    </main>
    <footer>
        <div class="container">
            <p>&copy; 2024 ${escapeHtml(appName)}. All rights reserved.</p>
            <p style="margin-top: 0.5rem; font-size: 0.875rem;">Powered by ${escapeHtml(serverName)}</p>
        </div>
    </footer>
</body>
</html>`;
    }

    function renderErrorPage(
        status: number,
        message: string,
        session: SessionData,
    ): string {
        const titles: Record<number, string> = {
            403: '403 Forbidden',
            404: '404 Not Found',
            500: '500 Internal Server Error',
        };

        const content = `
            <div style="text-align: center; padding: 3rem 0;">
                <h1 style="font-size: 4rem; color: #ff4757; margin-bottom: 1rem;">${status}</h1>
                <p style="font-size: 1.25rem; color: #b0b0b0; margin-bottom: 2rem;">${escapeHtml(message)}</p>
                <a href="/" class="btn btn-primary">Go Home</a>
            </div>
        `;

        return renderPage(titles[status] ?? 'Error', content, session, { noContainer: true });
    }

    // ── Route Handlers ──────────────────────────────────────────

    // Home page
    registerRoute({
        method: 'GET',
        path: '/',
        handler: (_req, _ctx, session) => {
            const content = `
                <div style="text-align: center; padding: 2rem 0;">
                    <h1 style="font-size: 2.5rem; margin-bottom: 1rem;">Welcome to ${escapeHtml(appName)}</h1>
                    <p style="font-size: 1.125rem; color: #b0b0b0; margin-bottom: 2rem;">
                        Your one-stop shop for penetration testing equipment and security research tools.
                    </p>
                    <div style="display: flex; gap: 1rem; justify-content: center;">
                        <a href="/search" class="btn btn-primary">Browse Products</a>
                        ${!session.username ? '<a href="/register" class="btn btn-secondary">Create Account</a>' : ''}
                    </div>
                </div>
                <h2 style="margin: 2rem 0 1rem; color: #00d4ff;">Featured Products</h2>
                <div class="product-grid">
                    ${products.slice(0, 3).map(p => `
                        <div class="product-card">
                            <h3>${escapeHtml(p.name)}</h3>
                            <p class="category">${escapeHtml(p.category.toUpperCase())}</p>
                            <p class="price">$${p.price.toFixed(2)}</p>
                        </div>
                    `).join('')}
                </div>
            `;
            return {
                status: 200,
                body: renderPage('Home', content, session, { noContainer: true }),
            };
        },
    });

    // Login page (SQLi vulnerable)
    registerRoute({
        method: 'GET',
        path: '/login',
        handler: (_req, _ctx, session) => {
            const content = `
                <h2>Login</h2>
                <form method="POST" action="/login">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Login</button>
                </form>
                <p style="margin-top: 1.5rem; text-align: center;">
                    Don't have an account? <a href="/register" style="color: #00d4ff;">Register</a>
                </p>
            `;
            return { status: 200, body: renderPage('Login', content, session) };
        },
    });

    registerRoute({
        method: 'POST',
        path: '/login',
        handler: (req, _ctx, session) => {
            const form = parseFormBody(req.body);
            const username = form.get('username') ?? '';
            const password = form.get('password') ?? '';

            let user: User | undefined;

            if (isVulnActive('sqli')) {
                // Vulnerable: Simulated SQL injection
                // In a real SQLi scenario, ' OR '1'='1' -- would bypass auth
                if (username.includes("'") || password.includes("'")) {
                    // Simulate SQL injection bypass
                    const sqliPatterns = [
                        /'\s*or\s*['"\d]/i,
                        /'\s*or\s*'\s*=\s*'/i,
                        /'\s*or\s*1\s*=\s*1/i,
                        /admin'--/i,
                    ];
                    const isSqli = sqliPatterns.some(p => p.test(username) || p.test(password));
                    if (isSqli) {
                        // SQLi successful - log in as first user (admin)
                        user = users[0];
                    }
                }
            }

            if (user === undefined) {
                // Normal authentication
                user = users.find(u => u.username === username && u.password === password);
            }

            if (user !== undefined) {
                const { sessionId } = createSession(user);
                return {
                    status: 302,
                    body: '',
                    headers: new Map([['location', '/']]),
                    setCookie: [`session_id=${sessionId}; HttpOnly; Path=/`],
                };
            }

            const content = `
                <div class="alert alert-error">Invalid username or password</div>
                <h2>Login</h2>
                <form method="POST" action="/login">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username" value="${escapeHtml(username)}" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Login</button>
                </form>
            `;
            return { status: 401, body: renderPage('Login', content, session) };
        },
    });

    // Register page (mass assignment vulnerable)
    registerRoute({
        method: 'GET',
        path: '/register',
        handler: (_req, _ctx, session) => {
            const content = `
                <h2>Create Account</h2>
                <form method="POST" action="/register">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="email">Email</label>
                        <input type="email" id="email" name="email" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <div class="form-group">
                        <label for="fullName">Full Name</label>
                        <input type="text" id="fullName" name="fullName" required>
                    </div>
                    ${isVulnActive('mass_assignment')
                        ? '<input type="hidden" name="role" value="user">'
                        : ''}
                    <button type="submit" class="btn btn-primary">Register</button>
                </form>
            `;
            return { status: 200, body: renderPage('Register', content, session) };
        },
    });

    registerRoute({
        method: 'POST',
        path: '/register',
        handler: (req, _ctx, session) => {
            const form = parseFormBody(req.body);
            const username = form.get('username') ?? '';
            const email = form.get('email') ?? '';
            const password = form.get('password') ?? '';
            const fullName = form.get('fullName') ?? '';

            if (!username || !email || !password) {
                return {
                    status: 400,
                    body: renderPage('Register', '<div class="alert alert-error">All fields are required</div>', session),
                };
            }

            // Check if username exists
            if (users.some(u => u.username === username)) {
                return {
                    status: 409,
                    body: renderPage('Register', '<div class="alert alert-error">Username already taken</div>', session),
                };
            }

            // Mass assignment vulnerability - accept role from form
            let role: 'user' | 'admin' = 'user';
            if (isVulnActive('mass_assignment')) {
                const requestedRole = form.get('role');
                if (requestedRole === 'admin') {
                    role = 'admin';
                }
            }

            const newUser: User = {
                id: users.length + 1,
                username,
                password,
                email,
                role,
                profile: {
                    fullName,
                    bio: '',
                    avatar: '/static/default.png',
                },
            };

            users.push(newUser);

            const { sessionId } = createSession(newUser);
            return {
                status: 302,
                body: '',
                headers: new Map([['location', '/']]),
                setCookie: [`session_id=${sessionId}; HttpOnly; Path=/`],
            };
        },
    });

    // Logout
    registerRoute({
        method: 'GET',
        path: '/logout',
        handler: (req, _ctx, _session) => {
            const sessionId = req.cookies.get('session_id');
            if (sessionId !== undefined) {
                destroySession(sessionId);
            }
            return {
                status: 302,
                body: '',
                headers: new Map([['location', '/login']]),
                setCookie: ['session_id=; HttpOnly; Path=/; Max-Age=0'],
            };
        },
    });

    // Profile page (IDOR vulnerable)
    registerRoute({
        method: 'GET',
        path: '/profile/:id',
        handler: (req, _ctx, session) => {
            const userId = req.params.get('id');
            const user = users.find(u => String(u.id) === userId);

            if (user === undefined) {
                return {
                    status: 404,
                    body: renderErrorPage(404, 'User not found', session),
                };
            }

            // IDOR check - only check if vulnerability is NOT active
            if (!isVulnActive('idor')) {
                if (session.userId !== String(user.id) && !session.isAdmin) {
                    return {
                        status: 403,
                        body: renderErrorPage(403, 'You can only view your own profile', session),
                    };
                }
            }

            const content = `
                <div style="display: flex; gap: 2rem; align-items: start;">
                    <div style="text-align: center;">
                        <div style="width: 120px; height: 120px; border-radius: 50%; background: linear-gradient(135deg, #00d4ff, #7b2cbf); display: flex; align-items: center; justify-content: center; font-size: 3rem; margin-bottom: 1rem;">
                            ${escapeHtml(user.username[0]!.toUpperCase())}
                        </div>
                        <span class="badge badge-${user.role}">${user.role.toUpperCase()}</span>
                    </div>
                    <div style="flex: 1;">
                        <h2>${escapeHtml(user.profile.fullName)}</h2>
                        <p style="color: #b0b0b0; margin-bottom: 1rem;">@${escapeHtml(user.username)}</p>
                        <p>${escapeHtml(user.profile.bio || 'No bio yet.')}</p>
                        <hr style="border: none; border-top: 1px solid rgba(255,255,255,0.1); margin: 1.5rem 0;">
                        <p><strong>Email:</strong> ${escapeHtml(user.email)}</p>
                        <p><strong>Member since:</strong> 2024</p>
                    </div>
                </div>
            `;
            return { status: 200, body: renderPage('Profile', content, session) };
        },
    });

    // Search page (XSS vulnerable)
    registerRoute({
        method: 'GET',
        path: '/search',
        handler: (req, _ctx, session) => {
            const query = req.query.get('q') ?? '';

            let resultsHtml = '';
            if (query) {
                const filtered = products.filter(p =>
                    p.name.toLowerCase().includes(query.toLowerCase()) ||
                    p.category.toLowerCase().includes(query.toLowerCase()),
                );

                if (filtered.length > 0) {
                    resultsHtml = `
                        <h3>Search Results</h3>
                        <div class="product-grid">
                            ${filtered.map(p => `
                                <div class="product-card">
                                    <h3>${escapeHtml(p.name)}</h3>
                                    <p class="category">${escapeHtml(p.category.toUpperCase())}</p>
                                    <p class="price">$${p.price.toFixed(2)}</p>
                                </div>
                            `).join('')}
                        </div>
                    `;
                } else {
                    resultsHtml = `<div class="alert alert-info">No products found matching "${isVulnActive('xss') ? query : escapeHtml(query)}"</div>`;
                }
            }

            // XSS vulnerability - reflect query without escaping when active
            const displayQuery = isVulnActive('xss') ? query : escapeHtml(query);

            const content = `
                <h2>Search Products</h2>
                <form method="GET" action="/search" class="search-box">
                    <input type="text" name="q" value="${displayQuery}" placeholder="Search for products...">
                    <button type="submit" class="btn btn-primary">Search</button>
                </form>
                ${resultsHtml}
            `;
            return { status: 200, body: renderPage('Search', content, session) };
        },
    });

    // Upload page (unrestricted upload vulnerable)
    registerRoute({
        method: 'GET',
        path: '/upload',
        handler: (_req, _ctx, session) => {
            const content = `
                <h2>File Upload</h2>
                <p style="margin-bottom: 1.5rem; color: #b0b0b0;">Upload your avatar or product images.</p>
                <form method="POST" action="/upload" enctype="multipart/form-data">
                    <div class="upload-area">
                        <p style="margin-bottom: 1rem;">📁 Drag and drop files here or click to browse</p>
                        <input type="file" name="file" style="margin-bottom: 1rem;">
                        <br>
                        <button type="submit" class="btn btn-primary">Upload File</button>
                    </div>
                </form>
                <div style="margin-top: 2rem;">
                    <h3>Allowed File Types</h3>
                    <p style="color: #b0b0b0;">Images: .jpg, .jpeg, .png, .gif, .svg</p>
                    <p style="color: #b0b0b0;">Documents: .pdf, .doc, .docx</p>
                    ${isVulnActive('unrestricted_upload') ? '<p style="color: #b0b0b0;">Scripts: .php, .jsp, .asp, .py (admin only)</p>' : ''}
                </div>
            `;
            return { status: 200, body: renderPage('Upload', content, session) };
        },
    });

    registerRoute({
        method: 'POST',
        path: '/upload',
        handler: (req, _ctx, session) => {
            // Parse multipart form data (simplified)
            const contentType = req.headers.get('content-type') ?? '';
            let filename = 'unknown';
            let fileContent = '';

            if (contentType.includes('multipart/form-data')) {
                const boundary = contentType.split('boundary=')[1];
                if (boundary !== undefined) {
                    const parts = req.body.split(`--${boundary}`);
                    for (const part of parts) {
                        if (part.includes('Content-Disposition') && part.includes('filename=')) {
                            const filenameMatch = part.match(/filename="([^"]+)"/);
                            if (filenameMatch !== null) {
                                filename = filenameMatch[1]!;
                            }
                            const contentStart = part.indexOf('\r\n\r\n');
                            if (contentStart > 0) {
                                fileContent = part.slice(contentStart + 4).trim();
                            }
                        }
                    }
                }
            }

            // Check file extension
            const ext = filename.split('.').pop()?.toLowerCase() ?? '';
            const dangerousExts = ['php', 'jsp', 'asp', 'aspx', 'py', 'rb', 'sh'];

            if (dangerousExts.includes(ext) && !isVulnActive('unrestricted_upload')) {
                return {
                    status: 403,
                    body: renderPage('Upload', '<div class="alert alert-error">File type not allowed</div>', session),
                };
            }

            // Simulate file storage
            const uploadPath = `${webRoot}/uploads/${filename}`;

            const content = `
                <div class="alert alert-success">File uploaded successfully!</div>
                <h2>Upload Complete</h2>
                <p><strong>Filename:</strong> ${escapeHtml(filename)}</p>
                <p><strong>Size:</strong> ${fileContent.length} bytes</p>
                <p><strong>Stored at:</strong> ${escapeHtml(uploadPath)}</p>
                ${isVulnActive('unrestricted_upload') && dangerousExts.includes(ext)
                    ? `<div class="alert alert-info">Your file is accessible at: <a href="/uploads/${encodeURIComponent(filename)}" style="color: #00d4ff;">/uploads/${escapeHtml(filename)}</a></div>`
                    : ''}
                <a href="/upload" class="btn btn-secondary">Upload Another</a>
            `;
            return { status: 200, body: renderPage('Upload Complete', content, session) };
        },
    });

    // Admin panel (broken auth vulnerable)
    registerRoute({
        method: 'GET',
        path: '/admin',
        requireAuth: !isVulnActive('broken_auth'),
        handler: (req, _ctx, session) => {
            // Check admin access
            if (!isVulnActive('broken_auth') && !session.isAdmin) {
                return {
                    status: 403,
                    body: renderErrorPage(403, 'Admin access required', session),
                };
            }

            // Broken auth: accept admin=true query param
            if (isVulnActive('broken_auth')) {
                const forceAdmin = req.query.get('admin') === 'true';
                if (!session.isAdmin && !forceAdmin) {
                    return {
                        status: 403,
                        body: renderErrorPage(403, 'Admin access required. Try adding ?admin=true', session),
                    };
                }
            }

            const content = `
                <h2>Admin Panel</h2>
                <p style="color: #b0b0b0; margin-bottom: 1.5rem;">Manage users, products, and system settings.</p>
                
                <h3>User Management</h3>
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${users.map(u => `
                            <tr>
                                <td>${u.id}</td>
                                <td>${escapeHtml(u.username)}</td>
                                <td>${escapeHtml(u.email)}</td>
                                <td><span class="badge badge-${u.role}">${u.role}</span></td>
                                <td><a href="/profile/${u.id}" style="color: #00d4ff;">View</a></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>

                <h3 style="margin-top: 2rem;">System Statistics</h3>
                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem;">
                    <div class="card" style="text-align: center;">
                        <div style="font-size: 2rem; color: #00d4ff;">${users.length}</div>
                        <div style="color: #b0b0b0;">Total Users</div>
                    </div>
                    <div class="card" style="text-align: center;">
                        <div style="font-size: 2rem; color: #2ed573;">${products.length}</div>
                        <div style="color: #b0b0b0;">Products</div>
                    </div>
                    <div class="card" style="text-align: center;">
                        <div style="font-size: 2rem; color: #ff4757;">${sessions.size}</div>
                        <div style="color: #b0b0b0;">Active Sessions</div>
                    </div>
                </div>

                <h3 style="margin-top: 2rem;">Quick Links</h3>
                <div style="display: flex; gap: 1rem; flex-wrap: wrap;">
                    <a href="/api/config" class="btn btn-secondary">View Config</a>
                    <a href="/api/export" class="btn btn-secondary">Export Data</a>
                    <a href="/api/users" class="btn btn-secondary">API Users</a>
                </div>
            `;
            return { status: 200, body: renderPage('Admin Panel', content, session) };
        },
    });

    // API: Users (BOLA vulnerable)
    registerRoute({
        method: 'GET',
        path: '/api/users',
        handler: (req, _ctx, session) => {
            const userId = req.query.get('id');

            if (userId !== null) {
                // BOLA: No authorization check when vulnerability is active
                const user = users.find(u => String(u.id) === userId);
                if (user === undefined) {
                    return {
                        status: 404,
                        body: JSON.stringify({ error: 'User not found' }),
                        contentType: 'application/json',
                    };
                }

                if (!isVulnActive('bola') && session.userId !== String(user.id) && !session.isAdmin) {
                    return {
                        status: 403,
                        body: JSON.stringify({ error: 'Forbidden' }),
                        contentType: 'application/json',
                    };
                }

                return {
                    status: 200,
                    body: JSON.stringify({
                        id: user.id,
                        username: user.username,
                        email: user.email,
                        role: user.role,
                        profile: user.profile,
                    }, null, 2),
                    contentType: 'application/json',
                };
            }

            // List all users (admin only unless BOLA active)
            if (!isVulnActive('bola') && !session.isAdmin) {
                return {
                    status: 403,
                    body: JSON.stringify({ error: 'Admin access required' }),
                    contentType: 'application/json',
                };
            }

            return {
                status: 200,
                body: JSON.stringify({
                    users: users.map(u => ({
                        id: u.id,
                        username: u.username,
                        email: u.email,
                        role: u.role,
                    })),
                }, null, 2),
                contentType: 'application/json',
            };
        },
    });

    // API: Export (SSRF vulnerable)
    registerRoute({
        method: 'GET',
        path: '/api/export',
        handler: (req, _ctx, _session) => {
            const urlStr = req.query.get('url');

            if (urlStr === null) {
                return {
                    status: 200,
                    body: JSON.stringify({
                        message: 'Data export API',
                        usage: 'GET /api/export?url=<endpoint>',
                        example: '/api/export?url=http://internal-api/data',
                    }, null, 2),
                    contentType: 'application/json',
                };
            }

            if (!isVulnActive('ssrf')) {
                // Validate URL - only allow certain domains
                const allowedHosts = ['api.cybershop.local', 'cdn.cybershop.local'];
                try {
                    // urlStr is guaranteed to be non-null here
                    const parsed = new URL(urlStr!);
                    if (!allowedHosts.includes(parsed.hostname)) {
                        return {
                            status: 403,
                            body: JSON.stringify({ error: 'URL not allowed' }),
                            contentType: 'application/json',
                        };
                    }
                } catch {
                    return {
                        status: 400,
                        body: JSON.stringify({ error: 'Invalid URL' }),
                        contentType: 'application/json',
                    };
                }
            }

            // Simulate fetching data from URL
            return {
                status: 200,
                body: JSON.stringify({
                    source: urlStr,
                    timestamp: new Date().toISOString(),
                    data: {
                        internal_service: 'metadata',
                        version: '1.0.0',
                        secrets: isVulnActive('ssrf') ? ['aws_key=AKIAIOSFODNN7EXAMPLE'] : [],
                    },
                }, null, 2),
                contentType: 'application/json',
            };
        },
    });

    // API: Config (Info disclosure vulnerable)
    registerRoute({
        method: 'GET',
        path: '/api/config',
        handler: (_req, _ctx, _session) => {
            const baseConfig = {
                app: {
                    name: appName,
                    version: '2.1.0',
                    environment: 'production',
                },
                features: {
                    registration: true,
                    upload: true,
                    api: true,
                },
            };

            if (isVulnActive('info_disclosure')) {
                return {
                    status: 200,
                    body: JSON.stringify({
                        ...baseConfig,
                        database: {
                            host: 'db.internal',
                            port: 3306,
                            name: 'cybershop_prod',
                            user: 'cybershop_user',
                            password: 'SuperSecretDBPass123!',
                        },
                        secrets: {
                            jwt_secret: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
                            api_key: 'cs_live_51H7xYZABC123xyz789',
                            encryption_key: 'AES256-Key-For-Data-Encryption-12345',
                        },
                        internal: {
                            admin_panel: '/admin',
                            debug_mode: true,
                            log_level: 'debug',
                        },
                    }, null, 2),
                    contentType: 'application/json',
                };
            }

            return {
                status: 200,
                body: JSON.stringify(baseConfig, null, 2),
                contentType: 'application/json',
            };
        },
    });

    // robots.txt
    registerRoute({
        method: 'GET',
        path: '/robots.txt',
        handler: () => ({
            status: 200,
            body: `User-agent: *
Disallow: /admin
Disallow: /api/
Disallow: /backup/
Disallow: /.git/
Disallow: /uploads/

# Private endpoints - do not crawl
# /admin/config.php
# /api/internal/
# /backup/database.sql
`,
            contentType: 'text/plain',
        }),
    });

    // Exposed backup directory
    registerRoute({
        method: 'GET',
        path: '/backup/*',
        handler: (_req, _ctx, _session) => {
            if (!isVulnActive('exposed_backup')) {
                return {
                    status: 404,
                    body: renderErrorPage(404, 'Not found', _session),
                };
            }

            return {
                status: 200,
                body: `<!DOCTYPE html>
<html>
<head><title>Index of /backup/</title></head>
<body>
<h1>Index of /backup/</h1>
<hr>
<pre>
<a href="../">../</a>
<a href="database.sql.gz">database.sql.gz</a>                                2024-01-15 03:22    12M
<a href="www-backup.zip">www-backup.zip</a>                                 2024-01-14 12:00    45M
<a href="config.php.bak">config.php.bak</a>                                 2024-01-13 08:15    4.2K
<a href=".env.backup">.env.backup</a>                                    2024-01-12 22:45    1.1K
<a href="credentials.xlsx">credentials.xlsx</a>                               2024-01-10 16:30    25K
</pre>
<hr>
<address>${serverName}</address>
</body>
</html>`,
            };
        },
    });

    // Exposed git directory
    registerRoute({
        method: 'GET',
        path: '/.git/*',
        handler: (_req, _ctx, _session) => {
            if (!isVulnActive('exposed_git')) {
                return {
                    status: 404,
                    body: renderErrorPage(404, 'Not found', _session),
                };
            }

            const path = '/.git/HEAD';
            if (path.endsWith('HEAD')) {
                return {
                    status: 200,
                    body: 'ref: refs/heads/main\n',
                    contentType: 'text/plain',
                };
            }

            return {
                status: 200,
                body: `Git repository exposed

This directory contains sensitive version control information.

Files available:
- HEAD
- config
- description
- index
- objects/
- refs/

Use a tool like git-dumper to extract the full repository.`,
                contentType: 'text/plain',
            };
        },
    });

    // PHP info / server status (info leak)
    registerRoute({
        method: 'GET',
        path: '/phpinfo.php',
        handler: (_req, _ctx, session) => {
            if (!isVulnActive('info_leak')) {
                return {
                    status: 404,
                    body: renderErrorPage(404, 'Not found', session),
                };
            }

            return {
                status: 200,
                body: `<!DOCTYPE html>
<html>
<head><title>phpinfo()</title></head>
<body>
<div class="center">
<table>
<tr class="h"><td>
<a href="http://www.php.net/"><img border="0" src="/php-logo.png" alt="PHP Logo"></a>
<h1 class="p">PHP Version 7.4.3</h1>
</td></tr>
</table>
<table>
<tr><td class="e">System</td><td class="v">Linux web01 5.4.0-65-generic #73-Ubuntu SMP</td></tr>
<tr><td class="e">Server API</td><td class="v">Apache 2.0 Handler</td></tr>
<tr><td class="e">Configuration File</td><td class="v">/etc/php/7.4/apache2/php.ini</td></tr>
<tr><td class="e">PHP API</td><td class="v">20190902</td></tr>
<tr><td class="e">Zend Extension Build</td><td class="v">API320190902,NTS</td></tr>
<tr><td class="e">Debug Build</td><td class="v">no</td></tr>
<tr><td class="e">Thread Safety</td><td class="v">disabled</td></tr>
<tr><td class="e">Registered PHP Streams</td><td class="v">https, ftps, compress.zlib, php, file, glob, data, http, ftp</td></tr>
<tr><td class="e">Registered Stream Socket Transports</td><td class="v">tcp, udp, unix, udg, ssl, tls, tlsv1.0, tlsv1.1, tlsv1.2, tlsv1.3</td></tr>
</table>
<h2>Environment</h2>
<table>
<tr><td class="e">DB_HOST</td><td class="v">db.internal.cybershop.local</td></tr>
<tr><td class="e">DB_USER</td><td class="v">cybershop_app</td></tr>
<tr><td class="e">DB_PASS</td><td class="v">Production_DB_Pass_2024!</td></tr>
<tr><td class="e">AWS_ACCESS_KEY</td><td class="v">AKIAIOSFODNN7EXAMPLE</td></tr>
<tr><td class="e">AWS_SECRET_KEY</td><td class="v">wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</td></tr>
<tr><td class="e">STRIPE_SECRET</td><td class="v">sk_test_VARIANT_FAKE_51H7xYZABC123x</td></tr>
</table>
<h2>HTTP Headers Information</h2>
<table>
<tr><td class="e">HTTP_X_FORWARDED_FOR</td><td class="v">10.0.0.5</td></tr>
<tr><td class="e">HTTP_X_REAL_IP</td><td class="v">192.168.1.100</td></tr>
</table>
</div>
<style>
body { background-color: #fff; color: #222; font-family: sans-serif; margin: 0; padding: 0; }
table { border-collapse: collapse; width: 100%; margin-bottom: 1em; }
.center { text-align: center; }
h1 { font-size: 150%; }
h2 { font-size: 125%; }
.e { background-color: #ccf; width: 30%; font-weight: bold; }
.v { background-color: #ddd; width: 70%; }
h, th { background-color: #99c; font-weight: bold; }
</style>
</body>
</html>`,
            };
        },
    });

    registerRoute({
        method: 'GET',
        path: '/server-status',
        handler: (_req, _ctx, session) => {
            if (!isVulnActive('info_leak')) {
                return {
                    status: 404,
                    body: renderErrorPage(404, 'Not found', session),
                };
            }

            return {
                status: 200,
                body: `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html><head>
<title>Apache Status</title>
</head><body>
<h1>Apache Server Status for web01.cybershop.local</h1>

<dl><dt>Server Version: ${serverName}</dt>
<dt>Server MPM: prefork</dt>
<dt>Server Built: 2024-01-10T12:00:00
</dt></dl><hr /><dl>
<dt>Current Time: ${new Date().toUTCString()}</dt>
<dt>Restart Time: ${new Date(Date.now() - 86400000).toUTCString()}</dt>
<dt>Parent Server Config. Generation: 1</dt>
<dt>Parent Server MPM Generation: 0</dt>
<dt>Server uptime: 1 day 4 hours 32 minutes</dt>
<dt>Total accesses: 154320 - Total Traffic: 2.3 GB</dt>
<dt>CPU Usage: u124.5 s45.2 cu89.1 cs23.4</dt>
<dt>1.54 requests/sec - 23.4 kB/second - 15.3 kB/request</dt>
<dt>8 requests currently being processed</dt></dl>

<table rules="all" border="1">
<tr><th>Srv</th><th>PID</th><th>Acc</th><th>M</th><th>CPU
</th><th>SS</th><th>Req</th><th>Conn</th><th>Child</th><th>Slot</th><th>Client</th><th>Protocol</th><th>VHost</th><th>Request</th></tr>
<tr><td>0-0</td><td>12345</td><td>1/15/152</td><td>W</td><td>0.25</td><td>0</td><td>0</td><td>0.0</td><td>0.12</td><td>1.45</td><td>192.168.1.100</td><td>http/1.1</td><td>cybershop.local:80</td><td>GET /admin HTTP/1.1</td></tr>
<tr><td>1-0</td><td>12346</td><td>0/12/98</td><td>R</td><td>0.18</td><td>2</td><td>0</td><td>0.0</td><td>0.08</td><td>0.95</td><td>10.0.0.15</td><td>http/1.1</td><td>api.cybershop.local:80</td><td>POST /api/users HTTP/1.1</td></tr>
<tr><td>2-0</td><td>12347</td><td>0/8/76</td><td>K</td><td>0.12</td><td>5</td><td>0</td><td>0.0</td><td>0.05</td><td>0.72</td><td>172.16.0.5</td><td>http/1.1</td><td>cybershop.local:80</td><td>GET /api/config HTTP/1.1</td></tr>
</table>

<hr />
<h2>Server Details</h2>
<pre>
Server Root: /etc/apache2
Main Document Root: /var/www/html
Configuration File: /etc/apache2/apache2.conf
Access Config: /etc/apache2/conf-enabled/
Error Log: /var/log/apache2/error.log
Custom Log: /var/log/apache2/access.log
</pre>

</body></html>`,
            };
        },
    });

    // Static file serving fallback
    registerRoute({
        method: 'GET',
        path: '/static/*',
        handler: () => ({
            status: 200,
            body: '', // Would serve from VFS in full implementation
            contentType: 'image/png',
        }),
    });

    // ── Service Handler Implementation ─────────────────────────

    return {
        name: 'http',
        port,
        protocol: 'tcp',

        handle(request: ServiceRequest, ctx: ServiceContext): ServiceResponse | null {
            const text = request.payloadText;
            const lines = text.split('\r\n');
            if (lines.length === 0) return null;

            const requestLine = lines[0]!;
            const method = requestLine.split(' ')[0] ?? 'GET';
            const path = requestLine.split(' ')[1]?.split('?')[0] ?? '/';

            // Match route
            const match = matchRoute(method, path);

            let parsedReq: ParsedRequest;
            let route: Route;

            if (match !== null) {
                parsedReq = parseRequest(text, { params: match.params })!;
                route = match.route;
            } else {
                // Try to parse anyway for 404
                parsedReq = parseRequest(text)!;
                if (parsedReq === null) return null;
                route = { method: '*', path: '/', handler: () => ({ status: 404, body: '' }) };
            }

            // Get session
            const session = getSession(parsedReq);

            // Check auth requirement
            if (route.requireAuth && !session.userId) {
                return buildResponse({
                    status: 302,
                    body: '',
                    headers: new Map([['location', '/login']]),
                }, serverName);
            }

            // Execute handler
            let responseData: ResponseData;
            try {
                responseData = route.handler(parsedReq, ctx, session);
            } catch (error) {
                responseData = {
                    status: 500,
                    body: renderErrorPage(500, 'Internal Server Error', session),
                };
            }

            // Handle 404 for unknown routes
            if (match === null) {
                responseData = {
                    status: 404,
                    body: renderErrorPage(404, 'The page you are looking for does not exist.', session),
                };
            }

            // Emit HTTP request event
            ctx.emit({
                type: 'http:request',
                method: parsedReq.method,
                path: parsedReq.path,
                headers: parsedReq.headers,
                body: parsedReq.body,
                sourceIP: request.sourceIP,
                responseCode: responseData.status,
            });

            return buildResponse(responseData, serverName);
        },
    };
}

// ── Helpers ────────────────────────────────────────────────────

function buildResponse(data: ResponseData, serverName: string): ServiceResponse {
    const headers = new Map(data.headers ?? []);
    headers.set('content-type', data.contentType ?? 'text/html; charset=utf-8');
    headers.set('server', serverName);

    if (data.setCookie !== undefined) {
        for (const cookie of data.setCookie) {
            headers.set('set-cookie', cookie);
        }
    }

    const statusText = HTTP_STATUS_TEXT.get(data.status) ?? 'Unknown';
    let response = `HTTP/1.1 ${data.status} ${statusText}\r\n`;

    for (const [key, value] of headers) {
        response += `${key}: ${value}\r\n`;
    }

    response += `content-length: ${new TextEncoder().encode(data.body).byteLength}\r\n`;
    response += 'connection: close\r\n';
    response += '\r\n';
    response += data.body;

    return {
        payload: new TextEncoder().encode(response),
        close: true,
    };
}

function escapeHtml(text: string): string {
    const div = typeof document !== 'undefined' ? document.createElement('div') : null;
    if (div !== null) {
        div.textContent = text;
        return div.innerHTML;
    }
    // Server-side fallback
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
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
    [409, 'Conflict'],
    [429, 'Too Many Requests'],
    [500, 'Internal Server Error'],
    [502, 'Bad Gateway'],
    [503, 'Service Unavailable'],
]);

// ── Exports ────────────────────────────────────────────────────

// Type exports are at the top of the file
