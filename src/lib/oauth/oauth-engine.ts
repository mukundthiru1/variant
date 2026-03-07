/**
 * VARIANT — OAuth/SSO Engine
 *
 * Simulates OAuth 2.0 / OIDC with:
 * - Authorization code flow (with PKCE support)
 * - Client credentials grant
 * - Token lifecycle (issue, validate, refresh, revoke)
 * - SSO session management
 *
 * All operations are synchronous and pure-data.
 */

import type {
    OAuthEngine,
    OAuthClient,
    OAuthUser,
    AuthorizationRequest,
    AuthorizationCode,
    AuthorizationResult,
    OAuthToken,
    TokenInfo,
    SSOSession,
} from './types';

// ── Helpers ───────────────────────────────────────────────

let clientCounter = 0;
let tokenCounter = 0;
let codeCounter = 0;
let sessionCounter = 0;

function generateClientId(): string {
    return `client_${++clientCounter}_${Math.random().toString(36).slice(2, 10)}`;
}

function generateSecret(): string {
    return `secret_${Math.random().toString(36).slice(2)}${Math.random().toString(36).slice(2)}`;
}

function generateToken(): string {
    return `tok_${++tokenCounter}_${Math.random().toString(36).slice(2)}${Math.random().toString(36).slice(2)}`;
}

function generateCode(): string {
    return `code_${++codeCounter}_${Math.random().toString(36).slice(2, 14)}`;
}

function generateSessionId(): string {
    return `sess_${++sessionCounter}_${Math.random().toString(36).slice(2, 10)}`;
}

// Simple S256 simulation (not cryptographic — pure-data simulator)
function simulateS256(verifier: string): string {
    let hash = 0;
    for (let i = 0; i < verifier.length; i++) {
        hash = ((hash << 5) - hash + verifier.charCodeAt(i)) | 0;
    }
    return Math.abs(hash).toString(36);
}

// ── Factory ──────────────────────────────────────────────

export function createOAuthEngine(): OAuthEngine {
    const clients = new Map<string, OAuthClient>();
    const users = new Map<string, OAuthUser>();
    const authCodes = new Map<string, AuthorizationCode & { _mutable_used: boolean }>();
    const tokens = new Map<string, TokenInfo & { _refreshToken?: string }>();
    const refreshTokenMap = new Map<string, string>(); // refresh → access
    const sessions = new Map<string, SSOSession & { _active: boolean; _clients: string[] }>();
    let totalTokensIssued = 0;

    function authResult(base: Omit<AuthorizationResult, 'state'>, state?: string): AuthorizationResult {
        return state !== undefined ? { ...base, state } : base;
    }

    function createTokenPair(clientId: string, userId: string | undefined, scope: string, grantType: string): OAuthToken {
        const accessToken = generateToken();
        const refreshToken = generateToken();
        const now = Date.now();
        totalTokensIssued++;

        const base = {
            accessToken,
            clientId,
            scope,
            issuedAt: now,
            expiresAt: now + 3600_000,
            revoked: false as const,
            grantType: grantType as TokenInfo['grantType'],
            _refreshToken: refreshToken,
        };
        const info: TokenInfo & { _refreshToken?: string } = userId !== undefined
            ? { ...base, userId }
            : base;
        tokens.set(accessToken, info);
        refreshTokenMap.set(refreshToken, accessToken);

        return Object.freeze({
            accessToken,
            tokenType: 'Bearer' as const,
            expiresIn: 3600,
            refreshToken,
            scope,
        });
    }

    const engine: OAuthEngine = {
        registerClient(config) {
            const clientId = generateClientId();
            const clientSecret = generateSecret();
            const client: OAuthClient = Object.freeze({
                ...config,
                clientId,
                clientSecret,
                created: Date.now(),
            });
            clients.set(clientId, client);
            return client;
        },

        getClient(clientId) {
            return clients.get(clientId) ?? null;
        },

        listClients() {
            return Object.freeze(Array.from(clients.values()));
        },

        registerUser(user) {
            users.set(user.userId, user);
        },

        getUser(userId) {
            return users.get(userId) ?? null;
        },

        authorize(request: AuthorizationRequest, userId: string): AuthorizationResult {
            const client = clients.get(request.clientId);
            if (!client) {
                return authResult({ success: false, error: 'invalid_client' }, request.state);
            }

            // Validate redirect URI
            if (!client.redirectUris.includes(request.redirectUri)) {
                return authResult({ success: false, error: 'invalid_redirect_uri' }, request.state);
            }

            // Validate scopes
            const requestedScopes = request.scope.split(' ');
            for (const s of requestedScopes) {
                if (!client.allowedScopes.includes(s)) {
                    return authResult({ success: false, error: 'invalid_scope' }, request.state);
                }
            }

            if (request.responseType === 'code') {
                if (!client.allowedGrantTypes.includes('authorization_code') &&
                    !client.allowedGrantTypes.includes('pkce')) {
                    return authResult({ success: false, error: 'unauthorized_grant_type' }, request.state);
                }

                const code = generateCode();
                const codeBase = {
                    code,
                    clientId: request.clientId,
                    userId,
                    scope: request.scope,
                    redirectUri: request.redirectUri,
                    expiresAt: Date.now() + 600_000, // 10 min
                    used: false,
                    _mutable_used: false,
                };
                const codeEntry = request.codeChallenge !== undefined
                    ? { ...codeBase, codeChallenge: request.codeChallenge, codeChallengeMethod: request.codeChallengeMethod! }
                    : codeBase;
                authCodes.set(code, codeEntry as AuthorizationCode & { _mutable_used: boolean });

                return authResult({
                    success: true,
                    code,
                    redirectUri: `${request.redirectUri}?code=${code}${request.state ? `&state=${request.state}` : ''}`,
                }, request.state);
            }

            if (request.responseType === 'token') {
                if (!client.allowedGrantTypes.includes('implicit')) {
                    return authResult({ success: false, error: 'unauthorized_grant_type' }, request.state);
                }

                const token = createTokenPair(request.clientId, userId, request.scope, 'implicit');
                return authResult({
                    success: true,
                    accessToken: token.accessToken,
                    redirectUri: `${request.redirectUri}#access_token=${token.accessToken}&token_type=Bearer`,
                }, request.state);
            }

            return authResult({ success: false, error: 'unsupported_response_type' }, request.state);
        },

        exchangeCode(code, clientId, clientSecret, redirectUri, codeVerifier) {
            const authCode = authCodes.get(code);
            if (!authCode) {
                return { error: 'invalid_grant', errorDescription: 'Authorization code not found' };
            }

            if (authCode._mutable_used) {
                return { error: 'invalid_grant', errorDescription: 'Authorization code already used' };
            }

            if (authCode.clientId !== clientId) {
                return { error: 'invalid_grant', errorDescription: 'Client ID mismatch' };
            }

            const client = clients.get(clientId);
            if (!client || client.clientSecret !== clientSecret) {
                return { error: 'invalid_client', errorDescription: 'Invalid client credentials' };
            }

            if (authCode.redirectUri !== redirectUri) {
                return { error: 'invalid_grant', errorDescription: 'Redirect URI mismatch' };
            }

            if (authCode.expiresAt < Date.now()) {
                return { error: 'invalid_grant', errorDescription: 'Authorization code expired' };
            }

            // PKCE verification
            if (authCode.codeChallenge) {
                if (!codeVerifier) {
                    return { error: 'invalid_grant', errorDescription: 'Code verifier required for PKCE' };
                }
                const expected = authCode.codeChallengeMethod === 'S256'
                    ? simulateS256(codeVerifier)
                    : codeVerifier;
                if (expected !== authCode.codeChallenge) {
                    return { error: 'invalid_grant', errorDescription: 'PKCE verification failed' };
                }
            }

            authCode._mutable_used = true;
            return createTokenPair(clientId, authCode.userId, authCode.scope, 'authorization_code');
        },

        clientCredentials(clientId, clientSecret, scope) {
            const client = clients.get(clientId);
            if (!client || client.clientSecret !== clientSecret) {
                return { error: 'invalid_client', errorDescription: 'Invalid client credentials' };
            }

            if (!client.allowedGrantTypes.includes('client_credentials')) {
                return { error: 'unauthorized_client', errorDescription: 'Client credentials grant not allowed' };
            }

            const requestedScopes = scope.split(' ');
            for (const s of requestedScopes) {
                if (!client.allowedScopes.includes(s)) {
                    return { error: 'invalid_scope', errorDescription: `Scope ${s} not allowed` };
                }
            }

            return createTokenPair(clientId, undefined, scope, 'client_credentials');
        },

        refreshToken(refreshTok, clientId, clientSecret) {
            const client = clients.get(clientId);
            if (!client || client.clientSecret !== clientSecret) {
                return { error: 'invalid_client', errorDescription: 'Invalid client credentials' };
            }

            const accessToken = refreshTokenMap.get(refreshTok);
            if (!accessToken) {
                return { error: 'invalid_grant', errorDescription: 'Refresh token not found' };
            }

            const oldInfo = tokens.get(accessToken);
            if (!oldInfo || oldInfo.revoked) {
                return { error: 'invalid_grant', errorDescription: 'Token has been revoked' };
            }

            // Revoke old token
            tokens.set(accessToken, { ...oldInfo, revoked: true });

            return createTokenPair(clientId, oldInfo.userId, oldInfo.scope, 'refresh_token');
        },

        validateToken(accessToken) {
            const info = tokens.get(accessToken);
            if (!info) return null;
            if (info.revoked) return null;
            const base = {
                accessToken: info.accessToken,
                clientId: info.clientId,
                scope: info.scope,
                issuedAt: info.issuedAt,
                expiresAt: info.expiresAt,
                revoked: info.revoked,
                grantType: info.grantType,
            };
            return Object.freeze(
                info.userId !== undefined ? { ...base, userId: info.userId } : base
            ) as TokenInfo;
        },

        revokeToken(accessToken) {
            const info = tokens.get(accessToken);
            if (!info) return false;
            tokens.set(accessToken, { ...info, revoked: true });
            return true;
        },

        createSession(userId, ipAddress) {
            const sessionId = generateSessionId();
            const now = Date.now();
            const sessionBase = {
                sessionId,
                userId,
                createdAt: now,
                expiresAt: now + 86400_000, // 24h
                active: true,
                clientIds: [] as readonly string[],
                _active: true,
                _clients: [] as string[],
            };
            const session = ipAddress !== undefined
                ? { ...sessionBase, ipAddress }
                : sessionBase;
            sessions.set(sessionId, session as SSOSession & { _active: boolean; _clients: string[] });

            const resultBase = {
                sessionId: session.sessionId,
                userId: session.userId,
                createdAt: session.createdAt,
                expiresAt: session.expiresAt,
                active: session._active,
                clientIds: Object.freeze([...session._clients]),
            };
            return Object.freeze(
                ipAddress !== undefined ? { ...resultBase, ipAddress } : resultBase
            ) as SSOSession;
        },

        getSession(sessionId) {
            const session = sessions.get(sessionId);
            if (!session) return null;
            const base = {
                sessionId: session.sessionId,
                userId: session.userId,
                createdAt: session.createdAt,
                expiresAt: session.expiresAt,
                active: session._active,
                clientIds: Object.freeze([...session._clients]),
            };
            const ip = (session as any).ipAddress as string | undefined;
            return Object.freeze(
                ip !== undefined ? { ...base, ipAddress: ip } : base
            ) as SSOSession;
        },

        endSession(sessionId) {
            const session = sessions.get(sessionId);
            if (!session) return false;
            session._active = false;
            return true;
        },

        getStats() {
            let active = 0;
            let revoked = 0;
            for (const t of tokens.values()) {
                if (t.revoked) revoked++;
                else active++;
            }
            let activeSessions = 0;
            for (const s of sessions.values()) {
                if (s._active) activeSessions++;
            }
            return Object.freeze({
                totalClients: clients.size,
                totalUsers: users.size,
                totalTokensIssued,
                activeTokens: active,
                revokedTokens: revoked,
                activeSessions,
                totalAuthCodes: authCodes.size,
            });
        },
    };

    return engine;
}
