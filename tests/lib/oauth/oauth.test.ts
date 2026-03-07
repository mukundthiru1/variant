import { describe, it, expect, beforeEach } from 'vitest';
import { createOAuthEngine } from '../../../src/lib/oauth';
import type { OAuthEngine, OAuthClient, OAuthError, OAuthToken } from '../../../src/lib/oauth';

function isError(v: OAuthToken | OAuthError): v is OAuthError {
    return 'error' in v;
}

describe('OAuth Engine', () => {
    let engine: OAuthEngine;
    let client: OAuthClient;

    beforeEach(() => {
        engine = createOAuthEngine();
        client = engine.registerClient({
            name: 'Test App',
            redirectUris: ['https://app.example.com/callback'],
            allowedGrantTypes: ['authorization_code', 'client_credentials', 'refresh_token', 'implicit'],
            allowedScopes: ['openid', 'profile', 'email', 'admin'],
            trusted: false,
        });
        engine.registerUser({
            userId: 'user1', username: 'alice', email: 'alice@example.com',
            roles: ['user'], mfaEnabled: false, active: true,
        });
    });

    // ── Client Management ────────────────────────────────────

    it('registers client with generated ID and secret', () => {
        expect(client.clientId).toBeTruthy();
        expect(client.clientSecret).toBeTruthy();
        expect(client.name).toBe('Test App');
    });

    it('getClient retrieves by ID', () => {
        expect(engine.getClient(client.clientId)).not.toBeNull();
        expect(engine.getClient('nonexistent')).toBeNull();
    });

    it('listClients returns all clients', () => {
        engine.registerClient({
            name: 'Another', redirectUris: [], allowedGrantTypes: [],
            allowedScopes: [], trusted: true,
        });
        expect(engine.listClients()).toHaveLength(2);
    });

    // ── User Management ──────────────────────────────────────

    it('registers and retrieves users', () => {
        expect(engine.getUser('user1')).not.toBeNull();
        expect(engine.getUser('user1')!.username).toBe('alice');
        expect(engine.getUser('nonexistent')).toBeNull();
    });

    // ── Authorization Code Flow ──────────────────────────────

    it('authorize returns code for valid request', () => {
        const result = engine.authorize({
            clientId: client.clientId,
            responseType: 'code',
            redirectUri: 'https://app.example.com/callback',
            scope: 'openid profile',
        }, 'user1');
        expect(result.success).toBe(true);
        expect(result.code).toBeTruthy();
        expect(result.redirectUri).toContain('code=');
    });

    it('authorize preserves state parameter', () => {
        const result = engine.authorize({
            clientId: client.clientId,
            responseType: 'code',
            redirectUri: 'https://app.example.com/callback',
            scope: 'openid',
            state: 'csrf_token_123',
        }, 'user1');
        expect(result.state).toBe('csrf_token_123');
        expect(result.redirectUri).toContain('state=csrf_token_123');
    });

    it('authorize fails for invalid client', () => {
        const result = engine.authorize({
            clientId: 'invalid',
            responseType: 'code',
            redirectUri: 'https://app.example.com/callback',
            scope: 'openid',
        }, 'user1');
        expect(result.success).toBe(false);
        expect(result.error).toBe('invalid_client');
    });

    it('authorize fails for invalid redirect URI', () => {
        const result = engine.authorize({
            clientId: client.clientId,
            responseType: 'code',
            redirectUri: 'https://evil.com/steal',
            scope: 'openid',
        }, 'user1');
        expect(result.success).toBe(false);
        expect(result.error).toBe('invalid_redirect_uri');
    });

    it('authorize fails for invalid scope', () => {
        const result = engine.authorize({
            clientId: client.clientId,
            responseType: 'code',
            redirectUri: 'https://app.example.com/callback',
            scope: 'openid superadmin',
        }, 'user1');
        expect(result.success).toBe(false);
        expect(result.error).toBe('invalid_scope');
    });

    // ── Code Exchange ────────────────────────────────────────

    it('exchangeCode returns tokens for valid code', () => {
        const auth = engine.authorize({
            clientId: client.clientId,
            responseType: 'code',
            redirectUri: 'https://app.example.com/callback',
            scope: 'openid profile',
        }, 'user1');

        const result = engine.exchangeCode(
            auth.code!, client.clientId, client.clientSecret,
            'https://app.example.com/callback',
        );
        expect(isError(result)).toBe(false);
        const token = result as OAuthToken;
        expect(token.accessToken).toBeTruthy();
        expect(token.refreshToken).toBeTruthy();
        expect(token.tokenType).toBe('Bearer');
        expect(token.scope).toBe('openid profile');
    });

    it('exchangeCode fails for used code', () => {
        const auth = engine.authorize({
            clientId: client.clientId, responseType: 'code',
            redirectUri: 'https://app.example.com/callback', scope: 'openid',
        }, 'user1');

        engine.exchangeCode(auth.code!, client.clientId, client.clientSecret, 'https://app.example.com/callback');
        const result = engine.exchangeCode(auth.code!, client.clientId, client.clientSecret, 'https://app.example.com/callback');
        expect(isError(result)).toBe(true);
        expect((result as OAuthError).error).toBe('invalid_grant');
    });

    it('exchangeCode fails for wrong client secret', () => {
        const auth = engine.authorize({
            clientId: client.clientId, responseType: 'code',
            redirectUri: 'https://app.example.com/callback', scope: 'openid',
        }, 'user1');

        const result = engine.exchangeCode(auth.code!, client.clientId, 'wrong_secret', 'https://app.example.com/callback');
        expect(isError(result)).toBe(true);
    });

    it('exchangeCode fails for wrong redirect URI', () => {
        const auth = engine.authorize({
            clientId: client.clientId, responseType: 'code',
            redirectUri: 'https://app.example.com/callback', scope: 'openid',
        }, 'user1');

        const result = engine.exchangeCode(auth.code!, client.clientId, client.clientSecret, 'https://evil.com/callback');
        expect(isError(result)).toBe(true);
    });

    // ── Implicit Flow ────────────────────────────────────────

    it('implicit flow returns access token directly', () => {
        const result = engine.authorize({
            clientId: client.clientId,
            responseType: 'token',
            redirectUri: 'https://app.example.com/callback',
            scope: 'openid',
        }, 'user1');
        expect(result.success).toBe(true);
        expect(result.accessToken).toBeTruthy();
        expect(result.redirectUri).toContain('access_token=');
    });

    // ── Client Credentials ───────────────────────────────────

    it('client credentials grant returns token', () => {
        const result = engine.clientCredentials(client.clientId, client.clientSecret, 'openid');
        expect(isError(result)).toBe(false);
        const token = result as OAuthToken;
        expect(token.accessToken).toBeTruthy();
    });

    it('client credentials fails for wrong secret', () => {
        const result = engine.clientCredentials(client.clientId, 'wrong', 'openid');
        expect(isError(result)).toBe(true);
    });

    it('client credentials fails for disallowed scope', () => {
        const result = engine.clientCredentials(client.clientId, client.clientSecret, 'openid superadmin');
        expect(isError(result)).toBe(true);
        expect((result as OAuthError).error).toBe('invalid_scope');
    });

    // ── Token Validation & Revocation ────────────────────────

    it('validateToken returns info for valid token', () => {
        const result = engine.clientCredentials(client.clientId, client.clientSecret, 'openid');
        const token = result as OAuthToken;
        const info = engine.validateToken(token.accessToken);
        expect(info).not.toBeNull();
        expect(info!.clientId).toBe(client.clientId);
        expect(info!.scope).toBe('openid');
    });

    it('validateToken returns null for unknown token', () => {
        expect(engine.validateToken('fake_token')).toBeNull();
    });

    it('revokeToken revokes and invalidates a token', () => {
        const result = engine.clientCredentials(client.clientId, client.clientSecret, 'openid') as OAuthToken;
        expect(engine.revokeToken(result.accessToken)).toBe(true);
        expect(engine.validateToken(result.accessToken)).toBeNull();
    });

    it('revokeToken returns false for unknown token', () => {
        expect(engine.revokeToken('fake')).toBe(false);
    });

    // ── Refresh Token ────────────────────────────────────────

    it('refresh token issues new access token', () => {
        const auth = engine.authorize({
            clientId: client.clientId, responseType: 'code',
            redirectUri: 'https://app.example.com/callback', scope: 'openid',
        }, 'user1');
        const original = engine.exchangeCode(auth.code!, client.clientId, client.clientSecret, 'https://app.example.com/callback') as OAuthToken;
        const refreshed = engine.refreshToken(original.refreshToken!, client.clientId, client.clientSecret);
        expect(isError(refreshed)).toBe(false);
        const newToken = refreshed as OAuthToken;
        expect(newToken.accessToken).not.toBe(original.accessToken);
        // Old token should be revoked
        expect(engine.validateToken(original.accessToken)).toBeNull();
    });

    it('refresh fails with wrong client secret', () => {
        const result = engine.clientCredentials(client.clientId, client.clientSecret, 'openid') as OAuthToken;
        const refreshed = engine.refreshToken(result.refreshToken!, client.clientId, 'wrong');
        expect(isError(refreshed)).toBe(true);
    });

    // ── SSO Sessions ─────────────────────────────────────────

    it('creates and retrieves SSO session', () => {
        const session = engine.createSession('user1', '10.0.0.1');
        expect(session.sessionId).toBeTruthy();
        expect(session.userId).toBe('user1');
        expect(session.active).toBe(true);
        expect(session.ipAddress).toBe('10.0.0.1');
    });

    it('getSession retrieves by ID', () => {
        const session = engine.createSession('user1');
        expect(engine.getSession(session.sessionId)).not.toBeNull();
        expect(engine.getSession('nonexistent')).toBeNull();
    });

    it('endSession deactivates session', () => {
        const session = engine.createSession('user1');
        expect(engine.endSession(session.sessionId)).toBe(true);
        expect(engine.getSession(session.sessionId)!.active).toBe(false);
    });

    it('endSession returns false for unknown session', () => {
        expect(engine.endSession('nonexistent')).toBe(false);
    });

    // ── Stats ────────────────────────────────────────────────

    it('getStats returns accurate counts', () => {
        // Issue some tokens
        engine.clientCredentials(client.clientId, client.clientSecret, 'openid');
        const tok = engine.clientCredentials(client.clientId, client.clientSecret, 'openid') as OAuthToken;
        engine.revokeToken(tok.accessToken);
        engine.createSession('user1');

        engine.authorize({
            clientId: client.clientId, responseType: 'code',
            redirectUri: 'https://app.example.com/callback', scope: 'openid',
        }, 'user1');

        const stats = engine.getStats();
        expect(stats.totalClients).toBe(1);
        expect(stats.totalUsers).toBe(1);
        expect(stats.totalTokensIssued).toBe(2);
        expect(stats.revokedTokens).toBe(1);
        expect(stats.activeTokens).toBe(1);
        expect(stats.activeSessions).toBe(1);
        expect(stats.totalAuthCodes).toBe(1);
    });
});
