/**
 * VARIANT — OAuth/SSO Provider Types
 *
 * Simulates OAuth 2.0 / OpenID Connect flows:
 * - Authorization code, implicit, client credentials, PKCE
 * - Token generation/validation/revocation
 * - Scope management and consent
 * - SSO session management
 * - Common OAuth attack vectors (token theft, CSRF, redirect hijack)
 *
 * EXTENSIBILITY: Custom grant types via open union.
 * SWAPPABILITY: Implements OAuthEngine interface.
 */

// ── OAuth Client ─────────────────────────────────────────

export interface OAuthClient {
    readonly clientId: string;
    readonly clientSecret: string;
    readonly name: string;
    readonly redirectUris: readonly string[];
    readonly allowedGrantTypes: readonly GrantType[];
    readonly allowedScopes: readonly string[];
    readonly trusted: boolean;
    readonly created: number;
}

export type GrantType =
    | 'authorization_code' | 'implicit' | 'client_credentials'
    | 'refresh_token' | 'device_code' | 'pkce'
    | (string & {});

// ── OAuth User ───────────────────────────────────────────

export interface OAuthUser {
    readonly userId: string;
    readonly username: string;
    readonly email: string;
    readonly roles: readonly string[];
    readonly mfaEnabled: boolean;
    readonly active: boolean;
}

// ── Authorization ────────────────────────────────────────

export interface AuthorizationRequest {
    readonly clientId: string;
    readonly responseType: 'code' | 'token';
    readonly redirectUri: string;
    readonly scope: string;
    readonly state?: string;
    readonly codeChallenge?: string;
    readonly codeChallengeMethod?: 'S256' | 'plain';
    readonly nonce?: string;
}

export interface AuthorizationCode {
    readonly code: string;
    readonly clientId: string;
    readonly userId: string;
    readonly scope: string;
    readonly redirectUri: string;
    readonly expiresAt: number;
    readonly codeChallenge?: string;
    readonly codeChallengeMethod?: 'S256' | 'plain';
    readonly used: boolean;
}

// ── Tokens ───────────────────────────────────────────────

export interface OAuthToken {
    readonly accessToken: string;
    readonly tokenType: 'Bearer';
    readonly expiresIn: number;
    readonly refreshToken?: string;
    readonly scope: string;
    readonly idToken?: string;
}

export interface TokenInfo {
    readonly accessToken: string;
    readonly clientId: string;
    readonly userId?: string;
    readonly scope: string;
    readonly issuedAt: number;
    readonly expiresAt: number;
    readonly revoked: boolean;
    readonly grantType: GrantType;
}

// ── SSO Session ──────────────────────────────────────────

export interface SSOSession {
    readonly sessionId: string;
    readonly userId: string;
    readonly createdAt: number;
    readonly expiresAt: number;
    readonly active: boolean;
    readonly clientIds: readonly string[];
    readonly ipAddress?: string;
}

// ── OAuth Engine Interface ───────────────────────────────

export interface OAuthEngine {
    /** Register an OAuth client. */
    registerClient(config: Omit<OAuthClient, 'clientId' | 'clientSecret' | 'created'>): OAuthClient;
    /** Get client by ID. */
    getClient(clientId: string): OAuthClient | null;
    /** List clients. */
    listClients(): readonly OAuthClient[];
    /** Register a user. */
    registerUser(user: OAuthUser): void;
    /** Get user by ID. */
    getUser(userId: string): OAuthUser | null;
    /** Start authorization (returns auth code or implicit token). */
    authorize(request: AuthorizationRequest, userId: string): AuthorizationResult;
    /** Exchange auth code for tokens. */
    exchangeCode(code: string, clientId: string, clientSecret: string, redirectUri: string, codeVerifier?: string): OAuthToken | OAuthError;
    /** Client credentials grant. */
    clientCredentials(clientId: string, clientSecret: string, scope: string): OAuthToken | OAuthError;
    /** Refresh an access token. */
    refreshToken(refreshToken: string, clientId: string, clientSecret: string): OAuthToken | OAuthError;
    /** Validate an access token. */
    validateToken(accessToken: string): TokenInfo | null;
    /** Revoke a token. */
    revokeToken(accessToken: string): boolean;
    /** Create SSO session. */
    createSession(userId: string, ipAddress?: string): SSOSession;
    /** Get SSO session. */
    getSession(sessionId: string): SSOSession | null;
    /** End SSO session. */
    endSession(sessionId: string): boolean;
    /** Get stats. */
    getStats(): OAuthStats;
}

export interface AuthorizationResult {
    readonly success: boolean;
    readonly code?: string;
    readonly accessToken?: string;
    readonly error?: string;
    readonly redirectUri?: string;
    readonly state?: string;
}

export interface OAuthError {
    readonly error: string;
    readonly errorDescription: string;
}

export interface OAuthStats {
    readonly totalClients: number;
    readonly totalUsers: number;
    readonly totalTokensIssued: number;
    readonly activeTokens: number;
    readonly revokedTokens: number;
    readonly activeSessions: number;
    readonly totalAuthCodes: number;
}
