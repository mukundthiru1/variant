/**
 * VARIANT — TLS/Certificate System Types
 *
 * Simulates certificate chains, TLS handshakes, and PKI
 * infrastructure. Players learn about MITM, cert pinning,
 * CA trust hierarchies, and certificate-based attacks.
 *
 * EXTENSIBILITY: Custom cipher suites via open union.
 * SWAPPABILITY: Implements TLSEngine interface.
 */

// ── Certificate ───────────────────────────────────────────

export interface Certificate {
    readonly serialNumber: string;
    readonly subject: CertificateSubject;
    readonly issuer: CertificateSubject;
    readonly notBefore: number;
    readonly notAfter: number;
    readonly publicKeyAlgorithm: KeyAlgorithm;
    readonly publicKeyBits: number;
    readonly signatureAlgorithm: SignatureAlgorithm;
    readonly fingerprint: string;
    readonly isCA: boolean;
    readonly pathLenConstraint?: number;
    readonly keyUsage: readonly KeyUsage[];
    readonly extKeyUsage: readonly ExtKeyUsage[];
    readonly subjectAltNames: readonly SubjectAltName[];
    readonly ocspResponders?: readonly string[];
    readonly crlDistributionPoints?: readonly string[];
    readonly authorityKeyIdentifier?: string;
    readonly subjectKeyIdentifier?: string;
    readonly selfSigned: boolean;
    readonly raw?: string;
}

export interface CertificateSubject {
    readonly commonName: string;
    readonly organization?: string;
    readonly organizationalUnit?: string;
    readonly country?: string;
    readonly state?: string;
    readonly locality?: string;
}

export type KeyAlgorithm = 'RSA' | 'ECDSA' | 'Ed25519' | 'DSA' | (string & {});
export type SignatureAlgorithm =
    | 'sha256WithRSAEncryption' | 'sha384WithRSAEncryption' | 'sha512WithRSAEncryption'
    | 'sha1WithRSAEncryption' | 'md5WithRSAEncryption'
    | 'ecdsa-with-SHA256' | 'ecdsa-with-SHA384' | 'ecdsa-with-SHA512'
    | 'Ed25519'
    | (string & {});

export type KeyUsage =
    | 'digitalSignature' | 'nonRepudiation' | 'keyEncipherment'
    | 'dataEncipherment' | 'keyAgreement' | 'keyCertSign'
    | 'crlSign' | 'encipherOnly' | 'decipherOnly'
    | (string & {});

export type ExtKeyUsage =
    | 'serverAuth' | 'clientAuth' | 'codeSigning' | 'emailProtection'
    | 'timeStamping' | 'ocspSigning'
    | (string & {});

export interface SubjectAltName {
    readonly type: 'dns' | 'ip' | 'email' | 'uri';
    readonly value: string;
}

// ── Certificate Chain ─────────────────────────────────────

export interface CertificateChain {
    readonly certificates: readonly Certificate[];
    readonly valid: boolean;
    readonly errors: readonly CertificateError[];
    readonly trustAnchor?: Certificate;
}

export interface CertificateError {
    readonly type: CertErrorType;
    readonly certificate: Certificate;
    readonly message: string;
}

export type CertErrorType =
    | 'expired' | 'not-yet-valid' | 'self-signed'
    | 'untrusted-root' | 'revoked' | 'weak-signature'
    | 'name-mismatch' | 'missing-san' | 'path-length-exceeded'
    | 'key-usage-missing' | 'chain-incomplete'
    | (string & {});

// ── TLS Session ───────────────────────────────────────────

export interface TLSSession {
    readonly id: string;
    readonly version: TLSVersion;
    readonly cipherSuite: CipherSuite;
    readonly serverCertChain: CertificateChain;
    readonly clientCertChain?: CertificateChain;
    readonly sni: string;
    readonly alpn?: string;
    readonly resumed: boolean;
    readonly startTick: number;
    readonly state: TLSSessionState;
}

export type TLSVersion =
    | 'TLS 1.0' | 'TLS 1.1' | 'TLS 1.2' | 'TLS 1.3'
    | 'SSL 3.0' | 'SSL 2.0'
    | (string & {});

export type CipherSuite =
    | 'TLS_AES_128_GCM_SHA256' | 'TLS_AES_256_GCM_SHA384'
    | 'TLS_CHACHA20_POLY1305_SHA256'
    | 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
    | 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
    | 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'
    | 'TLS_RSA_WITH_AES_128_CBC_SHA' | 'TLS_RSA_WITH_AES_256_CBC_SHA'
    | 'TLS_RSA_WITH_RC4_128_SHA' | 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
    | 'TLS_RSA_WITH_NULL_SHA'
    | (string & {});

export type TLSSessionState =
    | 'handshake' | 'established' | 'renegotiating' | 'closing' | 'closed' | 'error'
    | (string & {});

// ── Certificate Authority ─────────────────────────────────

export interface CertificateAuthority {
    readonly name: string;
    readonly certificate: Certificate;
    readonly isRoot: boolean;
    readonly parent?: string;
    readonly revokedSerials: readonly string[];
}

// ── TLS Configuration ─────────────────────────────────────

export interface TLSConfig {
    readonly minVersion: TLSVersion;
    readonly maxVersion: TLSVersion;
    readonly cipherSuites: readonly CipherSuite[];
    readonly requireClientCert: boolean;
    readonly pinnedCerts?: readonly string[];
    readonly trustedCAs?: readonly string[];
}

// ── TLS Engine Interface ──────────────────────────────────

export interface TLSEngine {
    /** Create a self-signed certificate. */
    createSelfSigned(subject: CertificateSubject, options?: CertCreateOptions): Certificate;
    /** Create a certificate signed by a CA. */
    issueCertificate(subject: CertificateSubject, issuerSerial: string, options?: CertCreateOptions): Certificate | null;
    /** Add a trusted root CA. */
    addTrustedCA(ca: CertificateAuthority): void;
    /** Remove a trusted CA by name. */
    removeTrustedCA(name: string): boolean;
    /** Get all trusted CAs. */
    getTrustedCAs(): readonly CertificateAuthority[];
    /** Store a certificate. */
    storeCertificate(cert: Certificate): void;
    /** Get a certificate by serial. */
    getCertificate(serial: string): Certificate | null;
    /** Validate a certificate chain for a hostname. */
    validateChain(chain: readonly Certificate[], hostname: string, tick?: number): CertificateChain;
    /** Revoke a certificate. */
    revokeCertificate(caName: string, serialNumber: string): boolean;
    /** Check if a certificate is revoked. */
    isRevoked(serialNumber: string): boolean;
    /** Initiate a TLS handshake (simulated). */
    handshake(sni: string, config: TLSConfig): TLSSession;
    /** Get active TLS sessions. */
    getSessions(): readonly TLSSession[];
    /** Assess a TLS configuration for weaknesses. */
    assessConfig(config: TLSConfig): readonly TLSWeakness[];
    /** Get stats. */
    getStats(): TLSStats;
}

export interface CertCreateOptions {
    readonly validityDays?: number;
    readonly keyAlgorithm?: KeyAlgorithm;
    readonly keyBits?: number;
    readonly signatureAlgorithm?: SignatureAlgorithm;
    readonly isCA?: boolean;
    readonly pathLenConstraint?: number;
    readonly keyUsage?: readonly KeyUsage[];
    readonly extKeyUsage?: readonly ExtKeyUsage[];
    readonly subjectAltNames?: readonly SubjectAltName[];
}

export interface TLSWeakness {
    readonly type: TLSWeaknessType;
    readonly severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
    readonly description: string;
    readonly recommendation: string;
    readonly mitre?: string;
}

export type TLSWeaknessType =
    | 'weak-cipher' | 'deprecated-protocol' | 'no-pfs'
    | 'short-key' | 'weak-signature' | 'missing-hsts'
    | 'cert-expired' | 'self-signed-in-chain'
    | 'rc4-enabled' | 'null-cipher' | 'cbc-mode'
    | (string & {});

export interface TLSStats {
    readonly totalCertificates: number;
    readonly trustedCAs: number;
    readonly revokedCertificates: number;
    readonly activeSessions: number;
    readonly totalHandshakes: number;
    readonly expiredCertificates: number;
}
