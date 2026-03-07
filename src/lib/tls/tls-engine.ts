/**
 * VARIANT — TLS/Certificate Engine
 *
 * Simulates PKI infrastructure with:
 * - Self-signed and CA-issued certificate generation
 * - Certificate chain validation (expiry, trust, hostname, key usage)
 * - CRL-based revocation checking
 * - TLS handshake simulation
 * - Configuration weakness assessment
 *
 * All operations are synchronous and pure-data.
 */

import type {
    TLSEngine,
    Certificate,
    CertificateSubject,
    CertificateChain,
    CertificateError,
    CertErrorType,
    CertificateAuthority,
    CertCreateOptions,
    TLSConfig,
    TLSSession,
    TLSWeakness,
    TLSWeaknessType,
    TLSStats,
    KeyUsage,
    ExtKeyUsage,
} from './types';

// ── Helpers ───────────────────────────────────────────────

let serialCounter = 0;
let sessionCounter = 0;

function generateSerial(): string {
    return `${++serialCounter}:${Date.now().toString(16)}:${Math.random().toString(36).slice(2, 8)}`;
}

function generateFingerprint(): string {
    const bytes: string[] = [];
    for (let i = 0; i < 20; i++) {
        bytes.push(Math.floor(Math.random() * 256).toString(16).padStart(2, '0'));
    }
    return bytes.join(':').toUpperCase();
}

function generateSessionId(): string {
    return `tls-${++sessionCounter}-${Date.now().toString(36)}`;
}

function matchesHostname(hostname: string, cert: Certificate): boolean {
    // Check CN
    if (cert.subject.commonName === hostname) return true;
    if (matchesWildcard(hostname, cert.subject.commonName)) return true;

    // Check SANs
    for (const san of cert.subjectAltNames) {
        if (san.type === 'dns') {
            if (san.value === hostname || matchesWildcard(hostname, san.value)) return true;
        }
        if (san.type === 'ip' && san.value === hostname) return true;
    }

    return false;
}

function matchesWildcard(hostname: string, pattern: string): boolean {
    if (!pattern.startsWith('*.')) return false;
    const domain = pattern.slice(2);
    const hostParts = hostname.split('.');
    if (hostParts.length < 2) return false;
    return hostParts.slice(1).join('.') === domain;
}

const WEAK_SIGNATURE_ALGORITHMS = new Set([
    'sha1WithRSAEncryption', 'md5WithRSAEncryption',
]);

const DEPRECATED_PROTOCOLS = new Set(['SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1']);

const WEAK_CIPHERS = new Set([
    'TLS_RSA_WITH_RC4_128_SHA',
    'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    'TLS_RSA_WITH_NULL_SHA',
]);

const NO_PFS_CIPHERS = new Set([
    'TLS_RSA_WITH_AES_128_CBC_SHA',
    'TLS_RSA_WITH_AES_256_CBC_SHA',
    'TLS_RSA_WITH_RC4_128_SHA',
    'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    'TLS_RSA_WITH_NULL_SHA',
]);

const CBC_CIPHERS = new Set([
    'TLS_RSA_WITH_AES_128_CBC_SHA',
    'TLS_RSA_WITH_AES_256_CBC_SHA',
]);

// ── Factory ──────────────────────────────────────────────

export function createTLSEngine(): TLSEngine {
    const certificates = new Map<string, Certificate>();
    const trustedCAs = new Map<string, CertificateAuthority>();
    const sessions: TLSSession[] = [];
    let totalHandshakes = 0;

    function findCABySubject(subject: CertificateSubject): CertificateAuthority | undefined {
        for (const ca of trustedCAs.values()) {
            if (ca.certificate.subject.commonName === subject.commonName &&
                ca.certificate.subject.organization === subject.organization) {
                return ca;
            }
        }
        return undefined;
    }

    const engine: TLSEngine = {
        createSelfSigned(subject: CertificateSubject, options?: CertCreateOptions): Certificate {
            const now = Date.now();
            const validityMs = (options?.validityDays ?? 365) * 86_400_000;

            const base = {
                serialNumber: generateSerial(),
                subject,
                issuer: subject,
                notBefore: now,
                notAfter: now + validityMs,
                publicKeyAlgorithm: options?.keyAlgorithm ?? 'RSA' as Certificate['publicKeyAlgorithm'],
                publicKeyBits: options?.keyBits ?? 2048,
                signatureAlgorithm: options?.signatureAlgorithm ?? 'sha256WithRSAEncryption' as Certificate['signatureAlgorithm'],
                fingerprint: generateFingerprint(),
                isCA: options?.isCA ?? false,
                keyUsage: options?.keyUsage ?? ['digitalSignature', 'keyEncipherment'] as readonly KeyUsage[],
                extKeyUsage: options?.extKeyUsage ?? ['serverAuth'] as readonly ExtKeyUsage[],
                subjectAltNames: options?.subjectAltNames ?? [{ type: 'dns' as const, value: subject.commonName }],
                selfSigned: true as const,
            };
            const withOptional = {
                ...base,
                ...(options?.pathLenConstraint !== undefined ? { pathLenConstraint: options.pathLenConstraint } : {}),
            };
            const cert = Object.freeze(withOptional) as Certificate;

            certificates.set(cert.serialNumber, cert);
            return cert;
        },

        issueCertificate(subject: CertificateSubject, issuerSerial: string, options?: CertCreateOptions): Certificate | null {
            const issuerCert = certificates.get(issuerSerial);
            if (!issuerCert) return null;

            // Verify issuer is a CA
            if (!issuerCert.isCA) return null;

            const now = Date.now();
            const validityMs = (options?.validityDays ?? 365) * 86_400_000;
            const akid = issuerCert.subjectKeyIdentifier ?? issuerCert.fingerprint;

            const base = {
                serialNumber: generateSerial(),
                subject,
                issuer: issuerCert.subject,
                notBefore: now,
                notAfter: Math.min(now + validityMs, issuerCert.notAfter),
                publicKeyAlgorithm: options?.keyAlgorithm ?? 'RSA' as Certificate['publicKeyAlgorithm'],
                publicKeyBits: options?.keyBits ?? 2048,
                signatureAlgorithm: options?.signatureAlgorithm ?? 'sha256WithRSAEncryption' as Certificate['signatureAlgorithm'],
                fingerprint: generateFingerprint(),
                isCA: options?.isCA ?? false,
                keyUsage: options?.keyUsage ?? (options?.isCA
                    ? ['keyCertSign', 'crlSign'] as readonly KeyUsage[]
                    : ['digitalSignature', 'keyEncipherment'] as readonly KeyUsage[]),
                extKeyUsage: options?.extKeyUsage ?? (options?.isCA
                    ? [] as readonly ExtKeyUsage[]
                    : ['serverAuth'] as readonly ExtKeyUsage[]),
                subjectAltNames: options?.subjectAltNames ?? [{ type: 'dns' as const, value: subject.commonName }],
                authorityKeyIdentifier: akid,
                selfSigned: false as const,
            };
            const withOptional = {
                ...base,
                ...(options?.pathLenConstraint !== undefined ? { pathLenConstraint: options.pathLenConstraint } : {}),
            };
            const cert = Object.freeze(withOptional) as Certificate;

            certificates.set(cert.serialNumber, cert);
            return cert;
        },

        addTrustedCA(ca: CertificateAuthority): void {
            trustedCAs.set(ca.name, ca);
            certificates.set(ca.certificate.serialNumber, ca.certificate);
        },

        removeTrustedCA(name: string): boolean {
            return trustedCAs.delete(name);
        },

        getTrustedCAs(): readonly CertificateAuthority[] {
            return Object.freeze(Array.from(trustedCAs.values()));
        },

        storeCertificate(cert: Certificate): void {
            certificates.set(cert.serialNumber, cert);
        },

        getCertificate(serial: string): Certificate | null {
            return certificates.get(serial) ?? null;
        },

        validateChain(chain: readonly Certificate[], hostname: string, tick?: number): CertificateChain {
            const now = tick ?? Date.now();
            const errors: CertificateError[] = [];

            if (chain.length === 0) {
                return Object.freeze({
                    certificates: [],
                    valid: false,
                    errors: [{ type: 'chain-incomplete' as CertErrorType, certificate: {} as Certificate, message: 'Empty certificate chain' }],
                });
            }

            const leaf = chain[0]!;

            // Check hostname match on leaf
            if (!matchesHostname(hostname, leaf)) {
                errors.push({
                    type: 'name-mismatch',
                    certificate: leaf,
                    message: `Certificate CN/SAN does not match hostname '${hostname}'`,
                });
            }

            // Check each certificate in the chain
            let trustAnchor: Certificate | undefined;

            for (let i = 0; i < chain.length; i++) {
                const cert = chain[i]!;

                // Expiry check
                if (now > cert.notAfter) {
                    errors.push({
                        type: 'expired',
                        certificate: cert,
                        message: `Certificate '${cert.subject.commonName}' has expired`,
                    });
                }
                if (now < cert.notBefore) {
                    errors.push({
                        type: 'not-yet-valid',
                        certificate: cert,
                        message: `Certificate '${cert.subject.commonName}' is not yet valid`,
                    });
                }

                // Weak signature check
                if (WEAK_SIGNATURE_ALGORITHMS.has(cert.signatureAlgorithm)) {
                    errors.push({
                        type: 'weak-signature',
                        certificate: cert,
                        message: `Certificate '${cert.subject.commonName}' uses weak signature algorithm: ${cert.signatureAlgorithm}`,
                    });
                }

                // Short key check
                if (cert.publicKeyAlgorithm === 'RSA' && cert.publicKeyBits < 2048) {
                    errors.push({
                        type: 'weak-signature',
                        certificate: cert,
                        message: `Certificate '${cert.subject.commonName}' has weak ${cert.publicKeyBits}-bit RSA key`,
                    });
                }

                // Revocation check
                if (engine.isRevoked(cert.serialNumber)) {
                    errors.push({
                        type: 'revoked',
                        certificate: cert,
                        message: `Certificate '${cert.subject.commonName}' has been revoked`,
                    });
                }

                // Key usage check for non-leaf
                if (i > 0 && !cert.keyUsage.includes('keyCertSign')) {
                    errors.push({
                        type: 'key-usage-missing',
                        certificate: cert,
                        message: `Intermediate '${cert.subject.commonName}' lacks keyCertSign key usage`,
                    });
                }

                // Path length constraint check
                if (i > 0 && cert.pathLenConstraint !== undefined) {
                    const remainingIntermediates = i - 1;
                    if (remainingIntermediates > cert.pathLenConstraint) {
                        errors.push({
                            type: 'path-length-exceeded',
                            certificate: cert,
                            message: `Path length constraint exceeded for '${cert.subject.commonName}'`,
                        });
                    }
                }

                // Trust anchor check (is this cert a trusted root?)
                const ca = findCABySubject(cert.subject);
                if (ca !== undefined) {
                    trustAnchor = cert;
                }
            }

            // Check if we reach a trusted root
            const lastCert = chain[chain.length - 1]!;
            if (!trustAnchor) {
                if (lastCert.selfSigned) {
                    errors.push({
                        type: 'untrusted-root',
                        certificate: lastCert,
                        message: `Self-signed root '${lastCert.subject.commonName}' is not in the trust store`,
                    });
                } else {
                    errors.push({
                        type: 'chain-incomplete',
                        certificate: lastCert,
                        message: `Certificate chain does not reach a trusted root`,
                    });
                }
            }

            // Check leaf has serverAuth EKU
            if (!leaf.extKeyUsage.includes('serverAuth') && leaf.extKeyUsage.length > 0) {
                errors.push({
                    type: 'key-usage-missing',
                    certificate: leaf,
                    message: `Leaf certificate '${leaf.subject.commonName}' lacks serverAuth extended key usage`,
                });
            }

            const chainResult = {
                certificates: chain,
                valid: errors.length === 0,
                errors: Object.freeze(errors),
            };
            return Object.freeze(
                trustAnchor !== undefined ? { ...chainResult, trustAnchor } : chainResult
            ) as CertificateChain;
        },

        revokeCertificate(caName: string, serialNumber: string): boolean {
            const ca = trustedCAs.get(caName);
            if (!ca) return false;
            const updated: CertificateAuthority = {
                ...ca,
                revokedSerials: [...ca.revokedSerials, serialNumber],
            };
            trustedCAs.set(caName, updated);
            return true;
        },

        isRevoked(serialNumber: string): boolean {
            for (const ca of trustedCAs.values()) {
                if (ca.revokedSerials.includes(serialNumber)) return true;
            }
            return false;
        },

        handshake(sni: string, config: TLSConfig): TLSSession {
            totalHandshakes++;

            // Find certificate matching SNI
            let serverCert: Certificate | undefined;
            for (const cert of certificates.values()) {
                if (matchesHostname(sni, cert) && !cert.isCA) {
                    serverCert = cert;
                    break;
                }
            }

            const chain: Certificate[] = serverCert ? [serverCert] : [];

            // Build chain up to root
            if (serverCert && !serverCert.selfSigned) {
                let current = serverCert;
                for (let depth = 0; depth < 10; depth++) {
                    const issuerCA = findCABySubject(current.issuer);
                    if (issuerCA) {
                        chain.push(issuerCA.certificate);
                        if (issuerCA.isRoot) break;
                        current = issuerCA.certificate;
                    } else {
                        break;
                    }
                }
            }

            const validatedChain = engine.validateChain(chain, sni);

            // Select cipher suite
            const selectedCipher = config.cipherSuites[0] ?? 'TLS_AES_128_GCM_SHA256';

            const session: TLSSession = Object.freeze({
                id: generateSessionId(),
                version: config.maxVersion,
                cipherSuite: selectedCipher,
                serverCertChain: validatedChain,
                sni,
                resumed: false,
                startTick: Date.now(),
                state: validatedChain.valid ? 'established' as const : 'error' as const,
            });

            sessions.push(session);
            return session;
        },

        getSessions(): readonly TLSSession[] {
            return Object.freeze([...sessions]);
        },

        assessConfig(config: TLSConfig): readonly TLSWeakness[] {
            const weaknesses: TLSWeakness[] = [];

            // Check for deprecated protocols
            if (DEPRECATED_PROTOCOLS.has(config.minVersion)) {
                weaknesses.push(Object.freeze({
                    type: 'deprecated-protocol' as TLSWeaknessType,
                    severity: config.minVersion === 'SSL 2.0' || config.minVersion === 'SSL 3.0' ? 'critical' : 'high',
                    description: `Deprecated protocol version allowed: ${config.minVersion}`,
                    recommendation: `Set minimum TLS version to TLS 1.2 or higher`,
                    mitre: 'T1557',
                }));
            }

            for (const suite of config.cipherSuites) {
                // Weak ciphers
                if (WEAK_CIPHERS.has(suite)) {
                    weaknesses.push(Object.freeze({
                        type: (suite.includes('RC4') ? 'rc4-enabled' : suite.includes('NULL') ? 'null-cipher' : 'weak-cipher') as TLSWeaknessType,
                        severity: suite.includes('NULL') ? 'critical' : 'high',
                        description: `Weak cipher suite enabled: ${suite}`,
                        recommendation: `Remove ${suite} from allowed cipher suites`,
                    }));
                }

                // No PFS
                if (NO_PFS_CIPHERS.has(suite)) {
                    weaknesses.push(Object.freeze({
                        type: 'no-pfs' as TLSWeaknessType,
                        severity: 'medium',
                        description: `Cipher suite without Perfect Forward Secrecy: ${suite}`,
                        recommendation: `Use ECDHE-based cipher suites for PFS`,
                    }));
                }

                // CBC mode
                if (CBC_CIPHERS.has(suite)) {
                    weaknesses.push(Object.freeze({
                        type: 'cbc-mode' as TLSWeaknessType,
                        severity: 'low',
                        description: `CBC mode cipher suite (vulnerable to BEAST/Lucky13): ${suite}`,
                        recommendation: `Prefer GCM or ChaCha20 cipher suites`,
                    }));
                }
            }

            return Object.freeze(weaknesses);
        },

        getStats(): TLSStats {
            const now = Date.now();
            let expired = 0;
            let revoked = 0;
            for (const cert of certificates.values()) {
                if (now > cert.notAfter) expired++;
                if (engine.isRevoked(cert.serialNumber)) revoked++;
            }

            return Object.freeze({
                totalCertificates: certificates.size,
                trustedCAs: trustedCAs.size,
                revokedCertificates: revoked,
                activeSessions: sessions.filter(s => s.state === 'established').length,
                totalHandshakes,
                expiredCertificates: expired,
            });
        },
    };

    return engine;
}

/** Bootstrap common trusted CAs for a realistic simulation. */
export function bootstrapTrustedCAs(engine: TLSEngine): void {
    const rootCAs: Array<{ name: string; cn: string; org: string }> = [
        { name: 'DigiCert Global Root G2', cn: 'DigiCert Global Root G2', org: 'DigiCert Inc' },
        { name: 'ISRG Root X1', cn: 'ISRG Root X1', org: "Let's Encrypt" },
        { name: 'GlobalSign Root CA', cn: 'GlobalSign Root CA', org: 'GlobalSign' },
        { name: 'Baltimore CyberTrust Root', cn: 'Baltimore CyberTrust Root', org: 'Baltimore' },
        { name: 'Amazon Root CA 1', cn: 'Amazon Root CA 1', org: 'Amazon' },
    ];

    for (const root of rootCAs) {
        const cert = engine.createSelfSigned(
            { commonName: root.cn, organization: root.org, country: 'US' },
            {
                validityDays: 7300,
                isCA: true,
                keyBits: 4096,
                keyUsage: ['keyCertSign', 'crlSign'],
                extKeyUsage: [],
            },
        );

        engine.addTrustedCA({
            name: root.name,
            certificate: cert,
            isRoot: true,
            revokedSerials: [],
        });
    }
}
