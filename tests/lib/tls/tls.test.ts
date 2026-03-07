/**
 * VARIANT — TLS/Certificate Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createTLSEngine, bootstrapTrustedCAs } from '../../../src/lib/tls/tls-engine';
import type { CertificateSubject, TLSConfig } from '../../../src/lib/tls/types';

const testSubject: CertificateSubject = {
    commonName: 'example.com',
    organization: 'Test Corp',
    country: 'US',
};

const caSubject: CertificateSubject = {
    commonName: 'Test Root CA',
    organization: 'Test CA Inc',
    country: 'US',
};

describe('TLSEngine', () => {
    // ── Certificate Creation ──────────────────────────────

    it('creates self-signed certificates', () => {
        const tls = createTLSEngine();
        const cert = tls.createSelfSigned(testSubject);
        expect(cert.serialNumber).toBeTruthy();
        expect(cert.subject.commonName).toBe('example.com');
        expect(cert.issuer.commonName).toBe('example.com');
        expect(cert.selfSigned).toBe(true);
        expect(cert.fingerprint).toBeTruthy();
    });

    it('creates CA certificates', () => {
        const tls = createTLSEngine();
        const ca = tls.createSelfSigned(caSubject, {
            isCA: true,
            keyUsage: ['keyCertSign', 'crlSign'],
            extKeyUsage: [],
        });
        expect(ca.isCA).toBe(true);
        expect(ca.keyUsage).toContain('keyCertSign');
    });

    it('issues certificates signed by CA', () => {
        const tls = createTLSEngine();
        const ca = tls.createSelfSigned(caSubject, { isCA: true });
        const cert = tls.issueCertificate(testSubject, ca.serialNumber);
        expect(cert).not.toBeNull();
        expect(cert!.selfSigned).toBe(false);
        expect(cert!.issuer.commonName).toBe('Test Root CA');
    });

    it('refuses to issue from non-CA certificate', () => {
        const tls = createTLSEngine();
        const leaf = tls.createSelfSigned(testSubject, { isCA: false });
        const cert = tls.issueCertificate({ commonName: 'sub.example.com' }, leaf.serialNumber);
        expect(cert).toBeNull();
    });

    it('returns null for unknown issuer serial', () => {
        const tls = createTLSEngine();
        const cert = tls.issueCertificate(testSubject, 'nonexistent');
        expect(cert).toBeNull();
    });

    it('creates certificates with custom SAN', () => {
        const tls = createTLSEngine();
        const cert = tls.createSelfSigned(testSubject, {
            subjectAltNames: [
                { type: 'dns', value: 'example.com' },
                { type: 'dns', value: '*.example.com' },
                { type: 'ip', value: '10.0.0.1' },
            ],
        });
        expect(cert.subjectAltNames).toHaveLength(3);
    });

    // ── Certificate Storage ───────────────────────────────

    it('stores and retrieves certificates', () => {
        const tls = createTLSEngine();
        const cert = tls.createSelfSigned(testSubject);
        const retrieved = tls.getCertificate(cert.serialNumber);
        expect(retrieved).not.toBeNull();
        expect(retrieved!.subject.commonName).toBe('example.com');
    });

    it('returns null for unknown serial', () => {
        const tls = createTLSEngine();
        expect(tls.getCertificate('nonexistent')).toBeNull();
    });

    // ── Trusted CA Management ─────────────────────────────

    it('adds and retrieves trusted CAs', () => {
        const tls = createTLSEngine();
        const ca = tls.createSelfSigned(caSubject, { isCA: true });
        tls.addTrustedCA({
            name: 'Test Root CA',
            certificate: ca,
            isRoot: true,
            revokedSerials: [],
        });
        expect(tls.getTrustedCAs()).toHaveLength(1);
    });

    it('removes trusted CAs', () => {
        const tls = createTLSEngine();
        const ca = tls.createSelfSigned(caSubject, { isCA: true });
        tls.addTrustedCA({ name: 'Test CA', certificate: ca, isRoot: true, revokedSerials: [] });
        expect(tls.removeTrustedCA('Test CA')).toBe(true);
        expect(tls.getTrustedCAs()).toHaveLength(0);
    });

    // ── Chain Validation ──────────────────────────────────

    it('validates a trusted chain', () => {
        const tls = createTLSEngine();
        const ca = tls.createSelfSigned(caSubject, { isCA: true, keyUsage: ['keyCertSign', 'crlSign'] });
        tls.addTrustedCA({ name: 'Test CA', certificate: ca, isRoot: true, revokedSerials: [] });
        const leaf = tls.issueCertificate(testSubject, ca.serialNumber)!;

        const result = tls.validateChain([leaf, ca], 'example.com');
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
    });

    it('detects hostname mismatch', () => {
        const tls = createTLSEngine();
        const ca = tls.createSelfSigned(caSubject, { isCA: true });
        tls.addTrustedCA({ name: 'Test CA', certificate: ca, isRoot: true, revokedSerials: [] });
        const leaf = tls.issueCertificate(testSubject, ca.serialNumber)!;

        const result = tls.validateChain([leaf, ca], 'evil.com');
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.type === 'name-mismatch')).toBe(true);
    });

    it('validates wildcard certificates', () => {
        const tls = createTLSEngine();
        const ca = tls.createSelfSigned(caSubject, { isCA: true, keyUsage: ['keyCertSign', 'crlSign'] });
        tls.addTrustedCA({ name: 'Test CA', certificate: ca, isRoot: true, revokedSerials: [] });
        const leaf = tls.issueCertificate(
            { commonName: '*.example.com' },
            ca.serialNumber,
            { subjectAltNames: [{ type: 'dns', value: '*.example.com' }] },
        )!;

        const result = tls.validateChain([leaf, ca], 'sub.example.com');
        expect(result.valid).toBe(true);
    });

    it('detects expired certificates', () => {
        const tls = createTLSEngine();
        const cert = tls.createSelfSigned(testSubject, { validityDays: 0 });
        // Check with a tick far in the future
        const result = tls.validateChain([cert], 'example.com', Date.now() + 86_400_000);
        expect(result.errors.some(e => e.type === 'expired')).toBe(true);
    });

    it('detects untrusted self-signed root', () => {
        const tls = createTLSEngine();
        const cert = tls.createSelfSigned(testSubject);
        const result = tls.validateChain([cert], 'example.com');
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.type === 'untrusted-root')).toBe(true);
    });

    it('detects weak signature algorithms', () => {
        const tls = createTLSEngine();
        const cert = tls.createSelfSigned(testSubject, { signatureAlgorithm: 'sha1WithRSAEncryption' });
        const result = tls.validateChain([cert], 'example.com');
        expect(result.errors.some(e => e.type === 'weak-signature')).toBe(true);
    });

    // ── Revocation ────────────────────────────────────────

    it('revokes certificates via CA', () => {
        const tls = createTLSEngine();
        const ca = tls.createSelfSigned(caSubject, { isCA: true });
        tls.addTrustedCA({ name: 'Test CA', certificate: ca, isRoot: true, revokedSerials: [] });
        const leaf = tls.issueCertificate(testSubject, ca.serialNumber)!;

        expect(tls.isRevoked(leaf.serialNumber)).toBe(false);
        expect(tls.revokeCertificate('Test CA', leaf.serialNumber)).toBe(true);
        expect(tls.isRevoked(leaf.serialNumber)).toBe(true);

        const result = tls.validateChain([leaf, ca], 'example.com');
        expect(result.errors.some(e => e.type === 'revoked')).toBe(true);
    });

    it('returns false for revoking from unknown CA', () => {
        const tls = createTLSEngine();
        expect(tls.revokeCertificate('Nonexistent CA', 'serial-123')).toBe(false);
    });

    // ── TLS Handshake ─────────────────────────────────────

    it('performs TLS handshake with valid cert', () => {
        const tls = createTLSEngine();
        const ca = tls.createSelfSigned(caSubject, { isCA: true, keyUsage: ['keyCertSign', 'crlSign'] });
        tls.addTrustedCA({ name: 'Test CA', certificate: ca, isRoot: true, revokedSerials: [] });
        tls.issueCertificate(testSubject, ca.serialNumber);

        const config: TLSConfig = {
            minVersion: 'TLS 1.2',
            maxVersion: 'TLS 1.3',
            cipherSuites: ['TLS_AES_128_GCM_SHA256'],
            requireClientCert: false,
        };

        const session = tls.handshake('example.com', config);
        expect(session.state).toBe('established');
        expect(session.version).toBe('TLS 1.3');
        expect(session.sni).toBe('example.com');
    });

    it('tracks sessions', () => {
        const tls = createTLSEngine();
        tls.createSelfSigned(testSubject);
        const config: TLSConfig = {
            minVersion: 'TLS 1.2', maxVersion: 'TLS 1.3',
            cipherSuites: ['TLS_AES_128_GCM_SHA256'], requireClientCert: false,
        };
        tls.handshake('example.com', config);
        expect(tls.getSessions()).toHaveLength(1);
    });

    // ── Configuration Assessment ──────────────────────────

    it('detects deprecated protocol versions', () => {
        const tls = createTLSEngine();
        const weaknesses = tls.assessConfig({
            minVersion: 'SSL 3.0',
            maxVersion: 'TLS 1.2',
            cipherSuites: ['TLS_AES_128_GCM_SHA256'],
            requireClientCert: false,
        });
        expect(weaknesses.some(w => w.type === 'deprecated-protocol')).toBe(true);
    });

    it('detects weak cipher suites', () => {
        const tls = createTLSEngine();
        const weaknesses = tls.assessConfig({
            minVersion: 'TLS 1.2',
            maxVersion: 'TLS 1.3',
            cipherSuites: ['TLS_RSA_WITH_RC4_128_SHA'],
            requireClientCert: false,
        });
        expect(weaknesses.some(w => w.type === 'rc4-enabled')).toBe(true);
    });

    it('detects null cipher suite', () => {
        const tls = createTLSEngine();
        const weaknesses = tls.assessConfig({
            minVersion: 'TLS 1.2',
            maxVersion: 'TLS 1.3',
            cipherSuites: ['TLS_RSA_WITH_NULL_SHA'],
            requireClientCert: false,
        });
        expect(weaknesses.some(w => w.type === 'null-cipher')).toBe(true);
    });

    it('detects ciphers without PFS', () => {
        const tls = createTLSEngine();
        const weaknesses = tls.assessConfig({
            minVersion: 'TLS 1.2',
            maxVersion: 'TLS 1.3',
            cipherSuites: ['TLS_RSA_WITH_AES_128_CBC_SHA'],
            requireClientCert: false,
        });
        expect(weaknesses.some(w => w.type === 'no-pfs')).toBe(true);
    });

    it('passes clean config assessment', () => {
        const tls = createTLSEngine();
        const weaknesses = tls.assessConfig({
            minVersion: 'TLS 1.2',
            maxVersion: 'TLS 1.3',
            cipherSuites: ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384'],
            requireClientCert: false,
        });
        expect(weaknesses).toHaveLength(0);
    });

    // ── Bootstrap ─────────────────────────────────────────

    it('bootstraps trusted CAs', () => {
        const tls = createTLSEngine();
        bootstrapTrustedCAs(tls);
        expect(tls.getTrustedCAs().length).toBeGreaterThanOrEqual(5);
        expect(tls.getTrustedCAs().some(ca => ca.name.includes('DigiCert'))).toBe(true);
        expect(tls.getTrustedCAs().some(ca => ca.name.includes("ISRG"))).toBe(true);
    });

    // ── Stats ─────────────────────────────────────────────

    it('reports statistics', () => {
        const tls = createTLSEngine();
        tls.createSelfSigned(testSubject);
        const ca = tls.createSelfSigned(caSubject, { isCA: true });
        tls.addTrustedCA({ name: 'Test CA', certificate: ca, isRoot: true, revokedSerials: [] });

        const stats = tls.getStats();
        expect(stats.totalCertificates).toBe(2);
        expect(stats.trustedCAs).toBe(1);
    });
});
