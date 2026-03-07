/**
 * VARIANT — Crypto Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createCryptoEngine } from '../../../src/lib/crypto/crypto-engine';
import type { CryptoAlgorithm } from '../../../src/lib/crypto/types';

function sha256(): CryptoAlgorithm {
    return {
        id: 'sha256',
        name: 'SHA-256',
        category: 'hash',
        keySizeBits: 0,
        blockSizeBits: 512,
        strength: 'strong',
        deprecated: false,
        weaknesses: [],
    };
}

function md5(): CryptoAlgorithm {
    return {
        id: 'md5',
        name: 'MD5',
        category: 'hash',
        keySizeBits: 0,
        blockSizeBits: 512,
        strength: 'broken',
        deprecated: true,
        weaknesses: ['Collision attacks practical since 2004'],
    };
}

function aes256(): CryptoAlgorithm {
    return {
        id: 'aes-256-cbc',
        name: 'AES-256-CBC',
        category: 'symmetric',
        keySizeBits: 256,
        blockSizeBits: 128,
        strength: 'strong',
        deprecated: false,
        weaknesses: [],
    };
}

function rsa2048(): CryptoAlgorithm {
    return {
        id: 'rsa-2048',
        name: 'RSA-2048',
        category: 'asymmetric',
        keySizeBits: 2048,
        blockSizeBits: 0,
        strength: 'acceptable',
        deprecated: false,
        weaknesses: [],
    };
}

function des(): CryptoAlgorithm {
    return {
        id: 'des',
        name: 'DES',
        category: 'symmetric',
        keySizeBits: 56,
        blockSizeBits: 64,
        strength: 'weak',
        deprecated: true,
        weaknesses: ['56-bit key space is brute-forceable'],
    };
}

describe('CryptoEngine', () => {
    // ── Algorithm Registry ─────────────────────────────────────

    it('registers and retrieves algorithms', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(sha256());
        engine.registerAlgorithm(aes256());

        expect(engine.getAlgorithm('sha256')).not.toBeNull();
        expect(engine.getAlgorithm('nonexistent')).toBeNull();
        expect(engine.listAlgorithms().length).toBe(2);
    });

    it('throws on duplicate algorithm', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(sha256());
        expect(() => engine.registerAlgorithm(sha256())).toThrow();
    });

    it('lists algorithms by category', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(sha256());
        engine.registerAlgorithm(md5());
        engine.registerAlgorithm(aes256());

        const hashes = engine.listAlgorithmsByCategory('hash');
        expect(hashes.length).toBe(2);
        const symmetric = engine.listAlgorithmsByCategory('symmetric');
        expect(symmetric.length).toBe(1);
        const asymmetric = engine.listAlgorithmsByCategory('asymmetric');
        expect(asymmetric.length).toBe(0);
    });

    // ── Key Management ─────────────────────────────────────────

    it('generates keys with correct metadata', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(aes256());

        const key = engine.generateKey('aes-256-cbc', 'alice', 'any', 0);
        expect(key).not.toBeNull();
        expect(key!.algorithmId).toBe('aes-256-cbc');
        expect(key!.owner).toBe('alice');
        expect(key!.sizeBits).toBe(256);
        expect(key!.strength).toBe('strong');
        expect(key!.compromised).toBe(false);
        expect(key!.material.length).toBeGreaterThan(0);
    });

    it('returns null for key with unknown algorithm', () => {
        const engine = createCryptoEngine();
        expect(engine.generateKey('nonexistent', 'alice', 'any', 0)).toBeNull();
    });

    it('generates unique keys', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(aes256());

        const k1 = engine.generateKey('aes-256-cbc', 'alice', 'any', 0);
        const k2 = engine.generateKey('aes-256-cbc', 'alice', 'any', 0);
        expect(k1!.id).not.toBe(k2!.id);
    });

    it('lists keys by owner', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(aes256());

        engine.generateKey('aes-256-cbc', 'alice', 'any', 0);
        engine.generateKey('aes-256-cbc', 'alice', 'any', 1);
        engine.generateKey('aes-256-cbc', 'bob', 'any', 0);

        expect(engine.listKeys('alice').length).toBe(2);
        expect(engine.listKeys('bob').length).toBe(1);
        expect(engine.listKeys('charlie').length).toBe(0);
    });

    it('compromises a key', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(aes256());

        const key = engine.generateKey('aes-256-cbc', 'alice', 'any', 0)!;
        expect(engine.isKeyValid(key.id, 0)).toBe(true);

        expect(engine.compromiseKey(key.id)).toBe(true);
        expect(engine.isKeyValid(key.id, 0)).toBe(false);
        expect(engine.getKey(key.id)!.compromised).toBe(true);
    });

    it('compromiseKey returns false for unknown key', () => {
        const engine = createCryptoEngine();
        expect(engine.compromiseKey('nonexistent')).toBe(false);
    });

    it('key expiry', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(aes256());

        const key = engine.generateKey('aes-256-cbc', 'alice', 'any', 0, 100)!;
        expect(engine.isKeyValid(key.id, 50)).toBe(true);
        expect(engine.isKeyValid(key.id, 100)).toBe(false);
        expect(engine.isKeyValid(key.id, 200)).toBe(false);
    });

    it('isKeyValid returns false for unknown key', () => {
        const engine = createCryptoEngine();
        expect(engine.isKeyValid('nonexistent', 0)).toBe(false);
    });

    // ── Hashing ────────────────────────────────────────────────

    it('hashes data with correct algorithm', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(sha256());

        const result = engine.hash('sha256', 'hello world', 'alice', 0);
        expect(result.success).toBe(true);
        expect(result.output.length).toBe(64); // SHA-256 produces 64 hex chars
        expect(result.operation).toBe('hash');
        expect(result.algorithmId).toBe('sha256');
        expect(result.warnings.length).toBe(0);
    });

    it('same input produces same hash', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(sha256());

        const r1 = engine.hash('sha256', 'hello', 'alice', 0);
        const r2 = engine.hash('sha256', 'hello', 'bob', 5);
        expect(r1.output).toBe(r2.output);
    });

    it('different input produces different hash', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(sha256());

        const r1 = engine.hash('sha256', 'hello', 'alice', 0);
        const r2 = engine.hash('sha256', 'world', 'alice', 0);
        expect(r1.output).not.toBe(r2.output);
    });

    it('hash warns for deprecated algorithm', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(md5());

        const result = engine.hash('md5', 'test', 'alice', 0);
        expect(result.success).toBe(true);
        expect(result.warnings.length).toBeGreaterThan(0);
        expect(result.warnings.some(w => w.includes('deprecated'))).toBe(true);
        expect(result.warnings.some(w => w.includes('broken'))).toBe(true);
    });

    it('hash fails for unknown algorithm', () => {
        const engine = createCryptoEngine();
        const result = engine.hash('nonexistent', 'test', 'alice', 0);
        expect(result.success).toBe(false);
        expect(result.failureReason).toContain('Unknown algorithm');
    });

    it('hash fails for non-hash algorithm', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(aes256());
        const result = engine.hash('aes-256-cbc', 'test', 'alice', 0);
        expect(result.success).toBe(false);
        expect(result.failureReason).toContain('not a hash algorithm');
    });

    // ── Encrypt / Decrypt ──────────────────────────────────────

    it('encrypt then decrypt round-trips', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(aes256());

        const key = engine.generateKey('aes-256-cbc', 'alice', 'any', 0)!;
        const encrypted = engine.encrypt(key.id, 'secret message', 'alice', 1);
        expect(encrypted.success).toBe(true);
        expect(encrypted.output).not.toBe('secret message');

        const decrypted = engine.decrypt(key.id, encrypted.output, 'alice', 2);
        expect(decrypted.success).toBe(true);
        expect(decrypted.output).toBe('secret message');
    });

    it('encrypt fails for unknown key', () => {
        const engine = createCryptoEngine();
        const result = engine.encrypt('nonexistent', 'data', 'alice', 0);
        expect(result.success).toBe(false);
        expect(result.failureReason).toContain('not found');
    });

    it('encrypt fails for wrong key usage', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(aes256());
        const key = engine.generateKey('aes-256-cbc', 'alice', 'sign', 0)!;

        const result = engine.encrypt(key.id, 'data', 'alice', 0);
        expect(result.success).toBe(false);
        expect(result.failureReason).toContain('not authorized');
    });

    it('encrypt with compromised key warns', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(aes256());
        const key = engine.generateKey('aes-256-cbc', 'alice', 'any', 0)!;

        engine.compromiseKey(key.id);
        const result = engine.encrypt(key.id, 'data', 'alice', 0);
        expect(result.success).toBe(true);
        expect(result.warnings.some(w => w.includes('compromised'))).toBe(true);
    });

    it('decrypt fails for unknown key', () => {
        const engine = createCryptoEngine();
        const result = engine.decrypt('nonexistent', 'aabb', 'alice', 0);
        expect(result.success).toBe(false);
    });

    it('decrypt fails for wrong key usage', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(aes256());
        const key = engine.generateKey('aes-256-cbc', 'alice', 'encrypt', 0)!;

        const result = engine.decrypt(key.id, 'aabb', 'alice', 0);
        expect(result.success).toBe(false);
        expect(result.failureReason).toContain('not authorized');
    });

    // ── Sign / Verify ──────────────────────────────────────────

    it('sign then verify round-trips', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(rsa2048());

        const key = engine.generateKey('rsa-2048', 'alice', 'any', 0)!;
        const signed = engine.sign(key.id, 'important document', 'alice', 1);
        expect(signed.success).toBe(true);
        expect(signed.output.length).toBeGreaterThan(0);

        const verified = engine.verify(key.id, 'important document', signed.output, 'alice', 2);
        expect(verified.success).toBe(true);
        expect(verified.output).toBe('valid');
    });

    it('verify detects tampered data', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(rsa2048());

        const key = engine.generateKey('rsa-2048', 'alice', 'any', 0)!;
        const signed = engine.sign(key.id, 'original', 'alice', 1);

        const verified = engine.verify(key.id, 'tampered', signed.output, 'alice', 2);
        expect(verified.output).toBe('invalid');
    });

    it('verify detects wrong signature', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(rsa2048());

        const key = engine.generateKey('rsa-2048', 'alice', 'any', 0)!;
        const verified = engine.verify(key.id, 'data', 'wrong-signature', 'alice', 0);
        expect(verified.output).toBe('invalid');
    });

    it('sign fails for wrong key usage', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(rsa2048());
        const key = engine.generateKey('rsa-2048', 'alice', 'encrypt', 0)!;

        const result = engine.sign(key.id, 'data', 'alice', 0);
        expect(result.success).toBe(false);
    });

    it('verify fails for wrong key usage', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(rsa2048());
        const key = engine.generateKey('rsa-2048', 'alice', 'encrypt', 0)!;

        const result = engine.verify(key.id, 'data', 'sig', 'alice', 0);
        expect(result.success).toBe(false);
    });

    // ── Certificates ───────────────────────────────────────────

    it('issues and retrieves certificates', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(rsa2048());
        const key = engine.generateKey('rsa-2048', 'ca', 'any', 0)!;

        const cert = engine.issueCertificate('example.com', 'Root CA', 'rsa-2048', key.id, 0, 1000, false);
        expect(cert).not.toBeNull();
        expect(cert!.subject).toBe('example.com');
        expect(cert!.issuer).toBe('Root CA');
        expect(engine.getCertificate(cert!.serialNumber)).not.toBeNull();
    });

    it('returns null for cert with unknown algorithm', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(rsa2048());
        const key = engine.generateKey('rsa-2048', 'ca', 'any', 0)!;

        expect(engine.issueCertificate('x', 'CA', 'nonexistent', key.id, 0, 100, false)).toBeNull();
    });

    it('returns null for cert with unknown key', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(rsa2048());

        expect(engine.issueCertificate('x', 'CA', 'rsa-2048', 'nonexistent', 0, 100, false)).toBeNull();
    });

    it('certificate chain verification', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(rsa2048());
        const rootKey = engine.generateKey('rsa-2048', 'root-ca', 'any', 0)!;
        const leafKey = engine.generateKey('rsa-2048', 'server', 'any', 0)!;

        const rootCert = engine.issueCertificate('Root CA', 'Root CA', 'rsa-2048', rootKey.id, 0, 1000, true)!;
        const leafCert = engine.issueCertificate('example.com', 'Root CA', 'rsa-2048', leafKey.id, 0, 500, false, rootCert.serialNumber)!;

        expect(leafCert.chain).toContain(rootCert.serialNumber);

        const result = engine.verifyCertificateChain(leafCert.serialNumber, 100);
        expect(result.valid).toBe(true);
    });

    it('chain fails for revoked certificate', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(rsa2048());
        const key = engine.generateKey('rsa-2048', 'ca', 'any', 0)!;

        const cert = engine.issueCertificate('example.com', 'CA', 'rsa-2048', key.id, 0, 1000, false)!;
        engine.revokeCertificate(cert.serialNumber);

        const result = engine.verifyCertificateChain(cert.serialNumber, 50);
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('revoked');
    });

    it('chain fails for expired certificate', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(rsa2048());
        const key = engine.generateKey('rsa-2048', 'ca', 'any', 0)!;

        const cert = engine.issueCertificate('example.com', 'CA', 'rsa-2048', key.id, 0, 100, false)!;

        expect(engine.verifyCertificateChain(cert.serialNumber, 50).valid).toBe(true);
        expect(engine.verifyCertificateChain(cert.serialNumber, 100).valid).toBe(false);
    });

    it('chain fails for not-yet-valid certificate', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(rsa2048());
        const key = engine.generateKey('rsa-2048', 'ca', 'any', 0)!;

        const cert = engine.issueCertificate('example.com', 'CA', 'rsa-2048', key.id, 50, 200, false)!;
        expect(engine.verifyCertificateChain(cert.serialNumber, 10).valid).toBe(false);
        expect(engine.verifyCertificateChain(cert.serialNumber, 50).valid).toBe(true);
    });

    it('chain fails when parent CA is revoked', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(rsa2048());
        const rootKey = engine.generateKey('rsa-2048', 'root', 'any', 0)!;
        const leafKey = engine.generateKey('rsa-2048', 'leaf', 'any', 0)!;

        const rootCert = engine.issueCertificate('Root', 'Root', 'rsa-2048', rootKey.id, 0, 1000, true)!;
        const leafCert = engine.issueCertificate('Leaf', 'Root', 'rsa-2048', leafKey.id, 0, 500, false, rootCert.serialNumber)!;

        engine.revokeCertificate(rootCert.serialNumber);
        const result = engine.verifyCertificateChain(leafCert.serialNumber, 100);
        expect(result.valid).toBe(false);
        expect(result.reason).toContain(rootCert.serialNumber);
    });

    it('cannot chain from non-CA parent', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(rsa2048());
        const parentKey = engine.generateKey('rsa-2048', 'parent', 'any', 0)!;
        const childKey = engine.generateKey('rsa-2048', 'child', 'any', 0)!;

        const parentCert = engine.issueCertificate('Parent', 'Parent', 'rsa-2048', parentKey.id, 0, 1000, false)!;
        const childCert = engine.issueCertificate('Child', 'Parent', 'rsa-2048', childKey.id, 0, 500, false, parentCert.serialNumber);
        expect(childCert).toBeNull();
    });

    it('revokeCertificate returns false for unknown cert', () => {
        const engine = createCryptoEngine();
        expect(engine.revokeCertificate('nonexistent')).toBe(false);
    });

    it('verifyCertificateChain returns invalid for unknown cert', () => {
        const engine = createCryptoEngine();
        const result = engine.verifyCertificateChain('nonexistent', 0);
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('not found');
    });

    it('lists all certificates', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(rsa2048());
        const k1 = engine.generateKey('rsa-2048', 'a', 'any', 0)!;
        const k2 = engine.generateKey('rsa-2048', 'b', 'any', 0)!;

        engine.issueCertificate('A', 'CA', 'rsa-2048', k1.id, 0, 100, false);
        engine.issueCertificate('B', 'CA', 'rsa-2048', k2.id, 0, 100, false);
        expect(engine.listCertificates().length).toBe(2);
    });

    // ── Audit Log ──────────────────────────────────────────────

    it('records all operations in audit log', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(sha256());
        engine.registerAlgorithm(aes256());

        engine.hash('sha256', 'test', 'alice', 0);
        const key = engine.generateKey('aes-256-cbc', 'alice', 'any', 0)!;
        engine.encrypt(key.id, 'data', 'alice', 1);
        engine.decrypt(key.id, engine.encrypt(key.id, 'data', 'alice', 2).output, 'alice', 3);

        const log = engine.getAuditLog();
        expect(log.length).toBe(4);
        expect(log[0]!.operation).toBe('hash');
        expect(log[1]!.operation).toBe('encrypt');
    });

    it('audit log includes warnings', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(md5());

        engine.hash('md5', 'test', 'alice', 0);
        const log = engine.getAuditLog();
        expect(log[0]!.warnings.length).toBeGreaterThan(0);
    });

    // ── Weak Algorithm Warnings ────────────────────────────────

    it('weak algorithm generates warnings on encrypt', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(des());
        const key = engine.generateKey('des', 'alice', 'any', 0)!;

        const result = engine.encrypt(key.id, 'data', 'alice', 0);
        expect(result.success).toBe(true);
        expect(result.warnings.some(w => w.includes('deprecated'))).toBe(true);
        expect(result.warnings.some(w => w.includes('insufficient'))).toBe(true);
    });

    // ── Clear ──────────────────────────────────────────────────

    it('clear removes everything', () => {
        const engine = createCryptoEngine();
        engine.registerAlgorithm(sha256());
        engine.registerAlgorithm(aes256());
        engine.generateKey('aes-256-cbc', 'alice', 'any', 0);
        engine.hash('sha256', 'test', 'alice', 0);

        engine.clear();

        expect(engine.listAlgorithms().length).toBe(0);
        expect(engine.listKeys('alice').length).toBe(0);
        expect(engine.listCertificates().length).toBe(0);
        expect(engine.getAuditLog().length).toBe(0);
    });
});
