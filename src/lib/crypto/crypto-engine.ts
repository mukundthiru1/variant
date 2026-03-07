/**
 * VARIANT — Crypto Engine Implementation
 *
 * Deterministic cryptographic simulation for cybersecurity training.
 * NOT real cryptography — outputs are predictable and inspectable.
 *
 * SWAPPABILITY: Implements CryptoEngine. Replace this file.
 */

import type {
    CryptoEngine,
    CryptoAlgorithm,
    AlgorithmCategory,
    CryptoKey,
    KeyUsage,
    StrengthRating,
    Certificate,
    CryptoOperationResult,
    CryptoOperationType,
    CryptoAuditEntry,
} from './types';

interface MutableKey {
    readonly id: string;
    readonly algorithmId: string;
    readonly material: string;
    readonly sizeBits: number;
    readonly strength: StrengthRating;
    readonly createdAt: number;
    readonly expiresAt?: number;
    readonly owner: string;
    readonly usage: KeyUsage;
    compromised: boolean;
}

interface MutableCertificate {
    readonly serialNumber: string;
    readonly subject: string;
    readonly issuer: string;
    readonly algorithmId: string;
    readonly publicKeyId: string;
    readonly validFrom: number;
    readonly validUntil: number;
    revoked: boolean;
    readonly chain: string[];
    readonly isCA: boolean;
}

/**
 * Deterministic "hash" for simulation purposes.
 * Produces a hex string derived from the input — NOT cryptographically secure.
 */
function simHash(input: string, algorithmId: string): string {
    let h = 0x811c9dc5; // FNV offset basis
    for (let i = 0; i < input.length; i++) {
        h ^= input.charCodeAt(i);
        h = Math.imul(h, 0x01000193); // FNV prime
    }
    // Mix in algorithm ID for uniqueness
    for (let i = 0; i < algorithmId.length; i++) {
        h ^= algorithmId.charCodeAt(i);
        h = Math.imul(h, 0x01000193);
    }
    // Produce hex output
    const u = h >>> 0;
    const hex = u.toString(16).padStart(8, '0');
    // Extend to look realistic based on algorithm
    if (algorithmId.includes('256') || algorithmId.includes('sha256')) {
        return (hex + hex + hex + hex + hex + hex + hex + hex).slice(0, 64);
    }
    if (algorithmId.includes('512') || algorithmId.includes('sha512')) {
        return (hex.repeat(16)).slice(0, 128);
    }
    if (algorithmId.includes('md5')) {
        return (hex + hex + hex + hex).slice(0, 32);
    }
    return (hex + hex + hex + hex).slice(0, 32);
}

/**
 * Deterministic "encrypt" — XOR-style simulation.
 * The output is reversible with the same key material.
 */
function simEncrypt(plaintext: string, keyMaterial: string): string {
    const result: string[] = [];
    for (let i = 0; i < plaintext.length; i++) {
        const pc = plaintext.charCodeAt(i);
        const kc = keyMaterial.charCodeAt(i % keyMaterial.length);
        result.push((pc ^ kc).toString(16).padStart(2, '0'));
    }
    return result.join('');
}

/**
 * Deterministic "decrypt" — reverses simEncrypt.
 */
function simDecrypt(ciphertext: string, keyMaterial: string): string {
    const result: string[] = [];
    for (let i = 0; i < ciphertext.length; i += 2) {
        const byte = parseInt(ciphertext.slice(i, i + 2), 16);
        const kc = keyMaterial.charCodeAt((i / 2) % keyMaterial.length);
        result.push(String.fromCharCode(byte ^ kc));
    }
    return result.join('');
}

/**
 * Generate deterministic "key material" from seed values.
 */
function generateKeyMaterial(algorithmId: string, owner: string, tick: number, counter: number): string {
    const seed = `${algorithmId}:${owner}:${tick}:${counter}`;
    return simHash(seed, 'keygen');
}

function deriveStrength(algorithm: CryptoAlgorithm): StrengthRating {
    return algorithm.strength;
}

function warningsForAlgorithm(algorithm: CryptoAlgorithm): string[] {
    const warnings: string[] = [];
    if (algorithm.deprecated) {
        warnings.push(`Algorithm '${algorithm.id}' is deprecated and should not be used`);
    }
    if (algorithm.strength === 'broken') {
        warnings.push(`Algorithm '${algorithm.id}' is cryptographically broken`);
    }
    if (algorithm.strength === 'weak') {
        warnings.push(`Algorithm '${algorithm.id}' provides insufficient security`);
    }
    for (const w of algorithm.weaknesses) {
        warnings.push(w);
    }
    return warnings;
}

function toKey(k: MutableKey): CryptoKey {
    const base: CryptoKey = {
        id: k.id,
        algorithmId: k.algorithmId,
        material: k.material,
        sizeBits: k.sizeBits,
        strength: k.strength,
        createdAt: k.createdAt,
        owner: k.owner,
        usage: k.usage,
        compromised: k.compromised,
    };
    if (k.expiresAt !== undefined) {
        return { ...base, expiresAt: k.expiresAt };
    }
    return base;
}

function toCertificate(c: MutableCertificate): Certificate {
    return {
        serialNumber: c.serialNumber,
        subject: c.subject,
        issuer: c.issuer,
        algorithmId: c.algorithmId,
        publicKeyId: c.publicKeyId,
        validFrom: c.validFrom,
        validUntil: c.validUntil,
        revoked: c.revoked,
        chain: [...c.chain],
        isCA: c.isCA,
    };
}

export function createCryptoEngine(): CryptoEngine {
    const algorithms = new Map<string, CryptoAlgorithm>();
    const keys = new Map<string, MutableKey>();
    const certificates = new Map<string, MutableCertificate>();
    const auditLog: CryptoAuditEntry[] = [];
    let keyCounter = 0;
    let certCounter = 0;

    function recordAudit(
        tick: number,
        principal: string,
        operation: CryptoOperationType,
        algorithmId: string,
        success: boolean,
        warnings: readonly string[],
        keyId?: string,
    ): void {
        const entry: CryptoAuditEntry = keyId !== undefined
            ? { tick, principal, operation, algorithmId, keyId, success, warnings }
            : { tick, principal, operation, algorithmId, success, warnings };
        auditLog.push(entry);
    }

    return {
        // ── Algorithm Registry ──────────────────────────────────

        registerAlgorithm(algorithm: CryptoAlgorithm): void {
            if (algorithms.has(algorithm.id)) {
                throw new Error(`Algorithm '${algorithm.id}' already registered`);
            }
            algorithms.set(algorithm.id, algorithm);
        },

        getAlgorithm(id: string): CryptoAlgorithm | null {
            return algorithms.get(id) ?? null;
        },

        listAlgorithms(): readonly CryptoAlgorithm[] {
            return [...algorithms.values()];
        },

        listAlgorithmsByCategory(category: AlgorithmCategory): readonly CryptoAlgorithm[] {
            return [...algorithms.values()].filter(a => a.category === category);
        },

        // ── Key Management ──────────────────────────────────────

        generateKey(
            algorithmId: string,
            owner: string,
            usage: KeyUsage,
            tick: number,
            expiresAt?: number,
        ): CryptoKey | null {
            const algorithm = algorithms.get(algorithmId);
            if (algorithm === undefined) return null;

            keyCounter++;
            const id = `key-${keyCounter}`;
            const material = generateKeyMaterial(algorithmId, owner, tick, keyCounter);
            const strength = deriveStrength(algorithm);

            const base = {
                id,
                algorithmId,
                material,
                sizeBits: algorithm.keySizeBits,
                strength,
                createdAt: tick,
                owner,
                usage,
                compromised: false,
            };

            const key: MutableKey = expiresAt !== undefined
                ? { ...base, expiresAt }
                : base;

            keys.set(id, key);
            return toKey(key);
        },

        getKey(id: string): CryptoKey | null {
            const k = keys.get(id);
            if (k === undefined) return null;
            return toKey(k);
        },

        listKeys(owner: string): readonly CryptoKey[] {
            return [...keys.values()]
                .filter(k => k.owner === owner)
                .map(toKey);
        },

        compromiseKey(keyId: string): boolean {
            const key = keys.get(keyId);
            if (key === undefined) return false;
            key.compromised = true;
            return true;
        },

        isKeyValid(keyId: string, tick: number): boolean {
            const key = keys.get(keyId);
            if (key === undefined) return false;
            if (key.compromised) return false;
            if (key.expiresAt !== undefined && tick >= key.expiresAt) return false;
            return true;
        },

        // ── Crypto Operations ───────────────────────────────────

        hash(algorithmId: string, data: string, principal: string, tick: number): CryptoOperationResult {
            const algorithm = algorithms.get(algorithmId);
            if (algorithm === undefined) {
                const result: CryptoOperationResult = {
                    success: false,
                    output: '',
                    operation: 'hash',
                    algorithmId,
                    warnings: [],
                    failureReason: `Unknown algorithm '${algorithmId}'`,
                };
                recordAudit(tick, principal, 'hash', algorithmId, false, []);
                return result;
            }

            if (algorithm.category !== 'hash') {
                const result: CryptoOperationResult = {
                    success: false,
                    output: '',
                    operation: 'hash',
                    algorithmId,
                    warnings: [],
                    failureReason: `Algorithm '${algorithmId}' is not a hash algorithm`,
                };
                recordAudit(tick, principal, 'hash', algorithmId, false, []);
                return result;
            }

            const warnings = warningsForAlgorithm(algorithm);
            const output = simHash(data, algorithmId);
            const result: CryptoOperationResult = {
                success: true,
                output,
                operation: 'hash',
                algorithmId,
                warnings,
            };
            recordAudit(tick, principal, 'hash', algorithmId, true, warnings);
            return result;
        },

        encrypt(keyId: string, plaintext: string, principal: string, tick: number): CryptoOperationResult {
            const key = keys.get(keyId);
            if (key === undefined) {
                const result: CryptoOperationResult = {
                    success: false,
                    output: '',
                    operation: 'encrypt',
                    algorithmId: 'unknown',
                    warnings: [],
                    failureReason: `Key '${keyId}' not found`,
                };
                recordAudit(tick, principal, 'encrypt', 'unknown', false, []);
                return result;
            }

            if (key.usage !== 'encrypt' && key.usage !== 'any') {
                const result: CryptoOperationResult = {
                    success: false,
                    output: '',
                    operation: 'encrypt',
                    algorithmId: key.algorithmId,
                    keyId,
                    warnings: [],
                    failureReason: `Key '${keyId}' is not authorized for encryption`,
                };
                recordAudit(tick, principal, 'encrypt', key.algorithmId, false, [], keyId);
                return result;
            }

            if (key.compromised) {
                const algorithm = algorithms.get(key.algorithmId);
                const warnings = algorithm !== undefined ? warningsForAlgorithm(algorithm) : [];
                warnings.push('Key has been compromised — encryption may be insecure');
                const output = simEncrypt(plaintext, key.material);
                const result: CryptoOperationResult = {
                    success: true,
                    output,
                    operation: 'encrypt',
                    algorithmId: key.algorithmId,
                    keyId,
                    warnings,
                };
                recordAudit(tick, principal, 'encrypt', key.algorithmId, true, warnings, keyId);
                return result;
            }

            const algorithm = algorithms.get(key.algorithmId);
            const warnings = algorithm !== undefined ? warningsForAlgorithm(algorithm) : [];
            const output = simEncrypt(plaintext, key.material);
            const result: CryptoOperationResult = {
                success: true,
                output,
                operation: 'encrypt',
                algorithmId: key.algorithmId,
                keyId,
                warnings,
            };
            recordAudit(tick, principal, 'encrypt', key.algorithmId, true, warnings, keyId);
            return result;
        },

        decrypt(keyId: string, ciphertext: string, principal: string, tick: number): CryptoOperationResult {
            const key = keys.get(keyId);
            if (key === undefined) {
                const result: CryptoOperationResult = {
                    success: false,
                    output: '',
                    operation: 'decrypt',
                    algorithmId: 'unknown',
                    warnings: [],
                    failureReason: `Key '${keyId}' not found`,
                };
                recordAudit(tick, principal, 'decrypt', 'unknown', false, []);
                return result;
            }

            if (key.usage !== 'decrypt' && key.usage !== 'any') {
                const result: CryptoOperationResult = {
                    success: false,
                    output: '',
                    operation: 'decrypt',
                    algorithmId: key.algorithmId,
                    keyId,
                    warnings: [],
                    failureReason: `Key '${keyId}' is not authorized for decryption`,
                };
                recordAudit(tick, principal, 'decrypt', key.algorithmId, false, [], keyId);
                return result;
            }

            const algorithm = algorithms.get(key.algorithmId);
            const warnings = algorithm !== undefined ? warningsForAlgorithm(algorithm) : [];
            const output = simDecrypt(ciphertext, key.material);
            const result: CryptoOperationResult = {
                success: true,
                output,
                operation: 'decrypt',
                algorithmId: key.algorithmId,
                keyId,
                warnings,
            };
            recordAudit(tick, principal, 'decrypt', key.algorithmId, true, warnings, keyId);
            return result;
        },

        sign(keyId: string, data: string, principal: string, tick: number): CryptoOperationResult {
            const key = keys.get(keyId);
            if (key === undefined) {
                const result: CryptoOperationResult = {
                    success: false,
                    output: '',
                    operation: 'sign',
                    algorithmId: 'unknown',
                    warnings: [],
                    failureReason: `Key '${keyId}' not found`,
                };
                recordAudit(tick, principal, 'sign', 'unknown', false, []);
                return result;
            }

            if (key.usage !== 'sign' && key.usage !== 'any') {
                const result: CryptoOperationResult = {
                    success: false,
                    output: '',
                    operation: 'sign',
                    algorithmId: key.algorithmId,
                    keyId,
                    warnings: [],
                    failureReason: `Key '${keyId}' is not authorized for signing`,
                };
                recordAudit(tick, principal, 'sign', key.algorithmId, false, [], keyId);
                return result;
            }

            const algorithm = algorithms.get(key.algorithmId);
            const warnings = algorithm !== undefined ? warningsForAlgorithm(algorithm) : [];
            // Signature = hash of (data + key material)
            const signature = simHash(data + key.material, key.algorithmId);
            const result: CryptoOperationResult = {
                success: true,
                output: signature,
                operation: 'sign',
                algorithmId: key.algorithmId,
                keyId,
                warnings,
            };
            recordAudit(tick, principal, 'sign', key.algorithmId, true, warnings, keyId);
            return result;
        },

        verify(keyId: string, data: string, signature: string, principal: string, tick: number): CryptoOperationResult {
            const key = keys.get(keyId);
            if (key === undefined) {
                const result: CryptoOperationResult = {
                    success: false,
                    output: 'invalid',
                    operation: 'verify',
                    algorithmId: 'unknown',
                    warnings: [],
                    failureReason: `Key '${keyId}' not found`,
                };
                recordAudit(tick, principal, 'verify', 'unknown', false, []);
                return result;
            }

            if (key.usage !== 'verify' && key.usage !== 'any') {
                const result: CryptoOperationResult = {
                    success: false,
                    output: 'invalid',
                    operation: 'verify',
                    algorithmId: key.algorithmId,
                    keyId,
                    warnings: [],
                    failureReason: `Key '${keyId}' is not authorized for verification`,
                };
                recordAudit(tick, principal, 'verify', key.algorithmId, false, [], keyId);
                return result;
            }

            const algorithm = algorithms.get(key.algorithmId);
            const warnings = algorithm !== undefined ? warningsForAlgorithm(algorithm) : [];
            const expectedSig = simHash(data + key.material, key.algorithmId);
            const valid = expectedSig === signature;
            const result: CryptoOperationResult = {
                success: true,
                output: valid ? 'valid' : 'invalid',
                operation: 'verify',
                algorithmId: key.algorithmId,
                keyId,
                warnings,
            };
            recordAudit(tick, principal, 'verify', key.algorithmId, true, warnings, keyId);
            return result;
        },

        // ── Certificates ────────────────────────────────────────

        issueCertificate(
            subject: string,
            issuer: string,
            algorithmId: string,
            publicKeyId: string,
            validFrom: number,
            validUntil: number,
            isCA: boolean,
            parentSerial?: string,
        ): Certificate | null {
            const algorithm = algorithms.get(algorithmId);
            if (algorithm === undefined) return null;

            const pubKey = keys.get(publicKeyId);
            if (pubKey === undefined) return null;

            // If parent specified, it must exist and be a CA
            const chain: string[] = [];
            if (parentSerial !== undefined) {
                const parent = certificates.get(parentSerial);
                if (parent === undefined) return null;
                if (!parent.isCA) return null;
                chain.push(parentSerial, ...parent.chain);
            }

            certCounter++;
            const serialNumber = `cert-${certCounter}`;

            const cert: MutableCertificate = {
                serialNumber,
                subject,
                issuer,
                algorithmId,
                publicKeyId,
                validFrom,
                validUntil,
                revoked: false,
                chain,
                isCA,
            };

            certificates.set(serialNumber, cert);
            return toCertificate(cert);
        },

        getCertificate(serialNumber: string): Certificate | null {
            const c = certificates.get(serialNumber);
            if (c === undefined) return null;
            return toCertificate(c);
        },

        revokeCertificate(serialNumber: string): boolean {
            const cert = certificates.get(serialNumber);
            if (cert === undefined) return false;
            cert.revoked = true;
            return true;
        },

        verifyCertificateChain(serialNumber: string, tick: number): { valid: boolean; reason: string } {
            const cert = certificates.get(serialNumber);
            if (cert === undefined) {
                return { valid: false, reason: 'certificate not found' };
            }

            if (cert.revoked) {
                return { valid: false, reason: `certificate '${serialNumber}' has been revoked` };
            }

            if (tick < cert.validFrom) {
                return { valid: false, reason: `certificate '${serialNumber}' is not yet valid` };
            }

            if (tick >= cert.validUntil) {
                return { valid: false, reason: `certificate '${serialNumber}' has expired` };
            }

            // Verify chain
            for (const parentSerial of cert.chain) {
                const parent = certificates.get(parentSerial);
                if (parent === undefined) {
                    return { valid: false, reason: `chain certificate '${parentSerial}' not found` };
                }
                if (parent.revoked) {
                    return { valid: false, reason: `chain certificate '${parentSerial}' has been revoked` };
                }
                if (tick < parent.validFrom || tick >= parent.validUntil) {
                    return { valid: false, reason: `chain certificate '${parentSerial}' is not valid at tick ${tick}` };
                }
            }

            return { valid: true, reason: 'certificate chain is valid' };
        },

        listCertificates(): readonly Certificate[] {
            return [...certificates.values()].map(toCertificate);
        },

        // ── Audit ───────────────────────────────────────────────

        getAuditLog(): readonly CryptoAuditEntry[] {
            return [...auditLog];
        },

        // ── Reset ───────────────────────────────────────────────

        clear(): void {
            algorithms.clear();
            keys.clear();
            certificates.clear();
            auditLog.length = 0;
            keyCounter = 0;
            certCounter = 0;
        },
    };
}
