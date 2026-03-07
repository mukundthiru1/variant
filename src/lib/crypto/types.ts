/**
 * VARIANT — Crypto Engine Types
 *
 * Simulates cryptographic operations for cybersecurity training:
 * hashing, symmetric/asymmetric encryption, key exchange, certificates,
 * and key management. Players interact with realistic crypto systems,
 * discover weak algorithms, exploit misconfigurations, and learn
 * how real-world cryptography works.
 *
 * NOT real cryptography — this is a deterministic simulation engine.
 * Outputs are predictable and inspectable for educational purposes.
 *
 * FEATURES:
 * - Algorithm registry (hash, symmetric, asymmetric, KDF, key-exchange)
 * - Key generation and storage with metadata
 * - Encrypt/decrypt simulation with configurable weakness
 * - Certificate chain simulation (issue, verify, revoke)
 * - Weakness modeling (short keys, deprecated algorithms, bad RNG)
 * - Audit trail of all crypto operations
 *
 * SWAPPABILITY: Implements CryptoEngine. Replace this file.
 */

// ── Algorithms ──────────────────────────────────────────────────

/** Category of cryptographic algorithm. */
export type AlgorithmCategory =
    | 'hash'
    | 'symmetric'
    | 'asymmetric'
    | 'kdf'
    | 'key-exchange';

/** Strength rating for an algorithm or key. */
export type StrengthRating = 'broken' | 'weak' | 'acceptable' | 'strong' | 'military';

/** A registered cryptographic algorithm. */
export interface CryptoAlgorithm {
    /** Unique algorithm ID (e.g., 'sha256', 'aes-256-cbc', 'rsa-2048'). */
    readonly id: string;
    /** Display name. */
    readonly name: string;
    /** Algorithm category. */
    readonly category: AlgorithmCategory;
    /** Key size in bits (0 for hash algorithms). */
    readonly keySizeBits: number;
    /** Block size in bits (0 if not applicable). */
    readonly blockSizeBits: number;
    /** Strength rating. */
    readonly strength: StrengthRating;
    /** Whether this algorithm is deprecated/insecure. */
    readonly deprecated: boolean;
    /** Known vulnerabilities or weaknesses. */
    readonly weaknesses: readonly string[];
}

// ── Keys ────────────────────────────────────────────────────────

/** A cryptographic key in the simulation. */
export interface CryptoKey {
    /** Unique key ID. */
    readonly id: string;
    /** Algorithm this key is used with. */
    readonly algorithmId: string;
    /** Key material (simulated — deterministic hex string). */
    readonly material: string;
    /** Key size in bits. */
    readonly sizeBits: number;
    /** Strength rating (derived from algorithm + size). */
    readonly strength: StrengthRating;
    /** When the key was generated (tick). */
    readonly createdAt: number;
    /** Optional expiry tick. */
    readonly expiresAt?: number;
    /** Owner identifier. */
    readonly owner: string;
    /** Key usage restrictions. */
    readonly usage: KeyUsage;
    /** Whether this key has been compromised. */
    readonly compromised: boolean;
}

/** What a key can be used for. */
export type KeyUsage = 'encrypt' | 'decrypt' | 'sign' | 'verify' | 'key-exchange' | 'any';

// ── Certificates ────────────────────────────────────────────────

/** A simulated X.509-style certificate. */
export interface Certificate {
    /** Unique certificate ID / serial number. */
    readonly serialNumber: string;
    /** Subject (who the cert is issued to). */
    readonly subject: string;
    /** Issuer (who signed the cert). */
    readonly issuer: string;
    /** Signing algorithm ID. */
    readonly algorithmId: string;
    /** Public key ID. */
    readonly publicKeyId: string;
    /** Valid from (tick). */
    readonly validFrom: number;
    /** Valid until (tick). */
    readonly validUntil: number;
    /** Whether this cert has been revoked. */
    readonly revoked: boolean;
    /** Certificate chain — parent cert serial numbers up to root. */
    readonly chain: readonly string[];
    /** Is this a CA certificate? */
    readonly isCA: boolean;
}

// ── Operations ──────────────────────────────────────────────────

/** Result of a crypto operation. */
export interface CryptoOperationResult {
    /** Whether the operation succeeded. */
    readonly success: boolean;
    /** Output data (ciphertext, hash, signature, etc.). */
    readonly output: string;
    /** Operation that was performed. */
    readonly operation: CryptoOperationType;
    /** Algorithm used. */
    readonly algorithmId: string;
    /** Key used (if applicable). */
    readonly keyId?: string;
    /** Warnings about the operation (e.g., weak algorithm). */
    readonly warnings: readonly string[];
    /** Reason for failure (if success is false). */
    readonly failureReason?: string;
}

/** Types of crypto operations. */
export type CryptoOperationType =
    | 'hash'
    | 'encrypt'
    | 'decrypt'
    | 'sign'
    | 'verify'
    | 'key-exchange'
    | 'derive-key';

// ── Audit ───────────────────────────────────────────────────────

/** An entry in the crypto audit log. */
export interface CryptoAuditEntry {
    /** Tick when the operation occurred. */
    readonly tick: number;
    /** Principal who performed the operation. */
    readonly principal: string;
    /** Operation type. */
    readonly operation: CryptoOperationType;
    /** Algorithm used. */
    readonly algorithmId: string;
    /** Key ID used (if applicable). */
    readonly keyId?: string;
    /** Whether the operation succeeded. */
    readonly success: boolean;
    /** Warnings generated. */
    readonly warnings: readonly string[];
}

// ── Engine ──────────────────────────────────────────────────────

/** The crypto simulation engine. */
export interface CryptoEngine {
    // ── Algorithm Registry ──────────────────────────────────────

    /** Register a cryptographic algorithm. */
    registerAlgorithm(algorithm: CryptoAlgorithm): void;

    /** Get an algorithm by ID. */
    getAlgorithm(id: string): CryptoAlgorithm | null;

    /** List all registered algorithms. */
    listAlgorithms(): readonly CryptoAlgorithm[];

    /** List algorithms by category. */
    listAlgorithmsByCategory(category: AlgorithmCategory): readonly CryptoAlgorithm[];

    // ── Key Management ──────────────────────────────────────────

    /** Generate a key for the given algorithm. */
    generateKey(algorithmId: string, owner: string, usage: KeyUsage, tick: number, expiresAt?: number): CryptoKey | null;

    /** Get a key by ID. */
    getKey(id: string): CryptoKey | null;

    /** List all keys for an owner. */
    listKeys(owner: string): readonly CryptoKey[];

    /** Mark a key as compromised. */
    compromiseKey(keyId: string): boolean;

    /** Check if a key is valid (not expired, not compromised). */
    isKeyValid(keyId: string, tick: number): boolean;

    // ── Crypto Operations ───────────────────────────────────────

    /** Hash data using the specified algorithm. */
    hash(algorithmId: string, data: string, principal: string, tick: number): CryptoOperationResult;

    /** Encrypt data using the specified key. */
    encrypt(keyId: string, plaintext: string, principal: string, tick: number): CryptoOperationResult;

    /** Decrypt data using the specified key. */
    decrypt(keyId: string, ciphertext: string, principal: string, tick: number): CryptoOperationResult;

    /** Sign data using the specified key. */
    sign(keyId: string, data: string, principal: string, tick: number): CryptoOperationResult;

    /** Verify a signature. */
    verify(keyId: string, data: string, signature: string, principal: string, tick: number): CryptoOperationResult;

    // ── Certificates ────────────────────────────────────────────

    /** Issue a certificate. */
    issueCertificate(
        subject: string,
        issuer: string,
        algorithmId: string,
        publicKeyId: string,
        validFrom: number,
        validUntil: number,
        isCA: boolean,
        parentSerial?: string,
    ): Certificate | null;

    /** Get a certificate by serial number. */
    getCertificate(serialNumber: string): Certificate | null;

    /** Revoke a certificate. */
    revokeCertificate(serialNumber: string): boolean;

    /** Verify a certificate chain (checks expiry, revocation, chain integrity). */
    verifyCertificateChain(serialNumber: string, tick: number): { valid: boolean; reason: string };

    /** List all certificates. */
    listCertificates(): readonly Certificate[];

    // ── Audit ───────────────────────────────────────────────────

    /** Get the crypto audit log. */
    getAuditLog(): readonly CryptoAuditEntry[];

    // ── Reset ───────────────────────────────────────────────────

    /** Clear all state. */
    clear(): void;
}
