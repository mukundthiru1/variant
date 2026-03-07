/**
 * VARIANT — Misconfiguration Template Types
 *
 * Pre-built security misconfigurations that level designers can
 * compose into levels. Each template generates VFS overlays,
 * service configs, and detection criteria.
 *
 * DESIGN: Templates are pure data. They describe WHAT to misconfigure,
 * not HOW to do it at runtime. The engine applies them during boot.
 */

import type { VulnClue } from '../vuln/types';

// ── Misconfiguration Categories ─────────────────────────────────

export type MisconfigCategory =
    | 'authentication'    // Weak passwords, default creds, missing MFA
    | 'authorization'     // Overly permissive ACLs, open shares
    | 'encryption'        // Weak ciphers, plaintext protocols, expired certs
    | 'network'           // Open ports, missing firewall rules, DNS zone transfer
    | 'service'           // Debug modes, default configs, unnecessary services
    | 'file-permissions'  // World-readable secrets, SUID binaries, writable configs
    | 'logging'           // Disabled logging, missing audit trails
    | 'patching'          // Outdated software, missing security patches
    | 'container'         // Privileged containers, exposed APIs
    | 'cloud'             // Open S3 buckets, IMDS exposure, overly broad IAM
    | 'application';      // Debug endpoints, verbose errors, insecure headers

export type MisconfigSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

// ── Misconfiguration Template ───────────────────────────────────

export interface MisconfigTemplate {
    /** Unique template ID. Format: MISC-XXXX. */
    readonly id: string;

    /** Human-readable name. */
    readonly name: string;

    /** Description of the misconfiguration. */
    readonly description: string;

    /** What this looks like in the real world. */
    readonly realWorldContext: string;

    /** Category. */
    readonly category: MisconfigCategory;

    /** Severity if exploited. */
    readonly severity: MisconfigSeverity;

    /** MITRE ATT&CK technique IDs this misconfiguration enables. */
    readonly mitreTechniques: readonly string[];

    /** CWE IDs (if applicable). */
    readonly cweIds?: readonly string[];

    /**
     * Files to inject into the VFS.
     * Key = absolute path, Value = file content.
     */
    readonly files: Readonly<Record<string, MisconfigFile>>;

    /**
     * Service configuration overrides.
     * Key = service name.
     */
    readonly serviceOverrides?: Readonly<Record<string, Readonly<Record<string, unknown>>>>;

    /**
     * Environment variables to set.
     */
    readonly envVars?: Readonly<Record<string, string>>;

    /**
     * Clues for the player (hints that something is misconfigured).
     */
    readonly clues: readonly VulnClue[];

    /**
     * How to detect this misconfiguration (for blue team objectives).
     */
    readonly detectionHints: readonly string[];

    /**
     * How to fix this misconfiguration (for remediation objectives).
     */
    readonly remediation: readonly string[];

    /** Tags for filtering. */
    readonly tags: readonly string[];

    /** Compatible machine roles. */
    readonly applicableRoles: readonly ('player' | 'target' | 'defend' | 'infrastructure')[];
}

export interface MisconfigFile {
    readonly content: string;
    readonly mode?: number;
    readonly owner?: string;
}

// ── Misconfiguration Catalog Interface ──────────────────────────

export interface MisconfigCatalog {
    /** Get a template by ID. */
    get(id: string): MisconfigTemplate | null;

    /** List all templates. */
    list(): readonly MisconfigTemplate[];

    /** List templates by category. */
    listByCategory(category: MisconfigCategory): readonly MisconfigTemplate[];

    /** List templates by severity. */
    listBySeverity(severity: MisconfigSeverity): readonly MisconfigTemplate[];

    /** List templates that enable a specific MITRE technique. */
    listByMitreTechnique(techniqueId: string): readonly MisconfigTemplate[];

    /** Search templates by keyword. */
    search(query: string): readonly MisconfigTemplate[];

    /** Add a custom template. */
    addTemplate(template: MisconfigTemplate): void;

    /** Get catalog stats. */
    getStats(): MisconfigCatalogStats;
}

export interface MisconfigCatalogStats {
    readonly totalTemplates: number;
    readonly byCategory: Readonly<Record<string, number>>;
    readonly bySeverity: Readonly<Record<string, number>>;
    readonly uniqueMitreTechniques: number;
}
