/**
 * VARIANT — Vulnerability Injection System
 *
 * Applies custom, ungoogleable vulnerabilities to base codebases.
 * Level designers select a base codebase, choose vulns to inject,
 * and the system produces VFS overlays with the vulnerable code.
 *
 * DESIGN: Pure functions. No side effects. No dependencies on core/.
 *   - Input:  BaseCodebase + VulnConfig[]
 *   - Output: VFS overlay with injected vulnerabilities
 *
 * SECURITY: The injected code is entirely static. It runs inside
 * the Simulacrum's VFS and shell. No host code execution.
 *
 * Each vulnerability consists of:
 *   1. A unique ID
 *   2. A category (SQLi, XSS, RCE, etc.)
 *   3. A set of file patches (safe → vulnerable transforms)
 *   4. Optional clues (breadcrumbs for the player)
 *   5. Optional red herrings (fake "fixes" that don't work)
 *   6. Detection criteria (how the objective checker knows it's found)
 */

import type { VFSOverlay, VFSOverlayEntry } from '../vfs/types';

// ── Types ──────────────────────────────────────────────────────

export type VulnCategory =
    | 'sqli'          // SQL Injection
    | 'xss'           // Cross-Site Scripting
    | 'rce'           // Remote Code Execution
    | 'lfi'           // Local File Inclusion
    | 'rfi'           // Remote File Inclusion
    | 'ssrf'          // Server-Side Request Forgery
    | 'idor'          // Insecure Direct Object Reference
    | 'auth-bypass'   // Authentication Bypass
    | 'privesc'       // Privilege Escalation
    | 'path-traversal'
    | 'command-injection'
    | 'deserialization'
    | 'xxe'           // XML External Entity
    | 'csrf'          // Cross-Site Request Forgery
    | 'jwt-bypass'    // JWT Validation Bypass
    | 'race-condition'
    | 'supply-chain'  // Backdoored dependency
    | 'misconfiguration'
    | 'info-leak'     // Information Disclosure
    | 'hardcoded-creds'
    | 'weak-crypto'
    | 'custom'        // Custom/novel vulnerability
    | (string & {});  // open — third-party categories accepted

export type VulnDifficulty = 'beginner' | 'intermediate' | 'advanced' | 'expert' | (string & {});

/**
 * A vulnerability definition.
 * These are authored by level designers and stored in the
 * vulnerability catalog.
 */
export interface VulnDefinition {
    /** Unique vulnerability ID. Format: VART-XXXX. */
    readonly id: string;
    /** Human-readable name. */
    readonly name: string;
    /** Description (shown post-exploitation or in hints). */
    readonly description: string;
    /** Category. */
    readonly category: VulnCategory;
    /** Difficulty level. */
    readonly difficulty: VulnDifficulty;
    /**
     * Compatible base codebases.
     * Each string is a codebase ID from the catalog.
     */
    readonly compatibleBases: readonly string[];
    /**
     * File patches that transform safe code into vulnerable code.
     * Applied in order.
     */
    readonly patches: readonly VulnPatch[];
    /**
     * Clues left in the system for the player to discover.
     * These are breadcrumbs that hint at the vulnerability.
     */
    readonly clues?: readonly VulnClue[];
    /**
     * Red herrings — fake "clues" that mislead.
     */
    readonly redHerrings?: readonly VulnClue[];
    /**
     * Detection criteria for objective checking.
     */
    readonly detection: VulnDetection;
    /**
     * CVSS-like severity score (0-10).
     */
    readonly severity: number;
    /**
     * MITRE ATT&CK technique IDs associated with this vulnerability.
     * Maps to the MITRE catalog for kill chain coverage analysis.
     * e.g., ['T1190', 'T1059.004']
     */
    readonly mitreTechniques?: readonly string[];
    /**
     * CWE (Common Weakness Enumeration) IDs.
     * e.g., ['CWE-89', 'CWE-79']
     */
    readonly cweIds?: readonly string[];
    /**
     * Tags for filtering.
     */
    readonly tags?: readonly string[];
}

/**
 * A file patch that transforms code.
 */
export interface VulnPatch {
    /** Target file path in the VFS. */
    readonly path: string;
    /** Patch type. */
    readonly type: 'replace' | 'insert' | 'delete' | 'create' | (string & {});
    /**
     * For 'replace': search string to find.
     * For 'insert': anchor string to insert after.
     * For 'delete': string to remove.
     * For 'create': ignored (file is created from content).
     */
    readonly search?: string;
    /**
     * For 'replace': replacement content.
     * For 'insert': content to insert.
     * For 'create': full file content.
     */
    readonly content?: string;
    /** File permissions (for 'create'). */
    readonly mode?: number;
}

/**
 * A clue or red herring.
 */
export interface VulnClue {
    /** Where the clue is placed. */
    readonly location: 'file' | 'log' | 'process' | 'network' | 'env' | 'config' | (string & {});
    /** Path (for file/log/config clues). */
    readonly path?: string;
    /** Content of the clue. */
    readonly content: string;
    /** How obvious this clue is (1=subtle, 5=obvious). */
    readonly visibility: 1 | 2 | 3 | 4 | 5;
}

/**
 * How the simulation detects that this vuln was exploited.
 */
export interface VulnDetection {
    /** Events that indicate exploitation. */
    readonly triggers: readonly DetectionTrigger[];
    /** Whether ALL triggers must fire, or ANY. */
    readonly mode: 'all' | 'any';
}

export type DetectionTrigger =
    | FileReadTrigger
    | FileWriteTrigger
    | CommandTrigger
    | HTTPTrigger
    | CustomTrigger;

export interface FileReadTrigger {
    readonly type: 'file:read';
    readonly path: string;
}

export interface FileWriteTrigger {
    readonly type: 'file:write';
    readonly path: string;
    readonly contentContains?: string;
}

export interface CommandTrigger {
    readonly type: 'command';
    /** Regex pattern to match against executed command. */
    readonly pattern: string;
}

export interface HTTPTrigger {
    readonly type: 'http';
    /** HTTP method. */
    readonly method: string;
    /** URL path pattern. */
    readonly path: string;
    /** Body must contain this string. */
    readonly bodyContains?: string;
    /** Expected response code. */
    readonly responseCode?: number;
}

export interface CustomTrigger {
    readonly type: 'custom';
    readonly eventType: string;
    readonly match: Record<string, unknown>;
}

// ── Base codebase definition ───────────────────────────────────

export interface BaseCodebase {
    /** Unique ID. */
    readonly id: string;
    /** Name. */
    readonly name: string;
    /** Category (e-commerce, banking, etc.). */
    readonly category: string;
    /** Technology stack. */
    readonly stack: readonly string[];
    /** License (must be MIT/Apache/BSD). */
    readonly license: string;
    /** Attribution text. */
    readonly attribution: string;
    /** Base VFS overlay (the "safe" version of the codebase). */
    readonly files: ReadonlyMap<string, VFSOverlayEntry>;
}

// ── Injection engine ───────────────────────────────────────────

/**
 * Apply vulnerability patches to a base codebase,
 * producing a VFS overlay with the vulnerable code.
 */
export function injectVulnerabilities(
    base: BaseCodebase,
    vulns: readonly VulnDefinition[],
): InjectionResult {
    // Start with a mutable copy of the base files
    const files = new Map<string, VFSOverlayEntry>();
    for (const [path, entry] of base.files) {
        files.set(path, { ...entry });
    }

    const applied: string[] = [];
    const errors: InjectionError[] = [];

    for (const vuln of vulns) {
        // Verify compatibility
        if (!vuln.compatibleBases.includes(base.id) && !vuln.compatibleBases.includes('*')) {
            errors.push({
                vulnId: vuln.id,
                message: `Vulnerability '${vuln.id}' is not compatible with base '${base.id}'`,
            });
            continue;
        }

        // Apply patches
        let allPatchesApplied = true;
        for (const patch of vuln.patches) {
            const result = applyPatch(files, patch);
            if (!result.success) {
                errors.push({
                    vulnId: vuln.id,
                    message: `Patch failed for '${patch.path}': ${result.error}`,
                });
                allPatchesApplied = false;
                break;
            }
        }

        // Apply clues
        if (allPatchesApplied && vuln.clues !== undefined) {
            for (const clue of vuln.clues) {
                applyClue(files, clue);
            }
        }

        // Apply red herrings
        if (allPatchesApplied && vuln.redHerrings !== undefined) {
            for (const herring of vuln.redHerrings) {
                applyClue(files, herring);
            }
        }

        if (allPatchesApplied) {
            applied.push(vuln.id);
        }
    }

    const overlay: VFSOverlay = { files };

    return { overlay, applied, errors };
}

export interface InjectionResult {
    /** VFS overlay with the vulnerable codebase. */
    readonly overlay: VFSOverlay;
    /** IDs of successfully applied vulnerabilities. */
    readonly applied: readonly string[];
    /** Errors encountered during injection. */
    readonly errors: readonly InjectionError[];
}

export interface InjectionError {
    readonly vulnId: string;
    readonly message: string;
}

// ── Path validation (no traversal in vuln patches/clues) ────────

function validateVulnPath(path: string): boolean {
    if (path.length === 0 || !path.startsWith('/')) return false;
    if (path.includes('..') || path.includes('\0')) return false;
    return true;
}

// ── Patch application ──────────────────────────────────────────

interface PatchResult {
    readonly success: boolean;
    readonly error?: string;
}

function applyPatch(
    files: Map<string, VFSOverlayEntry>,
    patch: VulnPatch,
): PatchResult {
    if (!validateVulnPath(patch.path)) {
        return { success: false, error: `invalid or forbidden path: ${patch.path}` };
    }

    switch (patch.type) {
        case 'create': {
            if (patch.content === undefined) {
                return { success: false, error: 'create patch requires content' };
            }
            files.set(patch.path, {
                content: patch.content,
                mode: patch.mode,
            });
            return { success: true };
        }

        case 'replace': {
            const existing = files.get(patch.path);
            if (existing === undefined) {
                return { success: false, error: `file not found: ${patch.path}` };
            }
            if (patch.search === undefined || patch.content === undefined) {
                return { success: false, error: 'replace patch requires search and content' };
            }
            const existingContent = typeof existing.content === 'string'
                ? existing.content
                : new TextDecoder().decode(existing.content);
            if (!existingContent.includes(patch.search)) {
                return { success: false, error: `search string not found in ${patch.path}` };
            }
            files.set(patch.path, {
                ...existing,
                content: existingContent.replace(patch.search, patch.content),
            });
            return { success: true };
        }

        case 'insert': {
            const existing = files.get(patch.path);
            if (existing === undefined) {
                return { success: false, error: `file not found: ${patch.path}` };
            }
            if (patch.search === undefined || patch.content === undefined) {
                return { success: false, error: 'insert patch requires search (anchor) and content' };
            }
            const existingContent = typeof existing.content === 'string'
                ? existing.content
                : new TextDecoder().decode(existing.content);
            const idx = existingContent.indexOf(patch.search);
            if (idx === -1) {
                return { success: false, error: `anchor string not found in ${patch.path}` };
            }
            const insertAt = idx + patch.search.length;
            const newContent = existingContent.slice(0, insertAt) + patch.content + existingContent.slice(insertAt);
            files.set(patch.path, {
                ...existing,
                content: newContent,
            });
            return { success: true };
        }

        case 'delete': {
            const existing = files.get(patch.path);
            if (existing === undefined) {
                return { success: false, error: `file not found: ${patch.path}` };
            }
            if (patch.search === undefined) {
                // Delete entire file
                files.delete(patch.path);
                return { success: true };
            }
            const existingContent = typeof existing.content === 'string'
                ? existing.content
                : new TextDecoder().decode(existing.content);
            if (!existingContent.includes(patch.search)) {
                return { success: false, error: `delete string not found in ${patch.path}` };
            }
            files.set(patch.path, {
                ...existing,
                content: existingContent.replace(patch.search, ''),
            });
            return { success: true };
        }

        default:
            return { success: false, error: `unknown patch type: ${(patch as VulnPatch).type}` };
    }
}

function applyClue(
    files: Map<string, VFSOverlayEntry>,
    clue: VulnClue,
): void {
    if (clue.location === 'file' || clue.location === 'config') {
        if (clue.path !== undefined) {
            if (!validateVulnPath(clue.path)) return;
            const existing = files.get(clue.path);
            if (existing !== undefined) {
                const existingContent = typeof existing.content === 'string'
                    ? existing.content
                    : new TextDecoder().decode(existing.content);
                files.set(clue.path, {
                    ...existing,
                    content: existingContent + '\n' + clue.content,
                });
            } else {
                files.set(clue.path, { content: clue.content });
            }
        }
    } else if (clue.location === 'log') {
        const logPath = clue.path ?? '/var/log/syslog';
        const existing = files.get(logPath);
        const existingContent = existing !== undefined
            ? (typeof existing.content === 'string'
                ? existing.content
                : new TextDecoder().decode(existing.content))
            : '';
        files.set(logPath, {
            content: existingContent + '\n' + clue.content,
        });
    } else if (clue.location === 'env') {
        const envPath = '/etc/environment';
        const existing = files.get(envPath);
        const existingContent = existing !== undefined
            ? (typeof existing.content === 'string'
                ? existing.content
                : new TextDecoder().decode(existing.content))
            : '';
        files.set(envPath, {
            content: existingContent + '\n' + clue.content,
        });
    }
}
