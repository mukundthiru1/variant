/**
 * VARIANT — Memory Forensics Types
 *
 * Simulates volatile memory analysis:
 * - Process memory maps (heap, stack, code, shared)
 * - Injected code detection (shellcode, DLL injection, hollowing)
 * - String extraction from process memory
 * - Memory artifact detection (credentials, keys, URLs)
 * - Rootkit detection via hidden process analysis
 *
 * EXTENSIBILITY: Custom artifact types via open union.
 * SWAPPABILITY: Implements MemoryForensicsEngine interface.
 */

// ── Memory Region ────────────────────────────────────────

export interface MemoryRegion {
    readonly baseAddress: string;
    readonly size: number;
    readonly type: MemoryRegionType;
    readonly protection: MemoryProtection;
    readonly mapped?: string;
    readonly content?: string;
}

export type MemoryRegionType =
    | 'code' | 'heap' | 'stack' | 'mapped_file' | 'shared'
    | 'private' | 'guard' | 'reserve'
    | (string & {});

export type MemoryProtection =
    | 'r--' | 'rw-' | 'r-x' | 'rwx' | '---' | 'rws'
    | (string & {});

// ── Process Memory ───────────────────────────────────────

export interface ProcessMemory {
    readonly pid: number;
    readonly name: string;
    readonly ppid: number;
    readonly user: string;
    readonly commandLine: string;
    readonly regions: readonly MemoryRegion[];
    readonly hidden: boolean;
    readonly injected: boolean;
    readonly hollowed: boolean;
    readonly strings: readonly string[];
}

// ── Memory Artifact ──────────────────────────────────────

export interface MemoryArtifact {
    readonly type: MemoryArtifactType;
    readonly pid: number;
    readonly processName: string;
    readonly description: string;
    readonly data: string;
    readonly severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
    readonly mitre?: string;
}

export type MemoryArtifactType =
    | 'injected_code' | 'shellcode' | 'dll_injection' | 'process_hollowing'
    | 'hidden_process' | 'credential' | 'crypto_key' | 'url'
    | 'suspicious_string' | 'hook' | 'rootkit_indicator'
    | (string & {});

// ── Memory Dump ──────────────────────────────────────────

export interface MemoryDump {
    readonly id: string;
    readonly timestamp: number;
    readonly totalProcesses: number;
    readonly totalMemoryBytes: number;
    readonly processes: readonly ProcessMemory[];
}

// ── Memory Forensics Engine Interface ────────────────────

export interface MemoryForensicsEngine {
    /** Add a process to the simulated memory. */
    addProcess(process: Omit<ProcessMemory, 'strings'>): void;
    /** Get process by PID. */
    getProcess(pid: number): ProcessMemory | null;
    /** List all processes (optionally including hidden). */
    listProcesses(includeHidden?: boolean): readonly ProcessMemory[];
    /** Extract strings from a process. */
    extractStrings(pid: number): readonly string[];
    /** Scan for injected code across all processes. */
    scanInjection(): readonly MemoryArtifact[];
    /** Scan for hidden processes. */
    scanHiddenProcesses(): readonly MemoryArtifact[];
    /** Scan for credentials in memory. */
    scanCredentials(): readonly MemoryArtifact[];
    /** Full memory scan (all artifact types). */
    fullScan(): readonly MemoryArtifact[];
    /** Create a memory dump snapshot. */
    createDump(): MemoryDump;
    /** Get stats. */
    getStats(): MemoryForensicsStats;
}

export interface MemoryForensicsStats {
    readonly totalProcesses: number;
    readonly hiddenProcesses: number;
    readonly injectedProcesses: number;
    readonly hollowedProcesses: number;
    readonly totalMemoryRegions: number;
    readonly rwxRegions: number;
    readonly totalArtifactsFound: number;
}
