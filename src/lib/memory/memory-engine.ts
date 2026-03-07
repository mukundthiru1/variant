/**
 * VARIANT — Memory Forensics Engine
 *
 * Simulates volatile memory analysis with:
 * - Process memory map management
 * - Code injection detection (RWX regions, shellcode patterns)
 * - Hidden process detection
 * - Credential/key/URL extraction from strings
 * - Memory dump snapshots
 *
 * All operations are synchronous and pure-data.
 */

import type {
    MemoryForensicsEngine,
    ProcessMemory,
    MemoryArtifact,
} from './types';

// ── Helpers ───────────────────────────────────────────────

let dumpCounter = 0;

const CREDENTIAL_PATTERNS = [
    /password[=:]\s*\S+/i,
    /passwd[=:]\s*\S+/i,
    /api[_-]?key[=:]\s*\S+/i,
    /secret[=:]\s*\S+/i,
    /token[=:]\s*\S+/i,
    /authorization:\s*bearer\s+\S+/i,
];

const CRYPTO_KEY_PATTERNS = [
    /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/,
    /-----BEGIN CERTIFICATE-----/,
    /AKIA[0-9A-Z]{16}/,    // AWS access key
];

const URL_PATTERN = /https?:\/\/[^\s"'<>]+/i;

const SUSPICIOUS_STRINGS = [
    /cmd\.exe|powershell|bash\s+-i/i,
    /\x4d\x5a/,  // MZ header
    /CreateRemoteThread|VirtualAllocEx|WriteProcessMemory/i,
    /NtUnmapViewOfSection|ZwUnmapViewOfSection/i,
    /mimikatz|sekurlsa|kerberos::/i,
];

// ── Factory ──────────────────────────────────────────────

export function createMemoryForensicsEngine(): MemoryForensicsEngine {
    const processes = new Map<number, ProcessMemory>();

    const engine: MemoryForensicsEngine = {
        addProcess(input) {
            // Extract strings from all regions with content
            const strings: string[] = [];
            for (const region of input.regions) {
                if (region.content) {
                    strings.push(region.content);
                }
            }

            const proc: ProcessMemory = Object.freeze({
                ...input,
                strings: Object.freeze(strings),
            });
            processes.set(input.pid, proc);
        },

        getProcess(pid) {
            return processes.get(pid) ?? null;
        },

        listProcesses(includeHidden) {
            const result = Array.from(processes.values());
            if (includeHidden) return Object.freeze(result);
            return Object.freeze(result.filter(p => !p.hidden));
        },

        extractStrings(pid) {
            const proc = processes.get(pid);
            if (!proc) return [];
            return proc.strings;
        },

        scanInjection() {
            const artifacts: MemoryArtifact[] = [];

            for (const proc of processes.values()) {
                // RWX regions in non-JIT processes
                for (const region of proc.regions) {
                    if (region.protection === 'rwx' && region.type !== 'code') {
                        artifacts.push(Object.freeze({
                            type: 'injected_code',
                            pid: proc.pid,
                            processName: proc.name,
                            description: `RWX memory region at ${region.baseAddress} (${region.size} bytes) — possible code injection`,
                            data: region.baseAddress,
                            severity: 'high',
                            mitre: 'T1055',
                        }));
                    }
                }

                // Injected flag
                if (proc.injected) {
                    artifacts.push(Object.freeze({
                        type: 'dll_injection',
                        pid: proc.pid,
                        processName: proc.name,
                        description: `Process ${proc.name} (PID ${proc.pid}) has injected code`,
                        data: proc.commandLine,
                        severity: 'critical',
                        mitre: 'T1055.001',
                    }));
                }

                // Hollowed flag
                if (proc.hollowed) {
                    artifacts.push(Object.freeze({
                        type: 'process_hollowing',
                        pid: proc.pid,
                        processName: proc.name,
                        description: `Process ${proc.name} (PID ${proc.pid}) appears to be hollowed — code section replaced`,
                        data: proc.commandLine,
                        severity: 'critical',
                        mitre: 'T1055.012',
                    }));
                }

                // Suspicious strings in memory
                for (const str of proc.strings) {
                    for (const pattern of SUSPICIOUS_STRINGS) {
                        if (pattern.test(str)) {
                            artifacts.push(Object.freeze({
                                type: 'shellcode',
                                pid: proc.pid,
                                processName: proc.name,
                                description: `Suspicious string found in ${proc.name} memory`,
                                data: str.slice(0, 200),
                                severity: 'high',
                                mitre: 'T1059',
                            }));
                            break;
                        }
                    }
                }
            }

            return Object.freeze(artifacts);
        },

        scanHiddenProcesses() {
            const artifacts: MemoryArtifact[] = [];
            for (const proc of processes.values()) {
                if (proc.hidden) {
                    artifacts.push(Object.freeze({
                        type: 'hidden_process',
                        pid: proc.pid,
                        processName: proc.name,
                        description: `Hidden process detected: ${proc.name} (PID ${proc.pid}) — possible rootkit`,
                        data: proc.commandLine,
                        severity: 'critical',
                        mitre: 'T1014',
                    }));
                }
            }
            return Object.freeze(artifacts);
        },

        scanCredentials() {
            const artifacts: MemoryArtifact[] = [];

            for (const proc of processes.values()) {
                for (const str of proc.strings) {
                    for (const pattern of CREDENTIAL_PATTERNS) {
                        const match = pattern.exec(str);
                        if (match) {
                            artifacts.push(Object.freeze({
                                type: 'credential',
                                pid: proc.pid,
                                processName: proc.name,
                                description: `Credential found in ${proc.name} memory`,
                                data: match[0].slice(0, 100),
                                severity: 'high',
                                mitre: 'T1003',
                            }));
                            break;
                        }
                    }

                    for (const pattern of CRYPTO_KEY_PATTERNS) {
                        if (pattern.test(str)) {
                            artifacts.push(Object.freeze({
                                type: 'crypto_key',
                                pid: proc.pid,
                                processName: proc.name,
                                description: `Cryptographic key material found in ${proc.name} memory`,
                                data: str.slice(0, 100),
                                severity: 'high',
                                mitre: 'T1552.004',
                            }));
                            break;
                        }
                    }

                    const urlMatch = URL_PATTERN.exec(str);
                    if (urlMatch) {
                        artifacts.push(Object.freeze({
                            type: 'url',
                            pid: proc.pid,
                            processName: proc.name,
                            description: `URL found in ${proc.name} memory`,
                            data: urlMatch[0],
                            severity: 'info',
                        }));
                    }
                }
            }

            return Object.freeze(artifacts);
        },

        fullScan() {
            const injection = engine.scanInjection();
            const hidden = engine.scanHiddenProcesses();
            const creds = engine.scanCredentials();
            return Object.freeze([...injection, ...hidden, ...creds]);
        },

        createDump() {
            const allProcs = Array.from(processes.values());
            let totalMem = 0;
            for (const p of allProcs) {
                for (const r of p.regions) totalMem += r.size;
            }
            return Object.freeze({
                id: `dump-${++dumpCounter}`,
                timestamp: Date.now(),
                totalProcesses: allProcs.length,
                totalMemoryBytes: totalMem,
                processes: Object.freeze(allProcs),
            });
        },

        getStats() {
            let hidden = 0;
            let injected = 0;
            let hollowed = 0;
            let totalRegions = 0;
            let rwx = 0;

            for (const p of processes.values()) {
                if (p.hidden) hidden++;
                if (p.injected) injected++;
                if (p.hollowed) hollowed++;
                for (const r of p.regions) {
                    totalRegions++;
                    if (r.protection === 'rwx') rwx++;
                }
            }

            const artifacts = engine.fullScan();

            return Object.freeze({
                totalProcesses: processes.size,
                hiddenProcesses: hidden,
                injectedProcesses: injected,
                hollowedProcesses: hollowed,
                totalMemoryRegions: totalRegions,
                rwxRegions: rwx,
                totalArtifactsFound: artifacts.length,
            });
        },
    };

    return engine;
}
