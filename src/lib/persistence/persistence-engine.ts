/**
 * VARIANT — Persistence Mechanism Engine
 *
 * Manages persistence mechanisms across all machines in the simulation.
 * Supports both offensive (installing persistence) and defensive
 * (detecting persistence via signature scanning) workflows.
 *
 * What it does:
 *   - Catalogs 20+ Linux persistence mechanism types
 *   - Installs mechanisms with proper VFS overlay generation
 *   - Scans for persistence using signature-based detection
 *   - Generates forensic timelines for blue team training
 *   - Maps every mechanism to MITRE ATT&CK
 *
 * SWAPPABILITY: Implements PersistenceEngine. Replace this file.
 */

import type {
    PersistenceEngine,
    PersistenceMechanism,
    PersistenceSignature,
    PersistenceScanResult,
    PersistenceMechanismType,
    PersistenceStats,
} from './types';

// ── Built-in Detection Signatures ──────────────────────────

function createBuiltinSignatures(): PersistenceSignature[] {
    return [
        {
            id: 'sig/cron-user',
            name: 'User Crontab Modification',
            description: 'A user crontab file has been created or modified',
            mechanismType: 'cron',
            indicators: [
                { type: 'file-exists', path: '/var/spool/cron/crontabs/*' },
            ],
            severity: 'medium',
            mitreTechnique: 'T1053.003',
            falsePositiveRate: 'medium',
        },
        {
            id: 'sig/cron-system',
            name: 'System Cron Directory Entry',
            description: 'New file in /etc/cron.d/ or /etc/cron.daily/',
            mechanismType: 'cron',
            indicators: [
                { type: 'file-exists', path: '/etc/cron.d/*' },
                { type: 'file-exists', path: '/etc/cron.daily/*' },
                { type: 'file-exists', path: '/etc/cron.hourly/*' },
            ],
            severity: 'high',
            mitreTechnique: 'T1053.003',
            falsePositiveRate: 'low',
        },
        {
            id: 'sig/systemd-service',
            name: 'Systemd Service Unit',
            description: 'Custom systemd service unit installed',
            mechanismType: 'systemd-service',
            indicators: [
                { type: 'file-exists', path: '/etc/systemd/system/*.service' },
                { type: 'file-exists', path: '/home/*/.config/systemd/user/*.service' },
            ],
            severity: 'high',
            mitreTechnique: 'T1543.002',
            falsePositiveRate: 'low',
        },
        {
            id: 'sig/systemd-timer',
            name: 'Systemd Timer Unit',
            description: 'Custom systemd timer for scheduled execution',
            mechanismType: 'systemd-timer',
            indicators: [
                { type: 'file-exists', path: '/etc/systemd/system/*.timer' },
            ],
            severity: 'high',
            mitreTechnique: 'T1053.006',
            falsePositiveRate: 'low',
        },
        {
            id: 'sig/ssh-authorized-key',
            name: 'SSH Authorized Key Addition',
            description: 'New SSH public key added to authorized_keys',
            mechanismType: 'ssh-authorized-key',
            indicators: [
                { type: 'file-contains', path: '/root/.ssh/authorized_keys', pattern: 'ssh-rsa|ssh-ed25519|ecdsa-sha2' },
                { type: 'file-contains', path: '/home/*/.ssh/authorized_keys', pattern: 'ssh-rsa|ssh-ed25519|ecdsa-sha2' },
            ],
            severity: 'high',
            mitreTechnique: 'T1098.004',
            falsePositiveRate: 'medium',
        },
        {
            id: 'sig/web-shell',
            name: 'Web Shell Detection',
            description: 'Suspicious file in web root with eval/exec patterns',
            mechanismType: 'web-shell',
            indicators: [
                { type: 'file-contains', path: '/var/www/*', pattern: 'eval|exec|system|passthru|shell_exec|base64_decode' },
                { type: 'file-contains', path: '/var/www/*', pattern: '\\$_(?:GET|POST|REQUEST|COOKIE)\\[' },
            ],
            severity: 'critical',
            mitreTechnique: 'T1505.003',
            falsePositiveRate: 'low',
        },
        {
            id: 'sig/bashrc-backdoor',
            name: 'Bashrc/Profile Backdoor',
            description: 'Suspicious commands in shell profile files',
            mechanismType: 'bashrc',
            indicators: [
                { type: 'file-contains', path: '/root/.bashrc', pattern: 'nc\\s|ncat\\s|bash\\s-i|/dev/tcp|reverse|socat' },
                { type: 'file-contains', path: '/home/*/.bashrc', pattern: 'nc\\s|ncat\\s|bash\\s-i|/dev/tcp|reverse|socat' },
            ],
            severity: 'critical',
            mitreTechnique: 'T1546.004',
            falsePositiveRate: 'none',
        },
        {
            id: 'sig/ld-preload',
            name: 'LD_PRELOAD Hijacking',
            description: 'Shared library preloading for code injection',
            mechanismType: 'ld-preload',
            indicators: [
                { type: 'file-exists', path: '/etc/ld.so.preload' },
                { type: 'file-contains', path: '/etc/environment', pattern: 'LD_PRELOAD' },
            ],
            severity: 'critical',
            mitreTechnique: 'T1574.006',
            falsePositiveRate: 'none',
        },
        {
            id: 'sig/init-script',
            name: 'Init Script Persistence',
            description: 'Custom init script in /etc/init.d/',
            mechanismType: 'init-script',
            indicators: [
                { type: 'file-exists', path: '/etc/init.d/*' },
            ],
            severity: 'high',
            mitreTechnique: 'T1037.004',
            falsePositiveRate: 'medium',
        },
        {
            id: 'sig/rc-local',
            name: 'RC Local Modification',
            description: 'Commands added to /etc/rc.local',
            mechanismType: 'rc-local',
            indicators: [
                { type: 'file-contains', path: '/etc/rc.local', pattern: 'nc\\s|ncat\\s|bash|python|perl|wget|curl' },
            ],
            severity: 'high',
            mitreTechnique: 'T1037.004',
            falsePositiveRate: 'low',
        },
        {
            id: 'sig/motd-script',
            name: 'MOTD Script Backdoor',
            description: 'Executable script in /etc/update-motd.d/',
            mechanismType: 'motd-script',
            indicators: [
                { type: 'file-exists', path: '/etc/update-motd.d/*' },
            ],
            severity: 'high',
            mitreTechnique: 'T1037',
            falsePositiveRate: 'medium',
        },
        {
            id: 'sig/pam-backdoor',
            name: 'PAM Module Backdoor',
            description: 'Custom PAM module installed for authentication bypass',
            mechanismType: 'pam-module',
            indicators: [
                { type: 'file-exists', path: '/lib/security/pam_*.so' },
                { type: 'file-exists', path: '/lib/x86_64-linux-gnu/security/pam_*.so' },
            ],
            severity: 'critical',
            mitreTechnique: 'T1556.003',
            falsePositiveRate: 'low',
        },
        {
            id: 'sig/at-job',
            name: 'AT Job Scheduled',
            description: 'One-time job scheduled via at command',
            mechanismType: 'at-job',
            indicators: [
                { type: 'file-exists', path: '/var/spool/at/*' },
            ],
            severity: 'medium',
            mitreTechnique: 'T1053.002',
            falsePositiveRate: 'medium',
        },
        {
            id: 'sig/udev-rule',
            name: 'Udev Rule Persistence',
            description: 'Custom udev rule for execution on device events',
            mechanismType: 'udev-rule',
            indicators: [
                { type: 'file-exists', path: '/etc/udev/rules.d/*.rules' },
            ],
            severity: 'high',
            mitreTechnique: 'T1546',
            falsePositiveRate: 'medium',
        },
        {
            id: 'sig/kernel-module',
            name: 'Kernel Module Rootkit',
            description: 'Custom kernel module loaded for rootkit functionality',
            mechanismType: 'kernel-module',
            indicators: [
                { type: 'file-exists', path: '/lib/modules/*/extra/*.ko' },
                { type: 'file-contains', path: '/etc/modules', pattern: '.*' },
            ],
            severity: 'critical',
            mitreTechnique: 'T1547.006',
            falsePositiveRate: 'none',
        },
        {
            id: 'sig/git-hook',
            name: 'Git Hook Backdoor',
            description: 'Malicious git hook for code execution on operations',
            mechanismType: 'git-hook',
            indicators: [
                { type: 'file-contains', path: '.git/hooks/*', pattern: 'bash|sh|python|perl|nc|curl|wget' },
            ],
            severity: 'medium',
            mitreTechnique: 'T1546',
            falsePositiveRate: 'high',
        },
    ];
}

// ── Factory ────────────────────────────────────────────────

export function createPersistenceEngine(): PersistenceEngine {
    const mechanisms = new Map<string, PersistenceMechanism>();
    const signatures: PersistenceSignature[] = [...createBuiltinSignatures()];

    function matchIndicatorPath(indicatorPath: string, filePath: string): boolean {
        if (indicatorPath.includes('*')) {
            const parts = indicatorPath.split('*');
            if (parts.length === 2) {
                const prefix = parts[0]!;
                const suffix = parts[1]!;
                return filePath.startsWith(prefix) && filePath.endsWith(suffix);
            }
        }
        return indicatorPath === filePath;
    }

    return {
        install(mechanism: PersistenceMechanism): void {
            mechanisms.set(mechanism.id, mechanism);
        },

        remove(id: string): boolean {
            return mechanisms.delete(id);
        },

        getAll(): readonly PersistenceMechanism[] {
            return [...mechanisms.values()];
        },

        getByMachine(machine: string): readonly PersistenceMechanism[] {
            return [...mechanisms.values()].filter(m => m.machine === machine);
        },

        getByType(type: PersistenceMechanismType): readonly PersistenceMechanism[] {
            return [...mechanisms.values()].filter(m => m.type === type);
        },

        scan(machine: string, vfsReadFile: (path: string) => string | null): readonly PersistenceScanResult[] {
            const results: PersistenceScanResult[] = [];
            const machineMechanisms = [...mechanisms.values()].filter(m => m.machine === machine);

            for (const mechanism of machineMechanisms) {
                if (!mechanism.detectable) continue;

                for (const sig of signatures) {
                    if (sig.mechanismType !== mechanism.type) continue;

                    let matchCount = 0;
                    const evidence: string[] = [];

                    for (const indicator of sig.indicators) {
                        switch (indicator.type) {
                            case 'file-exists': {
                                if (matchIndicatorPath(indicator.path, mechanism.path)) {
                                    matchCount++;
                                    evidence.push(`File exists: ${mechanism.path}`);
                                }
                                break;
                            }
                            case 'file-contains': {
                                const content = vfsReadFile(mechanism.path);
                                if (content !== null) {
                                    try {
                                        if (new RegExp(indicator.pattern, 'i').test(content)) {
                                            matchCount++;
                                            evidence.push(`File ${mechanism.path} contains pattern: ${indicator.pattern}`);
                                        }
                                    } catch {
                                        if (content.includes(indicator.pattern)) {
                                            matchCount++;
                                            evidence.push(`File ${mechanism.path} contains: ${indicator.pattern}`);
                                        }
                                    }
                                }
                                break;
                            }
                            case 'file-modified-after': {
                                if (mechanism.installedAtTick >= indicator.tick) {
                                    matchCount++;
                                    evidence.push(`File ${mechanism.path} modified at tick ${mechanism.installedAtTick}`);
                                }
                                break;
                            }
                            case 'process-running': {
                                // Would need process tree integration
                                break;
                            }
                            case 'cron-entry': {
                                const content = vfsReadFile(mechanism.path);
                                if (content !== null) {
                                    try {
                                        if (new RegExp(indicator.pattern).test(content)) {
                                            matchCount++;
                                            evidence.push(`Cron entry matches: ${indicator.pattern}`);
                                        }
                                    } catch {
                                        // Pattern is not a valid regex
                                    }
                                }
                                break;
                            }
                            default:
                                break;
                        }
                    }

                    if (matchCount > 0) {
                        const confidence = Math.min(1.0, matchCount / sig.indicators.length);
                        results.push({
                            mechanism,
                            matchedSignature: sig,
                            confidence,
                            evidence,
                        });
                    }
                }
            }

            return results;
        },

        addSignature(signature: PersistenceSignature): void {
            signatures.push(signature);
        },

        getSignatures(): readonly PersistenceSignature[] {
            return [...signatures];
        },

        timeline(): readonly PersistenceMechanism[] {
            return [...mechanisms.values()].sort((a, b) => a.installedAtTick - b.installedAtTick);
        },

        getStats(): PersistenceStats {
            const all = [...mechanisms.values()];
            const byType: Record<string, number> = {};
            const byMachine: Record<string, number> = {};

            for (const m of all) {
                byType[m.type] = (byType[m.type] ?? 0) + 1;
                byMachine[m.machine] = (byMachine[m.machine] ?? 0) + 1;
            }

            return {
                totalInstalled: all.length,
                byType,
                byMachine,
                detectable: all.filter(m => m.detectable).length,
                survivesReboot: all.filter(m => m.surviveReboot).length,
            };
        },

        generateOverlay(machine: string): Readonly<Record<string, string>> {
            const overlay: Record<string, string> = {};
            for (const m of mechanisms.values()) {
                if (m.machine === machine) {
                    overlay[m.path] = m.content;
                }
            }
            return overlay;
        },
    };
}
