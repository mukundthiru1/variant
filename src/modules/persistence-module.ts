import type { EventBus, EventHandler, FsWriteEvent } from '../core/events';
import type { Capability, Module, SimulationContext } from '../core/modules';
import type { VirtualFilesystem } from '../lib/vfs/types';

const MODULE_ID = 'persistence-catalog';
const MODULE_VERSION = '1.0.0';

const MODULE_ALIASES = [
    'persistence',
    'backdoor-detection',
] as const;

export interface PersistenceTechnique {
    readonly id: string;
    readonly name: string;
    readonly category: string;
    readonly paths: readonly string[];
    readonly description: string;
}

export interface PersistenceIndicator {
    readonly technique: string;
    readonly path: string;
    readonly confidence: 'high' | 'medium' | 'low';
    readonly detail: string;
}

interface InternalTechnique extends PersistenceTechnique {
    readonly detectMethod: (vfs: VirtualFilesystem) => PersistenceIndicator[];
    readonly installMethod: (vfs: VirtualFilesystem, payload: string) => boolean;
}

type NodeStat = ReturnType<VirtualFilesystem['stat']>;

const CRON_SUSPICIOUS_TOKENS = [
    'curl ',
    'wget ',
    'nc ',
    'bash -i',
    'sh -c',
    '/dev/tcp',
    '/tmp/',
    'python -c',
    'perl -e',
    'php -r',
];

const SYSTEMD_SUSPICIOUS_TOKENS = [
    'curl ',
    'wget ',
    'nc ',
    'bash -i',
    'sh -c',
    '/tmp/',
    'ExecStart=',
    'ExecStartPre=',
    'ExecStartPost=',
];

const WEB_SHELL_TOKENS = [
    'system(',
    'passthru(',
    'shell_exec',
    'proc_open',
    'popen(',
    'eval(',
    'exec(',
    '$_get',
    '$_post',
];

const SHELL_PROFILE_TOKENS = [
    'nohup ',
    'bash -i',
    'nc ',
    'curl ',
    'wget ',
    '/dev/tcp',
    '/tmp/',
];

const GENERIC_SCRIPT_TOKENS = [
    'nc -e',
    'bash -i',
    'curl ',
    'wget ',
    'wget\\x20',
    '/tmp/',
    '/dev/tcp',
];

const SOCKET_SUSPICIOUS_TOKENS = [
    'listenstream=',
    'backdoor',
    'persistent',
    '/tmp/',
];

function toLowerText(value: string): string {
    return value.toLowerCase();
}

function containsAny(value: string, patterns: readonly string[]): boolean {
    const lower = toLowerText(value);
    return patterns.some((pattern) => lower.includes(pattern));
}

function readText(vfs: VirtualFilesystem, path: string): string | null {
    try {
        return vfs.readFile(path);
    } catch {
        return null;
    }
}

function readDirSafe(vfs: VirtualFilesystem, path: string): readonly string[] {
    try {
        const listing = vfs.readDir(path);
        return listing ?? [];
    } catch {
        return [];
    }
}

function hasSetuidBit(node: NodeStat): boolean {
    if (node === null || node.type === 'symlink' || node.type !== 'file') return false;
    return (node.mode & 0o4000) === 0o4000;
}

function splitLines(value: string): string[] {
    return value.split('\n');
}

function writeLineContent(
    vfs: VirtualFilesystem,
    path: string,
    content: string,
    mode?: number,
): boolean {
    try {
        vfs.writeFile(path, content, { mode });
        return true;
    } catch {
        return false;
    }
}

function appendLineContent(
    vfs: VirtualFilesystem,
    path: string,
    content: string,
    mode?: number,
): boolean {
    try {
        const existing = vfs.readFile(path) ?? '';
        const merged = `${existing}${existing.length > 0 ? '\n' : ''}${content}`;
        vfs.writeFile(path, merged, { mode });
        return true;
    } catch {
        return false;
    }
}

function patternToRegex(pattern: string): RegExp {
    const escaped = pattern
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\\*\\*/g, '§§')
        .replace(/\*/g, '[^/]*')
        .replace(/§§/g, '.*');
    return new RegExp(`^${escaped}$`);
}

function pathMatchesPattern(path: string, pattern: string): boolean {
    return patternToRegex(pattern).test(path);
}

function techniqueMatchesPath(
    technique: InternalTechnique,
    path: string,
): boolean {
    return technique.paths.some((pathPattern) => pathMatchesPattern(path, pathPattern));
}

function detectCronContent(path: string, content: string): PersistenceIndicator[] {
    const indicators: PersistenceIndicator[] = [];
    const lines = splitLines(content).map((line) => line.trim());
    const suspiciousLine = lines.find((line) => {
        if (line.length === 0 || line.startsWith('#')) return false;
        return containsAny(line, CRON_SUSPICIOUS_TOKENS);
    });
    if (suspiciousLine !== undefined) {
        indicators.push({
            technique: 'cron-job',
            path,
            confidence: containsAny(suspiciousLine, ['nc -e', 'bash -i', '/dev/tcp']) ? 'high' : 'medium',
            detail: `Suspicious command in cron definition at ${path}`,
        });
    }
    return indicators;
}

function collectDirectoryFiles(vfs: VirtualFilesystem, directory: string): string[] {
    const files: string[] = [];
    const entries = readDirSafe(vfs, directory);
    for (const entry of entries) {
        if (entry.startsWith('.')) continue;
        files.push(`${directory}/${entry}`);
    }
    return files;
}

const PERSISTENCE_TECHNIQUES: readonly InternalTechnique[] = [
    {
        id: 'cron-job',
        name: 'Cron Job',
        category: 'execution',
        paths: [
            '/etc/crontab',
            '/etc/cron.d/*',
            '/var/spool/cron/*',
            '/var/spool/cron/crontabs/*',
        ],
        description:
            'Persistence via cron entries and scheduled job directories that execute attacker-controlled commands.',
        detectMethod: (vfs) => {
            const found: PersistenceIndicator[] = [];
            const cronFile = readText(vfs, '/etc/crontab');
            if (cronFile !== null) {
                found.push(...detectCronContent('/etc/crontab', cronFile));
            }

            for (const path of collectDirectoryFiles(vfs, '/etc/cron.d')) {
                const content = readText(vfs, path);
                if (content === null) continue;
                found.push(...detectCronContent(path, content));
            }

            for (const path of collectDirectoryFiles(vfs, '/var/spool/cron')) {
                const content = readText(vfs, path);
                if (content === null) continue;
                found.push(...detectCronContent(path, content));
            }

            for (const path of collectDirectoryFiles(vfs, '/var/spool/cron/crontabs')) {
                const content = readText(vfs, path);
                if (content === null) continue;
                found.push(...detectCronContent(path, content));
            }

            return found;
        },
        installMethod: (vfs, payload) => {
            return writeLineContent(
                vfs,
                '/etc/cron.d/persistence-backdoor',
                `* * * * * root ${payload}`,
                0o644,
            );
        },
    },
    {
        id: 'systemd-service',
        name: 'Systemd Service',
        category: 'execution',
        paths: ['/etc/systemd/system/*.service'],
        description:
            'Persistence via custom or modified systemd service unit files with suspicious ExecStart hooks.',
        detectMethod: (vfs) => {
            const found: PersistenceIndicator[] = [];
            const serviceDirs = ['/etc/systemd/system', '/usr/lib/systemd/system'];
            for (const serviceDir of serviceDirs) {
                for (const file of collectDirectoryFiles(vfs, serviceDir)) {
                    if (!file.endsWith('.service')) continue;
                    const content = readText(vfs, file);
                    if (content === null) continue;
                    const lower = toLowerText(content);
                    if (!containsAny(lower, SYSTEMD_SUSPICIOUS_TOKENS)) continue;
                    const hasExec = splitLines(content).some((line) => {
                        const lowerLine = toLowerText(line);
                        if (!lowerLine.includes('execstart')) return false;
                        return containsAny(lowerLine, SYSTEMD_SUSPICIOUS_TOKENS);
                    });
                    if (hasExec) {
                        found.push({
                            technique: 'systemd-service',
                            path: file,
                            confidence: containsAny(lower, ['curl ', 'wget ', 'bash -i']) ? 'high' : 'medium',
                            detail: `Suspicious execution directive in ${file}`,
                        });
                    }
                }
            }
            return found;
        },
        installMethod: (vfs, payload) => {
            const content = [
                '[Unit]',
                'Description=Persistence service',
                '[Service]',
                `ExecStart=${payload}`,
                'Restart=always',
                '[Install]',
                'WantedBy=multi-user.target',
            ].join('\n');
            return writeLineContent(vfs, '/etc/systemd/system/persistence-backdoor.service', content, 0o644);
        },
    },
    {
        id: 'ssh-authorized-keys',
        name: 'SSH Authorized Keys',
        category: 'access',
        paths: ['/root/.ssh/authorized_keys', '/home/*/.ssh/authorized_keys'],
        description:
            'Persistence via injected SSH keys that provide hidden or alternate authentication access.',
        detectMethod: (vfs) => {
            const found: PersistenceIndicator[] = [];
            const explicitPaths = [
                '/root/.ssh/authorized_keys',
                ...vfs.glob('/home/*/.ssh/authorized_keys'),
            ];
            for (const path of explicitPaths) {
                const content = readText(vfs, path);
                if (content === null) continue;
                const keyLines = splitLines(content)
                    .map((line) => line.trim())
                    .filter((line) => line.length > 0 && !line.startsWith('#'));
                if (keyLines.length <= 1) {
                    continue;
                }
                if (containsAny(keyLines.join(' ').toLowerCase(), ['command=', 'exec='])) {
                    found.push({
                        technique: 'ssh-authorized-keys',
                        path,
                        confidence: 'high',
                        detail: `Forced command or command option in ${path}`,
                    });
                    continue;
                }
                found.push({
                    technique: 'ssh-authorized-keys',
                    path,
                    confidence: 'medium',
                    detail: `Unexpected additional key material in ${path}`,
                });
            }
            return found;
        },
        installMethod: (vfs, payload) => {
            const existing = readText(vfs, '/root/.ssh/authorized_keys') ?? '';
            const content = existing.length > 0 ? `${existing}\n${payload}` : payload;
            return writeLineContent(vfs, '/root/.ssh/authorized_keys', content, 0o600);
        },
    },
    {
        id: 'web-shell',
        name: 'Web Shell',
        category: 'execution',
        paths: ['/var/www/html/*.php', '/var/www/html/*.jsp', '/srv/www/**/*.php', '/srv/www/**/*.jsp'],
        description:
            'Persistence via web shell files in common web roots containing command execution primitives.',
        detectMethod: (vfs) => {
            const found: PersistenceIndicator[] = [];
            const paths = [
                ...vfs.glob('/var/www/html/*.php'),
                ...vfs.glob('/var/www/html/**/*.php'),
                ...vfs.glob('/srv/www/**/*.php'),
                ...vfs.glob('/var/www/html/*.jsp'),
                ...vfs.glob('/var/www/html/**/*.jsp'),
                ...vfs.glob('/srv/www/**/*.jsp'),
            ];
            const seen = new Set<string>();
            for (const path of paths) {
                if (seen.has(path)) continue;
                seen.add(path);
                const content = readText(vfs, path);
                if (content === null) continue;
                const lower = toLowerText(content);
                if (!lower.includes('<?') || !containsAny(lower, WEB_SHELL_TOKENS)) {
                    continue;
                }
                found.push({
                    technique: 'web-shell',
                    path,
                    confidence: 'high',
                    detail: `Web execution payload indicators in ${path}`,
                });
            }
            return found;
        },
        installMethod: (vfs, payload) => {
            const content = `<?php\n${payload}\n?>\n`;
            return writeLineContent(vfs, '/var/www/html/backdoor-shell.php', content, 0o644);
        },
    },
    {
        id: 'bash-profile',
        name: 'Bash Profile',
        category: 'execution',
        paths: ['/root/.bashrc', '/root/.bash_profile', '/etc/profile'],
        description:
            'Persistence via shell startup scripts that execute attacker commands during user sessions.',
        detectMethod: (vfs) => {
            const found: PersistenceIndicator[] = [];
            const paths = [
                '/root/.bashrc',
                '/root/.bash_profile',
                '/etc/profile',
                ...vfs.glob('/home/*/.bashrc'),
            ];
            for (const path of paths) {
                const content = readText(vfs, path);
                if (content === null) continue;
                const has = splitLines(content)
                    .map((line) => line.trim())
                    .some((line) => line.length > 0 && !line.startsWith('#') && containsAny(line, SHELL_PROFILE_TOKENS));
                if (!has) continue;
                found.push({
                    technique: 'bash-profile',
                    path,
                    confidence: 'high',
                    detail: `Suspicious startup command in ${path}`,
                });
            }
            return found;
        },
        installMethod: (vfs, payload) => {
            const existing = readText(vfs, '/root/.bashrc') ?? '';
            const content = existing.length > 0 ? `${existing}\n${payload}` : payload;
            return writeLineContent(vfs, '/root/.bashrc', content, 0o644);
        },
    },
    {
        id: 'suid-backdoor',
        name: 'SUID Backdoor',
        category: 'privilege',
        paths: ['/usr/local/bin/*'],
        description:
            'Persistence via unexpectedly setuid-capable binaries under privileged writable locations.',
        detectMethod: (vfs) => {
            const found: PersistenceIndicator[] = [];
            for (const path of collectDirectoryFiles(vfs, '/usr/local/bin')) {
                const node = vfs.stat(path);
                if (!hasSetuidBit(node)) continue;
                found.push({
                    technique: 'suid-backdoor',
                    path,
                    confidence: 'medium',
                    detail: `Setuid binary found at ${path}`,
                });
            }
            return found;
        },
        installMethod: (vfs, payload) => {
            return writeLineContent(vfs, '/usr/local/bin/persistence-suid', payload, 0o4755);
        },
    },
    {
        id: 'ld-preload',
        name: 'LD_PRELOAD',
        category: 'execution',
        paths: ['/etc/ld.so.preload'],
        description:
            'Persistence by injecting preloaded libraries through /etc/ld.so.preload.',
        detectMethod: (vfs) => {
            const found: PersistenceIndicator[] = [];
            const content = readText(vfs, '/etc/ld.so.preload');
            if (content === null) return found;
            if (containsAny(content, ['/tmp/', '/var/tmp/', 'backdoor', 'attack', '.so'])) {
                found.push({
                    technique: 'ld-preload',
                    path: '/etc/ld.so.preload',
                    confidence: 'high',
                    detail: 'Custom preload entries detected in /etc/ld.so.preload',
                });
            }
            return found;
        },
        installMethod: (vfs, payload) => {
            const existing = readText(vfs, '/etc/ld.so.preload') ?? '';
            const merged = existing.length > 0 ? `${existing}\n${payload}` : payload;
            return writeLineContent(vfs, '/etc/ld.so.preload', merged, 0o644);
        },
    },
    {
        id: 'pam-backdoor',
        name: 'PAM Backdoor',
        category: 'access',
        paths: ['/etc/pam.d/*'],
        description:
            'Persistence through modified PAM modules using exec hooks to spawn attacker logic on auth events.',
        detectMethod: (vfs) => {
            const found: PersistenceIndicator[] = [];
            for (const file of collectDirectoryFiles(vfs, '/etc/pam.d')) {
                const content = readText(vfs, file);
                if (content === null) continue;
                const hasPamExec = splitLines(content)
                    .map((line) => line.trim())
                    .some((line) => line.length > 0 && !line.startsWith('#') && line.includes('pam_exec.so'));
                if (!hasPamExec) continue;
                found.push({
                    technique: 'pam-backdoor',
                    path: file,
                    confidence: 'high',
                    detail: `PAM exec hook detected in ${file}`,
                });
            }
            return found;
        },
        installMethod: (vfs, payload) => {
            const content = `auth optional pam_exec.so quiet expose_authtok ${payload}`;
            return appendLineContent(vfs, '/etc/pam.d/common-auth', content, 0o644);
        },
    },
    {
        id: 'git-hooks',
        name: 'Git Hooks',
        category: 'execution',
        paths: ['/**/*.git/hooks/*', '/**/.git/hooks/*', '/opt/repo/.git/hooks/*'],
        description:
            'Persistence through executable git hooks that run during repository lifecycle events.',
        detectMethod: (vfs) => {
            const found: PersistenceIndicator[] = [];
            const hooks = new Set([
                ...vfs.glob('/**/.git/hooks/*'),
                ...vfs.glob('/opt/repo/.git/hooks/*'),
                ...vfs.glob('/*/.git/hooks/*'),
            ]);
            for (const path of hooks) {
                const node = vfs.stat(path);
                if (node === null || node.type !== 'file') continue;
                const content = readText(vfs, path);
                if (content === null) continue;
                const lower = toLowerText(content);
                if (!containsAny(lower, GENERIC_SCRIPT_TOKENS)) continue;
                found.push({
                    technique: 'git-hooks',
                    path,
                    confidence: 'high',
                    detail: `Potential backdoor code in git hook ${path}`,
                });
            }
            return found;
        },
        installMethod: (vfs, payload) => {
            return writeLineContent(vfs, '/opt/repo/.git/hooks/pre-commit', `#!/bin/sh\n${payload}`, 0o755);
        },
    },
    {
        id: 'at-jobs',
        name: 'At Jobs',
        category: 'execution',
        paths: ['/var/spool/at/*'],
        description:
            'Persistence using delayed one-shot execution scheduled in At job spools.',
        detectMethod: (vfs) => {
            const found: PersistenceIndicator[] = [];
            const files = collectDirectoryFiles(vfs, '/var/spool/at');
            for (const file of files) {
                const fileName = file.split('/').at(-1);
                if (fileName === '.SEQ' || fileName === 'spool') continue;
                const content = readText(vfs, file);
                if (content === null) continue;
                const suspicious = splitLines(content)
                    .map((line) => line.trim())
                    .some((line) => line.length > 0 && containsAny(line, GENERIC_SCRIPT_TOKENS));
                if (!suspicious) continue;
                found.push({
                    technique: 'at-jobs',
                    path: file,
                    confidence: 'high',
                    detail: `Suspicious at-jobs payload in ${file}`,
                });
            }
            return found;
        },
        installMethod: (vfs, payload) => {
            return writeLineContent(vfs, '/var/spool/at/backdoor-01', payload, 0o600);
        },
    },
    {
        id: 'motd-scripts',
        name: 'MOTD Scripts',
        category: 'execution',
        paths: ['/etc/update-motd.d/*', '/etc/motd'],
        description:
            'Persistence hooks via MOTD scripts that execute on shell login or startup paths.',
        detectMethod: (vfs) => {
            const found: PersistenceIndicator[] = [];
            for (const path of collectDirectoryFiles(vfs, '/etc/update-motd.d')) {
                const content = readText(vfs, path);
                if (content === null) continue;
                if (!containsAny(content, GENERIC_SCRIPT_TOKENS)) continue;
                found.push({
                    technique: 'motd-scripts',
                    path,
                    confidence: 'medium',
                    detail: `Command execution signal in ${path}`,
                });
            }

            const motd = readText(vfs, '/etc/motd');
            if (motd !== null && containsAny(motd, GENERIC_SCRIPT_TOKENS)) {
                found.push({
                    technique: 'motd-scripts',
                    path: '/etc/motd',
                    confidence: 'low',
                    detail: 'MOTD content contains command-like payload',
                });
            }
            return found;
        },
        installMethod: (vfs, payload) => {
            return writeLineContent(vfs, '/etc/update-motd.d/99-backdoor', `#!/bin/sh\n${payload}`, 0o755);
        },
    },
    {
        id: 'rc-scripts',
        name: 'RC Scripts',
        category: 'execution',
        paths: ['/etc/rc.local', '/etc/rc.d/rc.local', '/etc/init.d/*'],
        description:
            'Persistence using rc startup scripts with hidden commands during boot.',
        detectMethod: (vfs) => {
            const found: PersistenceIndicator[] = [];
            const paths = [
                '/etc/rc.local',
                '/etc/rc.d/rc.local',
                ...collectDirectoryFiles(vfs, '/etc/init.d'),
            ];
            for (const path of paths) {
                const content = readText(vfs, path);
                if (content === null) continue;
                const lower = toLowerText(content);
                const suspicious = containsAny(lower, [...SHELL_PROFILE_TOKENS, 'service', '/usr/sbin/cron']);
                if (!suspicious) continue;
                found.push({
                    technique: 'rc-scripts',
                    path,
                    confidence: 'high',
                    detail: `Startup script command execution found in ${path}`,
                });
            }
            return found;
        },
        installMethod: (vfs, payload) => {
            const existing = readText(vfs, '/etc/rc.local') ?? '#!/bin/sh';
            const content = `${existing}\n${payload}\n`;
            return writeLineContent(vfs, '/etc/rc.local', content, 0o755);
        },
    },
    {
        id: 'docker-entrypoint',
        name: 'Docker Entrypoint',
        category: 'execution',
        paths: ['/entrypoint.sh', '/Dockerfile'],
        description:
            'Persistence via container startup entrypoints that run attacker commands.',
        detectMethod: (vfs) => {
            const found: PersistenceIndicator[] = [];
            const entrypoint = readText(vfs, '/entrypoint.sh');
            if (entrypoint !== null && containsAny(entrypoint, GENERIC_SCRIPT_TOKENS)) {
                found.push({
                    technique: 'docker-entrypoint',
                    path: '/entrypoint.sh',
                    confidence: 'high',
                    detail: 'Entry-point shell script includes command execution payload',
                });
            }
            const dockerfile = readText(vfs, '/Dockerfile');
            if (dockerfile !== null) {
                const lower = toLowerText(dockerfile);
                if (containsAny(lower, ['entrypoint', 'cmd']) && containsAny(lower, ['curl ', 'bash -i', 'nc ', 'sh -c'])) {
                    found.push({
                        technique: 'docker-entrypoint',
                        path: '/Dockerfile',
                        confidence: 'medium',
                        detail: 'Dockerfile entrypoint/command section suspicious',
                    });
                }
            }
            return found;
        },
        installMethod: (vfs, payload) => {
            const current = readText(vfs, '/entrypoint.sh') ?? '#!/bin/sh';
            const entrypoint = `${current}\n${payload}\n`;
            return writeLineContent(vfs, '/entrypoint.sh', entrypoint, 0o755);
        },
    },
    {
        id: 'kernel-module',
        name: 'Kernel Module',
        category: 'execution',
        paths: ['/etc/modules-load.d/*.conf', '/etc/modprobe.d/*.conf'],
        description:
            'Persistence via auto-loaded kernel module entries or modified loader hooks.',
        detectMethod: (vfs) => {
            const found: PersistenceIndicator[] = [];
            const paths = [
                ...collectDirectoryFiles(vfs, '/etc/modules-load.d'),
                ...collectDirectoryFiles(vfs, '/etc/modprobe.d'),
            ];
            for (const path of paths) {
                const content = readText(vfs, path);
                if (content === null) continue;
                const lower = toLowerText(content);
                const hasBackdoor = containsAny(lower, [
                    'backdoor',
                    'insmod',
                    '.ko',
                    'payload',
                ]);
                if (!hasBackdoor) continue;
                found.push({
                    technique: 'kernel-module',
                    path,
                    confidence: 'medium',
                    detail: `Kernel module configuration with backdoor token in ${path}`,
                });
            }
            return found;
        },
        installMethod: (vfs, payload) => {
            return writeLineContent(vfs, '/etc/modules-load.d/persistence-backdoor.conf', payload, 0o644);
        },
    },
    {
        id: 'socket-activation',
        name: 'Socket Activation',
        category: 'execution',
        paths: ['/etc/systemd/system/*.socket'],
        description:
            'Persistence via suspicious systemd socket activation units.',
        detectMethod: (vfs) => {
            const found: PersistenceIndicator[] = [];
            for (const path of collectDirectoryFiles(vfs, '/etc/systemd/system')) {
                if (!path.endsWith('.socket')) continue;
                const content = readText(vfs, path);
                if (content === null) continue;
                const lower = toLowerText(content);
                const suspicious = containsAny(lower, SOCKET_SUSPICIOUS_TOKENS) && containsAny(lower, ['listenstream=', '[socket]']);
                if (!suspicious) continue;
                found.push({
                    technique: 'socket-activation',
                    path,
                    confidence: 'medium',
                    detail: `Suspicious socket unit present at ${path}`,
                });
            }
            return found;
        },
        installMethod: (vfs, payload) => {
            const socket = [
                '[Unit]',
                'Description=persistence socket',
                '[Socket]',
                'ListenStream=1337',
                'Accept=yes',
                '[Install]',
                'WantedBy=sockets.target',
            ].join('\n');
            const service = [
                '[Unit]',
                'Description=persistence socket service',
                '[Service]',
                `ExecStart=${payload}`,
                'StandardInput=socket',
            ].join('\n');
            const okSocket = writeLineContent(vfs, '/etc/systemd/system/persistence-backdoor.socket', socket, 0o644);
            const okService = writeLineContent(vfs, '/etc/systemd/system/persistence-backdoor@.service', service, 0o644);
            return okSocket && okService;
        },
    },
];

export function detectPersistence(vfs: VirtualFilesystem): PersistenceIndicator[] {
    const indicators: PersistenceIndicator[] = [];
    for (const technique of PERSISTENCE_TECHNIQUES) {
        indicators.push(...technique.detectMethod(vfs));
    }
    return indicators;
}

export function installPersistence(
    vfs: VirtualFilesystem,
    technique: string,
    payload: string,
): boolean {
    const candidate = PERSISTENCE_TECHNIQUES.find((entry) => entry.id === technique);
    if (candidate === undefined) return false;
    return candidate.installMethod(vfs, payload);
}

function findTechniqueByPath(path: string): readonly InternalTechnique[] {
    return PERSISTENCE_TECHNIQUES.filter((technique) => techniqueMatchesPath(technique, path));
}

export { PERSISTENCE_TECHNIQUES };

export function createPersistenceModule(eventBus: EventBus): Module {
    const unsubs: Array<() => void> = [];
    const alertsSent = new Map<string, number>();

    const module: Module = {
        id: MODULE_ID,
        type: 'defense',
        version: MODULE_VERSION,
        description: 'Persistence mechanism catalog and detection with fs:write integration.',
        provides: MODULE_ALIASES.map((alias) => ({ name: alias }) as const) as readonly Capability[],
        requires: [] as readonly Capability[],
        init(_context: SimulationContext): void {
            const onWrite: EventHandler<FsWriteEvent> = (event) => {
                const matches = findTechniqueByPath(event.path);
                if (matches.length === 0) return;

                for (const technique of matches) {
                    const key = `${event.machine}:${event.path}:${technique.id}`;
                    const now = Date.now();
                    const last = alertsSent.get(key);
                    if (last !== undefined && now - last < 750) continue;
                    alertsSent.set(key, now);

                    eventBus.emit({
                        type: 'defense:alert',
                        machine: event.machine,
                        ruleId: `persistence/${technique.id}`,
                        severity: 'high',
                        detail: `${technique.name} persistence write observed at ${event.path}`,
                        timestamp: now,
                    });
                }
            };
            unsubs.push(eventBus.on('fs:write', onWrite));
        },
        destroy(): void {
            for (const unsub of unsubs) {
                unsub();
            }
            unsubs.length = 0;
            alertsSent.clear();
        },
    };

    return module;
}
