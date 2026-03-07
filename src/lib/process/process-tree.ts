/**
 * VARIANT — Process Tree System
 *
 * Realistic process hierarchy for forensics and monitoring.
 * Every machine has a process tree that mirrors a real Linux system.
 *
 * What it does:
 *   - Manages a tree of processes with parent/child relationships
 *   - Supports fork, exec, exit lifecycle
 *   - Generates realistic `ps auxf` output
 *   - Tracks process owners, start times, CPU/memory
 *   - Emits events for EDR/SIEM integration
 *   - Detects orphan processes and reparenting to init
 *   - Detects suspicious lineage (e.g., bash spawned from httpd)
 *
 * EXTENSIBILITY:
 *   - Custom process generators (third-party)
 *   - Anomaly detection hooks
 *   - Process monitoring rules
 *   - Forensic timeline export
 */

// ── Process Types ──────────────────────────────────────────────

/**
 * A process in the process tree.
 */
export interface ProcessNode {
    readonly pid: number;
    readonly ppid: number;
    readonly name: string;
    readonly command: string;
    readonly args: string;
    readonly user: string;
    readonly startTick: number;
    readonly state: ProcessState;
    /** CPU usage percentage (simulated). */
    readonly cpu: number;
    /** Memory usage in KB (simulated). */
    readonly memKB: number;
    /** Terminal/TTY. null = daemon. */
    readonly tty: string | null;
    /** Working directory. */
    readonly cwd: string;
    /** Environment variables (subset for forensics). */
    readonly env: Readonly<Record<string, string>>;
    /** Open file descriptors (for lsof integration). */
    readonly openFiles: readonly string[];
    /** Network connections (for netstat/ss). */
    readonly connections: readonly ProcessConnection[];
}

export type ProcessState = 'running' | 'sleeping' | 'stopped' | 'zombie' | 'dead';

export interface ProcessConnection {
    readonly protocol: 'tcp' | 'udp';
    readonly localAddr: string;
    readonly localPort: number;
    readonly remoteAddr: string;
    readonly remotePort: number;
    readonly state: 'LISTEN' | 'ESTABLISHED' | 'CLOSE_WAIT' | 'TIME_WAIT' | 'SYN_SENT';
}

// ── Process Tree ───────────────────────────────────────────────

/**
 * A process tree for a single machine.
 */
export interface ProcessTree {
    /** Spawn a new process. Returns PID. */
    spawn(config: SpawnConfig): number;
    /** Kill a process by PID. Returns true if found. */
    kill(pid: number, signal?: number): boolean;
    /** Get a process by PID. */
    get(pid: number): ProcessNode | null;
    /** Get all children of a process. */
    children(pid: number): readonly ProcessNode[];
    /** Get the full ancestry (parent chain) of a process. */
    ancestry(pid: number): readonly ProcessNode[];
    /** Get all processes. */
    all(): readonly ProcessNode[];
    /** Get process by name (first match). */
    findByName(name: string): ProcessNode | null;
    /** Get all processes by name. */
    findAllByName(name: string): readonly ProcessNode[];
    /** Get all processes by user. */
    findByUser(user: string): readonly ProcessNode[];
    /** Format as `ps auxf` output. */
    formatPsAux(): string;
    /** Format as `ps auxf` (forest/tree view). */
    formatPsAuxForest(): string;
    /** Format as `pstree` output. */
    formatPstree(): string;
    /** Get total process count. */
    count(): number;
    /** Advance the tick (for CPU/memory simulation). */
    tick(currentTick: number): void;
    /** Detect suspicious process lineage patterns. */
    detectAnomalies(): readonly ProcessAnomaly[];
}

export interface SpawnConfig {
    readonly name: string;
    readonly command: string;
    readonly args?: string;
    readonly user?: string;
    readonly ppid?: number;
    readonly tty?: string | null;
    readonly cwd?: string;
    readonly env?: Readonly<Record<string, string>>;
    readonly cpu?: number;
    readonly memKB?: number;
    readonly openFiles?: readonly string[];
    readonly connections?: readonly ProcessConnection[];
}

export interface ProcessAnomaly {
    readonly type: 'suspicious-parent' | 'orphan' | 'privilege-escalation' | 'unusual-binary';
    readonly pid: number;
    readonly description: string;
    readonly severity: 'info' | 'warning' | 'critical';
}

// ── Process Anomaly Rules ──────────────────────────────────────

/**
 * Known suspicious parent-child relationships.
 * If a child process spawns from an unexpected parent, flag it.
 */
const SUSPICIOUS_LINEAGE: ReadonlyArray<{ parent: string; child: string; severity: 'warning' | 'critical' }> = [
    { parent: 'httpd', child: 'bash', severity: 'critical' },
    { parent: 'apache2', child: 'bash', severity: 'critical' },
    { parent: 'nginx', child: 'sh', severity: 'critical' },
    { parent: 'nginx', child: 'bash', severity: 'critical' },
    { parent: 'mysqld', child: 'bash', severity: 'critical' },
    { parent: 'postgres', child: 'bash', severity: 'critical' },
    { parent: 'sshd', child: 'python', severity: 'warning' },
    { parent: 'sshd', child: 'perl', severity: 'warning' },
    { parent: 'cron', child: 'nc', severity: 'warning' },
    { parent: 'cron', child: 'ncat', severity: 'warning' },
    { parent: 'cron', child: 'curl', severity: 'warning' },
    { parent: 'cron', child: 'wget', severity: 'warning' },
];

// ── Factory ────────────────────────────────────────────────────

/**
 * Create a process tree for a machine.
 */
export function createProcessTree(_machineId: string): ProcessTree {
    let nextPid = 1;
    const processes = new Map<number, ProcessNode>();
    let currentTick = 0;

    // Init process (PID 1) — always present
    const initProcess: ProcessNode = {
        pid: 1,
        ppid: 0,
        name: 'init',
        command: '/sbin/init',
        args: '',
        user: 'root',
        startTick: 0,
        state: 'running',
        cpu: 0,
        memKB: 1024,
        tty: null,
        cwd: '/',
        env: {},
        openFiles: [],
        connections: [],
    };
    processes.set(1, initProcess);
    nextPid = 2;

    return {
        spawn(config: SpawnConfig): number {
            const pid = nextPid++;
            const ppid = config.ppid ?? 1;

            // Verify parent exists; reparent to init if not
            const actualPpid = processes.has(ppid) ? ppid : 1;

            const process: ProcessNode = {
                pid,
                ppid: actualPpid,
                name: config.name,
                command: config.command,
                args: config.args ?? '',
                user: config.user ?? 'root',
                startTick: currentTick,
                state: 'running',
                cpu: config.cpu ?? 0,
                memKB: config.memKB ?? 512,
                tty: config.tty === undefined ? null : config.tty,
                cwd: config.cwd ?? '/',
                env: config.env ?? {},
                openFiles: config.openFiles ?? [],
                connections: config.connections ?? [],
            };

            processes.set(pid, process);
            return pid;
        },

        kill(pid: number, _signal = 15): boolean {
            const process = processes.get(pid);
            if (process === undefined) return false;
            if (pid === 1) return false; // Can't kill init

            // Mark as dead
            processes.set(pid, { ...process, state: 'dead' });

            // Reparent children to init
            for (const [childPid, child] of processes) {
                if (child.ppid === pid) {
                    processes.set(childPid, { ...child, ppid: 1 });
                }
            }

            // Remove the process after marking dead
            processes.delete(pid);
            return true;
        },

        get(pid: number): ProcessNode | null {
            return processes.get(pid) ?? null;
        },

        children(pid: number): readonly ProcessNode[] {
            const result: ProcessNode[] = [];
            for (const [, proc] of processes) {
                if (proc.ppid === pid) {
                    result.push(proc);
                }
            }
            return Object.freeze(result);
        },

        ancestry(pid: number): readonly ProcessNode[] {
            const chain: ProcessNode[] = [];
            let current = processes.get(pid);

            while (current !== undefined && current.pid !== 0) {
                chain.push(current);
                if (current.ppid === 0) break;
                current = processes.get(current.ppid);
            }

            return Object.freeze(chain);
        },

        all(): readonly ProcessNode[] {
            return Object.freeze(Array.from(processes.values()));
        },

        findByName(name: string): ProcessNode | null {
            for (const [, proc] of processes) {
                if (proc.name === name) return proc;
            }
            return null;
        },

        findAllByName(name: string): readonly ProcessNode[] {
            const result: ProcessNode[] = [];
            for (const [, proc] of processes) {
                if (proc.name === name) result.push(proc);
            }
            return Object.freeze(result);
        },

        findByUser(user: string): readonly ProcessNode[] {
            const result: ProcessNode[] = [];
            for (const [, proc] of processes) {
                if (proc.user === user) result.push(proc);
            }
            return Object.freeze(result);
        },

        formatPsAux(): string {
            const lines: string[] = [];
            lines.push('USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND');

            const sorted = Array.from(processes.values()).sort((a, b) => a.pid - b.pid);

            for (const proc of sorted) {
                const user = proc.user.padEnd(8).slice(0, 8);
                const pid = String(proc.pid).padStart(5);
                const cpu = proc.cpu.toFixed(1).padStart(4);
                const mem = (proc.memKB / 1024 * 100).toFixed(1).padStart(4);
                const vsz = String(proc.memKB * 4).padStart(6);
                const rss = String(proc.memKB).padStart(5);
                const tty = (proc.tty ?? '?').padEnd(8);
                const stat = proc.state === 'running' ? 'R' : proc.state === 'sleeping' ? 'S' : proc.state === 'stopped' ? 'T' : proc.state === 'zombie' ? 'Z' : 'D';
                const time = '0:00';
                const cmd = `${proc.command}${proc.args !== '' ? ' ' + proc.args : ''}`;

                lines.push(`${user} ${pid} ${cpu} ${mem} ${vsz} ${rss} ${tty} ${stat}    ${currentTick.toString().padStart(5)}  ${time} ${cmd}`);
            }

            return lines.join('\n');
        },

        formatPsAuxForest(): string {
            const lines: string[] = [];
            lines.push('USER       PID %CPU %MEM COMMAND');

            function printTree(pid: number, prefix: string): void {
                const proc = processes.get(pid);
                if (proc === undefined) return;

                const user = proc.user.padEnd(8).slice(0, 8);
                const pidStr = String(proc.pid).padStart(5);
                const cpu = proc.cpu.toFixed(1).padStart(4);
                const mem = (proc.memKB / 1024 * 100).toFixed(1).padStart(4);
                const cmd = `${proc.command}${proc.args !== '' ? ' ' + proc.args : ''}`;

                lines.push(`${user} ${pidStr} ${cpu} ${mem} ${prefix}${cmd}`);

                // Find children
                const childProcs: ProcessNode[] = [];
                for (const [, child] of processes) {
                    if (child.ppid === pid && child.pid !== pid) {
                        childProcs.push(child);
                    }
                }

                childProcs.sort((a, b) => a.pid - b.pid);

                for (let i = 0; i < childProcs.length; i++) {
                    const child = childProcs[i];
                    if (child === undefined) continue;
                    const isLast = i === childProcs.length - 1;
                    const connector = isLast ? '└─ ' : '├─ ';
                    printTree(child.pid, prefix + connector);
                    // Set prefix for grandchildren
                    // (handled recursively via printTree)
                }
            }

            printTree(1, '');

            return lines.join('\n');
        },

        formatPstree(): string {
            function buildTree(pid: number): string {
                const proc = processes.get(pid);
                if (proc === undefined) return '';

                const childProcs: ProcessNode[] = [];
                for (const [, child] of processes) {
                    if (child.ppid === pid && child.pid !== pid) {
                        childProcs.push(child);
                    }
                }

                childProcs.sort((a, b) => a.pid - b.pid);

                if (childProcs.length === 0) {
                    return proc.name;
                }

                const childTrees = childProcs.map(c => buildTree(c.pid));
                return `${proc.name}─┬─${childTrees.join('\n' + ' '.repeat(proc.name.length) + ' ├─')}`;
            }

            return buildTree(1);
        },

        count(): number {
            return processes.size;
        },

        tick(tick: number): void {
            currentTick = tick;

            // Simulate CPU fluctuation for running processes
            for (const [pid, proc] of processes) {
                if (proc.state === 'running' && proc.cpu > 0) {
                    const jitter = (Math.random() - 0.5) * 0.2;
                    const newCpu = Math.max(0, Math.min(100, proc.cpu + jitter));
                    processes.set(pid, { ...proc, cpu: newCpu });
                }
            }
        },

        detectAnomalies(): readonly ProcessAnomaly[] {
            const anomalies: ProcessAnomaly[] = [];

            for (const [, proc] of processes) {
                // Check for orphaned processes (ppid doesn't exist, not init)
                if (proc.ppid !== 0 && !processes.has(proc.ppid)) {
                    anomalies.push({
                        type: 'orphan',
                        pid: proc.pid,
                        description: `Process ${proc.name} (PID ${proc.pid}) is orphaned — parent PID ${proc.ppid} does not exist`,
                        severity: 'info',
                    });
                }

                // Check for suspicious lineage
                const parent = processes.get(proc.ppid);
                if (parent !== undefined) {
                    for (const rule of SUSPICIOUS_LINEAGE) {
                        if (parent.name === rule.parent && proc.name === rule.child) {
                            anomalies.push({
                                type: 'suspicious-parent',
                                pid: proc.pid,
                                description: `${rule.child} (PID ${proc.pid}) spawned from ${rule.parent} (PID ${parent.pid}) — possible web shell or RCE`,
                                severity: rule.severity,
                            });
                        }
                    }
                }

                // Check for privilege escalation (non-root parent → root child)
                if (parent !== undefined && parent.user !== 'root' && proc.user === 'root') {
                    anomalies.push({
                        type: 'privilege-escalation',
                        pid: proc.pid,
                        description: `Process ${proc.name} (PID ${proc.pid}) running as root, spawned from ${parent.name} running as ${parent.user}`,
                        severity: 'critical',
                    });
                }
            }

            return Object.freeze(anomalies);
        },
    };
}

/**
 * Bootstrap a realistic Linux process tree for a machine.
 * Creates init, kernel threads, systemd services, etc.
 */
export function bootstrapLinuxProcessTree(
    machineId: string,
    services: readonly string[],
): ProcessTree {
    const tree = createProcessTree(machineId);

    // Kernel threads
    tree.spawn({ name: 'kthreadd', command: '[kthreadd]', user: 'root', ppid: 1, cpu: 0, memKB: 0 });
    tree.spawn({ name: 'rcu_gp', command: '[rcu_gp]', user: 'root', ppid: 2, cpu: 0, memKB: 0 });
    tree.spawn({ name: 'kworker/0:0', command: '[kworker/0:0-events]', user: 'root', ppid: 2, cpu: 0.1, memKB: 0 });

    // System daemons
    const systemdPid = tree.spawn({ name: 'systemd', command: '/lib/systemd/systemd', args: '--system', user: 'root', ppid: 1, cpu: 0.1, memKB: 4096 });
    tree.spawn({ name: 'systemd-journal', command: '/lib/systemd/systemd-journald', user: 'root', ppid: systemdPid, cpu: 0, memKB: 2048 });
    tree.spawn({ name: 'systemd-udevd', command: '/lib/systemd/systemd-udevd', user: 'root', ppid: systemdPid, cpu: 0, memKB: 1024 });

    // Login and getty
    tree.spawn({ name: 'agetty', command: '/sbin/agetty', args: '-o -p -- \\u --noclear tty1 linux', user: 'root', ppid: systemdPid, tty: 'tty1', cpu: 0, memKB: 256 });

    // SSH daemon
    if (services.includes('ssh') || services.includes('sshd')) {
        tree.spawn({
            name: 'sshd',
            command: '/usr/sbin/sshd',
            args: '-D',
            user: 'root',
            ppid: systemdPid,
            cpu: 0,
            memKB: 2048,
            connections: [{ protocol: 'tcp', localAddr: '0.0.0.0', localPort: 22, remoteAddr: '0.0.0.0', remotePort: 0, state: 'LISTEN' }],
        });
    }

    // Web server
    if (services.includes('http') || services.includes('nginx') || services.includes('apache2')) {
        const webPid = tree.spawn({
            name: 'nginx',
            command: 'nginx',
            args: '-g daemon off;',
            user: 'root',
            ppid: systemdPid,
            cpu: 0.2,
            memKB: 4096,
            connections: [{ protocol: 'tcp', localAddr: '0.0.0.0', localPort: 80, remoteAddr: '0.0.0.0', remotePort: 0, state: 'LISTEN' }],
        });
        // Worker processes
        tree.spawn({ name: 'nginx', command: 'nginx', args: 'worker process', user: 'www-data', ppid: webPid, cpu: 0.1, memKB: 2048 });
        tree.spawn({ name: 'nginx', command: 'nginx', args: 'worker process', user: 'www-data', ppid: webPid, cpu: 0.1, memKB: 2048 });
    }

    // Database
    if (services.includes('mysql') || services.includes('mariadb')) {
        tree.spawn({
            name: 'mysqld',
            command: '/usr/sbin/mysqld',
            args: '--basedir=/usr --datadir=/var/lib/mysql',
            user: 'mysql',
            ppid: systemdPid,
            cpu: 0.5,
            memKB: 32768,
            connections: [{ protocol: 'tcp', localAddr: '0.0.0.0', localPort: 3306, remoteAddr: '0.0.0.0', remotePort: 0, state: 'LISTEN' }],
        });
    }

    // Mail
    if (services.includes('smtp') || services.includes('postfix')) {
        const masterPid = tree.spawn({
            name: 'master',
            command: '/usr/lib/postfix/sbin/master',
            args: '-w',
            user: 'root',
            ppid: systemdPid,
            cpu: 0,
            memKB: 2048,
            connections: [{ protocol: 'tcp', localAddr: '0.0.0.0', localPort: 25, remoteAddr: '0.0.0.0', remotePort: 0, state: 'LISTEN' }],
        });
        tree.spawn({ name: 'qmgr', command: 'qmgr', args: '-l -t unix -u', user: 'postfix', ppid: masterPid, cpu: 0, memKB: 1024 });
        tree.spawn({ name: 'pickup', command: 'pickup', args: '-l -t unix -u', user: 'postfix', ppid: masterPid, cpu: 0, memKB: 1024 });
    }

    // DNS
    if (services.includes('dns') || services.includes('named') || services.includes('bind')) {
        tree.spawn({
            name: 'named',
            command: '/usr/sbin/named',
            args: '-u bind',
            user: 'bind',
            ppid: systemdPid,
            cpu: 0.1,
            memKB: 8192,
            connections: [
                { protocol: 'tcp', localAddr: '0.0.0.0', localPort: 53, remoteAddr: '0.0.0.0', remotePort: 0, state: 'LISTEN' },
                { protocol: 'udp', localAddr: '0.0.0.0', localPort: 53, remoteAddr: '0.0.0.0', remotePort: 0, state: 'LISTEN' },
            ],
        });
    }

    // Cron
    tree.spawn({ name: 'cron', command: '/usr/sbin/cron', args: '-f', user: 'root', ppid: systemdPid, cpu: 0, memKB: 512 });

    // Logging
    tree.spawn({ name: 'rsyslogd', command: '/usr/sbin/rsyslogd', args: '-n', user: 'syslog', ppid: systemdPid, cpu: 0, memKB: 1024 });

    return tree;
}
