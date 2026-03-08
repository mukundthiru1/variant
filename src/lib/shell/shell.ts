/**
 * VARIANT — Scripted Shell Implementation
 *
 * POSIX-like shell backed by a VirtualFilesystem.
 * Processes commands (ls, cat, cd, pwd, echo, grep, etc.)
 * against the VFS, producing text output.
 *
 * SECURITY:
 *   - No host code execution
 *   - No real filesystem access
 *   - No network access
 *   - Commands are pure functions against VFS state
 *
 * REPLACEABILITY: Implements ScriptedShell interface.
 * Swap this file. Nothing else changes.
 */


import type {
    ScriptedShell,
    ShellResult,
    ShellConfig,
    CommandHandler,
    CommandContext,
} from './types';

// ── Factory ────────────────────────────────────────────────────

export function createShell(config: ShellConfig): ScriptedShell {
    const vfs = config.vfs;
    let cwd = config.cwd ?? (config.user === 'root' || config.user === undefined ? '/root' : `/home/${config.user}`);
    let user = config.user ?? 'root';
    let hostname = config.hostname ?? 'localhost';
    const env = new Map<string, string>(config.env ?? []);
    const commands = new Map<string, CommandHandler>();
    const services = config.services ?? [];
    const users = config.users ?? [];
    const emit = config.emit;
    const resolveRemoteServices = config.resolveRemoteServices;
    const resolveRemoteHostname = config.resolveRemoteHostname;

    // Ensure cwd exists
    if (!vfs.exists(cwd)) {
        vfs.mkdir(cwd, { recursive: true, owner: user });
    }

    // Set default env
    if (!env.has('HOME')) env.set('HOME', cwd);
    if (!env.has('USER')) env.set('USER', user);
    if (!env.has('SHELL')) env.set('SHELL', '/bin/sh');
    if (!env.has('PATH')) env.set('PATH', '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin');

    // ── Path resolution ───────────────────────────────────────

    function resolvePath(path: string): string {
        if (path.startsWith('/')) return path;
        if (path === '~') return env.get('HOME') ?? '/root';
        if (path.startsWith('~/')) return (env.get('HOME') ?? '/root') + path.slice(1);
        return cwd === '/' ? `/${path}` : `${cwd}/${path}`;
    }

    // ── Command context ───────────────────────────────────────

    function makeContext(): CommandContext {
        const ctx: CommandContext = {
            vfs,
            cwd,
            user,
            hostname,
            env,
            resolvePath,
            services,
            users,
        };
        if (emit) ctx.emit = emit;
        if (resolveRemoteServices) ctx.resolveRemoteServices = resolveRemoteServices;
        if (resolveRemoteHostname) ctx.resolveRemoteHostname = resolveRemoteHostname;
        return ctx;
    }

    // ── Limits (DoS prevention) ─────────────────────────────────

    const MAX_COMMAND_LENGTH = 64 * 1024;
    const MAX_ARGS = 1000;
    const MAX_ENV_KEY = 256;
    const MAX_ENV_VALUE = 4096;
    const MAX_ENV_VARS = 500;

    // ── Argument parser (basic) ───────────────────────────────

    function parseArgs(line: string): string[] {
        const args: string[] = [];
        let current = '';
        let inSingle = false;
        let inDouble = false;
        let escaped = false;

        for (const ch of line) {
            if (escaped) {
                current += ch;
                escaped = false;
                continue;
            }
            if (ch === '\\' && !inSingle) {
                escaped = true;
                continue;
            }
            if (ch === "'" && !inDouble) {
                inSingle = !inSingle;
                continue;
            }
            if (ch === '"' && !inSingle) {
                inDouble = !inDouble;
                continue;
            }
            if (ch === ' ' && !inSingle && !inDouble) {
                if (current.length > 0) {
                    args.push(current);
                    current = '';
                }
                continue;
            }
            current += ch;
        }
        if (current.length > 0) args.push(current);
        return args;
    }

    // ── Built-in commands ─────────────────────────────────────

    function registerBuiltins(): void {
        commands.set('ls', builtinLs);
        commands.set('cat', builtinCat);
        commands.set('cd', builtinCd);
        commands.set('pwd', builtinPwd);
        commands.set('echo', builtinEcho);
        commands.set('whoami', builtinWhoami);
        commands.set('hostname', builtinHostname);
        commands.set('id', builtinId);
        commands.set('uname', builtinUname);
        commands.set('env', builtinEnv);
        commands.set('export', builtinExport);
        commands.set('mkdir', builtinMkdir);
        commands.set('rm', builtinRm);
        commands.set('touch', builtinTouch);
        commands.set('head', builtinHead);
        commands.set('tail', builtinTail);
        commands.set('wc', builtinWc);
        commands.set('grep', builtinGrep);
        commands.set('find', builtinFind);
        commands.set('chmod', builtinChmod);
        commands.set('chown', builtinChown);
        commands.set('cp', builtinCp);
        commands.set('mv', builtinMv);
        commands.set('file', builtinFile);
        commands.set('which', builtinWhich);
        commands.set('true', () => ({ output: '', exitCode: 0 }));
        commands.set('false', () => ({ output: '', exitCode: 1 }));
        commands.set('clear', () => ({ output: '\x1b[2J\x1b[H', exitCode: 0 }));
        commands.set('ps', builtinPs);
        commands.set('netstat', builtinNetstat);
        commands.set('ifconfig', builtinIfconfig);
        commands.set('ip', builtinIp);
        // Security-critical commands for pentesters
        commands.set('ss', builtinSs);
        commands.set('curl', builtinCurl);
        commands.set('wget', builtinWget);
        commands.set('nmap', builtinNmap);
        commands.set('awk', builtinAwk);
        commands.set('sed', builtinSed);
        commands.set('sort', builtinSort);
        commands.set('uniq', builtinUniq);
        commands.set('cut', builtinCut);
        commands.set('base64', builtinBase64);
        commands.set('xxd', builtinXxd);
        commands.set('strings', builtinStrings);
        commands.set('dig', builtinDig);
        commands.set('ping', builtinPing);
        commands.set('ssh', builtinSsh);
        commands.set('sudo', builtinSudo);
        commands.set('su', builtinSu);
        commands.set('tee', builtinTee);
        commands.set('tr', builtinTr);
        commands.set('xargs', builtinXargs);
        commands.set('rev', builtinRev);
        commands.set('nl', builtinNl);
        commands.set('tac', builtinTac);
        commands.set('test', builtinTest);
        commands.set('[', builtinTest);
        commands.set('nc', builtinNc);
        commands.set('netcat', builtinNc);
        commands.set('mysql', builtinMysql);
        commands.set('history', builtinHistory);
        commands.set('date', builtinDate);
        commands.set('uptime', builtinUptime);
        commands.set('w', builtinW);
        commands.set('last', builtinLast);
        commands.set('dmesg', builtinDmesg);
        commands.set('free', builtinFree);
        commands.set('df', builtinDf);
        commands.set('du', builtinDu);
        commands.set('mount', builtinMount);
        commands.set('stat', builtinStat);
        commands.set('ln', builtinLn);
        commands.set('readlink', builtinReadlink);
        commands.set('realpath', builtinRealpath);
        commands.set('basename', builtinBasename);
        commands.set('dirname', builtinDirname);
        commands.set('sleep', () => ({ output: '', exitCode: 0 }));
        commands.set('wait', () => ({ output: '', exitCode: 0 }));
        commands.set('yes', () => ({ output: 'y\ny\ny\ny\ny\n', exitCode: 0 }));
        commands.set('openssl', builtinOpenssl);
        commands.set('sha256sum', builtinSha256sum);
        commands.set('md5sum', builtinMd5sum);
        commands.set('crontab', builtinCrontab);
        commands.set('service', builtinService);
        commands.set('systemctl', builtinSystemctl);
    }

    // ── Built-in implementations ──────────────────────────────

    const builtinLs: CommandHandler = (args, ctx) => {
        const showAll = args.includes('-a') || args.includes('-la') || args.includes('-al');
        const longFormat = args.includes('-l') || args.includes('-la') || args.includes('-al');
        const target = args.find(a => !a.startsWith('-')) ?? ctx.cwd;
        const resolved = ctx.resolvePath(target);

        const node = ctx.vfs.stat(resolved);
        if (node === null) return { output: `ls: ${target}: No such file or directory\n`, exitCode: 1 };

        if (node.type === 'file') {
            if (longFormat) {
                return { output: formatLsEntry(target.split('/').pop() ?? target, node) + '\n', exitCode: 0 };
            }
            return { output: (target.split('/').pop() ?? target) + '\n', exitCode: 0 };
        }

        if (node.type !== 'dir') return { output: '', exitCode: 0 };

        const entries = ctx.vfs.readDir(resolved) ?? [];
        const filtered = showAll ? entries : entries.filter(e => !e.startsWith('.'));

        if (longFormat) {
            const lines: string[] = [];
            for (const name of filtered) {
                const childPath = resolved === '/' ? `/${name}` : `${resolved}/${name}`;
                const child = ctx.vfs.stat(childPath);
                if (child !== null) {
                    lines.push(formatLsEntry(name, child));
                }
            }
            return { output: lines.join('\n') + (lines.length > 0 ? '\n' : ''), exitCode: 0 };
        }

        return { output: filtered.join('  ') + (filtered.length > 0 ? '\n' : ''), exitCode: 0 };
    };

    function formatLsEntry(name: string, node: { type: string; mode?: number; owner?: string; group?: string }): string {
        const typeChar = node.type === 'dir' ? 'd' : node.type === 'symlink' ? 'l' : '-';
        const mode = node.mode ?? 0o644;
        const perms = formatPerms(mode);
        const owner = node.owner ?? 'root';
        const group = node.group ?? 'root';
        return `${typeChar}${perms} ${owner} ${group} ${name}`;
    }

    function formatPerms(mode: number): string {
        const r = (m: number) => (m & 4) !== 0 ? 'r' : '-';
        const w = (m: number) => (m & 2) !== 0 ? 'w' : '-';
        const x = (m: number) => (m & 1) !== 0 ? 'x' : '-';
        const u = (mode >> 6) & 7;
        const g = (mode >> 3) & 7;
        const o = mode & 7;
        return `${r(u)}${w(u)}${x(u)}${r(g)}${w(g)}${x(g)}${r(o)}${w(o)}${x(o)}`;
    }

    const builtinCat: CommandHandler = (args, ctx, stdin) => {
        if (args.length === 0) {
            // cat with no args reads from stdin (pipe support)
            if (stdin !== undefined && stdin.length > 0) return { output: stdin, exitCode: 0 };
            return { output: '', exitCode: 0 };
        }
        const parts: string[] = [];
        for (const arg of args) {
            if (arg.startsWith('-')) continue;
            const resolved = ctx.resolvePath(arg);
            const content = ctx.vfs.readFile(resolved);
            if (content === null) {
                return { output: `cat: ${arg}: No such file or directory\n`, exitCode: 1 };
            }
            parts.push(content);
        }
        const result = parts.join('');
        return { output: result.endsWith('\n') ? result : result + '\n', exitCode: 0 };
    };

    const builtinCd: CommandHandler = (args, ctx) => {
        const target = args[0] ?? ctx.env.get('HOME') ?? '/';
        const resolved = ctx.resolvePath(target);

        const node = ctx.vfs.stat(resolved);
        if (node === null) return { output: `cd: ${target}: No such file or directory\n`, exitCode: 1 };
        if (node.type !== 'dir') return { output: `cd: ${target}: Not a directory\n`, exitCode: 1 };

        cwd = resolved.replace(/\/+$/, '') || '/';
        return { output: '', exitCode: 0 };
    };

    const builtinPwd: CommandHandler = () => {
        return { output: cwd + '\n', exitCode: 0 };
    };

    const builtinEcho: CommandHandler = (args, ctx) => {
        // Handle env var substitution
        const expanded = args.map(a => {
            return a.replace(/\$(\w+)/g, (_, name: string) => ctx.env.get(name) ?? '');
        });
        return { output: expanded.join(' ') + '\n', exitCode: 0 };
    };

    const builtinWhoami: CommandHandler = () => {
        return { output: user + '\n', exitCode: 0 };
    };

    const builtinHostname: CommandHandler = () => {
        return { output: hostname + '\n', exitCode: 0 };
    };

    const builtinId: CommandHandler = () => {
        const uid = user === 'root' ? 0 : 1000;
        const gid = uid;
        return { output: `uid=${uid}(${user}) gid=${gid}(${user}) groups=${gid}(${user})\n`, exitCode: 0 };
    };

    const builtinUname: CommandHandler = (args) => {
        if (args.includes('-a')) {
            return { output: 'Linux ' + hostname + ' 5.15.0-variant #1 SMP x86_64 GNU/Linux\n', exitCode: 0 };
        }
        return { output: 'Linux\n', exitCode: 0 };
    };

    const builtinEnv: CommandHandler = (_args, ctx) => {
        const lines: string[] = [];
        for (const [k, v] of ctx.env) {
            lines.push(`${k}=${v}`);
        }
        return { output: lines.join('\n') + '\n', exitCode: 0 };
    };

    const builtinExport: CommandHandler = (args) => {
        for (const arg of args) {
            const eq = arg.indexOf('=');
            if (eq <= 0) continue;
            const key = arg.slice(0, eq);
            const value = arg.slice(eq + 1);
            if (key.length > MAX_ENV_KEY || value.length > MAX_ENV_VALUE) continue;
            if (!env.has(key) && env.size >= MAX_ENV_VARS) continue;
            env.set(key, value);
        }
        return { output: '', exitCode: 0 };
    };

    const builtinMkdir: CommandHandler = (args, ctx) => {
        const recursive = args.includes('-p');
        const dirs = args.filter(a => !a.startsWith('-'));
        for (const dir of dirs) {
            const resolved = ctx.resolvePath(dir);
            try {
                ctx.vfs.mkdir(resolved, { recursive, owner: ctx.user });
            } catch {
                return { output: `mkdir: cannot create directory '${dir}'\n`, exitCode: 1 };
            }
        }
        return { output: '', exitCode: 0 };
    };

    const builtinRm: CommandHandler = (args, ctx) => {
        const files = args.filter(a => !a.startsWith('-'));
        for (const file of files) {
            const resolved = ctx.resolvePath(file);
            if (!ctx.vfs.remove(resolved)) {
                return { output: `rm: ${file}: No such file or directory\n`, exitCode: 1 };
            }
        }
        return { output: '', exitCode: 0 };
    };

    const builtinTouch: CommandHandler = (args, ctx) => {
        const files = args.filter(a => !a.startsWith('-'));
        for (const file of files) {
            const resolved = ctx.resolvePath(file);
            if (!ctx.vfs.exists(resolved)) {
                ctx.vfs.writeFile(resolved, '', { owner: ctx.user });
            }
        }
        return { output: '', exitCode: 0 };
    };

    const MAX_HEAD_TAIL_LINES = 10_000;
    const builtinHead: CommandHandler = (args, ctx, stdin) => {
        let lines = 10;
        const nIdx = args.indexOf('-n');
        if (nIdx >= 0 && args[nIdx + 1] !== undefined) {
            const n = parseInt(args[nIdx + 1]!, 10);
            lines = Number.isFinite(n) && n > 0 ? Math.min(n, MAX_HEAD_TAIL_LINES) : 10;
        }
        const file = args.find(a => !a.startsWith('-') && (nIdx < 0 || a !== args[nIdx + 1]));
        let content: string;
        if (file !== undefined) {
            const resolved = ctx.resolvePath(file);
            const fc = ctx.vfs.readFile(resolved);
            if (fc === null) return { output: `head: ${file}: No such file or directory\n`, exitCode: 1 };
            content = fc;
        } else if (stdin !== undefined && stdin.length > 0) {
            content = stdin;
        } else {
            return { output: '', exitCode: 0 };
        }

        const result = content.split('\n').slice(0, lines).join('\n');
        return { output: result + '\n', exitCode: 0 };
    };

    const builtinTail: CommandHandler = (args, ctx, stdin) => {
        let lines = 10;
        const nIdx = args.indexOf('-n');
        if (nIdx >= 0 && args[nIdx + 1] !== undefined) {
            const n = parseInt(args[nIdx + 1]!, 10);
            lines = Number.isFinite(n) && n > 0 ? Math.min(n, MAX_HEAD_TAIL_LINES) : 10;
        }
        const file = args.find(a => !a.startsWith('-') && (nIdx < 0 || a !== args[nIdx + 1]));
        let content: string;
        if (file !== undefined) {
            const resolved = ctx.resolvePath(file);
            const fc = ctx.vfs.readFile(resolved);
            if (fc === null) return { output: `tail: ${file}: No such file or directory\n`, exitCode: 1 };
            content = fc;
        } else if (stdin !== undefined && stdin.length > 0) {
            content = stdin;
        } else {
            return { output: '', exitCode: 0 };
        }

        const allLines = content.split('\n');
        const result = allLines.slice(-lines).join('\n');
        return { output: result + '\n', exitCode: 0 };
    };

    const builtinWc: CommandHandler = (args, ctx, stdin) => {
        const file = args.find(a => !a.startsWith('-'));
        let content: string;
        if (file !== undefined) {
            const resolved = ctx.resolvePath(file);
            const fc = ctx.vfs.readFile(resolved);
            if (fc === null) return { output: `wc: ${file}: No such file or directory\n`, exitCode: 1 };
            content = fc;
        } else if (stdin !== undefined && stdin.length > 0) {
            content = stdin;
        } else {
            return { output: '  0  0 0\n', exitCode: 0 };
        }

        const lineCount = content.split('\n').length;
        const words = content.split(/\s+/).filter(w => w.length > 0).length;
        const bytes = new TextEncoder().encode(content).byteLength;
        const label = file ?? '';
        return { output: `  ${lineCount}  ${words} ${bytes} ${label}\n`.trimEnd() + '\n', exitCode: 0 };
    };

    const builtinGrep: CommandHandler = (args, ctx, stdin) => {
        const caseInsensitive = args.includes('-i');
        const invertMatch = args.includes('-v');
        const showLineNumbers = args.includes('-n');
        const countOnly = args.includes('-c');
        const cleanArgs = args.filter(a => !a.startsWith('-'));
        if (cleanArgs.length < 1) return { output: 'Usage: grep PATTERN [FILE]\n', exitCode: 2 };

        const pattern = cleanArgs[0]!;
        let content: string;
        if (cleanArgs.length >= 2) {
            const file = cleanArgs[1]!;
            const resolved = ctx.resolvePath(file);
            const fileContent = ctx.vfs.readFile(resolved);
            if (fileContent === null) return { output: `grep: ${file}: No such file or directory\n`, exitCode: 2 };
            content = fileContent;
        } else if (stdin !== undefined && stdin.length > 0) {
            content = stdin;
        } else {
            return { output: 'Usage: grep PATTERN [FILE]\n', exitCode: 2 };
        }

        // SECURITY: Use literal substring match only. User-controlled RegExp causes ReDoS.
        const search = caseInsensitive ? pattern.toLowerCase() : pattern;
        const lines = content.split('\n');
        const matches: string[] = [];
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i]!;
            const haystack = caseInsensitive ? line.toLowerCase() : line;
            const found = haystack.includes(search);
            if (invertMatch ? !found : found) {
                matches.push(showLineNumbers ? `${i + 1}:${line}` : line);
            }
        }

        if (countOnly) return { output: `${matches.length}\n`, exitCode: matches.length === 0 ? 1 : 0 };
        if (matches.length === 0) return { output: '', exitCode: 1 };
        return { output: matches.join('\n') + '\n', exitCode: 0 };
    };

    const builtinFind: CommandHandler = (args, ctx) => {
        const target = args[0] ?? ctx.cwd;
        const resolved = ctx.resolvePath(target);
        const nameIdx = args.indexOf('-name');
        const pattern = nameIdx >= 0 ? args[nameIdx + 1] : undefined;

        const results: string[] = [];
        function walk(path: string): void {
            const entries = ctx.vfs.readDir(path);
            if (entries === null) return;
            for (const entry of entries) {
                const full = path === '/' ? `/${entry}` : `${path}/${entry}`;
                if (pattern === undefined || matchSimple(entry, pattern)) {
                    results.push(full);
                }
                const node = ctx.vfs.stat(full);
                if (node !== null && node.type === 'dir') {
                    walk(full);
                }
            }
        }
        walk(resolved);
        return { output: results.join('\n') + (results.length > 0 ? '\n' : ''), exitCode: 0 };
    };

    const MAX_FIND_PATTERN_LENGTH = 256;
    const MAX_FIND_WILDCARDS = 10;

    function matchSimple(name: string, pattern: string): boolean {
        if (pattern.length > MAX_FIND_PATTERN_LENGTH) return false;
        const wildcards = (pattern.match(/\*/g) ?? []).length;
        if (wildcards > MAX_FIND_WILDCARDS) return false;
        const regex = pattern
            .replace(/[.+^${}()|[\]\\]/g, '\\$&')
            .replace(/\*/g, '.*')
            .replace(/\?/g, '.');
        return new RegExp(`^${regex}$`).test(name);
    }

    const builtinChmod: CommandHandler = (args, ctx) => {
        if (args.length < 2) return { output: 'Usage: chmod MODE FILE\n', exitCode: 1 };
        const modeStr = args[0]!;
        const file = args[1]!;
        const mode = parseInt(modeStr, 8);
        if (!Number.isFinite(mode) || mode < 0) return { output: `chmod: invalid mode: '${modeStr}'\n`, exitCode: 1 };
        const clampedMode = Math.min(0o7777, Math.max(0, mode));
        const resolved = ctx.resolvePath(file);
        try {
            ctx.vfs.chmod(resolved, clampedMode);
        } catch {
            return { output: `chmod: ${file}: No such file or directory\n`, exitCode: 1 };
        }
        return { output: '', exitCode: 0 };
    };

    const builtinChown: CommandHandler = (args, ctx) => {
        if (args.length < 2) return { output: 'Usage: chown OWNER[:GROUP] FILE\n', exitCode: 1 };
        const ownerSpec = args[0]!;
        const file = args[1]!;
        const [owner, group] = ownerSpec.split(':');
        const resolved = ctx.resolvePath(file);
        try {
            ctx.vfs.chown(resolved, owner!, group);
        } catch {
            return { output: `chown: ${file}: No such file or directory\n`, exitCode: 1 };
        }
        return { output: '', exitCode: 0 };
    };

    const builtinCp: CommandHandler = (args, ctx) => {
        const cleanArgs = args.filter(a => !a.startsWith('-'));
        if (cleanArgs.length < 2) return { output: 'Usage: cp SOURCE DEST\n', exitCode: 1 };
        const src = ctx.resolvePath(cleanArgs[0]!);
        const dest = ctx.resolvePath(cleanArgs[1]!);
        const content = ctx.vfs.readFile(src);
        if (content === null) return { output: `cp: ${cleanArgs[0]}: No such file or directory\n`, exitCode: 1 };
        ctx.vfs.writeFile(dest, content);
        return { output: '', exitCode: 0 };
    };

    const builtinMv: CommandHandler = (args, ctx) => {
        const cleanArgs = args.filter(a => !a.startsWith('-'));
        if (cleanArgs.length < 2) return { output: 'Usage: mv SOURCE DEST\n', exitCode: 1 };
        const src = ctx.resolvePath(cleanArgs[0]!);
        const dest = ctx.resolvePath(cleanArgs[1]!);
        const content = ctx.vfs.readFile(src);
        if (content === null) return { output: `mv: ${cleanArgs[0]}: No such file or directory\n`, exitCode: 1 };
        ctx.vfs.writeFile(dest, content);
        ctx.vfs.remove(src);
        return { output: '', exitCode: 0 };
    };

    const builtinFile: CommandHandler = (args, ctx) => {
        const file = args.find(a => !a.startsWith('-'));
        if (file === undefined) return { output: 'Usage: file FILE\n', exitCode: 1 };
        const resolved = ctx.resolvePath(file);
        const node = ctx.vfs.stat(resolved);
        if (node === null) return { output: `${file}: cannot open\n`, exitCode: 1 };
        if (node.type === 'dir') return { output: `${file}: directory\n`, exitCode: 0 };
        if (node.type === 'symlink') return { output: `${file}: symbolic link\n`, exitCode: 0 };
        if (node.type === 'file') {
            if (node.content.startsWith('#!')) return { output: `${file}: script, ASCII text executable\n`, exitCode: 0 };
            if (node.content.startsWith('{')) return { output: `${file}: JSON data\n`, exitCode: 0 };
            if (node.content.startsWith('<')) return { output: `${file}: HTML document, ASCII text\n`, exitCode: 0 };
            return { output: `${file}: ASCII text\n`, exitCode: 0 };
        }
        return { output: `${file}: data\n`, exitCode: 0 };
    };

    const builtinWhich: CommandHandler = (args) => {
        if (args.length === 0) return { output: '', exitCode: 1 };
        const cmd = args[0]!;
        if (commands.has(cmd)) {
            return { output: `/usr/bin/${cmd}\n`, exitCode: 0 };
        }
        return { output: `which: no ${cmd} in (${env.get('PATH') ?? ''})\n`, exitCode: 1 };
    };

    const builtinPs: CommandHandler = () => {
        return {
            output: 'PID   USER     TIME  COMMAND\n    1 root      0:00 init\n    2 root      0:00 [kthreadd]\n',
            exitCode: 0,
        };
    };

    const builtinNetstat: CommandHandler = (args) => {
        if (args.includes('-tlnp') || args.includes('-tulnp')) {
            return {
                output: 'Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n',
                exitCode: 0,
            };
        }
        return { output: 'Active Internet connections (w/o servers)\n', exitCode: 0 };
    };

    const builtinIfconfig: CommandHandler = () => {
        return {
            output: 'eth0      Link encap:Ethernet  HWaddr 00:00:00:00:00:00\n          inet addr:10.0.0.2  Bcast:10.0.0.255  Mask:255.255.255.0\n          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n\nlo        Link encap:Local Loopback\n          inet addr:127.0.0.1  Mask:255.0.0.0\n          UP LOOPBACK RUNNING  MTU:65536  Metric:1\n',
            exitCode: 0,
        };
    };

    const builtinIp: CommandHandler = (args) => {
        if (args[0] === 'addr' || args[0] === 'a') {
            return {
                output: '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 10.0.0.2/24 scope global eth0\n',
                exitCode: 0,
            };
        }
        if (args[0] === 'route' || args[0] === 'r') {
            return {
                output: 'default via 10.0.0.1 dev eth0\n10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.2\n',
                exitCode: 0,
            };
        }
        return { output: 'Usage: ip [addr|route]\n', exitCode: 0 };
    };

    // ── Security-critical commands for pentesters ─────────────

    // ss - socket statistics
    const builtinSs: CommandHandler = (args, ctx) => {
        const showListening = args.some(a => a.includes('l') || a === '-a');
        const showTcp = args.some(a => a.includes('t'));
        const showUdp = args.some(a => a.includes('u'));
        const showAll = !showTcp && !showUdp;

        const lines: string[] = [];
        if (showListening) {
            lines.push('State    Recv-Q   Send-Q     Local Address:Port      Peer Address:Port   Process');
        } else {
            lines.push('State    Recv-Q   Send-Q     Local Address:Port      Peer Address:Port');
        }

        // Read from machine's ServiceConfig
        const svcs = ctx.services ?? [];
        for (const svc of svcs) {
            for (const port of svc.ports) {
                // Determine if we should show this entry based on protocol filter
                let shouldShow = showAll;
                if (!shouldShow) {
                    if (showTcp) shouldShow = true;
                    if (showUdp) shouldShow = true;
                }
                if (shouldShow && showListening) {
                    lines.push(`LISTEN   0        128              0.0.0.0:${port}           0.0.0.0:*       ${svc.name}`);
                }
            }
        }

        // Always show at least some default connections if no services configured
        if (lines.length === 1 && svcs.length === 0) {
            lines.push('ESTAB    0        0               10.0.0.2:22            10.0.0.1:54321');
        }

        return { output: lines.join('\n') + '\n', exitCode: 0 };
    };

    // curl - HTTP client
    const builtinCurl: CommandHandler = (args, ctx) => {
        const silent = args.includes('-s') || args.includes('--silent');
        const outputIdx = args.indexOf('-o');
        const outputFile = outputIdx >= 0 ? args[outputIdx + 1] : undefined;
        const methodIdx = args.findIndex(a => a === '-X' || a === '--request');
        const method = methodIdx >= 0 ? (args[methodIdx + 1] ?? 'GET') : 'GET';

        // Parse headers
        const headers: Record<string, string> = {};
        for (let i = 0; i < args.length; i++) {
            if ((args[i] === '-H' || args[i] === '--header') && args[i + 1]) {
                const header = args[i + 1]!;
                const colonIdx = header.indexOf(':');
                if (colonIdx > 0) {
                    headers[header.slice(0, colonIdx).trim()] = header.slice(colonIdx + 1).trim();
                }
            }
        }

        // Find URL (first non-flag arg that doesn't follow a flag requiring value)
        const flagWithValue = new Set(['-o', '-X', '-H', '--header', '--request', '--output']);
        let url: string | undefined;
        for (let i = 0; i < args.length; i++) {
            if (!args[i]!.startsWith('-') && (i === 0 || !flagWithValue.has(args[i - 1]!))) {
                url = args[i];
                break;
            }
        }

        if (!url) {
            return { output: 'curl: no URL specified\n', exitCode: 2 };
        }

        // Emit net:request event
        ctx.emit?.({
            type: 'net:request',
            method,
            url,
            source: ctx.hostname,
            destination: url.replace(/^https?:\/\//, '').split('/')[0] ?? 'unknown',
            timestamp: Date.now(),
        });

        // Simulate response
        const isHtml = url.endsWith('.html') || !url.includes('.');
        const isJson = url.includes('.json') || url.includes('/api/');

        let body = '';
        if (isJson) {
            body = '{"status":"ok","data":[]}\n';
        } else if (isHtml) {
            body = '<html><body><h1>Welcome</h1></body></html>\n';
        } else {
            body = 'OK\n';
        }

        if (!silent) {
            const output = method === 'HEAD' ? '' : body;
            if (outputFile) {
                const resolved = ctx.resolvePath(outputFile);
                ctx.vfs.writeFile(resolved, output, { owner: ctx.user });
                return { output: '', exitCode: 0 };
            }
            return { output, exitCode: 0 };
        }

        if (outputFile) {
            const resolved = ctx.resolvePath(outputFile);
            ctx.vfs.writeFile(resolved, body, { owner: ctx.user });
        }
        return { output: '', exitCode: 0 };
    };

    // wget - HTTP download
    const builtinWget: CommandHandler = (args, ctx) => {
        const outputIdx = args.findIndex(a => a === '-O' || a === '--output-document');
        const outputFile = outputIdx >= 0 ? args[outputIdx + 1] : undefined;

        // Find URL
        const url = args.find(a => !a.startsWith('-') && (outputIdx < 0 || a !== args[outputIdx + 1]));
        if (!url) {
            return { output: 'wget: missing URL\n', exitCode: 1 };
        }

        // Emit net:request event
        ctx.emit?.({
            type: 'net:request',
            method: 'GET',
            url,
            source: ctx.hostname,
            destination: url.replace(/^https?:\/\//, '').split('/')[0] ?? 'unknown',
            timestamp: Date.now(),
        });

        const filename = outputFile ?? url.split('/').pop() ?? 'index.html';
        const resolved = ctx.resolvePath(filename);

        const content = `<html><title>Downloaded</title><body>Downloaded from ${url}</body></html>\n`;
        ctx.vfs.writeFile(resolved, content, { owner: ctx.user });

        return { output: `--${Date.now()}--  ${url}\nResolving... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: unspecified\nSaving to: '${filename}'\n\n${content.length} bytes saved\n`, exitCode: 0 };
    };

    // nmap - port scanner (context-aware: queries target machine's real services)
    const builtinNmap: CommandHandler = (args, ctx) => {
        const verbose = args.includes('-v') || args.includes('-sV');
        const scanSyn = args.includes('-sS');
        const scanUDP = args.includes('-sU');
        const osDetect = args.includes('-O');
        const host = args.find(a => !a.startsWith('-'));
        if (!host) {
            return { output: 'Nmap scan report for localhost\nHost is up (0.0001s latency).\nAll 1000 scanned ports on localhost are closed\n', exitCode: 0 };
        }

        // Resolve target: if scanning self, use local services; otherwise query remote
        // Falls back to local services if no remote resolver is configured
        const isLocalhost = host === 'localhost' || host === '127.0.0.1' || host === ctx.hostname;
        const remoteSvcs = ctx.resolveRemoteServices?.(host);
        const targetSvcs = isLocalhost
            ? (ctx.services ?? [])
            : (remoteSvcs ?? ctx.services ?? []);
        const targetHostname = isLocalhost
            ? ctx.hostname
            : (ctx.resolveRemoteHostname?.(host) ?? host);

        ctx.emit?.({
            type: 'net:scan',
            source: ctx.hostname,
            target: host,
            scanType: scanSyn ? 'SYN' : scanUDP ? 'UDP' : 'connect',
            timestamp: Date.now(),
        });

        const lines: string[] = [];
        lines.push(`Starting Nmap 7.94 ( https://nmap.org )`);
        if (verbose) lines.push(`Initiating ${scanSyn ? 'SYN Stealth' : 'Connect'} Scan against ${host}`);
        lines.push(`Nmap scan report for ${targetHostname} (${host})`);
        lines.push('Host is up (0.0023s latency).');

        if (targetSvcs.length === 0 && !isLocalhost) {
            lines.push('All 1000 scanned ports are filtered');
            lines.push('');
            lines.push('Nmap done: 1 IP address (1 host up) scanned');
            return { output: lines.join('\n') + '\n', exitCode: 0 };
        }

        lines.push('Not shown: ' + (1000 - targetSvcs.reduce((n, s) => n + s.ports.length, 0)) + ' closed ports');
        lines.push('');
        lines.push('PORT      STATE SERVICE' + (verbose ? '       VERSION' : ''));

        const commonPorts: Record<number, string> = { 22: 'ssh', 80: 'http', 443: 'https', 21: 'ftp', 23: 'telnet', 25: 'smtp', 53: 'dns', 110: 'pop3', 143: 'imap', 3306: 'mysql', 5432: 'postgresql', 6379: 'redis', 8080: 'http-proxy', 8443: 'https-alt', 27017: 'mongodb', 6443: 'sun-sr-https', 2379: 'etcd-client', 5000: 'docker-registry', 9200: 'elasticsearch' };

        for (const svc of targetSvcs) {
            for (const port of svc.ports) {
                const svcName = commonPorts[port] ?? svc.name ?? 'unknown';
                const portStr = `${port}/tcp`.padEnd(9);
                let line = `${portStr} open  ${svcName}`;
                if (verbose && svc.config !== undefined) {
                    const banner = svc.config['banner'] as string | undefined;
                    if (banner !== undefined) {
                        line += `       ${banner}`;
                    }
                }
                lines.push(line);
            }
        }

        if (osDetect) {
            lines.push('');
            lines.push('OS detection performed. Please report incorrect results.');
            lines.push('OS details: Linux 5.15 - 6.1');
        }

        lines.push('');
        lines.push('Nmap done: 1 IP address (1 host up) scanned');

        return { output: lines.join('\n') + '\n', exitCode: 0 };
    };

    // awk - pattern processing
    const builtinAwk: CommandHandler = (args, ctx, stdinPipe) => {
        const fIdx = args.indexOf('-F');
        const fieldSep = fIdx >= 0 ? (args[fIdx + 1] ?? ' ') : ' ';
        const pattern = args.find(a => !a.startsWith('-') && (fIdx < 0 || a !== args[fIdx + 1]));

        // Read from file or stdin
        let input = '';
        const fileArg = args[args.length - 1];
        if (fileArg && !fileArg.startsWith('-') && fileArg !== pattern) {
            const resolved = ctx.resolvePath(fileArg);
            const content = ctx.vfs.readFile(resolved);
            if (content !== null) {
                input = content;
            }
        } else if (stdinPipe !== undefined && stdinPipe.length > 0) {
            input = stdinPipe;
        }

        const lines = input.split('\n');
        const output: string[] = [];

        for (const line of lines) {
            if (line.trim() === '') continue;
            const fields = line.split(fieldSep);

            if (pattern?.startsWith('{print')) {
                const fieldMatch = pattern.match(/\$(\d+|NF|\$0)/);
                if (fieldMatch) {
                    const fieldSpec = fieldMatch[1] ?? '';
                    if (fieldSpec === '0' || fieldSpec === '$0') {
                        output.push(line);
                    } else if (fieldSpec === 'NF') {
                        output.push(fields[fields.length - 1] ?? '');
                    } else {
                        const idx = parseInt(fieldSpec, 10) - 1;
                        output.push(fields[idx] ?? '');
                    }
                }
            } else {
                output.push(line);
            }
        }

        return { output: output.join('\n') + '\n', exitCode: 0 };
    };

    // sed - stream editor
    const builtinSed: CommandHandler = (args, ctx, stdinPipe) => {
        const script = args.find(a => !a.startsWith('-'));
        const file = args[args.length - 1];

        let input = '';
        if (file && !file.startsWith('-') && file !== script) {
            const resolved = ctx.resolvePath(file);
            const content = ctx.vfs.readFile(resolved);
            if (content !== null) {
                input = content;
            }
        } else if (stdinPipe !== undefined && stdinPipe.length > 0) {
            input = stdinPipe;
        }

        if (!script || !script.startsWith('s/')) {
            return { output: input, exitCode: 0 };
        }

        // Parse s/pattern/replacement/flags
        const parts = script.slice(2).split('/');
        if (parts.length < 2) {
            return { output: input, exitCode: 0 };
        }

        const pattern = parts[0]!;
        const replacement = parts[1] ?? '';
        const flags = parts[2] ?? '';
        const global = flags.includes('g');

        const lines = input.split('\n');
        const output: string[] = [];

        for (const line of lines) {
            if (global) {
                output.push(line.split(pattern).join(replacement));
            } else {
                output.push(line.replace(pattern, replacement));
            }
        }

        return { output: output.join('\n') + (output.length > 0 && !output[output.length - 1]!.endsWith('\n') ? '\n' : ''), exitCode: 0 };
    };

    // sort - sort lines
    const builtinSort: CommandHandler = (args, ctx, stdinPipe) => {
        const reverse = args.includes('-r');
        const numeric = args.includes('-n');
        const unique = args.includes('-u');

        const file = args.find(a => !a.startsWith('-'));
        let input = '';

        if (file) {
            const resolved = ctx.resolvePath(file);
            const content = ctx.vfs.readFile(resolved);
            if (content !== null) {
                input = content;
            }
        } else if (stdinPipe !== undefined && stdinPipe.length > 0) {
            input = stdinPipe;
        }

        let lines = input.split('\n').filter(l => l.length > 0);

        lines.sort((a, b) => {
            if (numeric) {
                const na = parseFloat(a);
                const nb = parseFloat(b);
                if (!isNaN(na) && !isNaN(nb)) {
                    return reverse ? nb - na : na - nb;
                }
            }
            return reverse ? b.localeCompare(a) : a.localeCompare(b);
        });

        if (unique) {
            lines = [...new Set(lines)];
        }

        return { output: lines.join('\n') + '\n', exitCode: 0 };
    };

    // uniq - deduplicate adjacent lines
    const builtinUniq: CommandHandler = (args, ctx, stdinPipe) => {
        const count = args.includes('-c');

        const file = args.find(a => !a.startsWith('-'));
        let input = '';

        if (file) {
            const resolved = ctx.resolvePath(file);
            const content = ctx.vfs.readFile(resolved);
            if (content !== null) {
                input = content;
            }
        } else if (stdinPipe !== undefined && stdinPipe.length > 0) {
            input = stdinPipe;
        }

        const lines = input.split('\n');
        const output: string[] = [];
        let prev: string | null = null;
        let counter = 0;

        for (const line of lines) {
            if (line === prev) {
                counter++;
            } else {
                if (prev !== null) {
                    if (count) {
                        output.push(`${String(counter).padStart(7)} ${prev}`);
                    } else {
                        output.push(prev);
                    }
                }
                prev = line;
                counter = 1;
            }
        }

        if (prev !== null) {
            if (count) {
                output.push(`${String(counter).padStart(7)} ${prev}`);
            } else {
                output.push(prev);
            }
        }

        return { output: output.join('\n') + '\n', exitCode: 0 };
    };

    // cut - cut fields
    const builtinCut: CommandHandler = (args, ctx, stdinPipe) => {
        const dIdx = args.indexOf('-d');
        const delimiter = dIdx >= 0 ? (args[dIdx + 1] ?? '\t') : '\t';
        const fIdx = args.indexOf('-f');
        const fields = fIdx >= 0 ? (args[fIdx + 1] ?? '1') : '1';

        const file = args.find(a => !a.startsWith('-') && (dIdx < 0 || a !== args[dIdx + 1]) && (fIdx < 0 || a !== args[fIdx + 1]));
        let input = '';

        if (file) {
            const resolved = ctx.resolvePath(file);
            const content = ctx.vfs.readFile(resolved);
            if (content !== null) {
                input = content;
            }
        } else if (stdinPipe !== undefined && stdinPipe.length > 0) {
            input = stdinPipe;
        }

        const fieldList = fields.split(',').map(f => parseInt(f, 10));
        const lines = input.split('\n');
        const output: string[] = [];

        for (const line of lines) {
            if (line.trim() === '') continue;
            const parts = line.split(delimiter);
            const selected = fieldList.map(f => parts[f - 1] ?? '').join(delimiter);
            output.push(selected);
        }

        return { output: output.join('\n') + '\n', exitCode: 0 };
    };

    // base64 - encode/decode
    const builtinBase64: CommandHandler = (args, ctx, stdinPipe) => {
        const decode = args.includes('-d') || args.includes('--decode');
        const file = args.find(a => !a.startsWith('-'));

        let input = '';
        if (file) {
            const resolved = ctx.resolvePath(file);
            const content = ctx.vfs.readFile(resolved);
            if (content !== null) {
                input = content;
            }
        } else if (stdinPipe !== undefined && stdinPipe.length > 0) {
            input = stdinPipe;
        }

        if (decode) {
            // Simple base64 decode simulation
            try {
                const decoded = atob(input.trim());
                return { output: decoded, exitCode: 0 };
            } catch {
                return { output: 'base64: invalid input\n', exitCode: 1 };
            }
        }

        // Encode
        const encoded = btoa(input);
        // Format with 76-char line wrapping
        const lines = encoded.match(/.{1,76}/g) ?? [encoded];
        return { output: lines.join('\n') + '\n', exitCode: 0 };
    };

    // xxd - hex dump
    const builtinXxd: CommandHandler = (args, ctx) => {
        const file = args.find(a => !a.startsWith('-'));
        if (!file) {
            return { output: 'xxd: no input file\n', exitCode: 1 };
        }

        const resolved = ctx.resolvePath(file);
        const content = ctx.vfs.readFile(resolved);
        if (content === null) {
            return { output: `xxd: ${file}: No such file or directory\n`, exitCode: 1 };
        }

        const lines: string[] = [];
        const bytes = new TextEncoder().encode(content);

        for (let i = 0; i < bytes.length; i += 16) {
            const hexOffset = i.toString(16).padStart(8, '0');
            const chunk = bytes.slice(i, i + 16);
            const hexBytes = Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' ');
            const ascii = Array.from(chunk).map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('');
            lines.push(`${hexOffset}: ${hexBytes.padEnd(48, ' ')}  ${ascii}`);
        }

        return { output: lines.join('\n') + '\n', exitCode: 0 };
    };

    // strings - extract printable strings
    const builtinStrings: CommandHandler = (args, ctx) => {
        const file = args.find(a => !a.startsWith('-'));
        if (!file) {
            return { output: 'strings: no input file\n', exitCode: 1 };
        }

        const resolved = ctx.resolvePath(file);
        const content = ctx.vfs.readFile(resolved);
        if (content === null) {
            return { output: `strings: ${file}: No such file or directory\n`, exitCode: 1 };
        }

        const printable = content.match(/[\x20-\x7E]{4,}/g) ?? [];

        return { output: printable.join('\n') + '\n', exitCode: 0 };
    };

    // dig - DNS lookup
    const builtinDig: CommandHandler = (args) => {
        const domain = args.find(a => !a.startsWith('-'));
        if (!domain) {
            return { output: ';; global options: +cmd\n;; connection timed out\n', exitCode: 1 };
        }

        const lines: string[] = [];
        lines.push(`; <<>> DiG <<>> ${domain}`);
        lines.push(';; global options: +cmd');
        lines.push(';; Got answer:');
        lines.push(';; ->>HEADER<<- opcode: QUERY, status: NOERROR');
        lines.push('');
        lines.push(';; ANSWER SECTION:');

        // Simulate A record lookup
        if (domain === 'localhost' || domain === '127.0.0.1') {
            lines.push(`${domain}.\t\t604800\tIN\tA\t127.0.0.1`);
        } else {
            // Generate deterministic fake IP
            const hash = domain.split('').reduce((a, b) => { a = ((a << 5) - a) + b.charCodeAt(0); return a & a; }, 0);
            const ip = `10.${Math.abs(hash) % 256}.${Math.abs(hash >> 8) % 256}.${Math.abs(hash >> 16) % 256}`;
            lines.push(`${domain}.\t\t300\tIN\tA\t${ip}`);
        }

        lines.push('');
        lines.push(';; Query time: 23 msec');
        lines.push(';; SERVER: 8.8.8.8#53');
        lines.push(';; WHEN: ' + new Date().toUTCString());

        return { output: lines.join('\n') + '\n', exitCode: 0 };
    };

    // ping - ICMP ping simulation
    const builtinPing: CommandHandler = (args) => {
        const host = args.find(a => !a.startsWith('-'));
        if (!host) {
            return { output: 'ping: usage: ping [-c count] destination\n', exitCode: 2 };
        }

        const lines: string[] = [];
        lines.push(`PING ${host} (10.0.0.1) 56(84) bytes of data.`);
        lines.push('64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.5 ms');
        lines.push('64 bytes from 10.0.0.1: icmp_seq=2 ttl=64 time=0.4 ms');
        lines.push('64 bytes from 10.0.0.1: icmp_seq=3 ttl=64 time=0.6 ms');
        lines.push('');
        lines.push(`--- ${host} ping statistics ---`);
        lines.push('3 packets transmitted, 3 received, 0% packet loss, time 2002ms');
        lines.push('rtt min/avg/max/mdev = 0.400/0.500/0.600/0.081 ms');

        return { output: lines.join('\n') + '\n', exitCode: 0 };
    };

    // ssh - SSH client
    const builtinSsh: CommandHandler = (args, ctx) => {
        const userIdx = args.indexOf('-l');
        let targetUser = userIdx >= 0 ? args[userIdx + 1] : undefined;

        const host = args.find(a => !a.startsWith('-') && !a.includes('@') && (userIdx < 0 || a !== args[userIdx + 1]));

        // Check for user@host format
        const userHost = args.find(a => a.includes('@') && !a.startsWith('-'));
        if (userHost) {
            const parts = userHost.split('@');
            targetUser = parts[0];
        }

        targetUser = targetUser ?? ctx.user;
        const targetHost = host ?? userHost?.split('@')[1];

        if (!targetHost) {
            return { output: 'usage: ssh [user@]hostname [command]\n', exitCode: 255 };
        }

        // Emit auth:login event
        const success = targetUser === 'root' || targetUser === ctx.user;
        ctx.emit?.({
            type: 'auth:login',
            user: targetUser,
            machine: targetHost,
            service: 'ssh',
            success,
            timestamp: Date.now(),
        });

        if (success) {
            return {
                output: `Welcome to ${targetHost}!\n\nLast login: ${new Date().toUTCString()} from 10.0.0.2\n`,
                exitCode: 0,
            };
        }

        return { output: 'Permission denied (publickey,password).\n', exitCode: 255 };
    };

    // sudo - privilege escalation
    const builtinSudo: CommandHandler = (args, ctx) => {
        const command = args.find(a => !a.startsWith('-'));
        if (!command) {
            return { output: 'sudo: no command specified\n', exitCode: 1 };
        }

        // Check if current user can sudo
        const currentUser = ctx.users?.find(u => u.username === ctx.user);
        const canSudo = ctx.user === 'root' || currentUser?.sudo === true || currentUser?.groups?.includes('sudo');

        if (canSudo) {
            // Emit auth:escalate event
            ctx.emit?.({
                type: 'auth:escalate',
                machine: ctx.hostname,
                from: ctx.user,
                to: 'root',
                method: 'sudo',
                timestamp: Date.now(),
            });
            return { output: '', exitCode: 0 };
        }

        return { output: `${ctx.user} is not in the sudoers file.  This incident will be reported.\n`, exitCode: 1 };
    };

    // su - switch user
    const builtinSu: CommandHandler = (args, ctx) => {
        const targetUser = args.find(a => !a.startsWith('-')) ?? 'root';

        // Check /etc/shadow or /etc/passwd for password
        const shadowPath = ctx.resolvePath('/etc/shadow');
        const passwdPath = ctx.resolvePath('/etc/passwd');

        let authContent = '';
        const shadow = ctx.vfs.readFile(shadowPath);
        if (shadow) {
            authContent = shadow;
        } else {
            const passwd = ctx.vfs.readFile(passwdPath);
            if (passwd) {
                authContent = passwd;
            }
        }

        // Check if user exists
        const userExists = authContent.includes(`${targetUser}:`);
        if (!userExists && targetUser !== 'root') {
            return { output: `su: user ${targetUser} does not exist\n`, exitCode: 1 };
        }

        // Check if current user can bypass password (root or has sudo privilege)
        const currentUser = ctx.users?.find(u => u.username === ctx.user);
        const canBypass = ctx.user === 'root' || currentUser?.sudo === true;

        // Simple password check simulation
        const hasPassword = authContent.includes(`${targetUser}:`) && !authContent.includes(`${targetUser}::`);

        if (hasPassword && !canBypass) {
            return { output: 'Password: \nsu: Authentication failure\n', exitCode: 1 };
        }

        // Emit auth:escalate event
        ctx.emit?.({
            type: 'auth:escalate',
            machine: ctx.hostname,
            from: ctx.user,
            to: targetUser,
            method: 'su',
            timestamp: Date.now(),
        });

        return { output: '', exitCode: 0 };
    };

    // ── Additional commands for realism ────────────────────────

    const commandHistory: string[] = [];

    const builtinTee: CommandHandler = (_args, ctx, stdin) => {
        const files = _args.filter(a => !a.startsWith('-'));
        const append = _args.includes('-a');
        const data = stdin ?? '';
        for (const file of files) {
            const resolved = ctx.resolvePath(file);
            if (append) {
                const existing = ctx.vfs.readFile(resolved) ?? '';
                ctx.vfs.writeFile(resolved, existing + data, { owner: ctx.user });
            } else {
                ctx.vfs.writeFile(resolved, data, { owner: ctx.user });
            }
        }
        return { output: data, exitCode: 0 };
    };

    const builtinTr: CommandHandler = (args, _ctx, stdin) => {
        const deleteMode = args.includes('-d');
        const squeezeMode = args.includes('-s');
        const cleanArgs = args.filter(a => !a.startsWith('-'));
        const input = stdin ?? '';
        if (deleteMode && cleanArgs.length >= 1) {
            const chars = cleanArgs[0]!;
            const regex = new RegExp(`[${chars.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&')}]`, 'g');
            return { output: input.replace(regex, ''), exitCode: 0 };
        }
        if (cleanArgs.length >= 2) {
            const from = cleanArgs[0]!;
            const to = cleanArgs[1]!;
            let result = input;
            for (let i = 0; i < from.length && i < to.length; i++) {
                result = result.split(from[i]!).join(to[i]!);
            }
            if (squeezeMode && to.length > 0) {
                const last = to[to.length - 1]!;
                const squeezed = last.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
                result = result.replace(new RegExp(`${squeezed}+`, 'g'), last);
            }
            return { output: result, exitCode: 0 };
        }
        return { output: input, exitCode: 0 };
    };

    const builtinXargs: CommandHandler = (args, _ctx, stdin) => {
        const cmdName = args[0] ?? 'echo';
        const cmdArgs = args.slice(1);
        const inputItems = (stdin ?? '').trim().split(/\s+/).filter(s => s.length > 0);
        const fullArgs = [...cmdArgs, ...inputItems];
        const handler = commands.get(cmdName);
        if (handler === undefined) return { output: `-sh: ${cmdName}: not found\n`, exitCode: 127 };
        return handler(fullArgs, makeContext());
    };

    const builtinRev: CommandHandler = (_args, _ctx, stdin) => {
        const lines = (stdin ?? '').split('\n');
        return { output: lines.map(l => l.split('').reverse().join('')).join('\n'), exitCode: 0 };
    };

    const builtinNl: CommandHandler = (_args, _ctx, stdin) => {
        const lines = (stdin ?? '').split('\n');
        return { output: lines.map((l, i) => l.length > 0 ? `${String(i + 1).padStart(6)}\t${l}` : '').join('\n'), exitCode: 0 };
    };

    const builtinTac: CommandHandler = (args, ctx, stdin) => {
        let input = stdin ?? '';
        if (args.length > 0 && !args[0]!.startsWith('-')) {
            const resolved = ctx.resolvePath(args[0]!);
            const content = ctx.vfs.readFile(resolved);
            if (content !== null) input = content;
        }
        const lines = input.split('\n');
        return { output: lines.reverse().join('\n'), exitCode: 0 };
    };

    const builtinTest: CommandHandler = (args, ctx) => {
        const cleanArgs = args.filter(a => a !== ']');
        if (cleanArgs.length === 0) return { output: '', exitCode: 1 };
        if (cleanArgs.length === 2 && cleanArgs[0] === '-f') {
            return { output: '', exitCode: ctx.vfs.exists(ctx.resolvePath(cleanArgs[1]!)) ? 0 : 1 };
        }
        if (cleanArgs.length === 2 && cleanArgs[0] === '-d') {
            const stat = ctx.vfs.stat(ctx.resolvePath(cleanArgs[1]!));
            return { output: '', exitCode: stat !== null && stat.type === 'dir' ? 0 : 1 };
        }
        if (cleanArgs.length === 2 && cleanArgs[0] === '-z') {
            return { output: '', exitCode: cleanArgs[1]!.length === 0 ? 0 : 1 };
        }
        if (cleanArgs.length === 2 && cleanArgs[0] === '-n') {
            return { output: '', exitCode: cleanArgs[1]!.length > 0 ? 0 : 1 };
        }
        if (cleanArgs.length === 3 && cleanArgs[1] === '=') {
            return { output: '', exitCode: cleanArgs[0] === cleanArgs[2] ? 0 : 1 };
        }
        if (cleanArgs.length === 3 && cleanArgs[1] === '!=') {
            return { output: '', exitCode: cleanArgs[0] !== cleanArgs[2] ? 0 : 1 };
        }
        return { output: '', exitCode: 0 };
    };

    const builtinNc: CommandHandler = (args, ctx) => {
        const listen = args.includes('-l');
        const verbose = args.includes('-v');
        const cleanArgs = args.filter(a => !a.startsWith('-'));
        const host = cleanArgs[0] ?? 'localhost';
        const port = cleanArgs[1] ?? '0';

        ctx.emit?.({
            type: 'net:connect',
            host,
            port: parseInt(port, 10),
            source: ctx.hostname,
            protocol: 'tcp',
            timestamp: Date.now(),
        });

        if (listen) {
            return { output: verbose ? `listening on [any] ${port} ...\n` : '', exitCode: 0 };
        }
        return {
            output: verbose ? `Connection to ${host} ${port} port [tcp/*] succeeded!\n` : '',
            exitCode: 0,
        };
    };

    const builtinMysql: CommandHandler = (args, ctx) => {
        const hostIdx = args.indexOf('-h');
        const dbHost = hostIdx >= 0 ? (args[hostIdx + 1] ?? 'localhost') : 'localhost';
        const eIdx = args.indexOf('-e');
        const query = eIdx >= 0 ? args.slice(eIdx + 1).join(' ').replace(/^['"]|['"]$/g, '') : undefined;

        ctx.emit?.({
            type: 'net:connect',
            host: dbHost,
            port: 3306,
            source: ctx.hostname,
            protocol: 'tcp',
            timestamp: Date.now(),
        });

        if (query === undefined) {
            return {
                output: `Welcome to the MySQL monitor.  Commands end with ;.\nServer version: 8.0.35-variant\n\nType 'help;' for help.\n\nmysql> `,
                exitCode: 0,
            };
        }

        // Check for SELECT * FROM users pattern — return data from /tmp/users_export.txt if available
        const lowerQuery = query.toLowerCase();
        if (lowerQuery.includes('select') && lowerQuery.includes('from')) {
            // Try to find users_export.txt or similar database dump
            const exportPaths = ['/tmp/users_export.txt', '/var/lib/mysql/users.txt', '/tmp/db_dump.txt'];
            for (const epath of exportPaths) {
                const content = ctx.vfs.readFile(epath);
                if (content !== null) {
                    return { output: content + '\n', exitCode: 0 };
                }
            }
            return { output: 'Empty set (0.00 sec)\n', exitCode: 0 };
        }

        if (lowerQuery.includes('show databases')) {
            return {
                output: '+--------------------+\n| Database           |\n+--------------------+\n| information_schema |\n| mysql              |\n| performance_schema |\n| app_db             |\n+--------------------+\n4 rows in set (0.01 sec)\n',
                exitCode: 0,
            };
        }

        if (lowerQuery.includes('show tables')) {
            return {
                output: '+----------------+\n| Tables_in_app  |\n+----------------+\n| users          |\n| sessions       |\n| config         |\n+----------------+\n3 rows in set (0.00 sec)\n',
                exitCode: 0,
            };
        }

        return { output: 'Query OK, 0 rows affected (0.00 sec)\n', exitCode: 0 };
    };

    const builtinHistory: CommandHandler = () => {
        const lines = commandHistory.map((cmd, i) =>
            `${String(i + 1).padStart(5)}  ${cmd}`
        );
        return { output: lines.join('\n') + '\n', exitCode: 0 };
    };

    const builtinDate: CommandHandler = () => {
        return { output: new Date().toUTCString() + '\n', exitCode: 0 };
    };

    const builtinUptime: CommandHandler = () => {
        return { output: ' 09:42:15 up 47 days,  3:21,  1 user,  load average: 0.08, 0.03, 0.01\n', exitCode: 0 };
    };

    const builtinW: CommandHandler = () => {
        return {
            output: ' 09:42:15 up 47 days,  3:21,  1 user,  load average: 0.08, 0.03, 0.01\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n' + user + '     pts/0    10.0.0.1         09:12    0.00s  0.03s  0.00s w\n',
            exitCode: 0,
        };
    };

    const builtinLast: CommandHandler = () => {
        return {
            output: `${user}     pts/0        10.0.0.1         ${new Date().toDateString().slice(4)}   still logged in\nreboot   system boot  5.15.0-variant   ${new Date().toDateString().slice(4)}   still running\n\nwtmp begins ${new Date().toDateString().slice(4)}\n`,
            exitCode: 0,
        };
    };

    const builtinDmesg: CommandHandler = () => {
        return {
            output: '[    0.000000] Linux version 5.15.0-variant (gcc 12.2.0) #1 SMP\n[    0.000000] Command line: BOOT_IMAGE=/vmlinuz root=/dev/sda1\n[    0.123456] Memory: 262144K/262144K available\n[    0.234567] CPU: Intel Xeon E5-2686 v4 @ 2.30GHz\n[    1.234567] EXT4-fs (sda1): mounted filesystem\n[    2.345678] systemd[1]: Started.\n',
            exitCode: 0,
        };
    };

    const builtinFree: CommandHandler = (args) => {
        const human = args.includes('-h') || args.includes('-m');
        if (human) {
            return {
                output: '               total        used        free      shared  buff/cache   available\nMem:           256Mi       128Mi        64Mi       2.0Mi        64Mi       120Mi\nSwap:          512Mi         0Bi       512Mi\n',
                exitCode: 0,
            };
        }
        return {
            output: '               total        used        free      shared  buff/cache   available\nMem:          262144      131072       65536        2048       65536      122880\nSwap:         524288           0      524288\n',
            exitCode: 0,
        };
    };

    const builtinDf: CommandHandler = (args) => {
        const human = args.includes('-h');
        if (human) {
            return {
                output: 'Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        20G  4.2G   15G  22% /\ntmpfs           128M   12K  128M   1% /tmp\n',
                exitCode: 0,
            };
        }
        return {
            output: 'Filesystem     1K-blocks    Used Available Use% Mounted on\n/dev/sda1       20971520 4404224  15531008  22% /\ntmpfs            131072      12    131060   1% /tmp\n',
            exitCode: 0,
        };
    };

    const builtinDu: CommandHandler = (args, ctx) => {
        const human = args.includes('-h');
        const summary = args.includes('-s');
        const target = args.find(a => !a.startsWith('-')) ?? ctx.cwd;
        const resolved = ctx.resolvePath(target);
        if (summary) {
            return { output: `${human ? '4.2M' : '4300'}\t${resolved}\n`, exitCode: 0 };
        }
        return { output: `${human ? '4.0K' : '4'}\t${resolved}\n`, exitCode: 0 };
    };

    const builtinMount: CommandHandler = () => {
        return {
            output: '/dev/sda1 on / type ext4 (rw,relatime)\nproc on /proc type proc (rw,nosuid,nodev,noexec)\ntmpfs on /tmp type tmpfs (rw,nosuid,nodev)\nsysfs on /sys type sysfs (ro,nosuid,nodev,noexec)\n',
            exitCode: 0,
        };
    };

    const builtinStat: CommandHandler = (args, ctx) => {
        const file = args.find(a => !a.startsWith('-'));
        if (!file) return { output: "stat: missing operand\n", exitCode: 1 };
        const resolved = ctx.resolvePath(file);
        const node = ctx.vfs.stat(resolved);
        if (node === null) return { output: `stat: cannot stat '${file}': No such file or directory\n`, exitCode: 1 };
        const typeStr = node.type === 'dir' ? 'directory' : node.type === 'symlink' ? 'symbolic link' : 'regular file';
        return {
            output: `  File: ${file}\n  Size: ${node.type === 'file' ? node.content.length : 4096}\tBlocks: 8\tIO Block: 4096\t${typeStr}\nAccess: (${(node.type !== 'symlink' ? node.mode : 0o777).toString(8)}/${node.owner})\nModify: ${new Date().toISOString()}\n`,
            exitCode: 0,
        };
    };

    const builtinLn: CommandHandler = (args, ctx) => {
        const symbolic = args.includes('-s');
        const cleanArgs = args.filter(a => !a.startsWith('-'));
        if (cleanArgs.length < 2) return { output: 'Usage: ln [-s] TARGET LINK_NAME\n', exitCode: 1 };
        const target = cleanArgs[0]!;
        const linkName = ctx.resolvePath(cleanArgs[1]!);
        if (symbolic) {
            ctx.vfs.writeFile(linkName, target, { owner: ctx.user });
        }
        return { output: '', exitCode: 0 };
    };

    const builtinReadlink: CommandHandler = (args, ctx) => {
        const file = args.find(a => !a.startsWith('-'));
        if (!file) return { output: '', exitCode: 1 };
        const resolved = ctx.resolvePath(file);
        const content = ctx.vfs.readFile(resolved);
        return { output: (content ?? '') + '\n', exitCode: content !== null ? 0 : 1 };
    };

    const builtinRealpath: CommandHandler = (args, ctx) => {
        const file = args.find(a => !a.startsWith('-'));
        if (!file) return { output: '', exitCode: 1 };
        return { output: ctx.resolvePath(file) + '\n', exitCode: 0 };
    };

    const builtinBasename: CommandHandler = (args) => {
        if (args.length === 0) return { output: '', exitCode: 1 };
        const parts = args[0]!.split('/');
        return { output: (parts[parts.length - 1] ?? '') + '\n', exitCode: 0 };
    };

    const builtinDirname: CommandHandler = (args) => {
        if (args.length === 0) return { output: '', exitCode: 1 };
        const parts = args[0]!.split('/');
        parts.pop();
        return { output: (parts.join('/') || '.') + '\n', exitCode: 0 };
    };

    const builtinOpenssl: CommandHandler = (args) => {
        if (args[0] === 'version') return { output: 'OpenSSL 3.0.13 30 Jan 2024\n', exitCode: 0 };
        if (args[0] === 'rand' && args[1] === '-hex') {
            const bytes = parseInt(args[2] ?? '16', 10);
            const hex = Array.from({ length: Math.min(bytes, 64) }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join('');
            return { output: hex + '\n', exitCode: 0 };
        }
        if (args[0] === 'passwd') {
            return { output: '$6$rounds=5000$salt$hash_placeholder\n', exitCode: 0 };
        }
        return { output: 'openssl: use -help for summary\n', exitCode: 0 };
    };

    const builtinSha256sum: CommandHandler = (args, ctx, stdin) => {
        const file = args.find(a => !a.startsWith('-'));
        let input = stdin ?? '';
        let label = '-';
        if (file) {
            const resolved = ctx.resolvePath(file);
            const content = ctx.vfs.readFile(resolved);
            if (content === null) return { output: `sha256sum: ${file}: No such file or directory\n`, exitCode: 1 };
            input = content;
            label = file;
        }
        // Simple deterministic hash for simulation
        let hash = 0;
        for (let i = 0; i < input.length; i++) {
            hash = ((hash << 5) - hash + input.charCodeAt(i)) | 0;
        }
        const hex = Math.abs(hash).toString(16).padStart(64, 'a');
        return { output: `${hex}  ${label}\n`, exitCode: 0 };
    };

    const builtinMd5sum: CommandHandler = (args, ctx, stdin) => {
        const file = args.find(a => !a.startsWith('-'));
        let input = stdin ?? '';
        let label = '-';
        if (file) {
            const resolved = ctx.resolvePath(file);
            const content = ctx.vfs.readFile(resolved);
            if (content === null) return { output: `md5sum: ${file}: No such file or directory\n`, exitCode: 1 };
            input = content;
            label = file;
        }
        let hash = 0;
        for (let i = 0; i < input.length; i++) {
            hash = ((hash << 5) - hash + input.charCodeAt(i)) | 0;
        }
        const hex = Math.abs(hash).toString(16).padStart(32, 'b');
        return { output: `${hex}  ${label}\n`, exitCode: 0 };
    };

    const builtinCrontab: CommandHandler = (args, ctx) => {
        if (args.includes('-l')) {
            const content = ctx.vfs.readFile('/var/spool/cron/crontabs/' + ctx.user);
            return { output: content ?? 'no crontab for ' + ctx.user + '\n', exitCode: content !== null ? 0 : 1 };
        }
        return { output: '', exitCode: 0 };
    };

    const builtinService: CommandHandler = (args, ctx) => {
        const svcName = args[0];
        const action = args[1];
        if (!svcName || !action) return { output: 'Usage: service <name> <start|stop|status|restart>\n', exitCode: 1 };
        const svcs = ctx.services ?? [];
        const found = svcs.find(s => s.name === svcName);
        if (action === 'status') {
            return { output: `● ${svcName}.service - ${svcName}\n   Active: ${found ? 'active (running)' : 'inactive (dead)'}\n`, exitCode: found ? 0 : 3 };
        }
        return { output: '', exitCode: 0 };
    };

    const builtinSystemctl: CommandHandler = (args, ctx) => {
        const action = args[0];
        const svcName = args[1];
        if (action === 'list-units' || action === 'list-unit-files') {
            const svcs = ctx.services ?? [];
            const lines = svcs.map(s => `${s.name}.service\tloaded\tactive\trunning\t${s.name}`);
            return { output: lines.join('\n') + '\n', exitCode: 0 };
        }
        if (action === 'status' && svcName) {
            return builtinService([svcName, 'status'], ctx);
        }
        return { output: '', exitCode: 0 };
    };

    // ── Register built-ins ────────────────────────────────────

    registerBuiltins();

    // Register custom commands
    if (config.customCommands !== undefined) {
        for (const [name, handler] of config.customCommands) {
            commands.set(name, handler);
        }
    }

    // ── Shell instance ────────────────────────────────────────

    /** Internal execute with stdin support for pipes */
    function executeWithStdin(command: string, stdinData?: string): ShellResult {
        const trimmed = command.trim();
        if (trimmed.length === 0) return { output: '', exitCode: 0 };
        if (trimmed.length > MAX_COMMAND_LENGTH) {
            return { output: '-sh: command line too long\n', exitCode: 1 };
        }

        // Handle comments
        if (trimmed.startsWith('#')) return { output: '', exitCode: 0 };

        // Handle command substitution: $(cmd)
        let processed = trimmed;
        const subPattern = /\$\(([^)]+)\)/g;
        let subMatch: RegExpExecArray | null;
        while ((subMatch = subPattern.exec(processed)) !== null) {
            const innerResult = executeWithStdin(subMatch[1]!);
            const replacement = innerResult.output.trimEnd();
            processed = processed.slice(0, subMatch.index) + replacement + processed.slice(subMatch.index + subMatch[0].length);
            subPattern.lastIndex = 0; // Reset after mutation
        }

        // Handle backtick substitution: `cmd`
        const btPattern = /`([^`]+)`/g;
        let btMatch: RegExpExecArray | null;
        while ((btMatch = btPattern.exec(processed)) !== null) {
            const innerResult = executeWithStdin(btMatch[1]!);
            const replacement = innerResult.output.trimEnd();
            processed = processed.slice(0, btMatch.index) + replacement + processed.slice(btMatch.index + btMatch[0].length);
            btPattern.lastIndex = 0;
        }

        // Handle pipes — feed stdout of each command as stdin to the next
        if (processed.includes(' | ')) {
            const parts = processed.split(' | ');
            let pipeData = stdinData ?? '';
            let lastExit = 0;
            for (const part of parts) {
                const result = executeWithStdin(part.trim(), pipeData);
                pipeData = result.output;
                lastExit = result.exitCode;
            }
            return { output: pipeData, exitCode: lastExit };
        }

        // Handle && (AND list)
        if (processed.includes(' && ')) {
            const parts = processed.split(' && ');
            let lastOutput = '';
            for (const part of parts) {
                const result = executeWithStdin(part.trim(), stdinData);
                lastOutput += result.output;
                if (result.exitCode !== 0) {
                    return { output: lastOutput, exitCode: result.exitCode };
                }
            }
            return { output: lastOutput, exitCode: 0 };
        }

        // Handle || (OR list)
        if (processed.includes(' || ')) {
            const parts = processed.split(' || ');
            let lastOutput = '';
            let lastExit = 1;
            for (const part of parts) {
                const result = executeWithStdin(part.trim(), stdinData);
                lastOutput += result.output;
                lastExit = result.exitCode;
                if (result.exitCode === 0) break;
            }
            return { output: lastOutput, exitCode: lastExit };
        }

        // Handle semicolons (cmd1; cmd2)
        if (processed.includes('; ')) {
            const parts = processed.split('; ');
            let lastOutput = '';
            let lastExit = 0;
            for (const part of parts) {
                const result = executeWithStdin(part.trim(), stdinData);
                lastOutput += result.output;
                lastExit = result.exitCode;
            }
            return { output: lastOutput, exitCode: lastExit };
        }

        // Handle append redirect (>> must be checked before >)
        if (processed.includes(' >> ')) {
            const idx = processed.lastIndexOf(' >> ');
            const cmdPart = processed.slice(0, idx);
            const filePart = processed.slice(idx + 4).trim();
            const result = executeWithStdin(cmdPart.trim(), stdinData);
            const resolved = resolvePath(filePart);
            const existing = vfs.readFile(resolved) ?? '';
            vfs.writeFile(resolved, existing + result.output, { owner: user });
            return { output: '', exitCode: result.exitCode };
        }

        // Handle redirect (cmd > file)
        if (processed.includes(' > ')) {
            const idx = processed.lastIndexOf(' > ');
            const cmdPart = processed.slice(0, idx);
            const filePart = processed.slice(idx + 3).trim();
            const result = executeWithStdin(cmdPart.trim(), stdinData);
            const resolved = resolvePath(filePart);
            vfs.writeFile(resolved, result.output, { owner: user });
            return { output: '', exitCode: result.exitCode };
        }

        // Handle input redirect (cmd < file)
        let effectiveStdin = stdinData;
        let effectiveCmd = processed;
        if (processed.includes(' < ')) {
            const idx = processed.lastIndexOf(' < ');
            effectiveCmd = processed.slice(0, idx).trim();
            const filePart = processed.slice(idx + 3).trim();
            const resolved = resolvePath(filePart);
            const content = vfs.readFile(resolved);
            if (content === null) {
                return { output: `-sh: ${filePart}: No such file or directory\n`, exitCode: 1 };
            }
            effectiveStdin = content;
        }

        const args = parseArgs(effectiveCmd);
        if (args.length === 0) return { output: '', exitCode: 0 };
        if (args.length > MAX_ARGS) {
            return { output: '-sh: too many arguments\n', exitCode: 1 };
        }

        const cmdName = args[0]!;
        const cmdArgs = args.slice(1);

        // Store last exit code in $?
        let lastExitCode = 0;

        // Handle env var assignment: KEY=VALUE (same limits as export)
        if (cmdName.includes('=') && !cmdName.startsWith('=')) {
            const eq = cmdName.indexOf('=');
            const k = cmdName.slice(0, eq);
            const v = cmdName.slice(eq + 1);
            if (k.length <= MAX_ENV_KEY && v.length <= MAX_ENV_VALUE && (env.has(k) || env.size < MAX_ENV_VARS)) {
                env.set(k, v);
            }
            return { output: '', exitCode: 0 };
        }

        const handler = commands.get(cmdName);
        if (handler === undefined) {
            return { output: `-sh: ${cmdName}: not found\n`, exitCode: 127 };
        }

        const result = handler(cmdArgs, makeContext(), effectiveStdin);
        lastExitCode = result.exitCode;
        env.set('?', String(lastExitCode));
        return result;
    }

    const shell: ScriptedShell = {
        execute(command: string): ShellResult {
            return executeWithStdin(command);
        },

        getCwd() { return cwd; },
        getUser() { return user; },
        getHostname() { return hostname; },
        setHostname(name: string) { hostname = name; },
        setUser(name: string) {
            user = name;
            cwd = name === 'root' ? '/root' : `/home/${name}`;
            if (!vfs.exists(cwd)) vfs.mkdir(cwd, { recursive: true });
        },

        getPrompt(): string {
            const cwdDisplay = cwd === env.get('HOME') ? '~' : cwd;
            const promptChar = user === 'root' ? '#' : '$';
            return `${user}@${hostname}:${cwdDisplay}${promptChar} `;
        },

        getEnv(key: string) { return env.get(key); },
        setEnv(key: string, value: string) { env.set(key, value); },

        registerCommand(name: string, handler: CommandHandler) {
            commands.set(name, handler);
        },

        hasCommand(name: string) { return commands.has(name); },
        getVFS() { return vfs; },
    };

    return shell;
}
