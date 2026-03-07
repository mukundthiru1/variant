/**
 * VARIANT — Scripted Shell tests
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { createVFS } from '../../../src/lib/vfs/vfs';
import { createShell } from '../../../src/lib/shell/shell';
import type { VirtualFilesystem } from '../../../src/lib/vfs/types';
import type { ScriptedShell } from '../../../src/lib/shell/types';

describe('ScriptedShell', () => {
    let vfs: VirtualFilesystem;
    let shell: ScriptedShell;

    beforeEach(() => {
        vfs = createVFS();
        // Set up a minimal filesystem
        vfs.writeFile('/etc/hostname', 'web-server');
        vfs.writeFile('/etc/passwd', 'root:x:0:0:root:/root:/bin/sh\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin');
        vfs.writeFile('/var/www/index.html', '<html><body>Hello World</body></html>');
        vfs.writeFile('/var/log/auth.log', 'Jan  1 00:00:01 sshd[1234]: Accepted password for root\nJan  1 00:01:00 sshd[1235]: Failed password for admin');
        vfs.writeFile('/root/.bashrc', 'export PS1="\\u@\\h:\\w\\$ "');
        vfs.mkdir('/tmp');

        shell = createShell({
            vfs,
            hostname: 'web-server',
            user: 'root',
            cwd: '/root',
        });
    });

    // ── Basic commands ─────────────────────────────────────────

    describe('basic commands', () => {
        it('pwd returns cwd', () => {
            const result = shell.execute('pwd');
            expect(result.output).toBe('/root\n');
            expect(result.exitCode).toBe(0);
        });

        it('whoami returns user', () => {
            expect(shell.execute('whoami').output).toBe('root\n');
        });

        it('hostname returns hostname', () => {
            expect(shell.execute('hostname').output).toBe('web-server\n');
        });

        it('echo outputs text', () => {
            expect(shell.execute('echo hello world').output).toBe('hello world\n');
        });

        it('echo substitutes env vars', () => {
            shell.setEnv('FOO', 'bar');
            expect(shell.execute('echo $FOO').output).toBe('bar\n');
        });

        it('uname returns Linux', () => {
            expect(shell.execute('uname').output).toBe('Linux\n');
        });

        it('uname -a returns full info', () => {
            const result = shell.execute('uname -a');
            expect(result.output).toContain('Linux');
            expect(result.output).toContain('web-server');
        });

        it('id returns user info', () => {
            const result = shell.execute('id');
            expect(result.output).toContain('uid=0(root)');
        });
    });

    // ── File operations ────────────────────────────────────────

    describe('cat', () => {
        it('reads a file', () => {
            const result = shell.execute('cat /etc/hostname');
            expect(result.output).toBe('web-server\n');
        });

        it('errors on nonexistent file', () => {
            const result = shell.execute('cat /nope');
            expect(result.exitCode).toBe(1);
            expect(result.output).toContain('No such file');
        });
    });

    describe('ls', () => {
        it('lists current directory', () => {
            const result = shell.execute('ls /etc');
            expect(result.output).toContain('hostname');
            expect(result.output).toContain('passwd');
        });

        it('lists with long format', () => {
            const result = shell.execute('ls -l /etc');
            expect(result.output).toContain('root');
            expect(result.output).toContain('hostname');
        });

        it('hides dotfiles without -a', () => {
            const result = shell.execute('ls /root');
            expect(result.output).not.toContain('.bashrc');
        });

        it('shows dotfiles with -a', () => {
            const result = shell.execute('ls -a /root');
            expect(result.output).toContain('.bashrc');
        });

        it('errors on nonexistent path', () => {
            const result = shell.execute('ls /nonexistent');
            expect(result.exitCode).toBe(1);
        });
    });

    describe('head and tail', () => {
        it('head shows first 10 lines', () => {
            const result = shell.execute('head /etc/passwd');
            expect(result.output).toContain('root');
        });

        it('tail shows last lines', () => {
            const result = shell.execute('tail /var/log/auth.log');
            expect(result.output).toContain('Failed password');
        });
    });

    describe('grep', () => {
        it('finds matching lines', () => {
            const result = shell.execute('grep root /etc/passwd');
            expect(result.output).toContain('root:x:0:0');
            expect(result.exitCode).toBe(0);
        });

        it('returns exit 1 for no match', () => {
            const result = shell.execute('grep nonexistent /etc/passwd');
            expect(result.exitCode).toBe(1);
        });

        it('supports case-insensitive search', () => {
            const result = shell.execute('grep -i ROOT /etc/passwd');
            expect(result.output).toContain('root');
        });

        it('shows line numbers with -n', () => {
            const result = shell.execute('grep -n root /etc/passwd');
            expect(result.output).toContain('1:');
        });
    });

    describe('wc', () => {
        it('counts lines, words, bytes', () => {
            const result = shell.execute('wc /etc/hostname');
            expect(result.output).toContain('hostname');
            expect(result.exitCode).toBe(0);
        });
    });

    // ── Navigation ─────────────────────────────────────────────

    describe('cd', () => {
        it('changes directory', () => {
            shell.execute('cd /etc');
            expect(shell.getCwd()).toBe('/etc');
        });

        it('errors on nonexistent dir', () => {
            const result = shell.execute('cd /nonexistent');
            expect(result.exitCode).toBe(1);
        });

        it('errors on file', () => {
            const result = shell.execute('cd /etc/hostname');
            expect(result.exitCode).toBe(1);
        });

        it('cd with no args goes home', () => {
            shell.execute('cd /tmp');
            shell.execute('cd');
            expect(shell.getCwd()).toBe('/root');
        });
    });

    // ── File manipulation ──────────────────────────────────────

    describe('touch', () => {
        it('creates empty file', () => {
            shell.execute('touch /tmp/newfile');
            expect(vfs.exists('/tmp/newfile')).toBe(true);
        });

        it('does not overwrite existing', () => {
            vfs.writeFile('/tmp/existing', 'data');
            shell.execute('touch /tmp/existing');
            expect(vfs.readFile('/tmp/existing')).toBe('data');
        });
    });

    describe('mkdir', () => {
        it('creates directory', () => {
            shell.execute('mkdir /tmp/newdir');
            expect(vfs.exists('/tmp/newdir')).toBe(true);
        });

        it('creates recursively with -p', () => {
            shell.execute('mkdir -p /tmp/a/b/c');
            expect(vfs.exists('/tmp/a/b/c')).toBe(true);
        });
    });

    describe('rm', () => {
        it('removes file', () => {
            vfs.writeFile('/tmp/gone', 'bye');
            shell.execute('rm /tmp/gone');
            expect(vfs.exists('/tmp/gone')).toBe(false);
        });
    });

    describe('cp', () => {
        it('copies a file', () => {
            shell.execute('cp /etc/hostname /tmp/hostname-copy');
            expect(vfs.readFile('/tmp/hostname-copy')).toBe('web-server');
        });
    });

    describe('mv', () => {
        it('moves a file', () => {
            vfs.writeFile('/tmp/source', 'data');
            shell.execute('mv /tmp/source /tmp/dest');
            expect(vfs.exists('/tmp/source')).toBe(false);
            expect(vfs.readFile('/tmp/dest')).toBe('data');
        });
    });

    // ── Shell features ─────────────────────────────────────────

    describe('shell features', () => {
        it('handles empty input', () => {
            const result = shell.execute('');
            expect(result.output).toBe('');
            expect(result.exitCode).toBe(0);
        });

        it('handles comments', () => {
            const result = shell.execute('# this is a comment');
            expect(result.output).toBe('');
            expect(result.exitCode).toBe(0);
        });

        it('returns 127 for unknown commands', () => {
            const result = shell.execute('nonexistent');
            expect(result.exitCode).toBe(127);
            expect(result.output).toContain('not found');
        });

        it('handles semicolons', () => {
            const result = shell.execute('echo hello; echo world');
            expect(result.output).toBe('hello\nworld\n');
        });

        it('handles redirect to file', () => {
            shell.execute('echo hello > /tmp/output');
            expect(vfs.readFile('/tmp/output')).toBe('hello\n');
        });

        it('handles env var assignment', () => {
            shell.execute('FOO=bar');
            expect(shell.getEnv('FOO')).toBe('bar');
        });

        it('handles export', () => {
            shell.execute('export MY_VAR=test123');
            expect(shell.getEnv('MY_VAR')).toBe('test123');
        });

        it('handles quoted arguments', () => {
            shell.execute('echo "hello world" > /tmp/quoted');
            expect(vfs.readFile('/tmp/quoted')).toBe('hello world\n');
        });
    });

    // ── Prompt ─────────────────────────────────────────────────

    describe('prompt', () => {
        it('shows root prompt with #', () => {
            expect(shell.getPrompt()).toContain('#');
        });

        it('shows ~ for home directory', () => {
            expect(shell.getPrompt()).toContain('~');
        });

        it('shows full path when not home', () => {
            shell.execute('cd /etc');
            expect(shell.getPrompt()).toContain('/etc');
        });
    });

    // ── Custom commands ────────────────────────────────────────

    describe('custom commands', () => {
        it('registers and executes custom command', () => {
            shell.registerCommand('hello', () => ({ output: 'Hello from custom!\n', exitCode: 0 }));
            const result = shell.execute('hello');
            expect(result.output).toBe('Hello from custom!\n');
        });

        it('hasCommand checks for registered commands', () => {
            expect(shell.hasCommand('ls')).toBe(true);
            expect(shell.hasCommand('nonexistent')).toBe(false);
        });

        it('which finds builtin commands', () => {
            const result = shell.execute('which ls');
            expect(result.output).toContain('/usr/bin/ls');
        });

        it('which returns error for missing commands', () => {
            const result = shell.execute('which nonexistent');
            expect(result.exitCode).toBe(1);
        });
    });

    // ── Network commands (static output) ───────────────────────

    describe('network commands', () => {
        it('ifconfig shows interface info', () => {
            const result = shell.execute('ifconfig');
            expect(result.output).toContain('eth0');
            expect(result.output).toContain('10.0.0.2');
        });

        it('ip addr shows interface info', () => {
            const result = shell.execute('ip addr');
            expect(result.output).toContain('eth0');
        });

        it('ip route shows routing table', () => {
            const result = shell.execute('ip route');
            expect(result.output).toContain('default');
        });

        it('ps shows process list', () => {
            const result = shell.execute('ps');
            expect(result.output).toContain('PID');
            expect(result.output).toContain('init');
        });
    });
});
