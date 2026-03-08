import { beforeEach, describe, expect, it } from 'vitest';
import { createVFS } from '../vfs/vfs';
import { createShell } from './shell';

describe('createShell (src tests)', () => {
    let shell: ReturnType<typeof createShell>;

    beforeEach(() => {
        const vfs = createVFS();
        vfs.writeFile('/etc/hostname', 'variant-host');
        vfs.writeFile('/etc/passwd', 'root:x:0:0:root:/root:/bin/sh\nuser:x:1000:1000:user:/home/user:/bin/sh\n');
        vfs.writeFile('/etc/os-release', 'NAME=VariantOS\nVERSION=1\n');
        vfs.writeFile('/tmp/note.txt', 'hello from tmp\n');

        shell = createShell({
            vfs,
            hostname: 'variant-host',
            user: 'root',
            cwd: '/root',
        });
    });

    it("execute('pwd') returns current directory", () => {
        const result = shell.execute('pwd');
        expect(result.exitCode).toBe(0);
        expect(result.output).toBe('/root\n');
    });

    it("execute('whoami') returns current user", () => {
        const result = shell.execute('whoami');
        expect(result.exitCode).toBe(0);
        expect(result.output).toBe('root\n');
    });

    it("execute('echo hello') returns hello", () => {
        const result = shell.execute('echo hello');
        expect(result.exitCode).toBe(0);
        expect(result.output).toBe('hello\n');
    });

    it("execute('ls /etc') lists etc contents", () => {
        const result = shell.execute('ls /etc');
        expect(result.exitCode).toBe(0);
        expect(result.output).toContain('hostname');
        expect(result.output).toContain('passwd');
    });

    it("execute('cat /etc/hostname') returns hostname", () => {
        const result = shell.execute('cat /etc/hostname');
        expect(result.exitCode).toBe(0);
        expect(result.output).toBe('variant-host\n');
    });

    it("execute('cd /tmp && pwd') changes directory", () => {
        const result = shell.execute('cd /tmp && pwd');
        expect(result.exitCode).toBe(0);
        expect(result.output).toBe('/tmp\n');
    });

    it("pipe execute('echo hello | cat') returns hello", () => {
        const result = shell.execute('echo hello | cat');
        expect(result.exitCode).toBe(0);
        expect(result.output).toBe('hello\n');
    });

    it("exit code for execute('false') is non-zero", () => {
        const result = shell.execute('false');
        expect(result.exitCode).not.toBe(0);
    });

    it("execute('env') shows environment variables", () => {
        const result = shell.execute('env');
        expect(result.exitCode).toBe(0);
        expect(result.output).toContain('HOME=/root');
        expect(result.output).toContain('USER=root');
    });

    it("execute('id') shows user/group info", () => {
        const result = shell.execute('id');
        expect(result.exitCode).toBe(0);
        expect(result.output).toContain('uid=0(root)');
        expect(result.output).toContain('gid=0(root)');
    });

    it("execute('uname -a') returns system info", () => {
        const result = shell.execute('uname -a');
        expect(result.exitCode).toBe(0);
        expect(result.output).toContain('Linux');
        expect(result.output).toContain('variant-host');
    });

    it("unknown command returns 'not found' and 127", () => {
        const result = shell.execute('definitely-not-a-command');
        expect(result.exitCode).toBe(127);
        expect(result.output).toContain('not found');
    });

    it('supports redirection to file and cat readback', () => {
        const write = shell.execute('echo redirected > /tmp/out.txt');
        expect(write.exitCode).toBe(0);
        const read = shell.execute('cat /tmp/out.txt');
        expect(read.exitCode).toBe(0);
        expect(read.output).toBe('redirected\n');
    });

    it('supports sequential execution with semicolons', () => {
        const result = shell.execute('echo one; echo two');
        expect(result.exitCode).toBe(0);
        expect(result.output).toBe('one\ntwo\n');
    });

    it('supports env var expansion with echo', () => {
        shell.execute('export APP_ENV=test');
        const result = shell.execute('echo $APP_ENV');
        expect(result.exitCode).toBe(0);
        expect(result.output).toBe('test\n');
    });

    it('tracks current directory after cd and pwd calls', () => {
        shell.execute('cd /tmp');
        const result = shell.execute('pwd');
        expect(result.exitCode).toBe(0);
        expect(result.output).toBe('/tmp\n');
    });
});
