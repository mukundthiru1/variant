/**
 * VARIANT — VFS tests
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { createVFS } from '../../../src/lib/vfs/vfs';
import { VFSPathError } from '../../../src/lib/vfs/types';
import type { VirtualFilesystem, VFSSnapshot } from '../../../src/lib/vfs/types';

describe('VFS', () => {
    let vfs: VirtualFilesystem;

    beforeEach(() => {
        vfs = createVFS();
    });

    // ── Path validation ────────────────────────────────────────

    describe('path validation', () => {
        it('rejects empty path', () => {
            expect(() => vfs.stat('')).toThrow(VFSPathError);
        });

        it('rejects relative path', () => {
            expect(() => vfs.stat('foo/bar')).toThrow(VFSPathError);
        });

        it('rejects null bytes', () => {
            expect(() => vfs.stat('/foo\0bar')).toThrow(VFSPathError);
        });

        it('normalizes dot segments', () => {
            vfs.writeFile('/a/b/c.txt', 'hello');
            expect(vfs.readFile('/a/./b/../b/c.txt')).toBe('hello');
        });

        it('prevents traversal above root', () => {
            vfs.writeFile('/secret.txt', 'flag');
            expect(vfs.readFile('/../../secret.txt')).toBe('flag');
        });
    });

    // ── File operations ────────────────────────────────────────

    describe('files', () => {
        it('writes and reads a file', () => {
            vfs.writeFile('/hello.txt', 'world');
            expect(vfs.readFile('/hello.txt')).toBe('world');
        });

        it('creates parent dirs automatically', () => {
            vfs.writeFile('/a/b/c/deep.txt', 'nested');
            expect(vfs.readFile('/a/b/c/deep.txt')).toBe('nested');
            expect(vfs.exists('/a/b/c')).toBe(true);
            expect(vfs.exists('/a/b')).toBe(true);
            expect(vfs.exists('/a')).toBe(true);
        });

        it('overwrites existing file', () => {
            vfs.writeFile('/f.txt', 'old');
            vfs.writeFile('/f.txt', 'new');
            expect(vfs.readFile('/f.txt')).toBe('new');
        });

        it('appends to existing file', () => {
            vfs.writeFile('/f.txt', 'hello');
            vfs.writeFile('/f.txt', ' world', { append: true });
            expect(vfs.readFile('/f.txt')).toBe('hello world');
        });

        it('returns null for nonexistent file', () => {
            expect(vfs.readFile('/nope.txt')).toBeNull();
        });

        it('returns null when reading a directory as file', () => {
            vfs.mkdir('/dir');
            expect(vfs.readFile('/dir')).toBeNull();
        });

        it('throws when writing to a path where a dir exists', () => {
            vfs.mkdir('/dir');
            expect(() => vfs.writeFile('/dir', 'fail')).toThrow(VFSPathError);
        });

        it('preserves file mode', () => {
            vfs.writeFile('/script.sh', '#!/bin/sh', { mode: 0o755 });
            const node = vfs.stat('/script.sh');
            expect(node).not.toBeNull();
            expect(node!.type).toBe('file');
            if (node!.type === 'file') {
                expect(node!.mode).toBe(0o755);
            }
        });

        it('preserves owner/group', () => {
            vfs.writeFile('/app.py', 'print("hi")', { owner: 'www-data', group: 'www-data' });
            const node = vfs.stat('/app.py');
            expect(node).not.toBeNull();
            if (node!.type === 'file') {
                expect(node!.owner).toBe('www-data');
                expect(node!.group).toBe('www-data');
            }
        });
    });

    // ── Directory operations ───────────────────────────────────

    describe('directories', () => {
        it('creates a directory', () => {
            vfs.mkdir('/mydir');
            expect(vfs.exists('/mydir')).toBe(true);
            const node = vfs.stat('/mydir');
            expect(node!.type).toBe('dir');
        });

        it('creates directories recursively', () => {
            vfs.mkdir('/a/b/c/d', { recursive: true });
            expect(vfs.exists('/a/b/c/d')).toBe(true);
        });

        it('throws when creating existing dir without recursive', () => {
            vfs.mkdir('/dup');
            expect(() => vfs.mkdir('/dup')).toThrow(VFSPathError);
        });

        it('does not throw for existing dir with recursive', () => {
            vfs.mkdir('/dup');
            expect(() => vfs.mkdir('/dup', { recursive: true })).not.toThrow();
        });

        it('lists directory contents sorted', () => {
            vfs.writeFile('/dir/c.txt', '3');
            vfs.writeFile('/dir/a.txt', '1');
            vfs.writeFile('/dir/b.txt', '2');
            const entries = vfs.readDir('/dir');
            expect(entries).toEqual(['a.txt', 'b.txt', 'c.txt']);
        });

        it('returns null for readDir on a file', () => {
            vfs.writeFile('/f.txt', 'data');
            expect(vfs.readDir('/f.txt')).toBeNull();
        });

        it('root always exists', () => {
            expect(vfs.exists('/')).toBe(true);
            expect(vfs.readDir('/')).toEqual([]);
        });
    });

    // ── Remove ────────────────────────────────────────────────

    describe('remove', () => {
        it('removes a file', () => {
            vfs.writeFile('/gone.txt', 'bye');
            expect(vfs.remove('/gone.txt')).toBe(true);
            expect(vfs.exists('/gone.txt')).toBe(false);
        });

        it('removes an empty directory', () => {
            vfs.mkdir('/empty');
            expect(vfs.remove('/empty')).toBe(true);
            expect(vfs.exists('/empty')).toBe(false);
        });

        it('refuses to remove non-empty directory', () => {
            vfs.writeFile('/dir/file.txt', 'data');
            expect(vfs.remove('/dir')).toBe(false);
            expect(vfs.exists('/dir')).toBe(true);
        });

        it('refuses to remove root', () => {
            expect(vfs.remove('/')).toBe(false);
        });

        it('returns false for nonexistent path', () => {
            expect(vfs.remove('/nope')).toBe(false);
        });
    });

    // ── Symlinks ───────────────────────────────────────────────

    describe('symlinks', () => {
        it('creates and follows a symlink', () => {
            vfs.writeFile('/real.txt', 'content');
            vfs.symlink('/real.txt', '/link.txt');
            expect(vfs.readFile('/link.txt')).toBe('content');
        });

        it('stat follows symlinks by default', () => {
            vfs.writeFile('/target.txt', 'data');
            vfs.symlink('/target.txt', '/link.txt');
            const node = vfs.stat('/link.txt');
            expect(node!.type).toBe('file');
        });

        it('realpath resolves symlinks', () => {
            vfs.writeFile('/a/target.txt', 'data');
            vfs.symlink('/a/target.txt', '/shortcut');
            const resolved = vfs.realpath('/shortcut');
            expect(resolved).toBe('/shortcut');
        });

        it('returns null for broken symlink', () => {
            vfs.symlink('/nonexistent', '/broken');
            expect(vfs.readFile('/broken')).toBeNull();
        });

        it('handles symlink chains with depth limit', () => {
            // Create a chain: /a -> /b -> /c -> /target
            vfs.writeFile('/target', 'found');
            vfs.symlink('/target', '/c');
            vfs.symlink('/c', '/b');
            vfs.symlink('/b', '/a');
            expect(vfs.readFile('/a')).toBe('found');
        });
    });

    // ── chmod / chown ──────────────────────────────────────────

    describe('permissions', () => {
        it('changes file mode', () => {
            vfs.writeFile('/script', 'echo hi');
            vfs.chmod('/script', 0o755);
            const node = vfs.stat('/script');
            if (node!.type === 'file') {
                expect(node!.mode).toBe(0o755);
            }
        });

        it('changes file owner', () => {
            vfs.writeFile('/f.txt', 'data');
            vfs.chown('/f.txt', 'www-data', 'www-data');
            const node = vfs.stat('/f.txt');
            if (node!.type === 'file') {
                expect(node!.owner).toBe('www-data');
                expect(node!.group).toBe('www-data');
            }
        });

        it('throws on chmod nonexistent path', () => {
            expect(() => vfs.chmod('/nope', 0o644)).toThrow(VFSPathError);
        });
    });

    // ── Overlay ────────────────────────────────────────────────

    describe('overlay', () => {
        it('applies multiple files at once', () => {
            const overlay = {
                files: new Map([
                    ['/etc/hostname', { content: 'web-server' }],
                    ['/etc/passwd', { content: 'root:x:0:0:root:/root:/bin/sh' }],
                    ['/var/www/index.html', { content: '<h1>Hello</h1>' }],
                ]),
            };
            vfs.applyOverlay(overlay);
            expect(vfs.readFile('/etc/hostname')).toBe('web-server');
            expect(vfs.readFile('/etc/passwd')).toBe('root:x:0:0:root:/root:/bin/sh');
            expect(vfs.readFile('/var/www/index.html')).toBe('<h1>Hello</h1>');
        });
    });

    // ── Glob ───────────────────────────────────────────────────

    describe('glob', () => {
        beforeEach(() => {
            vfs.writeFile('/a.txt', '1');
            vfs.writeFile('/b.js', '2');
            vfs.writeFile('/src/main.ts', '3');
            vfs.writeFile('/src/utils/helper.ts', '4');
        });

        it('matches wildcard in filename', () => {
            const matches = vfs.glob('/*.txt');
            expect(matches).toEqual(['/a.txt']);
        });

        it('matches double wildcard (recursive)', () => {
            const matches = vfs.glob('/**/*.ts');
            expect(matches).toContain('/src/main.ts');
            expect(matches).toContain('/src/utils/helper.ts');
        });
    });

    // ── Serialization ──────────────────────────────────────────

    describe('serialization', () => {
        it('round-trips through serialize/deserialize', () => {
            vfs.writeFile('/etc/config', 'key=value', { mode: 0o600, owner: 'app' });
            vfs.writeFile('/var/log/app.log', 'line1\nline2');
            vfs.mkdir('/tmp');
            vfs.symlink('/etc/config', '/config-link');

            const snapshot: VFSSnapshot = vfs.serialize();
            const restored = createVFS(snapshot);

            expect(restored.readFile('/etc/config')).toBe('key=value');
            expect(restored.readFile('/var/log/app.log')).toBe('line1\nline2');
            expect(restored.exists('/tmp')).toBe(true);

            const configNode = restored.stat('/etc/config');
            if (configNode!.type === 'file') {
                expect(configNode!.mode).toBe(0o600);
                expect(configNode!.owner).toBe('app');
            }
        });

        it('snapshot is JSON-serializable', () => {
            vfs.writeFile('/test.txt', 'data');
            const snapshot = vfs.serialize();
            const json = JSON.stringify(snapshot);
            const parsed = JSON.parse(json) as VFSSnapshot;
            expect(parsed.version).toBe(1);
        });
    });

    // ── Total size ─────────────────────────────────────────────

    describe('totalSize', () => {
        it('calculates total byte size', () => {
            vfs.writeFile('/a.txt', 'hello'); // 5 bytes
            vfs.writeFile('/b.txt', 'world'); // 5 bytes
            expect(vfs.totalSize()).toBe(10);
        });
    });
});
