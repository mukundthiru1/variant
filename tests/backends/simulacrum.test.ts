/**
 * VARIANT — Simulacrum Backend tests
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { createSimulacrumBackend } from '../../src/backends/simulacrum';
import type { VMBackend, VMInstance, VMBootConfig } from '../../src/core/vm/types';
import type { SimulacrumConfig } from '../../src/backends/simulacrum';

const baseConfig: VMBootConfig = {
    imageUrl: 'https://cdn/webserver.bin',
    memoryMB: 64,
    networkMAC: '00:11:22:33:44:55',
    biosUrl: 'https://cdn/bios.bin',
    vgaBiosUrl: 'https://cdn/vgabios.bin',
    enableVGA: false,
};

describe('SimulacrumBackend', () => {
    let backend: VMBackend;
    let vm: VMInstance;

    // ── Boot ────────────────────────────────────────────────────

    describe('boot', () => {
        it('boots and returns a running VM instance', async () => {
            backend = createSimulacrumBackend();
            vm = await backend.boot(baseConfig);
            expect(vm.state).toBe('running');
            expect(vm.id).toContain('simulacrum');
        });

        it('creates unique IDs for each VM', async () => {
            backend = createSimulacrumBackend();
            const vm1 = await backend.boot(baseConfig);
            const vm2 = await backend.boot({ ...baseConfig, networkMAC: '00:11:22:33:44:66' });
            expect(vm1.id).not.toBe(vm2.id);
        });
    });

    // ── Terminal I/O ────────────────────────────────────────────

    describe('terminal', () => {
        beforeEach(async () => {
            backend = createSimulacrumBackend(new Map([
                ['webserver', {
                    hostname: 'web-01',
                    defaultUser: 'root',
                } as SimulacrumConfig],
            ]));
            vm = await backend.boot(baseConfig);
        });

        it('attaches terminal and receives output', async () => {
            const termIO = backend.attachTerminal(vm);
            const output: number[] = [];
            termIO.onOutput((byte) => output.push(byte));

            // Wait for initial prompt
            await new Promise(resolve => setTimeout(resolve, 50));

            expect(output.length).toBeGreaterThan(0);
            const text = new TextDecoder().decode(new Uint8Array(output));
            expect(text).toContain('web-01');
        });

        it('processes command and returns output', async () => {
            const termIO = backend.attachTerminal(vm);
            const output: number[] = [];
            termIO.onOutput((byte) => output.push(byte));

            // Wait for initial prompt
            await new Promise(resolve => setTimeout(resolve, 50));
            output.length = 0; // Clear initial output

            // Type "echo hello" + enter
            termIO.sendToVM('echo hello\r');

            // Allow processing
            await new Promise(resolve => setTimeout(resolve, 10));

            const text = new TextDecoder().decode(new Uint8Array(output));
            expect(text).toContain('hello');
        });

        it('handles backspace', async () => {
            const termIO = backend.attachTerminal(vm);
            const output: number[] = [];
            termIO.onOutput((byte) => output.push(byte));

            await new Promise(resolve => setTimeout(resolve, 50));
            output.length = 0;

            // Type "echp" then backspace, then "o hello" + enter
            termIO.sendToVM('echp\x7fo hello\r');

            await new Promise(resolve => setTimeout(resolve, 10));

            const text = new TextDecoder().decode(new Uint8Array(output));
            expect(text).toContain('hello');
        });

        it('handles Ctrl+C', async () => {
            const termIO = backend.attachTerminal(vm);
            const output: number[] = [];
            termIO.onOutput((byte) => output.push(byte));

            await new Promise(resolve => setTimeout(resolve, 50));
            output.length = 0;

            termIO.sendToVM('some partial command\x03');

            await new Promise(resolve => setTimeout(resolve, 10));

            const text = new TextDecoder().decode(new Uint8Array(output));
            expect(text).toContain('^C');
        });
    });

    // ── Overlay ─────────────────────────────────────────────────

    describe('overlay', () => {
        beforeEach(async () => {
            backend = createSimulacrumBackend();
            vm = await backend.boot(baseConfig);
        });

        it('applies filesystem overlay', async () => {
            await backend.applyOverlay(vm, {
                files: new Map([
                    ['/etc/custom.conf', { content: 'setting=true' }],
                ]),
            });

            const termIO = backend.attachTerminal(vm);
            const output: number[] = [];
            termIO.onOutput((byte) => output.push(byte));

            await new Promise(resolve => setTimeout(resolve, 50));
            output.length = 0;

            termIO.sendToVM('cat /etc/custom.conf\r');

            await new Promise(resolve => setTimeout(resolve, 10));

            const text = new TextDecoder().decode(new Uint8Array(output));
            expect(text).toContain('setting=true');
        });
    });

    // ── Snapshot / Restore ──────────────────────────────────────

    describe('snapshot', () => {
        beforeEach(async () => {
            backend = createSimulacrumBackend();
            vm = await backend.boot(baseConfig);
        });

        it('creates a snapshot', async () => {
            const snap = await backend.snapshot(vm);
            expect(snap.vmId).toBe(vm.id);
            expect(snap.data.byteLength).toBeGreaterThan(0);
        });

        it('restores from snapshot', async () => {
            // Write a file
            await backend.applyOverlay(vm, {
                files: new Map([
                    ['/tmp/before-snap', { content: 'before' }],
                ]),
            });

            const snap = await backend.snapshot(vm);

            // Write another file after snapshot
            await backend.applyOverlay(vm, {
                files: new Map([
                    ['/tmp/after-snap', { content: 'after' }],
                ]),
            });

            // Restore
            await backend.restore(vm, snap);

            // The "before" file should exist, "after" should not
            const termIO = backend.attachTerminal(vm);
            const output: number[] = [];
            termIO.onOutput((byte) => output.push(byte));

            await new Promise(resolve => setTimeout(resolve, 50));
            output.length = 0;

            termIO.sendToVM('cat /tmp/before-snap\r');
            await new Promise(resolve => setTimeout(resolve, 10));

            const text1 = new TextDecoder().decode(new Uint8Array(output));
            expect(text1).toContain('before');
        });
    });

    // ── Custom configuration ────────────────────────────────────

    describe('custom config', () => {
        it('uses configured processes for ps output', async () => {
            backend = createSimulacrumBackend(new Map([
                ['webserver', {
                    hostname: 'web-01',
                    processes: [
                        { pid: 1, user: 'root', command: 'init' },
                        { pid: 100, user: 'www-data', command: 'nginx', args: '-g "daemon off;"' },
                        { pid: 200, user: 'mysql', command: 'mysqld' },
                    ],
                } as SimulacrumConfig],
            ]));

            vm = await backend.boot(baseConfig);
            const termIO = backend.attachTerminal(vm);
            const output: number[] = [];
            termIO.onOutput((byte) => output.push(byte));

            await new Promise(resolve => setTimeout(resolve, 50));
            output.length = 0;

            termIO.sendToVM('ps\r');
            await new Promise(resolve => setTimeout(resolve, 10));

            const text = new TextDecoder().decode(new Uint8Array(output));
            expect(text).toContain('nginx');
            expect(text).toContain('mysqld');
        });

        it('uses configured network for ifconfig', async () => {
            backend = createSimulacrumBackend(new Map([
                ['webserver', {
                    hostname: 'web-01',
                    networkConfig: {
                        interfaces: [
                            { name: 'eth0', ip: '10.0.1.10', mac: '00:11:22:33:44:55', netmask: '255.255.255.0' },
                        ],
                    },
                } as SimulacrumConfig],
            ]));

            vm = await backend.boot(baseConfig);
            const termIO = backend.attachTerminal(vm);
            const output: number[] = [];
            termIO.onOutput((byte) => output.push(byte));

            await new Promise(resolve => setTimeout(resolve, 50));
            output.length = 0;

            termIO.sendToVM('ifconfig\r');
            await new Promise(resolve => setTimeout(resolve, 10));

            const text = new TextDecoder().decode(new Uint8Array(output));
            expect(text).toContain('10.0.1.10');
        });
    });

    // ── Destroy ─────────────────────────────────────────────────

    describe('destroy', () => {
        it('cleans up resources', async () => {
            backend = createSimulacrumBackend();
            vm = await backend.boot(baseConfig);
            backend.destroy(vm);

            // Subsequent calls should throw
            expect(() => backend.attachTerminal(vm)).toThrow();
        });
    });
});
