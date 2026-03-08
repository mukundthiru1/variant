import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createSimulacrumBackend } from './simulacrum';
import type { VMBootConfig, VMInstance, VMBackend, TerminalIO } from '../core/vm/types';

const bootConfig: VMBootConfig = {
    imageUrl: 'https://cdn.example.com/webserver.bin',
    memoryMB: 64,
    networkMAC: '00:11:22:33:44:55',
    biosUrl: 'https://cdn.example.com/bios.bin',
    vgaBiosUrl: 'https://cdn.example.com/vgabios.bin',
    enableVGA: false,
};

function decodeOutput(bytes: number[]): string {
    return new TextDecoder().decode(new Uint8Array(bytes));
}

function setupTerminal(io: TerminalIO): number[] {
    const output: number[] = [];
    io.onOutput((byte) => output.push(byte));
    vi.runAllTimers();
    return output;
}

function runCommand(io: TerminalIO, output: number[], command: string): string {
    output.length = 0;
    io.sendToVM(`${command}\r`);
    return decodeOutput(output);
}

describe('createSimulacrumBackend (src tests)', () => {
    let backend: VMBackend;
    let vm: VMInstance;

    beforeEach(async () => {
        vi.useFakeTimers();
        backend = createSimulacrumBackend();
        vm = await backend.boot(bootConfig);
    });

    it('boot() creates an instance with a valid id', () => {
        expect(vm.id).toMatch(/^simulacrum-\d+$/);
    });

    it("boot() sets instance state to 'running'", () => {
        expect(vm.state).toBe('running');
    });

    it('attachTerminal() returns TerminalIO with sendToVM and onOutput', () => {
        const io = backend.attachTerminal(vm);
        expect(typeof io.sendToVM).toBe('function');
        expect(typeof io.onOutput).toBe('function');
    });

    it('terminal writes + CR and echoes command/output', () => {
        const io = backend.attachTerminal(vm);
        const output = setupTerminal(io);
        const text = runCommand(io, output, 'echo hello');
        expect(text).toContain('echo hello');
        expect(text).toContain('hello');
    });

    it('shell command ls returns directory contents', () => {
        const io = backend.attachTerminal(vm);
        const output = setupTerminal(io);
        const text = runCommand(io, output, 'ls /etc');
        expect(text).toContain('hostname');
    });

    it('shell command cat returns file contents', () => {
        const io = backend.attachTerminal(vm);
        const output = setupTerminal(io);
        const text = runCommand(io, output, 'cat /etc/hostname');
        expect(text).toContain('webserver');
    });

    it('shell command pwd returns current directory', () => {
        const io = backend.attachTerminal(vm);
        const output = setupTerminal(io);
        const text = runCommand(io, output, 'pwd');
        expect(text).toContain('/root');
    });

    it('shell command whoami returns current user', () => {
        const io = backend.attachTerminal(vm);
        const output = setupTerminal(io);
        const text = runCommand(io, output, 'whoami');
        expect(text).toContain('root');
    });

    it('shell command echo returns provided text', () => {
        const io = backend.attachTerminal(vm);
        const output = setupTerminal(io);
        const text = runCommand(io, output, 'echo variant');
        expect(text).toContain('variant');
    });

    it('applyOverlay() makes overlaid files accessible via cat', async () => {
        await backend.applyOverlay(vm, {
            files: new Map([
                ['/etc/banner', { content: 'authorized users only' }],
            ]),
        });
        const io = backend.attachTerminal(vm);
        const output = setupTerminal(io);
        const text = runCommand(io, output, 'cat /etc/banner');
        expect(text).toContain('authorized users only');
    });

    it('VFS mkdir and writeFile behavior works via shell commands', () => {
        const io = backend.attachTerminal(vm);
        const output = setupTerminal(io);
        runCommand(io, output, 'mkdir -p /tmp/a/b');
        runCommand(io, output, 'echo payload > /tmp/a/b/file.txt');
        const text = runCommand(io, output, 'cat /tmp/a/b/file.txt');
        expect(text).toContain('payload');
    });

    it('destroy() cleans up and prevents further interaction', () => {
        backend.destroy(vm);
        expect(() => backend.attachTerminal(vm)).toThrow(/not found/);
    });

    it('can boot multiple instances independently', async () => {
        const vm2 = await backend.boot({
            ...bootConfig,
            imageUrl: 'https://cdn.example.com/dbserver.bin',
            networkMAC: '00:11:22:33:44:66',
        });
        await backend.applyOverlay(vm, { files: new Map([['/tmp/owner', { content: 'one' }]]) });
        await backend.applyOverlay(vm2, { files: new Map([['/tmp/owner', { content: 'two' }]]) });

        const io1 = backend.attachTerminal(vm);
        const output1 = setupTerminal(io1);
        const io2 = backend.attachTerminal(vm2);
        const output2 = setupTerminal(io2);

        expect(runCommand(io1, output1, 'cat /tmp/owner')).toContain('one');
        expect(runCommand(io2, output2, 'cat /tmp/owner')).toContain('two');
    });

    it('snapshot() captures state and restore() reverts changes', async () => {
        await backend.applyOverlay(vm, { files: new Map([['/tmp/state', { content: 'before' }]]) });
        const snap = await backend.snapshot(vm);
        await backend.applyOverlay(vm, { files: new Map([['/tmp/state', { content: 'after' }]]) });
        await backend.restore(vm, snap);

        const io = backend.attachTerminal(vm);
        const output = setupTerminal(io);
        const text = runCommand(io, output, 'cat /tmp/state');
        expect(text).toContain('before');
        expect(text).not.toContain('after');
    });

    it('reset() restores initial filesystem state', async () => {
        await backend.applyOverlay(vm, { files: new Map([['/tmp/reset-me', { content: 'transient' }]]) });
        await backend.reset(vm);
        const io = backend.attachTerminal(vm);
        const output = setupTerminal(io);
        const text = runCommand(io, output, 'cat /tmp/reset-me');
        expect(text).toContain('No such file or directory');
    });

    it('onFrame receives frames sent via sendFrame', () => {
        const frame = new Uint8Array([1, 2, 3]);
        const received: Uint8Array[] = [];
        backend.onFrame(vm, (f) => received.push(f));
        backend.sendFrame(vm, frame);
        expect(received).toHaveLength(1);
        expect(Array.from(received[0] ?? [])).toEqual([1, 2, 3]);
    });
});
