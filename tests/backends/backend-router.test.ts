/**
 * VARIANT — Backend Router tests
 */
import { describe, it, expect, vi } from 'vitest';
import { createBackendRouter } from '../../src/backends/backend-router';
import type { VMBackend, VMInstance, VMBootConfig } from '../../src/core/vm/types';

function stubBackend(name: string): VMBackend {
    let nextId = 0;
    return {
        boot: vi.fn(async (config: VMBootConfig): Promise<VMInstance> => {
            return { id: `${name}-${nextId++}`, config, state: 'running' };
        }),
        attachTerminal: vi.fn(() => ({
            sendToVM: vi.fn(),
            onOutput: vi.fn(() => () => { }),
        })),
        sendFrame: vi.fn(),
        onFrame: vi.fn(() => () => { }),
        applyOverlay: vi.fn(async () => { }),
        snapshot: vi.fn(async (vm: VMInstance) => ({
            vmId: vm.id,
            timestamp: Date.now(),
            data: new ArrayBuffer(0),
        })),
        restore: vi.fn(async () => { }),
        reset: vi.fn(async () => { }),
        destroy: vi.fn(),
    };
}

describe('BackendRouter', () => {
    it('routes boot to correct backend based on selector', async () => {
        const v86 = stubBackend('v86');
        const sim = stubBackend('sim');

        const router = createBackendRouter({
            backends: new Map([['v86', v86], ['sim', sim]]),
            selector: ({ imageUrl }) => imageUrl.includes('player') ? 'v86' : 'sim',
            fallback: 'sim',
        });

        const playerVM = await router.boot({
            imageUrl: 'https://cdn/player-alpine.bin',
            memoryMB: 128,
            networkMAC: '00:00:00:00:00:01',
            biosUrl: 'https://cdn/bios.bin',
            vgaBiosUrl: 'https://cdn/vgabios.bin',
            enableVGA: false,
        });

        const targetVM = await router.boot({
            imageUrl: 'https://cdn/webserver-nginx.bin',
            memoryMB: 64,
            networkMAC: '00:00:00:00:00:02',
            biosUrl: 'https://cdn/bios.bin',
            vgaBiosUrl: 'https://cdn/vgabios.bin',
            enableVGA: false,
        });

        expect(v86.boot).toHaveBeenCalledTimes(1);
        expect(sim.boot).toHaveBeenCalledTimes(1);
        expect(playerVM.id).toBe('v86-0');
        expect(targetVM.id).toBe('sim-0');
    });

    it('routes subsequent calls to the correct backend', async () => {
        const v86 = stubBackend('v86');
        const sim = stubBackend('sim');

        const router = createBackendRouter({
            backends: new Map([['v86', v86], ['sim', sim]]),
            selector: ({ imageUrl }) => imageUrl.includes('player') ? 'v86' : 'sim',
            fallback: 'sim',
        });

        const playerVM = await router.boot({
            imageUrl: 'https://cdn/player.bin',
            memoryMB: 128,
            networkMAC: '00:00:00:00:00:01',
            biosUrl: 'https://cdn/bios.bin',
            vgaBiosUrl: 'https://cdn/vgabios.bin',
            enableVGA: false,
        });

        router.attachTerminal(playerVM);
        expect(v86.attachTerminal).toHaveBeenCalledWith(playerVM);
        expect(sim.attachTerminal).not.toHaveBeenCalled();

        router.sendFrame(playerVM, new Uint8Array([1, 2, 3]));
        expect(v86.sendFrame).toHaveBeenCalled();
        expect(sim.sendFrame).not.toHaveBeenCalled();
    });

    it('uses fallback when selector returns unknown id', async () => {
        const sim = stubBackend('sim');

        const router = createBackendRouter({
            backends: new Map([['sim', sim]]),
            selector: () => 'unknown-id',
            fallback: 'sim',
        });

        const vm = await router.boot({
            imageUrl: 'https://cdn/test.bin',
            memoryMB: 64,
            networkMAC: '00:00:00:00:00:01',
            biosUrl: 'https://cdn/bios.bin',
            vgaBiosUrl: 'https://cdn/vgabios.bin',
            enableVGA: false,
        });

        expect(vm.id).toBe('sim-0');
        expect(sim.boot).toHaveBeenCalledTimes(1);
    });

    it('throws for unknown VM on subsequent calls', () => {
        const sim = stubBackend('sim');

        const router = createBackendRouter({
            backends: new Map([['sim', sim]]),
            selector: () => 'sim',
            fallback: 'sim',
        });

        const fakeVM: VMInstance = { id: 'nonexistent', config: {} as VMBootConfig, state: 'running' };
        expect(() => router.attachTerminal(fakeVM)).toThrow('no backend owns VM');
    });

    it('cleans up VM registry on destroy', async () => {
        const sim = stubBackend('sim');

        const router = createBackendRouter({
            backends: new Map([['sim', sim]]),
            selector: () => 'sim',
            fallback: 'sim',
        });

        const vm = await router.boot({
            imageUrl: 'https://cdn/test.bin',
            memoryMB: 64,
            networkMAC: '00:00:00:00:00:01',
            biosUrl: 'https://cdn/bios.bin',
            vgaBiosUrl: 'https://cdn/vgabios.bin',
            enableVGA: false,
        });

        router.destroy(vm);
        expect(sim.destroy).toHaveBeenCalledWith(vm);
        expect(() => router.attachTerminal(vm)).toThrow();
    });
});
