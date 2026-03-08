/**
 * VARIANT — Backend Router Implementation
 *
 * Implements VMBackend by delegating to registered backends
 * based on a selector function. The engine passes this as its
 * single backend. The router decides which real backend handles
 * each VM.
 *
 * VM ID → backend mapping is tracked so that subsequent calls
 * (sendFrame, attachTerminal, destroy) go to the correct backend.
 *
 * REPLACEABILITY: Implements VMBackend. Swap this file.
 * Nothing else changes.
 */

import type {
    VMBackend,
    VMBootConfig,
    VMInstance,
    VMSnapshot,
    TerminalIO,
    FilesystemOverlay,
} from '../core/vm/types';
import type { Unsubscribe } from '../core/events';
import type { BackendRouterConfig } from './types';

export function createBackendRouter(config: BackendRouterConfig): VMBackend {
    /** Tracks which backend owns each VM instance. */
    const vmOwners = new Map<string, VMBackend>();

    function getOwner(vm: VMInstance): VMBackend {
        const owner = vmOwners.get(vm.id);
        if (owner === undefined) {
            throw new Error(`BackendRouter: no backend owns VM '${vm.id}'`);
        }
        return owner;
    }

    function selectBackend(bootConfig: VMBootConfig): VMBackend {
        const id = config.selector({
            imageUrl: bootConfig.imageUrl,
            memoryMB: bootConfig.memoryMB,
            networkMAC: bootConfig.networkMAC,
        });

        const backend = config.backends.get(id);
        if (backend !== undefined) return backend;

        const fallback = config.backends.get(config.fallback);
        if (fallback !== undefined) return fallback;

        throw new Error(`BackendRouter: no backend registered for '${id}' and fallback '${config.fallback}' not found`);
    }

    const router: VMBackend = {
        async boot(bootConfig: VMBootConfig): Promise<VMInstance> {
            const backend = selectBackend(bootConfig);
            const vm = await backend.boot(bootConfig);
            vmOwners.set(vm.id, backend);
            return vm;
        },

        attachTerminal(vm: VMInstance): TerminalIO {
            return getOwner(vm).attachTerminal(vm);
        },

        sendFrame(vm: VMInstance, frame: Uint8Array): void {
            getOwner(vm).sendFrame(vm, frame);
        },

        onFrame(vm: VMInstance, handler: (frame: Uint8Array) => void): Unsubscribe {
            return getOwner(vm).onFrame(vm, handler);
        },

        async applyOverlay(vm: VMInstance, overlay: FilesystemOverlay): Promise<void> {
            await getOwner(vm).applyOverlay(vm, overlay);
        },

        async snapshot(vm: VMInstance): Promise<VMSnapshot> {
            return getOwner(vm).snapshot(vm);
        },

        async restore(vm: VMInstance, snap: VMSnapshot): Promise<void> {
            await getOwner(vm).restore(vm, snap);
        },

        async reset(vm: VMInstance): Promise<void> {
            await getOwner(vm).reset(vm);
        },

        setEmitter(vmId: string, emit: (event: { type: string; [key: string]: unknown }) => void): void {
            // Forward to all backends — only the owning backend will have this VM
            for (const backend of config.backends.values()) {
                backend.setEmitter?.(vmId, emit);
            }
        },

        destroy(vm: VMInstance): void {
            const owner = vmOwners.get(vm.id);
            if (owner !== undefined) {
                owner.destroy(vm);
                vmOwners.delete(vm.id);
            }
        },
    };

    return router;
}
