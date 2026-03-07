/**
 * VARIANT — Test helpers
 *
 * Shared utilities for test mocks.
 */

import type { SimulationContext, ServiceLocator } from '../src/core/modules';
import { createServiceLocator } from '../src/core/modules';

/**
 * Stub fabric that satisfies SimulationContext.fabric.
 * All methods are no-ops.
 */
export function stubFabric(): SimulationContext['fabric'] {
    return {
        getTrafficLog: () => [],
        getStats: () => ({
            totalFrames: 0,
            droppedFrames: 0,
            bytesRouted: 0,
            dnsQueries: 0,
            activeConnections: 0,
        }),
        tap: () => () => { },
        addDNSRecord: () => { },
        registerExternal: () => { },
        getExternalHandler: () => undefined,
        getExternalDomains: () => [],
    };
}

/**
 * Create a real ServiceLocator for tests.
 */
export function stubServices(): ServiceLocator {
    return createServiceLocator();
}

// Re-export createEventBus for test files that need it
export { createEventBus } from '../src/core/event-bus';
