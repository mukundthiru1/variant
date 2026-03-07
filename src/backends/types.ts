/**
 * VARIANT — Backend Router Contract
 *
 * A composite VMBackend that delegates to different backend
 * implementations based on a routing function.
 *
 * This allows the engine (which takes a single VMBackend)
 * to transparently use v86 for player machines and
 * Simulacra for everything else — WITHOUT modifying the
 * engine or any core code.
 *
 * DESIGN: The engine sees one VMBackend.
 * The router sees many. Zero core changes.
 */

import type { VMBackend } from '../core/vm/types';

// ── Types ──────────────────────────────────────────────────────

/**
 * Strategy for selecting which backend handles a given boot request.
 * Returns a backend ID string. The router maps this to a registered backend.
 */
export type BackendSelector = (config: {
    readonly imageUrl: string;
    readonly memoryMB: number;
    readonly networkMAC: string;
}) => string;

/**
 * Configuration for the backend router.
 */
export interface BackendRouterConfig {
    /** Map of backend ID → VMBackend implementation. */
    readonly backends: ReadonlyMap<string, VMBackend>;
    /** Function that decides which backend to use for a given VM. */
    readonly selector: BackendSelector;
    /** Fallback backend ID if selector returns unknown ID. */
    readonly fallback: string;
}
