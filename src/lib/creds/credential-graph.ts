/**
 * VARIANT — Credential Graph Runtime
 *
 * The attack graph backbone. Manages the lifecycle of every credential
 * in the simulation: discovery, validation, rotation, and tracking.
 *
 * Level designers define credentials as pure data in the WorldSpec:
 *   { id, type, value, foundAt, validAt }
 *
 * This runtime:
 *   1. Watches fs:read events → auto-discovers credentials in files
 *   2. Validates credential usage (SSH login, DB auth, etc.)
 *   3. Emits auth:credential-found when a credential is discovered
 *   4. Tracks which credentials the player has found
 *   5. Supports credential rotation (via dynamics engine)
 *   6. Provides the credential graph for objective detection
 *
 * SECURITY:
 *   - Read-only access to credential definitions
 *   - Never exposes credential values to modules that don't need them
 *   - Validation is constant-time (no timing oracle)
 *   - Rotation invalidates old values immediately
 *
 * MODULARITY:
 *   - Pure function of WorldSpec data → graph runtime
 *   - No dependencies on core/ (only lib types + event types)
 *   - Testable in isolation with a mock event bus
 *   - Replace this file in 20 years. The contract stays.
 *
 * ARCHITECTURE:
 *   The credential graph is a bipartite graph:
 *     Locations ──foundAt──▶ Credential ──validAt──▶ Targets
 *
 *   A credential has two sides:
 *     - WHERE it can be found (file path, env var, service output)
 *     - WHERE it can be used (SSH, MySQL, API, etc.)
 *
 *   The graph enables:
 *     - "Player read a file that contains a password" → auto-discover
 *     - "Player tries to SSH with this password" → validate
 *     - "NPC rotated the password" → invalidate old edge, create new
 *     - "Has the player found all credentials?" → objective detection
 */

import type {
    CredentialEntry,
    CredentialType,
} from '../../core/world/types';
import type {
    EventBus,
    Unsubscribe,
    AuthCredentialFoundEvent,
} from '../../core/events';

// ── Constants ──────────────────────────────────────────────────

/** Maximum credentials per simulation. Prevents DoS from malicious WorldSpecs. */
const MAX_CREDENTIALS = 500;

/**
 * Maximum content scan length per file.
 * When checking whether a file contains a credential value,
 * we only scan the first MAX_SCAN_BYTES characters.
 * This prevents DoS from enormous files.
 */
const MAX_SCAN_BYTES = 65_536;

// ── Types ──────────────────────────────────────────────────────

/**
 * The state of a credential in the simulation.
 * Immutable from the outside — only the graph runtime mutates this.
 */
export interface CredentialState {
    /** The original credential definition from the WorldSpec. */
    readonly entry: CredentialEntry;
    /** Whether the player has discovered this credential. */
    readonly discovered: boolean;
    /** Timestamp of discovery (ms since epoch). -1 if not discovered. */
    readonly discoveredAt: number;
    /** How the credential was discovered. */
    readonly discoveryMethod: string;
    /** Current value (may change via rotation). */
    readonly currentValue: string;
    /** Whether this credential has been used successfully. */
    readonly used: boolean;
}

/**
 * Result of a credential validation attempt.
 */
export interface ValidationResult {
    /** Whether the credential is valid for the target. */
    readonly valid: boolean;
    /** The matched credential ID, if valid. */
    readonly credentialId: string | null;
    /** Human-readable reason for rejection, if invalid. */
    readonly reason: string;
}

/**
 * The credential graph runtime.
 * Created once per simulation. Destroyed when the simulation ends.
 */
export interface CredentialGraph {
    /**
     * Validate a credential attempt against the graph.
     * Used by SSH service, database service, etc.
     *
     * @param machine  - Target machine ID
     * @param service  - Service name (e.g., 'ssh', 'mysql')
     * @param user     - Username being authenticated
     * @param value    - Credential value (password, key, token)
     * @param type     - Credential type
     * @returns        - Validation result
     */
    validate(
        machine: string,
        service: string,
        user: string,
        value: string,
        type?: CredentialType,
    ): ValidationResult;

    /**
     * Mark a credential as discovered.
     * Emits auth:credential-found event.
     *
     * @param credentialId - The credential ID from WorldSpec
     * @param machine      - Machine where it was found
     * @param location     - How/where it was found
     */
    discover(credentialId: string, machine: string, location: string): void;

    /**
     * Check if a file at the given path on the given machine
     * contains any credential values. If so, auto-discover them.
     *
     * Used by the fs:read event handler.
     *
     * @param machine    - Machine ID
     * @param path       - File path that was read
     * @param content    - File content (will be truncated to MAX_SCAN_BYTES)
     */
    scanFileForCredentials(machine: string, path: string, content: string): void;

    /**
     * Rotate a credential value. The old value becomes invalid immediately.
     * Used by the dynamics engine's 'rotate-credential' action.
     *
     * @param credentialId - The credential to rotate
     * @param newValue     - The new credential value
     */
    rotate(credentialId: string, newValue: string): void;

    /**
     * Get the state of a specific credential.
     */
    getState(credentialId: string): CredentialState | null;

    /**
     * Get all credential states.
     */
    getAllStates(): readonly CredentialState[];

    /**
     * Get all discovered credential IDs.
     */
    getDiscovered(): readonly string[];

    /**
     * Check if a specific credential has been discovered.
     */
    isDiscovered(credentialId: string): boolean;

    /**
     * Get credentials that are valid at a specific target.
     * Used internally for validation — does not expose values.
     *
     * @param machine - Target machine
     * @param service - Target service
     * @param user    - Target user
     * @returns       - Credential IDs (not values)
     */
    getCredentialsFor(machine: string, service: string, user: string): readonly string[];

    /**
     * Get credentials found at a specific location.
     *
     * @param machine - Source machine
     * @param path    - File path (optional)
     * @returns       - Credential IDs
     */
    getCredentialsAt(machine: string, path?: string): readonly string[];

    /**
     * Connect the credential graph to the event bus.
     * Subscribes to fs:read events for auto-discovery.
     * Subscribes to custom:dynamics-rotate-cred for rotation.
     * Returns an array of unsubscribe functions.
     */
    connect(events: EventBus): readonly Unsubscribe[];

    /**
     * Get a human-readable summary of the credential graph.
     * For debugging and tests only.
     */
    debugSummary(): string;
}

// ── Internal types ─────────────────────────────────────────────

/**
 * Mutable internal state for a credential.
 * The CredentialState returned to consumers is a frozen snapshot.
 */
interface MutableCredentialState {
    readonly entry: CredentialEntry;
    discovered: boolean;
    discoveredAt: number;
    discoveryMethod: string;
    currentValue: string;
    used: boolean;
}

/**
 * Index key for target lookups.
 * Format: "machine:service:user"
 */
function targetKey(machine: string, service: string, user: string): string {
    return `${machine}\0${service}\0${user}`;
}

/**
 * Index key for location lookups.
 * Format: "machine:path" or "machine" (if no path)
 */
function locationKey(machine: string, path?: string): string {
    return path !== undefined ? `${machine}\0${path}` : machine;
}

// ── Constant-time string comparison ────────────────────────────

/**
 * Constant-time string comparison to prevent timing oracles.
 * An attacker in the simulation could theoretically measure
 * response times to deduce credential values character by character.
 *
 * This is defense-in-depth. The simulation is client-side so
 * timing attacks are largely moot, but we enforce correctness
 * because this same code pattern will be used on server paths.
 */
function constantTimeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) {
        // Still do a full comparison to keep timing constant
        // relative to the shorter string's length.
        // We XOR against the longer string padded with nulls.
        const maxLen = Math.max(a.length, b.length);
        let diff = a.length ^ b.length; // non-zero → different lengths
        for (let i = 0; i < maxLen; i++) {
            const ca = i < a.length ? a.charCodeAt(i) : 0;
            const cb = i < b.length ? b.charCodeAt(i) : 0;
            diff |= ca ^ cb;
        }
        return diff === 0; // always false when lengths differ
    }

    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return diff === 0;
}

// ── Factory ────────────────────────────────────────────────────

/**
 * Create a credential graph runtime.
 *
 * @param credentials - Credential entries from the WorldSpec
 * @param events      - Optional event bus for emitting events.
 *                       If omitted, discovery events are not emitted.
 *                       Call connect() to subscribe to fs:read events.
 */
export function createCredentialGraph(
    credentials: readonly CredentialEntry[],
    events?: EventBus,
): CredentialGraph {
    // ── Validate input ─────────────────────────────────────────

    if (credentials.length > MAX_CREDENTIALS) {
        throw new Error(
            `CredentialGraph: Too many credentials (${credentials.length}). ` +
            `Maximum is ${MAX_CREDENTIALS}.`,
        );
    }

    // ── Initialize state ───────────────────────────────────────

    const states = new Map<string, MutableCredentialState>();
    const byTarget = new Map<string, string[]>();      // targetKey → credentialIds
    const byLocation = new Map<string, string[]>();     // locationKey → credentialIds
    const byMachine = new Map<string, string[]>();      // machine → credentialIds (for location)

    for (const entry of credentials) {
        // Duplicate ID check
        if (states.has(entry.id)) {
            throw new Error(
                `CredentialGraph: Duplicate credential ID '${entry.id}'.`,
            );
        }

        // Initialize mutable state
        const state: MutableCredentialState = {
            entry,
            discovered: false,
            discoveredAt: -1,
            discoveryMethod: '',
            currentValue: entry.value,
            used: false,
        };
        states.set(entry.id, state);

        // Index by target
        const tk = targetKey(entry.validAt.machine, entry.validAt.service, entry.validAt.user);
        let targetList = byTarget.get(tk);
        if (targetList === undefined) {
            targetList = [];
            byTarget.set(tk, targetList);
        }
        targetList.push(entry.id);

        // Index by location (file path)
        if (entry.foundAt.path !== undefined) {
            const lk = locationKey(entry.foundAt.machine, entry.foundAt.path);
            let locList = byLocation.get(lk);
            if (locList === undefined) {
                locList = [];
                byLocation.set(lk, locList);
            }
            locList.push(entry.id);
        }

        // Index by machine (for env var / service discoveries)
        let machineList = byMachine.get(entry.foundAt.machine);
        if (machineList === undefined) {
            machineList = [];
            byMachine.set(entry.foundAt.machine, machineList);
        }
        machineList.push(entry.id);
    }

    // ── Emit helper ────────────────────────────────────────────

    function emitDiscovery(credId: string, machine: string, location: string): void {
        if (events === undefined) return;

        const event: AuthCredentialFoundEvent = {
            type: 'auth:credential-found',
            credentialId: credId,
            machine,
            location,
            timestamp: Date.now(),
        };
        events.emit(event);
    }

    // ── Freeze a mutable state into a readonly snapshot ─────────

    function freezeState(state: MutableCredentialState): CredentialState {
        return Object.freeze({
            entry: state.entry,
            discovered: state.discovered,
            discoveredAt: state.discoveredAt,
            discoveryMethod: state.discoveryMethod,
            currentValue: state.currentValue,
            used: state.used,
        });
    }

    // ── Graph implementation ───────────────────────────────────

    const graph: CredentialGraph = {
        validate(
            machine: string,
            service: string,
            user: string,
            value: string,
            type?: CredentialType,
        ): ValidationResult {
            const tk = targetKey(machine, service, user);
            const candidateIds = byTarget.get(tk);

            if (candidateIds === undefined || candidateIds.length === 0) {
                return {
                    valid: false,
                    credentialId: null,
                    reason: `No credentials configured for ${user}@${machine} via ${service}`,
                };
            }

            // Check each candidate credential
            // We iterate ALL candidates even after finding a match
            // to keep timing constant.
            let matchedId: string | null = null;
            let anyTypeMatch = false;

            for (const id of candidateIds) {
                const state = states.get(id);
                if (state === undefined) continue;

                // Check type if specified
                if (type !== undefined && state.entry.type !== type) {
                    continue;
                }
                anyTypeMatch = true;

                // Constant-time value comparison
                const valueMatch = constantTimeEqual(value, state.currentValue);
                if (valueMatch && matchedId === null) {
                    matchedId = id;
                }
            }

            if (matchedId !== null) {
                // Mark as used
                const state = states.get(matchedId);
                if (state !== undefined) {
                    state.used = true;
                }
                return {
                    valid: true,
                    credentialId: matchedId,
                    reason: 'Authentication successful',
                };
            }

            if (!anyTypeMatch) {
                return {
                    valid: false,
                    credentialId: null,
                    reason: `No ${type ?? 'any'} credentials for ${user}@${machine} via ${service}`,
                };
            }

            return {
                valid: false,
                credentialId: null,
                reason: 'Invalid credentials',
            };
        },

        discover(credentialId: string, machine: string, location: string): void {
            const state = states.get(credentialId);
            if (state === undefined) {
                // Silently ignore unknown credential IDs.
                // This prevents a crash if a WorldSpec references
                // a credential that doesn't exist.
                return;
            }

            if (state.discovered) {
                // Already discovered — idempotent
                return;
            }

            state.discovered = true;
            state.discoveredAt = Date.now();
            state.discoveryMethod = location;

            emitDiscovery(credentialId, machine, location);
        },

        scanFileForCredentials(machine: string, path: string, content: string): void {
            // Truncate content for performance
            const scanContent = content.length > MAX_SCAN_BYTES
                ? content.slice(0, MAX_SCAN_BYTES)
                : content;

            // Check location index first (exact path match)
            const lk = locationKey(machine, path);
            const exactCreds = byLocation.get(lk);
            if (exactCreds !== undefined) {
                for (const credId of exactCreds) {
                    const state = states.get(credId);
                    if (state === undefined || state.discovered) continue;

                    // Verify the value is actually in the file content
                    if (scanContent.includes(state.currentValue)) {
                        graph.discover(credId, machine, `file:${path}`);
                    }
                }
            }

            // Also check all credentials on this machine
            // (some credentials have foundAt.path but the player
            //  might find them in a different file, e.g. grep output)
            const machineCreds = byMachine.get(machine);
            if (machineCreds !== undefined) {
                for (const credId of machineCreds) {
                    const state = states.get(credId);
                    if (state === undefined || state.discovered) continue;

                    // Only scan if the credential value is actually present
                    // in the file content. This is a substring search.
                    if (scanContent.includes(state.currentValue)) {
                        graph.discover(credId, machine, `file:${path}`);
                    }
                }
            }
        },

        rotate(credentialId: string, newValue: string): void {
            const state = states.get(credentialId);
            if (state === undefined) {
                return;
            }

            state.currentValue = newValue;
            // Reset discovery status — the player needs to find
            // the new credential value.
            state.discovered = false;
            state.discoveredAt = -1;
            state.discoveryMethod = '';
        },

        getState(credentialId: string): CredentialState | null {
            const state = states.get(credentialId);
            if (state === undefined) return null;
            return freezeState(state);
        },

        getAllStates(): readonly CredentialState[] {
            const result: CredentialState[] = [];
            for (const state of states.values()) {
                result.push(freezeState(state));
            }
            return Object.freeze(result);
        },

        getDiscovered(): readonly string[] {
            const result: string[] = [];
            for (const [id, state] of states) {
                if (state.discovered) {
                    result.push(id);
                }
            }
            return Object.freeze(result);
        },

        isDiscovered(credentialId: string): boolean {
            const state = states.get(credentialId);
            return state !== undefined && state.discovered;
        },

        getCredentialsFor(machine: string, service: string, user: string): readonly string[] {
            const tk = targetKey(machine, service, user);
            const ids = byTarget.get(tk);
            return ids !== undefined ? Object.freeze([...ids]) : Object.freeze([]);
        },

        getCredentialsAt(machine: string, path?: string): readonly string[] {
            if (path !== undefined) {
                const lk = locationKey(machine, path);
                const ids = byLocation.get(lk);
                return ids !== undefined ? Object.freeze([...ids]) : Object.freeze([]);
            }
            const ids = byMachine.get(machine);
            return ids !== undefined ? Object.freeze([...ids]) : Object.freeze([]);
        },

        connect(eventBus: EventBus): readonly Unsubscribe[] {
            const unsubs: Unsubscribe[] = [];

            // Listen for fs:read events → auto-discover credentials
            const fsReadUnsub = eventBus.on('fs:read', (event) => {
                // We need the file content to check for credential values.
                // The fs:read event doesn't include content — we check
                // by path match only. If the path matches a credential's
                // foundAt.path, we discover it immediately (assuming the
                // player saw the content by reading the file).
                const lk = locationKey(event.machine, event.path);
                const exactCreds = byLocation.get(lk);
                if (exactCreds !== undefined) {
                    for (const credId of exactCreds) {
                        const state = states.get(credId);
                        if (state === undefined || state.discovered) continue;
                        graph.discover(credId, event.machine, `file:${event.path}`);
                    }
                }
            });
            unsubs.push(fsReadUnsub);

            // Listen for credential rotation events
            const rotateUnsub = eventBus.onPrefix('custom:', (event) => {
                if (event.type !== 'custom:dynamics-rotate-cred') return;
                const data = (event as { data: { credentialId: string; newValue: string } }).data;
                if (
                    typeof data === 'object' &&
                    data !== null &&
                    typeof data.credentialId === 'string' &&
                    typeof data.newValue === 'string'
                ) {
                    graph.rotate(data.credentialId, data.newValue);
                }
            });
            unsubs.push(rotateUnsub);

            return Object.freeze(unsubs);
        },

        debugSummary(): string {
            const lines: string[] = [];
            lines.push(`Credential Graph: ${states.size} credentials`);
            lines.push('');

            for (const [id, state] of states) {
                const disc = state.discovered ? '✓ DISCOVERED' : '✗ hidden';
                const used = state.used ? '(used)' : '';
                const from = state.entry.foundAt.path ?? state.entry.foundAt.env ?? state.entry.foundAt.service ?? '?';
                const to = `${state.entry.validAt.user}@${state.entry.validAt.machine}:${state.entry.validAt.service}`;
                lines.push(`  [${id}] ${state.entry.type} ${disc} ${used}`);
                lines.push(`    found: ${state.entry.foundAt.machine}:${from}`);
                lines.push(`    valid: ${to}`);
            }

            return lines.join('\n');
        },
    };

    return graph;
}
