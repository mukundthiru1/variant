/**
 * VARIANT — Objective Detector Module
 *
 * Watches events from the simulation and automatically detects
 * when objectives are completed. This is the bridge between
 * "player typed something in a terminal" and "objective completed."
 *
 * Each objective type maps to a specific set of events:
 *   - 'find-file'       → fs:read with matching path+machine
 *   - 'read-data'       → fs:read on the target data
 *   - 'credential-find' → auth:credential-found with matching credentialId
 *   - 'escalate'        → auth:escalate on the target machine to target user
 *   - 'exfiltrate'      → net:request from the source machine
 *   - 'lateral-move'    → auth:login on the target machine
 *   - 'survive'         → N ticks elapse without game-over
 *   - 'patch-vuln'      → defense:alert with matching vulnId
 *   - 'write-rule'      → defense:alert with rule match
 *   - 'custom'          → forwarded to custom evaluator module
 *
 * SECURITY: This module receives SimulationContext (read-only).
 * It emits objective:progress and objective:complete events
 * through the event bus. It cannot mutate VM state, network
 * topology, or WorldSpec.
 *
 * MODULARITY: This is a Module. It can be swapped, extended,
 * or composed with other modules. The engine doesn't hardcode
 * any objective detection logic.
 */

import type { Module, SimulationContext, Capability } from '../core/modules';
import type { Unsubscribe, EventBus } from '../core/events';
import type { ObjectiveSpec, ObjectiveDetails, CredentialEntry } from '../core/world/types';

// ── Module ID ──────────────────────────────────────────────────

const MODULE_ID = 'objective-detector';
const MODULE_VERSION = '1.0.0';

// ── Internal types ─────────────────────────────────────────────

interface ObjectiveTracker {
    readonly spec: ObjectiveSpec;
    completed: boolean;
    readonly unsubscribers: Unsubscribe[];
}

// ── Factory ────────────────────────────────────────────────────

export function createObjectiveDetector(): Module {
    let trackers: ObjectiveTracker[] = [];

    function setupTracker(
        spec: ObjectiveSpec,
        events: EventBus,
        credentials: readonly CredentialEntry[],
    ): ObjectiveTracker {
        const tracker: ObjectiveTracker = {
            spec,
            completed: false,
            unsubscribers: [],
        };

        const details = spec.details;

        switch (details.kind) {
            case 'find-file':
                setupFindFileTracker(tracker, events, details);
                break;
            case 'read-data':
                setupReadDataTracker(tracker, events, details);
                break;
            case 'credential-find':
                setupCredentialFindTracker(tracker, events, details, credentials);
                break;
            case 'escalate':
                setupEscalateTracker(tracker, events, details);
                break;
            case 'exfiltrate':
                setupExfiltrateTracker(tracker, events, details);
                break;
            case 'lateral-move':
                setupLateralMoveTracker(tracker, events, details);
                break;
            case 'survive':
                setupSurviveTracker(tracker, events, details);
                break;
            case 'patch-vuln':
                setupPatchVulnTracker(tracker, events, details);
                break;
            case 'write-rule':
                setupWriteRuleTracker(tracker, events, details);
                break;
            case 'custom':
                setupCustomTracker(tracker, events, details);
                break;

            default:
                // Unknown objective kind — delegate to custom evaluator
                // using the kind as the evaluator namespace. This allows
                // third-party objective types to work without engine changes.
                setupUnknownKindTracker(tracker, events, details);
                break;
        }

        return tracker;
    }

    function completeObjective(tracker: ObjectiveTracker, events: EventBus): void {
        if (tracker.completed) return;

        tracker.completed = true;

        events.emit({
            type: 'objective:complete',
            objectiveId: tracker.spec.id,
            timestamp: Date.now(),
        });
    }

    function emitProgress(
        tracker: ObjectiveTracker,
        events: EventBus,
        detail: string,
    ): void {
        if (tracker.completed) return;

        events.emit({
            type: 'objective:progress',
            objectiveId: tracker.spec.id,
            detail,
            timestamp: Date.now(),
        });
    }

    // ── Tracker setups ────────────────────────────────────────

    function setupFindFileTracker(
        tracker: ObjectiveTracker,
        events: EventBus,
        details: Extract<ObjectiveDetails, { kind: 'find-file' }>,
    ): void {
        const unsub = events.on('fs:read', (event) => {
            // Match on worldMachine (WorldSpec machine ID) or hostname fallback
            const machineMatch = event.worldMachine === details.machine || event.machine === details.machine;
            if (machineMatch && event.path === details.path) {
                completeObjective(tracker, events);
            }
        });
        tracker.unsubscribers.push(unsub);
    }

    function setupReadDataTracker(
        tracker: ObjectiveTracker,
        events: EventBus,
        details: Extract<ObjectiveDetails, { kind: 'read-data' }>,
    ): void {
        const unsub = events.on('fs:read', (event) => {
            if (event.machine === details.machine) {
                emitProgress(tracker, events, `Read file on ${details.machine}`);
            }
        });
        tracker.unsubscribers.push(unsub);
    }

    function setupCredentialFindTracker(
        tracker: ObjectiveTracker,
        events: EventBus,
        details: Extract<ObjectiveDetails, { kind: 'credential-find' }>,
        credentials: readonly CredentialEntry[],
    ): void {
        // Listen for explicit credential-found events
        const unsub1 = events.on('auth:credential-found', (event) => {
            if (event.credentialId === details.credentialId) {
                completeObjective(tracker, events);
            }
        });
        tracker.unsubscribers.push(unsub1);

        // Also detect credential discovery via file reads:
        // If the player reads the file where the credential is stored,
        // that counts as finding the credential.
        const cred = credentials.find(c => c.id === details.credentialId);
        if (cred?.foundAt.path !== undefined) {
            const credMachine = cred.foundAt.machine;
            const credPath = cred.foundAt.path;
            const unsub2 = events.on('fs:read', (event) => {
                const machineMatch = event.worldMachine === credMachine || event.machine === credMachine;
                if (machineMatch && event.path === credPath) {
                    completeObjective(tracker, events);
                }
            });
            tracker.unsubscribers.push(unsub2);
        }
    }

    function setupEscalateTracker(
        tracker: ObjectiveTracker,
        events: EventBus,
        details: Extract<ObjectiveDetails, { kind: 'escalate' }>,
    ): void {
        const unsub = events.on('auth:escalate', (event) => {
            const machineMatch = event.worldMachine === details.machine || event.machine === details.machine;
            if (machineMatch && event.to === details.toUser) {
                completeObjective(tracker, events);
            }
        });
        tracker.unsubscribers.push(unsub);
    }

    function setupExfiltrateTracker(
        tracker: ObjectiveTracker,
        events: EventBus,
        details: Extract<ObjectiveDetails, { kind: 'exfiltrate' }>,
    ): void {
        const unsub = events.on('net:request', (event) => {
            if (event.source === details.fromMachine) {
                completeObjective(tracker, events);
            }
        });
        tracker.unsubscribers.push(unsub);
    }

    function setupLateralMoveTracker(
        tracker: ObjectiveTracker,
        events: EventBus,
        details: Extract<ObjectiveDetails, { kind: 'lateral-move' }>,
    ): void {
        const unsub = events.on('auth:login', (event) => {
            if (event.machine === details.toMachine && event.success) {
                completeObjective(tracker, events);
            }
        });
        tracker.unsubscribers.push(unsub);
    }

    function setupSurviveTracker(
        tracker: ObjectiveTracker,
        events: EventBus,
        details: Extract<ObjectiveDetails, { kind: 'survive' }>,
    ): void {
        let ticksSurvived = 0;
        const targetTicks = details.ticks;

        const unsub = events.on('sim:tick', () => {
            ticksSurvived++;
            if (ticksSurvived >= targetTicks) {
                completeObjective(tracker, events);
            }
        });
        tracker.unsubscribers.push(unsub);
    }

    function setupPatchVulnTracker(
        tracker: ObjectiveTracker,
        events: EventBus,
        details: Extract<ObjectiveDetails, { kind: 'patch-vuln' }>,
    ): void {
        const unsub = events.on('defense:alert', (event) => {
            if (event.machine === details.machine && event.ruleId === details.vulnId) {
                completeObjective(tracker, events);
            }
        });
        tracker.unsubscribers.push(unsub);
    }

    function setupWriteRuleTracker(
        tracker: ObjectiveTracker,
        events: EventBus,
        _details: Extract<ObjectiveDetails, { kind: 'write-rule' }>,
    ): void {
        const unsub = events.on('defense:alert', (event) => {
            if (event.ruleId.includes('custom-rule')) {
                completeObjective(tracker, events);
            }
        });
        tracker.unsubscribers.push(unsub);
    }

    function setupCustomTracker(
        tracker: ObjectiveTracker,
        events: EventBus,
        details: Extract<ObjectiveDetails, { kind: 'custom' }>,
    ): void {
        // Custom objectives are evaluated by a specific module
        // Listen for custom events that match the evaluator's namespace
        const prefix = `custom:${details.evaluator}`;

        const unsub = events.onPrefix(prefix, () => {
            completeObjective(tracker, events);
        });
        tracker.unsubscribers.push(unsub);
    }

    function setupUnknownKindTracker(
        tracker: ObjectiveTracker,
        events: EventBus,
        details: ObjectiveDetails,
    ): void {
        // For unknown objective kinds, listen for custom events
        // namespaced by the kind. A third-party module emits
        // `custom:<kind>:<objectiveId>` or `custom:<kind>` to complete.
        const prefix = `custom:${details.kind}`;

        const unsub = events.onPrefix(prefix, () => {
            completeObjective(tracker, events);
        });
        tracker.unsubscribers.push(unsub);
    }

    // ── Module interface ──────────────────────────────────────

    const module: Module = {
        id: MODULE_ID,
        type: 'engine',
        version: MODULE_VERSION,
        description: 'Watches simulation events and completes objectives automatically',

        provides: [{ name: 'objective-detection' }] as readonly Capability[],
        requires: [] as readonly Capability[],

        init(context: SimulationContext): void {
            trackers = [];
            const credentials = context.world.credentials;

            for (const objective of context.world.objectives) {
                const tracker = setupTracker(objective, context.events, credentials);
                trackers.push(tracker);
            }
        },

        destroy(): void {
            for (const tracker of trackers) {
                for (const unsub of tracker.unsubscribers) {
                    unsub();
                }
            }
            trackers = [];
        },
    };

    return module;
}
