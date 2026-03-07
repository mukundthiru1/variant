/**
 * VARIANT — Simulation Snapshot
 *
 * Captures simulation state as a serializable object for:
 *   - Save/load (persistence)
 *   - Debugging (capture state at failure point)
 *   - After-action review (replay with full context)
 *   - Test assertions (verify exact simulation state)
 *
 * DESIGN: Pure functions. No side effects.
 *   createSnapshot() captures state from a Simulation handle.
 *   Snapshots are plain JSON-serializable objects — no classes,
 *   no functions, no circular references.
 *
 * SECURITY: Snapshots contain the full WorldSpec including
 * credentials. Do not expose snapshots to untrusted code.
 *
 * SWAPPABILITY: Replace this file. The Snapshot type is stable.
 */

import type { EngineEvent } from './events';
import type { SimulationPhase, ObjectiveStatus } from './engine';

// ── Snapshot Types ──────────────────────────────────────────

/**
 * A serializable simulation snapshot.
 * Can be JSON.stringify'd and JSON.parse'd without loss.
 */
export interface SimulationSnapshot {
    /** Snapshot format version. */
    readonly formatVersion: 1;

    /** When this snapshot was taken. */
    readonly capturedAt: number;

    /** Simulation ID. */
    readonly simulationId: string;

    /** Current simulation phase. */
    readonly phase: SimulationPhase;

    /** Current tick number. */
    readonly tick: number;

    /** Simulation start time (epoch ms). */
    readonly startTime: number;

    /** Elapsed time (ms) at snapshot. */
    readonly elapsedMs: number;

    /** Current score. */
    readonly score: number;

    /** Number of hints used. */
    readonly hintsUsed: number;

    /** Objective status map. */
    readonly objectives: readonly ObjectiveSnapshotEntry[];

    /** Event log at time of snapshot. */
    readonly eventLog: readonly SerializedEvent[];

    /** Event counts by type prefix. */
    readonly eventCounts: Readonly<Record<string, number>>;
}

export interface ObjectiveSnapshotEntry {
    readonly id: string;
    readonly status: ObjectiveStatus;
}

/**
 * Serialized event. Same as EngineEvent but guaranteed
 * to be JSON-safe (no functions, no undefined values).
 */
export type SerializedEvent = Readonly<Record<string, unknown>> & {
    readonly type: string;
    readonly timestamp: number;
};

// ── Snapshot Creation ───────────────────────────────────────

export interface SnapshotSource {
    readonly id: string;
    getState(): {
        readonly phase: SimulationPhase;
        readonly tick: number;
        readonly startTime: number;
        readonly elapsedMs: number;
        readonly score: number;
        readonly hintsUsed: number;
        readonly objectiveStatus: ReadonlyMap<string, ObjectiveStatus>;
    };
    readonly events: {
        getLog(filter?: string): readonly EngineEvent[];
    };
}

/**
 * Capture a snapshot of a simulation.
 *
 * @param sim - The simulation to snapshot (or any object
 *              implementing SnapshotSource).
 * @param options - Optional configuration.
 */
export function createSnapshot(
    sim: SnapshotSource,
    options?: {
        /** Maximum number of events to include. Default: all. */
        readonly maxEvents?: number;
        /** Event type prefix filter. Default: include all. */
        readonly eventFilter?: string;
    },
): SimulationSnapshot {
    const state = sim.getState();

    // Serialize events
    const rawLog = sim.events.getLog(options?.eventFilter);
    const eventLog: SerializedEvent[] = [];
    const maxEvents = options?.maxEvents ?? rawLog.length;

    // Take the most recent events if limited
    const startIdx = Math.max(0, rawLog.length - maxEvents);
    for (let i = startIdx; i < rawLog.length; i++) {
        const event = rawLog[i];
        if (event === undefined) continue;
        eventLog.push(serializeEvent(event));
    }

    // Compute event counts by type prefix
    const fullLog = sim.events.getLog();
    const eventCounts: Record<string, number> = {};
    for (const event of fullLog) {
        const prefix = event.type.split(':')[0] ?? event.type;
        eventCounts[prefix] = (eventCounts[prefix] ?? 0) + 1;
    }

    // Serialize objective status
    const objectives: ObjectiveSnapshotEntry[] = [];
    for (const [id, status] of state.objectiveStatus) {
        objectives.push({ id, status });
    }

    return {
        formatVersion: 1,
        capturedAt: Date.now(),
        simulationId: sim.id,
        phase: state.phase,
        tick: state.tick,
        startTime: state.startTime,
        elapsedMs: state.elapsedMs,
        score: state.score,
        hintsUsed: state.hintsUsed,
        objectives,
        eventLog,
        eventCounts,
    };
}

/**
 * Serialize a single event to a JSON-safe object.
 */
function serializeEvent(event: EngineEvent): SerializedEvent {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(event)) {
        // Skip functions and undefined values
        if (typeof value === 'function' || value === undefined) continue;
        result[key] = value;
    }
    return result as SerializedEvent;
}

/**
 * Validate that an object is a valid SimulationSnapshot.
 * Used when loading snapshots from storage.
 */
export function isValidSnapshot(obj: unknown): obj is SimulationSnapshot {
    if (obj === null || typeof obj !== 'object') return false;
    const snap = obj as Record<string, unknown>;
    return (
        snap['formatVersion'] === 1 &&
        typeof snap['capturedAt'] === 'number' &&
        typeof snap['simulationId'] === 'string' &&
        typeof snap['phase'] === 'string' &&
        typeof snap['tick'] === 'number' &&
        typeof snap['startTime'] === 'number' &&
        typeof snap['elapsedMs'] === 'number' &&
        typeof snap['score'] === 'number' &&
        typeof snap['hintsUsed'] === 'number' &&
        Array.isArray(snap['objectives']) &&
        Array.isArray(snap['eventLog']) &&
        typeof snap['eventCounts'] === 'object' &&
        snap['eventCounts'] !== null
    );
}

/**
 * Compute a diff between two snapshots.
 * Useful for debugging and after-action review.
 */
export function diffSnapshots(
    before: SimulationSnapshot,
    after: SimulationSnapshot,
): SnapshotDiff {
    const objectiveChanges: ObjectiveChange[] = [];
    const beforeMap = new Map(before.objectives.map(o => [o.id, o.status]));

    for (const obj of after.objectives) {
        const prevStatus = beforeMap.get(obj.id);
        if (prevStatus !== obj.status) {
            objectiveChanges.push({
                id: obj.id,
                from: prevStatus ?? 'unknown',
                to: obj.status,
            });
        }
    }

    // Events that appeared between snapshots
    const newEvents = after.eventLog.filter(
        e => e.timestamp > (before.eventLog.at(-1)?.timestamp ?? 0),
    );

    return {
        tickDelta: after.tick - before.tick,
        elapsedMsDelta: after.elapsedMs - before.elapsedMs,
        scoreDelta: after.score - before.score,
        hintsDelta: after.hintsUsed - before.hintsUsed,
        phaseChanged: before.phase !== after.phase,
        phaseBefore: before.phase,
        phaseAfter: after.phase,
        objectiveChanges,
        newEventCount: newEvents.length,
        newEvents,
    };
}

export interface SnapshotDiff {
    readonly tickDelta: number;
    readonly elapsedMsDelta: number;
    readonly scoreDelta: number;
    readonly hintsDelta: number;
    readonly phaseChanged: boolean;
    readonly phaseBefore: SimulationPhase;
    readonly phaseAfter: SimulationPhase;
    readonly objectiveChanges: readonly ObjectiveChange[];
    readonly newEventCount: number;
    readonly newEvents: readonly SerializedEvent[];
}

export interface ObjectiveChange {
    readonly id: string;
    readonly from: string;
    readonly to: string;
}
