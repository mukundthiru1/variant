/**
 * VARIANT — Snapshot Tests
 */

import { describe, it, expect } from 'vitest';
import { createSnapshot, isValidSnapshot, diffSnapshots } from '../../src/core/snapshot';
import type { SnapshotSource } from '../../src/core/snapshot';
import type { EngineEvent } from '../../src/core/events';

function makeSource(overrides?: Partial<ReturnType<SnapshotSource['getState']>>): SnapshotSource {
    const log: EngineEvent[] = [
        { type: 'sim:tick', tick: 1, timestamp: 1000 } as EngineEvent,
        { type: 'auth:login', user: 'admin', machine: 'web-01', service: 'ssh', success: true, timestamp: 1100 } as EngineEvent,
        { type: 'sim:tick', tick: 2, timestamp: 2000 } as EngineEvent,
        { type: 'fs:read', machine: 'web-01', path: '/etc/passwd', user: 'admin', timestamp: 2100 } as EngineEvent,
        { type: 'objective:complete', objectiveId: 'obj-1', timestamp: 2200 } as EngineEvent,
    ];

    const objectives = new Map<string, 'locked' | 'available' | 'in-progress' | 'completed'>([
        ['obj-1', 'completed'],
        ['obj-2', 'available'],
    ]);

    return {
        id: 'sim-test-001',
        getState() {
            return {
                phase: 'running' as const,
                tick: 2,
                startTime: 900,
                elapsedMs: 1200,
                score: 800,
                hintsUsed: 1,
                objectiveStatus: objectives,
                ...overrides,
            };
        },
        events: {
            getLog(filter?: string) {
                if (filter === undefined) return log;
                return log.filter(e => e.type.startsWith(filter));
            },
        },
    };
}

describe('createSnapshot', () => {
    it('captures simulation state', () => {
        const snap = createSnapshot(makeSource());

        expect(snap.formatVersion).toBe(1);
        expect(snap.simulationId).toBe('sim-test-001');
        expect(snap.phase).toBe('running');
        expect(snap.tick).toBe(2);
        expect(snap.score).toBe(800);
        expect(snap.hintsUsed).toBe(1);
        expect(snap.objectives.length).toBe(2);
        expect(snap.eventLog.length).toBe(5);
    });

    it('serializes events as JSON-safe objects', () => {
        const snap = createSnapshot(makeSource());

        for (const event of snap.eventLog) {
            expect(typeof event.type).toBe('string');
            expect(typeof event.timestamp).toBe('number');
            // Verify JSON round-trip
            const json = JSON.stringify(event);
            const parsed = JSON.parse(json);
            expect(parsed.type).toBe(event.type);
        }
    });

    it('respects maxEvents option', () => {
        const snap = createSnapshot(makeSource(), { maxEvents: 2 });

        // Should take the 2 most recent events
        expect(snap.eventLog.length).toBe(2);
        expect(snap.eventLog[0]!.timestamp).toBe(2100);
        expect(snap.eventLog[1]!.timestamp).toBe(2200);
    });

    it('respects eventFilter option', () => {
        const snap = createSnapshot(makeSource(), { eventFilter: 'sim:' });

        expect(snap.eventLog.length).toBe(2);
        expect(snap.eventLog.every(e => e.type.startsWith('sim:'))).toBe(true);
    });

    it('computes event counts by prefix', () => {
        const snap = createSnapshot(makeSource());

        expect(snap.eventCounts['sim']).toBe(2);
        expect(snap.eventCounts['auth']).toBe(1);
        expect(snap.eventCounts['fs']).toBe(1);
        expect(snap.eventCounts['objective']).toBe(1);
    });

    it('captures objective status', () => {
        const snap = createSnapshot(makeSource());

        const obj1 = snap.objectives.find(o => o.id === 'obj-1');
        const obj2 = snap.objectives.find(o => o.id === 'obj-2');
        expect(obj1?.status).toBe('completed');
        expect(obj2?.status).toBe('available');
    });

    it('is JSON-serializable', () => {
        const snap = createSnapshot(makeSource());
        const json = JSON.stringify(snap);
        const parsed = JSON.parse(json);

        expect(parsed.formatVersion).toBe(1);
        expect(parsed.simulationId).toBe('sim-test-001');
        expect(parsed.eventLog.length).toBe(5);
    });
});

describe('isValidSnapshot', () => {
    it('validates a correct snapshot', () => {
        const snap = createSnapshot(makeSource());
        expect(isValidSnapshot(snap)).toBe(true);
    });

    it('validates a JSON-round-tripped snapshot', () => {
        const snap = createSnapshot(makeSource());
        const parsed = JSON.parse(JSON.stringify(snap));
        expect(isValidSnapshot(parsed)).toBe(true);
    });

    it('rejects null', () => {
        expect(isValidSnapshot(null)).toBe(false);
    });

    it('rejects non-object', () => {
        expect(isValidSnapshot('string')).toBe(false);
        expect(isValidSnapshot(42)).toBe(false);
    });

    it('rejects objects with wrong formatVersion', () => {
        expect(isValidSnapshot({ formatVersion: 2 })).toBe(false);
    });

    it('rejects objects with missing fields', () => {
        expect(isValidSnapshot({ formatVersion: 1 })).toBe(false);
        expect(isValidSnapshot({
            formatVersion: 1,
            capturedAt: 1000,
            simulationId: 'test',
            // missing other fields
        })).toBe(false);
    });
});

describe('diffSnapshots', () => {
    it('detects tick and time progression', () => {
        const before = createSnapshot(makeSource({
            tick: 1,
            elapsedMs: 500,
        }));
        const after = createSnapshot(makeSource({
            tick: 5,
            elapsedMs: 2500,
        }));

        const diff = diffSnapshots(before, after);
        expect(diff.tickDelta).toBe(4);
        expect(diff.elapsedMsDelta).toBe(2000);
    });

    it('detects score changes', () => {
        const before = createSnapshot(makeSource({ score: 1000 }));
        const after = createSnapshot(makeSource({ score: 850 }));

        const diff = diffSnapshots(before, after);
        expect(diff.scoreDelta).toBe(-150);
    });

    it('detects phase changes', () => {
        const before = createSnapshot(makeSource({ phase: 'running' as const }));
        const after = createSnapshot(makeSource({ phase: 'completed' as const }));

        const diff = diffSnapshots(before, after);
        expect(diff.phaseChanged).toBe(true);
        expect(diff.phaseBefore).toBe('running');
        expect(diff.phaseAfter).toBe('completed');
    });

    it('reports no phase change when phases match', () => {
        const before = createSnapshot(makeSource());
        const after = createSnapshot(makeSource());

        const diff = diffSnapshots(before, after);
        expect(diff.phaseChanged).toBe(false);
    });

    it('detects hints used delta', () => {
        const before = createSnapshot(makeSource({ hintsUsed: 0 }));
        const after = createSnapshot(makeSource({ hintsUsed: 2 }));

        const diff = diffSnapshots(before, after);
        expect(diff.hintsDelta).toBe(2);
    });
});
