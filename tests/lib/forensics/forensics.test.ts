/**
 * VARIANT — Forensics Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createForensicsEngine } from '../../../src/lib/forensics/forensics-engine';
import type { ForensicArtifact, ForensicIOC, TimelineEvent } from '../../../src/lib/forensics/types';

function makeArtifact(
    id: string,
    machine: string,
    content: string,
    overrides: Partial<ForensicArtifact> = {},
): ForensicArtifact {
    return {
        id,
        machine,
        category: 'file',
        path: `/evidence/${id}`,
        content,
        hash: `hash-of-${id}`,
        createdAt: 0,
        modifiedAt: 0,
        tags: [],
        isEvidence: false,
        matchedIOCs: [],
        ...overrides,
    };
}

function makeIOC(id: string, type: ForensicIOC['type'], value: string, severity: ForensicIOC['severity'] = 'high'): ForensicIOC {
    return { id, type, value, description: `IOC ${id}`, severity };
}

function makeEvent(tick: number, machine: string, type: string, severity: TimelineEvent['severity'] = 'info'): TimelineEvent {
    return {
        tick,
        machine,
        type,
        description: `${type} at tick ${tick}`,
        severity,
        associatedIOCs: [],
    };
}

describe('ForensicsEngine', () => {
    // ── Artifacts ──────────────────────────────────────────────

    it('adds and retrieves artifacts', () => {
        const engine = createForensicsEngine();
        engine.addArtifact(makeArtifact('a1', 'web-server', 'log data'));

        expect(engine.getArtifact('a1')).not.toBeNull();
        expect(engine.getArtifact('nonexistent')).toBeNull();
        expect(engine.listArtifacts().length).toBe(1);
    });

    it('throws on duplicate artifact', () => {
        const engine = createForensicsEngine();
        engine.addArtifact(makeArtifact('a1', 'srv', 'data'));
        expect(() => engine.addArtifact(makeArtifact('a1', 'srv', 'data'))).toThrow();
    });

    it('lists artifacts by machine', () => {
        const engine = createForensicsEngine();
        engine.addArtifact(makeArtifact('a1', 'web', 'data'));
        engine.addArtifact(makeArtifact('a2', 'db', 'data'));
        engine.addArtifact(makeArtifact('a3', 'web', 'data'));

        expect(engine.listArtifactsByMachine('web').length).toBe(2);
        expect(engine.listArtifactsByMachine('db').length).toBe(1);
        expect(engine.listArtifactsByMachine('nonexistent').length).toBe(0);
    });

    it('lists artifacts by category', () => {
        const engine = createForensicsEngine();
        engine.addArtifact(makeArtifact('a1', 'srv', 'data', { category: 'file' }));
        engine.addArtifact(makeArtifact('a2', 'srv', 'data', { category: 'log' }));
        engine.addArtifact(makeArtifact('a3', 'srv', 'data', { category: 'file' }));

        expect(engine.listArtifactsByCategory('file').length).toBe(2);
        expect(engine.listArtifactsByCategory('log').length).toBe(1);
        expect(engine.listArtifactsByCategory('memory').length).toBe(0);
    });

    // ── Evidence Collection ────────────────────────────────────

    it('collects evidence from an artifact', () => {
        const engine = createForensicsEngine();
        engine.addArtifact(makeArtifact('a1', 'srv', 'secret data'));

        const collectionId = engine.collectEvidence('a1', 'analyst-alice', 10);
        expect(collectionId).not.toBeNull();

        const ev = engine.getEvidence(collectionId!)!;
        expect(ev.artifactId).toBe('a1');
        expect(ev.collectedBy).toBe('analyst-alice');
        expect(ev.collectedAt).toBe(10);
        expect(ev.status).toBe('acquired');
        expect(ev.acquisitionHash).toBe('hash-of-a1');
    });

    it('returns null when collecting nonexistent artifact', () => {
        const engine = createForensicsEngine();
        expect(engine.collectEvidence('nonexistent', 'alice', 0)).toBeNull();
    });

    it('adds notes to evidence', () => {
        const engine = createForensicsEngine();
        engine.addArtifact(makeArtifact('a1', 'srv', 'data'));
        const id = engine.collectEvidence('a1', 'alice', 0)!;

        expect(engine.addNote(id, 'Found suspicious strings')).toBe(true);
        expect(engine.addNote(id, 'Matches known malware pattern')).toBe(true);

        const ev = engine.getEvidence(id)!;
        expect(ev.notes.length).toBe(2);
        expect(ev.notes[0]).toBe('Found suspicious strings');
    });

    it('addNote returns false for unknown evidence', () => {
        const engine = createForensicsEngine();
        expect(engine.addNote('nonexistent', 'note')).toBe(false);
    });

    it('marks evidence as analyzed', () => {
        const engine = createForensicsEngine();
        engine.addArtifact(makeArtifact('a1', 'srv', 'data'));
        const id = engine.collectEvidence('a1', 'alice', 0)!;

        expect(engine.markAnalyzed(id)).toBe(true);
        expect(engine.getEvidence(id)!.status).toBe('analyzed');
    });

    it('markAnalyzed returns false for unknown evidence', () => {
        const engine = createForensicsEngine();
        expect(engine.markAnalyzed('nonexistent')).toBe(false);
    });

    it('verifies integrity when artifact unchanged', () => {
        const engine = createForensicsEngine();
        engine.addArtifact(makeArtifact('a1', 'srv', 'data'));
        const id = engine.collectEvidence('a1', 'alice', 0)!;

        expect(engine.verifyIntegrity(id)).toBe(true);
        expect(engine.getEvidence(id)!.integrityVerified).toBe(true);
    });

    it('verifyIntegrity returns false for unknown evidence', () => {
        const engine = createForensicsEngine();
        expect(engine.verifyIntegrity('nonexistent')).toBe(false);
    });

    it('lists all evidence', () => {
        const engine = createForensicsEngine();
        engine.addArtifact(makeArtifact('a1', 'srv', 'data1'));
        engine.addArtifact(makeArtifact('a2', 'srv', 'data2'));

        engine.collectEvidence('a1', 'alice', 0);
        engine.collectEvidence('a2', 'bob', 1);

        expect(engine.listEvidence().length).toBe(2);
    });

    // ── IOC Management ─────────────────────────────────────────

    it('adds and retrieves IOCs', () => {
        const engine = createForensicsEngine();
        engine.addIOC(makeIOC('ioc-1', 'ip', '192.168.1.100'));

        expect(engine.getIOC('ioc-1')).not.toBeNull();
        expect(engine.getIOC('nonexistent')).toBeNull();
        expect(engine.listIOCs().length).toBe(1);
    });

    it('throws on duplicate IOC', () => {
        const engine = createForensicsEngine();
        engine.addIOC(makeIOC('ioc-1', 'ip', '1.2.3.4'));
        expect(() => engine.addIOC(makeIOC('ioc-1', 'ip', '5.6.7.8'))).toThrow();
    });

    // ── IOC Scanning ───────────────────────────────────────────

    it('scans artifact and finds IP IOC', () => {
        const engine = createForensicsEngine();
        engine.addArtifact(makeArtifact('a1', 'srv', 'Connection from 10.0.0.99 at 14:32'));
        engine.addIOC(makeIOC('ioc-1', 'ip', '10.0.0.99'));
        engine.addIOC(makeIOC('ioc-2', 'ip', '192.168.1.1'));

        const matches = engine.scanArtifact('a1');
        expect(matches).toContain('ioc-1');
        expect(matches).not.toContain('ioc-2');
    });

    it('scans artifact and finds domain IOC', () => {
        const engine = createForensicsEngine();
        engine.addArtifact(makeArtifact('a1', 'srv', 'DNS query to evil.example.com resolved'));
        engine.addIOC(makeIOC('ioc-1', 'domain', 'evil.example.com'));

        const matches = engine.scanArtifact('a1');
        expect(matches).toContain('ioc-1');
    });

    it('scans artifact with regex pattern IOC', () => {
        const engine = createForensicsEngine();
        engine.addArtifact(makeArtifact('a1', 'srv', 'User-Agent: Mozilla/5.0 (evil-bot)'));
        engine.addIOC(makeIOC('ioc-1', 'pattern', 'evil-bot'));

        const matches = engine.scanArtifact('a1');
        expect(matches).toContain('ioc-1');
    });

    it('scans artifact with filename IOC in path', () => {
        const engine = createForensicsEngine();
        engine.addArtifact(makeArtifact('a1', 'srv', 'clean content', { path: '/tmp/mimikatz.exe' }));
        engine.addIOC(makeIOC('ioc-1', 'filename', 'mimikatz.exe'));

        const matches = engine.scanArtifact('a1');
        expect(matches).toContain('ioc-1');
    });

    it('scan returns empty for unknown artifact', () => {
        const engine = createForensicsEngine();
        expect(engine.scanArtifact('nonexistent').length).toBe(0);
    });

    it('scan updates artifact matchedIOCs', () => {
        const engine = createForensicsEngine();
        engine.addArtifact(makeArtifact('a1', 'srv', 'call to c2.evil.com'));
        engine.addIOC(makeIOC('ioc-1', 'domain', 'c2.evil.com'));

        engine.scanArtifact('a1');
        const artifact = engine.getArtifact('a1')!;
        expect(artifact.matchedIOCs).toContain('ioc-1');
    });

    // ── Timeline ───────────────────────────────────────────────

    it('adds and retrieves timeline events sorted by tick', () => {
        const engine = createForensicsEngine();
        engine.addTimelineEvent(makeEvent(30, 'srv', 'login'));
        engine.addTimelineEvent(makeEvent(10, 'srv', 'boot'));
        engine.addTimelineEvent(makeEvent(20, 'srv', 'connection'));

        const tl = engine.getTimeline();
        expect(tl.length).toBe(3);
        expect(tl[0]!.tick).toBe(10);
        expect(tl[1]!.tick).toBe(20);
        expect(tl[2]!.tick).toBe(30);
    });

    it('filters timeline by machine', () => {
        const engine = createForensicsEngine();
        engine.addTimelineEvent(makeEvent(1, 'web', 'event-a'));
        engine.addTimelineEvent(makeEvent(2, 'db', 'event-b'));
        engine.addTimelineEvent(makeEvent(3, 'web', 'event-c'));

        const webEvents = engine.getTimelineByMachine('web');
        expect(webEvents.length).toBe(2);
        expect(webEvents[0]!.type).toBe('event-a');
    });

    it('filters timeline by tick range', () => {
        const engine = createForensicsEngine();
        engine.addTimelineEvent(makeEvent(5, 'srv', 'early'));
        engine.addTimelineEvent(makeEvent(15, 'srv', 'mid'));
        engine.addTimelineEvent(makeEvent(25, 'srv', 'late'));

        const range = engine.getTimelineRange(10, 20);
        expect(range.length).toBe(1);
        expect(range[0]!.type).toBe('mid');
    });

    it('timeline range is exclusive on end', () => {
        const engine = createForensicsEngine();
        engine.addTimelineEvent(makeEvent(10, 'srv', 'boundary'));

        expect(engine.getTimelineRange(10, 11).length).toBe(1);
        expect(engine.getTimelineRange(10, 10).length).toBe(0);
    });

    // ── Clear ──────────────────────────────────────────────────

    it('clear removes everything', () => {
        const engine = createForensicsEngine();
        engine.addArtifact(makeArtifact('a1', 'srv', 'data'));
        engine.addIOC(makeIOC('ioc-1', 'ip', '1.2.3.4'));
        engine.addTimelineEvent(makeEvent(1, 'srv', 'event'));
        engine.collectEvidence('a1', 'alice', 0);

        engine.clear();

        expect(engine.listArtifacts().length).toBe(0);
        expect(engine.listIOCs().length).toBe(0);
        expect(engine.getTimeline().length).toBe(0);
        expect(engine.listEvidence().length).toBe(0);
    });
});
