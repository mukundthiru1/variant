/**
 * VARIANT — Forensics Engine Implementation
 *
 * Digital forensics simulation for incident response training.
 *
 * SWAPPABILITY: Implements ForensicsEngine. Replace this file.
 */

import type {
    ForensicsEngine,
    ForensicArtifact,
    ArtifactCategory,
    CollectedEvidence,
    CollectionStatus,
    ForensicIOC,
    TimelineEvent,
} from './types';

interface MutableEvidence {
    readonly collectionId: string;
    readonly artifactId: string;
    readonly collectedBy: string;
    readonly collectedAt: number;
    readonly acquisitionHash: string;
    status: CollectionStatus;
    notes: string[];
    integrityVerified: boolean;
}

interface MutableArtifact {
    readonly id: string;
    readonly machine: string;
    readonly category: ArtifactCategory;
    readonly path: string;
    readonly content: string;
    readonly hash: string;
    readonly createdAt: number;
    readonly modifiedAt: number;
    readonly tags: readonly string[];
    readonly isEvidence: boolean;
    matchedIOCs: string[];
}

function toEvidence(e: MutableEvidence): CollectedEvidence {
    return {
        collectionId: e.collectionId,
        artifactId: e.artifactId,
        collectedBy: e.collectedBy,
        collectedAt: e.collectedAt,
        acquisitionHash: e.acquisitionHash,
        status: e.status,
        notes: [...e.notes],
        integrityVerified: e.integrityVerified,
    };
}

function toArtifact(a: MutableArtifact): ForensicArtifact {
    return {
        id: a.id,
        machine: a.machine,
        category: a.category,
        path: a.path,
        content: a.content,
        hash: a.hash,
        createdAt: a.createdAt,
        modifiedAt: a.modifiedAt,
        tags: [...a.tags],
        isEvidence: a.isEvidence,
        matchedIOCs: [...a.matchedIOCs],
    };
}

export function createForensicsEngine(): ForensicsEngine {
    const artifacts = new Map<string, MutableArtifact>();
    const evidence = new Map<string, MutableEvidence>();
    const iocs = new Map<string, ForensicIOC>();
    const timeline: TimelineEvent[] = [];
    let collectionCounter = 0;

    function matchIOC(ioc: ForensicIOC, content: string, path: string): boolean {
        switch (ioc.type) {
            case 'ip':
            case 'domain':
            case 'hash':
                return content.includes(ioc.value);
            case 'filename':
                return path.includes(ioc.value) || content.includes(ioc.value);
            case 'pattern':
                try {
                    return new RegExp(ioc.value).test(content);
                } catch {
                    return false;
                }
            case 'registry-key':
                return content.includes(ioc.value);
        }
    }

    return {
        // ── Artifact Management ─────────────────────────────────

        addArtifact(artifact: ForensicArtifact): void {
            if (artifacts.has(artifact.id)) {
                throw new Error(`Artifact '${artifact.id}' already exists`);
            }
            artifacts.set(artifact.id, {
                id: artifact.id,
                machine: artifact.machine,
                category: artifact.category,
                path: artifact.path,
                content: artifact.content,
                hash: artifact.hash,
                createdAt: artifact.createdAt,
                modifiedAt: artifact.modifiedAt,
                tags: [...artifact.tags],
                isEvidence: artifact.isEvidence,
                matchedIOCs: [...artifact.matchedIOCs],
            });
        },

        getArtifact(id: string): ForensicArtifact | null {
            const a = artifacts.get(id);
            if (a === undefined) return null;
            return toArtifact(a);
        },

        listArtifactsByMachine(machine: string): readonly ForensicArtifact[] {
            return [...artifacts.values()]
                .filter(a => a.machine === machine)
                .map(toArtifact);
        },

        listArtifactsByCategory(category: ArtifactCategory): readonly ForensicArtifact[] {
            return [...artifacts.values()]
                .filter(a => a.category === category)
                .map(toArtifact);
        },

        listArtifacts(): readonly ForensicArtifact[] {
            return [...artifacts.values()].map(toArtifact);
        },

        // ── Evidence Collection ─────────────────────────────────

        collectEvidence(artifactId: string, collectedBy: string, tick: number): string | null {
            const artifact = artifacts.get(artifactId);
            if (artifact === undefined) return null;

            collectionCounter++;
            const collectionId = `ev-${collectionCounter}`;

            evidence.set(collectionId, {
                collectionId,
                artifactId,
                collectedBy,
                collectedAt: tick,
                acquisitionHash: artifact.hash,
                status: 'acquired',
                notes: [],
                integrityVerified: false,
            });

            return collectionId;
        },

        getEvidence(collectionId: string): CollectedEvidence | null {
            const e = evidence.get(collectionId);
            if (e === undefined) return null;
            return toEvidence(e);
        },

        addNote(collectionId: string, note: string): boolean {
            const e = evidence.get(collectionId);
            if (e === undefined) return false;
            e.notes.push(note);
            return true;
        },

        markAnalyzed(collectionId: string): boolean {
            const e = evidence.get(collectionId);
            if (e === undefined) return false;
            e.status = 'analyzed';
            return true;
        },

        verifyIntegrity(collectionId: string): boolean {
            const e = evidence.get(collectionId);
            if (e === undefined) return false;

            const artifact = artifacts.get(e.artifactId);
            if (artifact === undefined) return false;

            const valid = artifact.hash === e.acquisitionHash;
            e.integrityVerified = valid;
            return valid;
        },

        listEvidence(): readonly CollectedEvidence[] {
            return [...evidence.values()].map(toEvidence);
        },

        // ── IOC Management ──────────────────────────────────────

        addIOC(ioc: ForensicIOC): void {
            if (iocs.has(ioc.id)) {
                throw new Error(`IOC '${ioc.id}' already registered`);
            }
            iocs.set(ioc.id, ioc);
        },

        getIOC(id: string): ForensicIOC | null {
            return iocs.get(id) ?? null;
        },

        listIOCs(): readonly ForensicIOC[] {
            return [...iocs.values()];
        },

        scanArtifact(artifactId: string): readonly string[] {
            const artifact = artifacts.get(artifactId);
            if (artifact === undefined) return [];

            const matched: string[] = [];
            for (const ioc of iocs.values()) {
                if (matchIOC(ioc, artifact.content, artifact.path)) {
                    matched.push(ioc.id);
                }
            }

            // Update artifact's matchedIOCs
            for (const iocId of matched) {
                if (!artifact.matchedIOCs.includes(iocId)) {
                    artifact.matchedIOCs.push(iocId);
                }
            }

            return matched;
        },

        // ── Timeline ────────────────────────────────────────────

        addTimelineEvent(event: TimelineEvent): void {
            timeline.push(event);
        },

        getTimeline(): readonly TimelineEvent[] {
            return [...timeline].sort((a, b) => a.tick - b.tick);
        },

        getTimelineByMachine(machine: string): readonly TimelineEvent[] {
            return timeline
                .filter(e => e.machine === machine)
                .sort((a, b) => a.tick - b.tick);
        },

        getTimelineRange(startTick: number, endTick: number): readonly TimelineEvent[] {
            return timeline
                .filter(e => e.tick >= startTick && e.tick < endTick)
                .sort((a, b) => a.tick - b.tick);
        },

        // ── Reset ───────────────────────────────────────────────

        clear(): void {
            artifacts.clear();
            evidence.clear();
            iocs.clear();
            timeline.length = 0;
            collectionCounter = 0;
        },
    };
}
