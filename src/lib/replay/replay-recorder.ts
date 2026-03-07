/**
 * VARIANT — Replay Recorder Implementation
 *
 * Records simulation frames into a ReplayRecording.
 * Used by the replay module to capture live simulations.
 *
 * SWAPPABILITY: Implements ReplayRecorder. Replace this file.
 */

import type {
    ReplayRecorder,
    ReplayRecording,
    ReplayFrame,
    ReplayFrameKind,
    ReplayFrameData,
    ReplayAnnotation,
} from './types';

const ENGINE_VERSION = '1.0.0';

export function createReplayRecorder(): ReplayRecorder {
    const frames: ReplayFrame[] = [];
    const annotations: ReplayAnnotation[] = [];
    let recording = false;
    let worldId = '';
    let worldTitle = '';
    let startedAt = '';
    let startWallTime = 0;
    let seq = 0;

    return {
        start(wId: string, wTitle: string): void {
            if (recording) return;
            frames.length = 0;
            annotations.length = 0;
            seq = 0;
            worldId = wId;
            worldTitle = wTitle;
            startedAt = new Date().toISOString();
            startWallTime = Date.now();
            recording = true;
        },

        record(kind: ReplayFrameKind, data: ReplayFrameData, tick: number): void {
            if (!recording) return;

            const frame: ReplayFrame = {
                seq: seq++,
                tick,
                wallTimeMs: Date.now() - startWallTime,
                kind,
                data,
            };
            frames.push(frame);
        },

        annotate(label: string, text: string, category: ReplayAnnotation['category'], tick: number): void {
            if (!recording) return;

            annotations.push({
                tick,
                seq: seq, // Current position
                label,
                text,
                category,
            });

            // Also record as a frame
            this.record('annotation', {
                kind: 'annotation',
                label,
                text,
                category,
            }, tick);
        },

        stop(
            finalScore: number,
            finalPhase: string,
            hintsUsed: number,
            objectivesCompleted: readonly string[],
        ): ReplayRecording {
            recording = false;
            const endedAt = new Date().toISOString();
            const durationMs = Date.now() - startWallTime;
            const lastFrame = frames[frames.length - 1];
            const totalTicks = lastFrame?.tick ?? 0;

            return Object.freeze({
                id: `replay-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
                worldId,
                worldTitle,
                startedAt,
                endedAt,
                durationMs,
                totalTicks,
                finalScore,
                finalPhase,
                frames: Object.freeze([...frames]),
                annotations: Object.freeze([...annotations]),
                meta: Object.freeze({
                    engineVersion: ENGINE_VERSION,
                    hintsUsed,
                    objectivesCompleted: Object.freeze([...objectivesCompleted]),
                    custom: Object.freeze({}),
                }),
            });
        },

        frameCount(): number {
            return frames.length;
        },

        isRecording(): boolean {
            return recording;
        },
    };
}
