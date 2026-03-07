/**
 * VARIANT — Replay Player Implementation
 *
 * Plays back a ReplayRecording, emitting frames at the correct
 * timing. Supports pause, seek, speed control, step-by-step.
 *
 * SWAPPABILITY: Implements ReplayPlayer. Replace this file.
 */

import type {
    ReplayPlayer,
    ReplayRecording,
    ReplayFrame,
    ReplayFrameFilter,
    ReplayPosition,
    PlaybackState,
    PlaybackSpeed,
} from './types';

export function createReplayPlayer(): ReplayPlayer {
    let recording: ReplayRecording | null = null;
    let state: PlaybackState = 'stopped';
    let speed: PlaybackSpeed = 1;
    let currentSeq = 0;
    let playbackTimer: ReturnType<typeof setTimeout> | null = null;

    const frameHandlers = new Set<(frame: ReplayFrame) => void>();
    const stateHandlers = new Set<(state: PlaybackState) => void>();

    function setState(newState: PlaybackState): void {
        if (state === newState) return;
        state = newState;
        for (const handler of stateHandlers) {
            handler(newState);
        }
    }

    function emitFrame(frame: ReplayFrame): void {
        for (const handler of frameHandlers) {
            handler(frame);
        }
    }

    function scheduleNext(): void {
        if (recording === null || state !== 'playing') return;
        if (currentSeq >= recording.frames.length) {
            setState('finished');
            return;
        }

        const currentFrame = recording.frames[currentSeq]!;
        const nextFrame = recording.frames[currentSeq + 1];

        // Emit current frame
        emitFrame(currentFrame);
        currentSeq++;

        if (nextFrame === undefined) {
            setState('finished');
            return;
        }

        // Calculate delay to next frame based on wall time difference and speed
        const delay = Math.max(1, (nextFrame.wallTimeMs - currentFrame.wallTimeMs) / speed);

        playbackTimer = setTimeout(scheduleNext, delay);
    }

    function stopTimer(): void {
        if (playbackTimer !== null) {
            clearTimeout(playbackTimer);
            playbackTimer = null;
        }
    }

    return {
        load(rec: ReplayRecording): void {
            stopTimer();
            recording = rec;
            currentSeq = 0;
            setState('stopped');
        },

        play(): void {
            if (recording === null) return;
            if (state === 'finished') {
                currentSeq = 0;
            }
            setState('playing');
            scheduleNext();
        },

        pause(): void {
            if (state !== 'playing') return;
            stopTimer();
            setState('paused');
        },

        stop(): void {
            stopTimer();
            currentSeq = 0;
            setState('stopped');
        },

        seekToTick(tick: number): void {
            if (recording === null) return;
            stopTimer();

            // Find the first frame at or after the target tick
            const idx = recording.frames.findIndex(f => f.tick >= tick);
            currentSeq = idx >= 0 ? idx : recording.frames.length;

            if (state === 'playing') {
                scheduleNext();
            }
        },

        seekToFrame(seq: number): void {
            if (recording === null) return;
            stopTimer();

            currentSeq = Math.max(0, Math.min(seq, recording.frames.length));

            if (state === 'playing') {
                scheduleNext();
            }
        },

        seekToAnnotation(index: number): void {
            if (recording === null) return;
            const annotation = recording.annotations[index];
            if (annotation === undefined) return;
            this.seekToFrame(annotation.seq);
        },

        setSpeed(newSpeed: PlaybackSpeed): void {
            speed = newSpeed;
            // If playing, restart timer with new speed
            if (state === 'playing') {
                stopTimer();
                scheduleNext();
            }
        },

        stepForward(): ReplayFrame | null {
            if (recording === null) return null;
            if (currentSeq >= recording.frames.length) return null;

            stopTimer();
            const frame = recording.frames[currentSeq]!;
            emitFrame(frame);
            currentSeq++;

            if (currentSeq >= recording.frames.length) {
                setState('finished');
            } else if (state === 'playing') {
                setState('paused');
            }

            return frame;
        },

        stepBackward(): ReplayFrame | null {
            if (recording === null) return null;
            if (currentSeq <= 0) return null;

            stopTimer();
            currentSeq--;
            const frame = recording.frames[currentSeq]!;
            emitFrame(frame);

            if (state === 'playing') {
                setState('paused');
            }

            return frame;
        },

        getState(): PlaybackState {
            return state;
        },

        getSpeed(): PlaybackSpeed {
            return speed;
        },

        getPosition(): ReplayPosition {
            if (recording === null) {
                return { seq: 0, tick: 0, wallTimeMs: 0, totalFrames: 0, totalTicks: 0, progressPercent: 0 };
            }

            const currentFrame = recording.frames[Math.min(currentSeq, recording.frames.length - 1)];
            const totalFrames = recording.frames.length;

            return {
                seq: currentSeq,
                tick: currentFrame?.tick ?? 0,
                wallTimeMs: currentFrame?.wallTimeMs ?? 0,
                totalFrames,
                totalTicks: recording.totalTicks,
                progressPercent: totalFrames > 0 ? (currentSeq / totalFrames) * 100 : 0,
            };
        },

        getRecording(): ReplayRecording | null {
            return recording;
        },

        onFrame(handler: (frame: ReplayFrame) => void): () => void {
            frameHandlers.add(handler);
            return () => { frameHandlers.delete(handler); };
        },

        onStateChange(handler: (state: PlaybackState) => void): () => void {
            stateHandlers.add(handler);
            return () => { stateHandlers.delete(handler); };
        },

        getFrames(filter?: ReplayFrameFilter): readonly ReplayFrame[] {
            if (recording === null) return [];
            let result = recording.frames as ReplayFrame[];

            if (filter !== undefined) {
                if (filter.kinds !== undefined) {
                    const kinds = new Set(filter.kinds);
                    result = result.filter(f => kinds.has(f.kind));
                }
                if (filter.fromTick !== undefined) {
                    const from = filter.fromTick;
                    result = result.filter(f => f.tick >= from);
                }
                if (filter.toTick !== undefined) {
                    const to = filter.toTick;
                    result = result.filter(f => f.tick <= to);
                }
                if (filter.fromSeq !== undefined) {
                    const from = filter.fromSeq;
                    result = result.filter(f => f.seq >= from);
                }
                if (filter.toSeq !== undefined) {
                    const to = filter.toSeq;
                    result = result.filter(f => f.seq <= to);
                }
            }

            return result;
        },
    };
}
