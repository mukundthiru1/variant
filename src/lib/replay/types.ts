/**
 * VARIANT — Replay System Types
 *
 * Records every event and player input during a simulation,
 * producing a deterministic replay that can be played back,
 * fast-forwarded, rewound, and shared.
 *
 * A replay is a timestamped sequence of frames. Each frame
 * records either an engine event or a player input. Playback
 * re-emits these frames through the event bus, producing
 * identical simulation state.
 *
 * EXTENSIBILITY:
 *   - Custom frame types via the 'custom' kind
 *   - Annotation system for bookmarks and commentary
 *   - Export to multiple formats (JSON, binary, shareable URL)
 *   - Frame filters for selective playback
 *
 * SWAPPABILITY: Pure types. No implementation here.
 */

import type { EngineEvent } from '../../core/events';

// ── Replay Frame ────────────────────────────────────────────

/**
 * A single frame in a replay recording.
 * The atomic unit of replay data.
 */
export interface ReplayFrame {
    /** Monotonic sequence number (0-indexed). */
    readonly seq: number;

    /** Simulation tick when this frame was recorded. */
    readonly tick: number;

    /** Wall clock time (ms since simulation start). */
    readonly wallTimeMs: number;

    /** What happened in this frame. */
    readonly kind: ReplayFrameKind;

    /** The payload — depends on kind. */
    readonly data: ReplayFrameData;
}

export type ReplayFrameKind =
    | 'event'       // An engine event was emitted
    | 'input'       // Player typed something in a terminal
    | 'command'     // Player executed a shell command
    | 'hint'        // Player used a hint
    | 'objective'   // Objective status changed
    | 'phase'       // Simulation phase changed
    | 'annotation'  // User/system annotation (bookmark, note)
    | 'custom';     // Extension point

export type ReplayFrameData =
    | EventFrameData
    | InputFrameData
    | CommandFrameData
    | HintFrameData
    | ObjectiveFrameData
    | PhaseFrameData
    | AnnotationFrameData
    | CustomFrameData;

export interface EventFrameData {
    readonly kind: 'event';
    readonly event: EngineEvent;
}

export interface InputFrameData {
    readonly kind: 'input';
    readonly machine: string;
    readonly input: string;
}

export interface CommandFrameData {
    readonly kind: 'command';
    readonly machine: string;
    readonly command: string;
    readonly user: string;
    readonly cwd: string;
}

export interface HintFrameData {
    readonly kind: 'hint';
    readonly hintIndex: number;
    readonly hintText: string;
}

export interface ObjectiveFrameData {
    readonly kind: 'objective';
    readonly objectiveId: string;
    readonly fromStatus: string;
    readonly toStatus: string;
}

export interface PhaseFrameData {
    readonly kind: 'phase';
    readonly fromPhase: string;
    readonly toPhase: string;
}

export interface AnnotationFrameData {
    readonly kind: 'annotation';
    readonly label: string;
    readonly text: string;
    readonly category: 'bookmark' | 'note' | 'milestone' | 'error' | 'custom';
}

export interface CustomFrameData {
    readonly kind: 'custom';
    readonly type: string;
    readonly payload: unknown;
}

// ── Replay Recording ────────────────────────────────────────

/**
 * A complete replay recording.
 * Immutable after recording stops.
 */
export interface ReplayRecording {
    /** Unique replay ID. */
    readonly id: string;

    /** WorldSpec ID this replay is for. */
    readonly worldId: string;

    /** WorldSpec title. */
    readonly worldTitle: string;

    /** When the recording started (ISO 8601). */
    readonly startedAt: string;

    /** When the recording ended (ISO 8601). */
    readonly endedAt: string;

    /** Total duration in milliseconds. */
    readonly durationMs: number;

    /** Total number of ticks. */
    readonly totalTicks: number;

    /** Final score. */
    readonly finalScore: number;

    /** Final phase (completed, failed, etc.). */
    readonly finalPhase: string;

    /** All frames in chronological order. */
    readonly frames: readonly ReplayFrame[];

    /** Annotations/bookmarks. */
    readonly annotations: readonly ReplayAnnotation[];

    /** Recording metadata. */
    readonly meta: ReplayMeta;
}

export interface ReplayAnnotation {
    readonly tick: number;
    readonly seq: number;
    readonly label: string;
    readonly text: string;
    readonly category: 'bookmark' | 'note' | 'milestone' | 'error' | 'custom';
}

export interface ReplayMeta {
    /** Engine version that created this replay. */
    readonly engineVersion: string;

    /** Player identifier (optional, for leaderboards). */
    readonly playerId?: string;

    /** Number of hints used. */
    readonly hintsUsed: number;

    /** Objectives completed. */
    readonly objectivesCompleted: readonly string[];

    /** Custom metadata from modules. */
    readonly custom: Readonly<Record<string, unknown>>;
}

// ── Replay Recorder ─────────────────────────────────────────

/**
 * Records frames during a live simulation.
 */
export interface ReplayRecorder {
    /** Start recording. */
    start(worldId: string, worldTitle: string): void;

    /** Record a frame. */
    record(kind: ReplayFrameKind, data: ReplayFrameData, tick: number): void;

    /** Add an annotation at the current position. */
    annotate(label: string, text: string, category: ReplayAnnotation['category'], tick: number): void;

    /** Stop recording and produce the final ReplayRecording. */
    stop(finalScore: number, finalPhase: string, hintsUsed: number, objectivesCompleted: readonly string[]): ReplayRecording;

    /** Get the current frame count. */
    frameCount(): number;

    /** Is currently recording? */
    isRecording(): boolean;
}

// ── Replay Player ───────────────────────────────────────────

export type PlaybackState = 'stopped' | 'playing' | 'paused' | 'finished';
export type PlaybackSpeed = 0.25 | 0.5 | 1 | 2 | 4 | 8 | 16;

/**
 * Plays back a replay recording.
 */
export interface ReplayPlayer {
    /** Load a recording. */
    load(recording: ReplayRecording): void;

    /** Start or resume playback. */
    play(): void;

    /** Pause playback. */
    pause(): void;

    /** Stop and reset to beginning. */
    stop(): void;

    /** Seek to a specific tick. */
    seekToTick(tick: number): void;

    /** Seek to a specific frame. */
    seekToFrame(seq: number): void;

    /** Seek to an annotation. */
    seekToAnnotation(index: number): void;

    /** Set playback speed. */
    setSpeed(speed: PlaybackSpeed): void;

    /** Step forward one frame. */
    stepForward(): ReplayFrame | null;

    /** Step backward one frame. */
    stepBackward(): ReplayFrame | null;

    /** Get current playback state. */
    getState(): PlaybackState;

    /** Get current speed. */
    getSpeed(): PlaybackSpeed;

    /** Get current position. */
    getPosition(): ReplayPosition;

    /** Get the loaded recording. */
    getRecording(): ReplayRecording | null;

    /** Subscribe to frame emissions during playback. */
    onFrame(handler: (frame: ReplayFrame) => void): () => void;

    /** Subscribe to state changes. */
    onStateChange(handler: (state: PlaybackState) => void): () => void;

    /** Get frames matching a filter. */
    getFrames(filter?: ReplayFrameFilter): readonly ReplayFrame[];
}

export interface ReplayPosition {
    readonly seq: number;
    readonly tick: number;
    readonly wallTimeMs: number;
    readonly totalFrames: number;
    readonly totalTicks: number;
    readonly progressPercent: number;
}

export interface ReplayFrameFilter {
    readonly kinds?: readonly ReplayFrameKind[];
    readonly fromTick?: number;
    readonly toTick?: number;
    readonly fromSeq?: number;
    readonly toSeq?: number;
}
