/**
 * VARIANT — Replay System tests
 */
import { describe, it, expect } from 'vitest';
import { createReplayRecorder } from '../../../src/lib/replay/replay-recorder';
import { createReplayPlayer } from '../../../src/lib/replay/replay-player';
import type { ReplayFrame } from '../../../src/lib/replay/types';

describe('ReplayRecorder', () => {
    it('starts and stops recording', () => {
        const recorder = createReplayRecorder();
        expect(recorder.isRecording()).toBe(false);

        recorder.start('level-01', 'Test Level');
        expect(recorder.isRecording()).toBe(true);

        const recording = recorder.stop(500, 'completed', 1, ['obj-1']);
        expect(recorder.isRecording()).toBe(false);
        expect(recording.worldId).toBe('level-01');
        expect(recording.worldTitle).toBe('Test Level');
        expect(recording.finalScore).toBe(500);
        expect(recording.finalPhase).toBe('completed');
    });

    it('records frames with correct sequence numbers', () => {
        const recorder = createReplayRecorder();
        recorder.start('level-01', 'Test');

        recorder.record('command', { kind: 'command', machine: 'web-01', command: 'ls', user: 'root', cwd: '/' }, 1);
        recorder.record('command', { kind: 'command', machine: 'web-01', command: 'cat /etc/passwd', user: 'root', cwd: '/' }, 2);
        recorder.record('input', { kind: 'input', machine: 'web-01', input: 'whoami' }, 3);

        expect(recorder.frameCount()).toBe(3);

        const recording = recorder.stop(100, 'running', 0, []);
        expect(recording.frames.length).toBe(3);
        expect(recording.frames[0]!.seq).toBe(0);
        expect(recording.frames[1]!.seq).toBe(1);
        expect(recording.frames[2]!.seq).toBe(2);
    });

    it('records annotations', () => {
        const recorder = createReplayRecorder();
        recorder.start('level-01', 'Test');

        recorder.annotate('Bookmark', 'Found the config file', 'bookmark', 5);

        const recording = recorder.stop(100, 'running', 0, []);
        expect(recording.annotations.length).toBe(1);
        expect(recording.annotations[0]!.label).toBe('Bookmark');
        expect(recording.annotations[0]!.category).toBe('bookmark');
    });

    it('ignores records when not recording', () => {
        const recorder = createReplayRecorder();
        recorder.record('command', { kind: 'command', machine: 'web-01', command: 'ls', user: 'root', cwd: '/' }, 1);
        expect(recorder.frameCount()).toBe(0);
    });

    it('produces frozen recordings', () => {
        const recorder = createReplayRecorder();
        recorder.start('level-01', 'Test');
        recorder.record('input', { kind: 'input', machine: 'web-01', input: 'test' }, 1);
        const recording = recorder.stop(100, 'completed', 0, ['obj-1']);

        expect(Object.isFrozen(recording)).toBe(true);
        expect(Object.isFrozen(recording.frames)).toBe(true);
        expect(recording.meta.objectivesCompleted).toContain('obj-1');
    });

    it('includes meta information', () => {
        const recorder = createReplayRecorder();
        recorder.start('level-01', 'Test');
        const recording = recorder.stop(750, 'completed', 2, ['obj-1', 'obj-2']);

        expect(recording.meta.hintsUsed).toBe(2);
        expect(recording.meta.objectivesCompleted.length).toBe(2);
        expect(recording.meta.engineVersion).toBe('1.0.0');
    });
});

describe('ReplayPlayer', () => {
    function makeRecording() {
        const recorder = createReplayRecorder();
        recorder.start('level-01', 'Test');
        recorder.record('command', { kind: 'command', machine: 'web-01', command: 'ls', user: 'root', cwd: '/' }, 1);
        recorder.record('command', { kind: 'command', machine: 'web-01', command: 'cat /etc/passwd', user: 'root', cwd: '/' }, 2);
        recorder.record('input', { kind: 'input', machine: 'web-01', input: 'whoami' }, 3);
        recorder.annotate('Key Moment', 'Found credentials', 'milestone', 2);
        return recorder.stop(500, 'completed', 0, ['obj-1']);
    }

    it('loads and reports state', () => {
        const player = createReplayPlayer();
        expect(player.getState()).toBe('stopped');
        expect(player.getRecording()).toBeNull();

        const recording = makeRecording();
        player.load(recording);
        expect(player.getState()).toBe('stopped');
        expect(player.getRecording()).toBe(recording);
    });

    it('steps forward through frames', () => {
        const player = createReplayPlayer();
        player.load(makeRecording());

        const frame1 = player.stepForward();
        expect(frame1).not.toBeNull();
        expect(frame1!.seq).toBe(0);

        const frame2 = player.stepForward();
        expect(frame2).not.toBeNull();
        expect(frame2!.seq).toBe(1);
    });

    it('steps backward', () => {
        const player = createReplayPlayer();
        player.load(makeRecording());

        player.stepForward(); // seq 0, currentSeq -> 1
        player.stepForward(); // seq 1, currentSeq -> 2
        const frame = player.stepBackward(); // currentSeq -> 1, emits seq 1
        expect(frame).not.toBeNull();
        expect(frame!.seq).toBe(1);
    });

    it('reports position correctly', () => {
        const player = createReplayPlayer();
        const recording = makeRecording();
        player.load(recording);

        const pos = player.getPosition();
        expect(pos.seq).toBe(0);
        expect(pos.totalFrames).toBe(recording.frames.length);
    });

    it('emits frames to handlers', () => {
        const player = createReplayPlayer();
        player.load(makeRecording());

        const received: ReplayFrame[] = [];
        player.onFrame(frame => received.push(frame));

        player.stepForward();
        player.stepForward();

        expect(received.length).toBe(2);
        expect(received[0]!.seq).toBe(0);
        expect(received[1]!.seq).toBe(1);
    });

    it('seeks to tick', () => {
        const player = createReplayPlayer();
        player.load(makeRecording());

        player.seekToTick(3);
        const pos = player.getPosition();
        expect(pos.tick).toBeGreaterThanOrEqual(3);
    });

    it('filters frames by kind', () => {
        const player = createReplayPlayer();
        player.load(makeRecording());

        const commands = player.getFrames({ kinds: ['command'] });
        expect(commands.every(f => f.kind === 'command')).toBe(true);
    });

    it('filters frames by tick range', () => {
        const player = createReplayPlayer();
        player.load(makeRecording());

        const inRange = player.getFrames({ fromTick: 2, toTick: 3 });
        expect(inRange.every(f => f.tick >= 2 && f.tick <= 3)).toBe(true);
    });

    it('changes speed', () => {
        const player = createReplayPlayer();
        player.setSpeed(4);
        expect(player.getSpeed()).toBe(4);
    });

    it('seeks to annotation', () => {
        const player = createReplayPlayer();
        const recording = makeRecording();
        player.load(recording);

        player.seekToAnnotation(0);
        const pos = player.getPosition();
        expect(pos.seq).toBe(recording.annotations[0]!.seq);
    });

    it('returns null for step when no recording loaded', () => {
        const player = createReplayPlayer();
        expect(player.stepForward()).toBeNull();
        expect(player.stepBackward()).toBeNull();
    });
});
