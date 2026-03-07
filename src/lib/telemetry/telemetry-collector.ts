/**
 * VARIANT — Telemetry Collector Implementation
 *
 * Passively collects simulation metrics and produces a
 * TelemetryReport at session end.
 *
 * SWAPPABILITY: Implements TelemetryCollector. Replace this file.
 */

import type {
    TelemetryCollector,
    TelemetryReport,
    TelemetryMetrics,
    CommandEntry,
    TimeBucket,
    StuckPeriod,
} from './types';

const BUCKET_SIZE_TICKS = 30; // ~30 seconds per bucket
const STUCK_THRESHOLD_TICKS = 60; // 60 ticks with no progress = stuck

export function createTelemetryCollector(): TelemetryCollector {
    const commands: CommandEntry[] = [];
    const eventCounts = new Map<string, number>();
    const eventTicks: { type: string; tick: number }[] = [];
    const objectiveTimeline: { objectiveId: string; tick: number }[] = [];
    const machinesAccessed = new Set<string>();
    const filesRead = new Set<string>();
    const filesModified = new Set<string>();
    const techniquesUsed = new Set<string>();
    const commandFrequency = new Map<string, number>();

    let successfulLogins = 0;
    let failedLogins = 0;
    let connectionsAttempted = 0;
    let hintsUsed = 0;
    let finalScore = 0;
    let finalPhase = 'running';
    let finalNoiseLevel = 0;

    function computeTimeBuckets(totalTicks: number): TimeBucket[] {
        const buckets: TimeBucket[] = [];
        for (let start = 0; start < totalTicks; start += BUCKET_SIZE_TICKS) {
            const end = Math.min(start + BUCKET_SIZE_TICKS, totalTicks);
            const cmds = commands.filter(c => c.tick >= start && c.tick < end);
            const evts = eventTicks.filter(e => e.tick >= start && e.tick < end).length;
            const objs = objectiveTimeline.filter(o => o.tick >= start && o.tick < end);

            const activityLevel = cmds.length > 10 ? 2 : cmds.length > 0 ? 1 : 0;

            buckets.push({
                fromTick: start,
                toTick: end,
                commands: cmds.length,
                events: evts,
                objectivesCompleted: objs.length,
                activityLevel,
            });
        }
        return buckets;
    }

    function detectStuckPeriods(): StuckPeriod[] {
        const periods: StuckPeriod[] = [];
        if (commands.length < 2) return periods;

        let gapStart = commands[0]!.tick;
        let lastCmd = commands[0]!;

        for (let i = 1; i < commands.length; i++) {
            const cmd = commands[i]!;
            const gap = cmd.tick - lastCmd.tick;

            if (gap >= STUCK_THRESHOLD_TICKS) {
                periods.push({
                    fromTick: gapStart,
                    toTick: cmd.tick,
                    durationTicks: gap,
                    lastCommand: lastCmd.command,
                    machine: lastCmd.machine,
                    context: `No activity for ${gap} ticks after: ${lastCmd.command}`,
                });
            }

            gapStart = cmd.tick;
            lastCmd = cmd;
        }

        return periods;
    }

    return {
        recordCommand(entry: CommandEntry): void {
            commands.push(entry);
            machinesAccessed.add(entry.machine);

            const baseCmd = entry.command.split(/\s+/)[0] ?? entry.command;
            const count = commandFrequency.get(baseCmd) ?? 0;
            commandFrequency.set(baseCmd, count + 1);
        },

        recordEvent(eventType: string, tick: number): void {
            const count = eventCounts.get(eventType) ?? 0;
            eventCounts.set(eventType, count + 1);
            eventTicks.push({ type: eventType, tick });
        },

        recordObjectiveComplete(objectiveId: string, tick: number): void {
            objectiveTimeline.push({ objectiveId, tick });
        },

        recordLogin(machine: string, _user: string, success: boolean, _tick: number): void {
            if (success) {
                successfulLogins++;
                machinesAccessed.add(machine);
            } else {
                failedLogins++;
            }
        },

        recordFileAccess(path: string, mode: 'read' | 'write', _tick: number): void {
            if (mode === 'read') {
                filesRead.add(path);
            } else {
                filesModified.add(path);
            }
        },

        recordConnection(_target: string, _port: number, _tick: number): void {
            connectionsAttempted++;
        },

        recordTechnique(technique: string, _tick: number): void {
            techniquesUsed.add(technique);
        },

        recordHint(_hintId: string, _tick: number): void {
            hintsUsed++;
        },

        setFinalState(score: number, phase: string, noiseLevel: number): void {
            finalScore = score;
            finalPhase = phase;
            finalNoiseLevel = noiseLevel;
        },

        generateReport(totalTicks: number, totalWallTimeMs: number): TelemetryReport {
            const uniqueCommands = new Set(commands.map(c => c.command.split(/\s+/)[0] ?? '')).size;
            const minutesElapsed = totalWallTimeMs / 60000;

            const metrics: TelemetryMetrics = {
                totalTicks,
                totalWallTimeMs,
                totalCommands: commands.length,
                uniqueCommands,
                commandsPerMinute: minutesElapsed > 0 ? commands.length / minutesElapsed : 0,
                machinesAccessed: [...machinesAccessed],
                filesRead: [...filesRead],
                filesModified: [...filesModified],
                connectionsAttempted,
                successfulLogins,
                failedLogins,
                techniquesUsed: [...techniquesUsed],
                finalNoiseLevel,
                hintsUsed,
                objectivesCompleted: objectiveTimeline.map(o => o.objectiveId),
                finalScore,
                finalPhase,
            };

            const freqObj: Record<string, number> = {};
            for (const [cmd, count] of commandFrequency) {
                freqObj[cmd] = count;
            }

            const evtFreqObj: Record<string, number> = {};
            for (const [evt, count] of eventCounts) {
                evtFreqObj[evt] = count;
            }

            return {
                metrics,
                commands: [...commands],
                timeBuckets: computeTimeBuckets(totalTicks),
                stuckPeriods: detectStuckPeriods(),
                commandFrequency: freqObj,
                eventFrequency: evtFreqObj,
                objectiveTimeline: [...objectiveTimeline],
            };
        },

        reset(): void {
            commands.length = 0;
            eventCounts.clear();
            eventTicks.length = 0;
            objectiveTimeline.length = 0;
            machinesAccessed.clear();
            filesRead.clear();
            filesModified.clear();
            techniquesUsed.clear();
            commandFrequency.clear();
            successfulLogins = 0;
            failedLogins = 0;
            connectionsAttempted = 0;
            hintsUsed = 0;
            finalScore = 0;
            finalPhase = 'running';
            finalNoiseLevel = 0;
        },
    };
}
