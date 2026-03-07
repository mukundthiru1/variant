/**
 * VARIANT — Telemetry Collector tests
 */
import { describe, it, expect } from 'vitest';
import { createTelemetryCollector } from '../../../src/lib/telemetry/telemetry-collector';

describe('TelemetryCollector', () => {
    it('records commands and generates report', () => {
        const collector = createTelemetryCollector();

        collector.recordCommand({ tick: 1, wallTimeMs: 1000, machine: 'web-01', user: 'root', command: 'ls -la', cwd: '/' });
        collector.recordCommand({ tick: 2, wallTimeMs: 2000, machine: 'web-01', user: 'root', command: 'cat /etc/passwd', cwd: '/' });
        collector.setFinalState(500, 'completed', 20);

        const report = collector.generateReport(100, 100000);
        expect(report.metrics.totalCommands).toBe(2);
        expect(report.metrics.finalScore).toBe(500);
        expect(report.metrics.finalPhase).toBe('completed');
        expect(report.commands.length).toBe(2);
    });

    it('tracks unique commands', () => {
        const collector = createTelemetryCollector();

        collector.recordCommand({ tick: 1, wallTimeMs: 1000, machine: 'web-01', user: 'root', command: 'ls', cwd: '/' });
        collector.recordCommand({ tick: 2, wallTimeMs: 2000, machine: 'web-01', user: 'root', command: 'ls', cwd: '/' });
        collector.recordCommand({ tick: 3, wallTimeMs: 3000, machine: 'web-01', user: 'root', command: 'cat /etc/passwd', cwd: '/' });
        collector.setFinalState(100, 'running', 0);

        const report = collector.generateReport(10, 10000);
        expect(report.metrics.uniqueCommands).toBe(2);
    });

    it('tracks machines accessed', () => {
        const collector = createTelemetryCollector();

        collector.recordLogin('web-01', 'root', true, 1);
        collector.recordLogin('db-01', 'admin', true, 2);
        collector.recordLogin('web-01', 'root', false, 3);
        collector.setFinalState(100, 'running', 0);

        const report = collector.generateReport(10, 10000);
        expect(report.metrics.machinesAccessed).toContain('web-01');
        expect(report.metrics.machinesAccessed).toContain('db-01');
        expect(report.metrics.successfulLogins).toBe(2);
        expect(report.metrics.failedLogins).toBe(1);
    });

    it('tracks file access', () => {
        const collector = createTelemetryCollector();

        collector.recordFileAccess('/etc/passwd', 'read', 1);
        collector.recordFileAccess('/etc/shadow', 'read', 2);
        collector.recordFileAccess('/tmp/evil.sh', 'write', 3);
        collector.setFinalState(100, 'running', 0);

        const report = collector.generateReport(10, 10000);
        expect(report.metrics.filesRead.length).toBe(2);
        expect(report.metrics.filesModified.length).toBe(1);
    });

    it('tracks techniques', () => {
        const collector = createTelemetryCollector();

        collector.recordTechnique('sqli', 5);
        collector.recordTechnique('xss', 10);
        collector.setFinalState(100, 'running', 0);

        const report = collector.generateReport(20, 20000);
        expect(report.metrics.techniquesUsed).toContain('sqli');
        expect(report.metrics.techniquesUsed).toContain('xss');
    });

    it('tracks connections', () => {
        const collector = createTelemetryCollector();

        collector.recordConnection('10.0.0.5', 22, 1);
        collector.recordConnection('10.0.0.5', 80, 2);
        collector.setFinalState(100, 'running', 0);

        const report = collector.generateReport(10, 10000);
        expect(report.metrics.connectionsAttempted).toBe(2);
    });

    it('tracks objective completions', () => {
        const collector = createTelemetryCollector();

        collector.recordObjectiveComplete('obj-1', 10);
        collector.recordObjectiveComplete('obj-2', 25);
        collector.setFinalState(100, 'completed', 0);

        const report = collector.generateReport(30, 30000);
        expect(report.metrics.objectivesCompleted.length).toBe(2);
        expect(report.objectiveTimeline.length).toBe(2);
        expect(report.objectiveTimeline[0]!.tick).toBe(10);
    });

    it('computes command frequency', () => {
        const collector = createTelemetryCollector();

        collector.recordCommand({ tick: 1, wallTimeMs: 1000, machine: 'web-01', user: 'root', command: 'ls -la', cwd: '/' });
        collector.recordCommand({ tick: 2, wallTimeMs: 2000, machine: 'web-01', user: 'root', command: 'ls /etc', cwd: '/' });
        collector.recordCommand({ tick: 3, wallTimeMs: 3000, machine: 'web-01', user: 'root', command: 'cat /etc/passwd', cwd: '/' });
        collector.setFinalState(100, 'running', 0);

        const report = collector.generateReport(10, 10000);
        expect(report.commandFrequency['ls']).toBe(2);
        expect(report.commandFrequency['cat']).toBe(1);
    });

    it('detects stuck periods', () => {
        const collector = createTelemetryCollector();

        collector.recordCommand({ tick: 1, wallTimeMs: 1000, machine: 'web-01', user: 'root', command: 'ls', cwd: '/' });
        // Gap of 100 ticks
        collector.recordCommand({ tick: 101, wallTimeMs: 101000, machine: 'web-01', user: 'root', command: 'cat /etc/passwd', cwd: '/' });
        collector.setFinalState(100, 'running', 0);

        const report = collector.generateReport(110, 110000);
        expect(report.stuckPeriods.length).toBe(1);
        expect(report.stuckPeriods[0]!.durationTicks).toBe(100);
    });

    it('computes commands per minute', () => {
        const collector = createTelemetryCollector();

        for (let i = 0; i < 10; i++) {
            collector.recordCommand({ tick: i, wallTimeMs: i * 1000, machine: 'web-01', user: 'root', command: 'cmd', cwd: '/' });
        }
        collector.setFinalState(100, 'running', 0);

        const report = collector.generateReport(60, 60000); // 1 minute
        expect(report.metrics.commandsPerMinute).toBe(10);
    });

    it('generates time buckets', () => {
        const collector = createTelemetryCollector();

        for (let i = 0; i < 5; i++) {
            collector.recordCommand({ tick: i, wallTimeMs: i * 1000, machine: 'web-01', user: 'root', command: 'cmd', cwd: '/' });
        }
        collector.setFinalState(100, 'running', 0);

        const report = collector.generateReport(90, 90000);
        expect(report.timeBuckets.length).toBeGreaterThan(0);
        expect(report.timeBuckets[0]!.commands).toBe(5);
    });

    it('tracks hints', () => {
        const collector = createTelemetryCollector();

        collector.recordHint('hint-1', 5);
        collector.recordHint('hint-2', 10);
        collector.setFinalState(100, 'running', 0);

        const report = collector.generateReport(20, 20000);
        expect(report.metrics.hintsUsed).toBe(2);
    });

    it('resets all data', () => {
        const collector = createTelemetryCollector();

        collector.recordCommand({ tick: 1, wallTimeMs: 1000, machine: 'web-01', user: 'root', command: 'ls', cwd: '/' });
        collector.recordLogin('web-01', 'root', true, 1);
        collector.setFinalState(500, 'completed', 0);

        collector.reset();
        const report = collector.generateReport(0, 0);
        expect(report.metrics.totalCommands).toBe(0);
        expect(report.metrics.successfulLogins).toBe(0);
        expect(report.metrics.finalScore).toBe(0);
    });
});
