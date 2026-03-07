/**
 * VARIANT — SIEM Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createSIEMEngine } from '../../../src/lib/siem/siem-engine';
import type { SIEMLogEntry, SIEMDetectionRule } from '../../../src/lib/siem/siem-engine';

let logId = 0;
function log(
    machine: string,
    service: string,
    message: string,
    tick: number = 0,
    severity: 'debug' | 'info' | 'notice' | 'warning' | 'error' | 'critical' | 'alert' | 'emergency' = 'info',
    fields: Record<string, string | number | boolean> = {},
    tags: string[] = [],
): SIEMLogEntry {
    logId++;
    return {
        id: `log-${logId}`,
        timestamp: Date.now(),
        tick,
        source: { machine, service, logFile: `/var/log/${service}.log` },
        severity,
        category: 'general',
        message,
        raw: message,
        fields,
        tags,
    };
}

function failedLoginRule(): SIEMDetectionRule {
    return {
        id: 'failed-logins',
        name: 'Brute Force Detection',
        description: 'Detects multiple failed logins',
        severity: 'warning',
        conditions: [
            { type: 'message-contains', substring: 'Failed password' },
        ],
        threshold: 3,
        windowTicks: 100,
        cooldownTicks: 50,
        enabled: true,
    };
}

describe('SIEMEngine', () => {
    // ── Log Ingestion ──────────────────────────────────────────

    it('ingests and counts logs', () => {
        const siem = createSIEMEngine();
        siem.ingest(log('web', 'sshd', 'Connection from 10.0.0.1'));
        siem.ingest(log('web', 'sshd', 'Connection from 10.0.0.2'));
        expect(siem.logCount()).toBe(2);
    });

    it('ingestBatch adds multiple logs', () => {
        const siem = createSIEMEngine();
        siem.ingestBatch([
            log('web', 'sshd', 'A'),
            log('web', 'sshd', 'B'),
            log('web', 'sshd', 'C'),
        ]);
        expect(siem.logCount()).toBe(3);
    });

    // ── Querying ───────────────────────────────────────────────

    it('queries by source machine', () => {
        const siem = createSIEMEngine();
        siem.ingest(log('web', 'sshd', 'A'));
        siem.ingest(log('db', 'mysql', 'B'));

        const results = siem.query({ source: { machine: 'web' } });
        expect(results.length).toBe(1);
        expect(results[0]!.source.machine).toBe('web');
    });

    it('queries by severity', () => {
        const siem = createSIEMEngine();
        siem.ingest(log('web', 'sshd', 'Info msg', 0, 'info'));
        siem.ingest(log('web', 'sshd', 'Error msg', 0, 'error'));

        const results = siem.query({ severity: 'error' });
        expect(results.length).toBe(1);
    });

    it('queries by message content', () => {
        const siem = createSIEMEngine();
        siem.ingest(log('web', 'sshd', 'Failed password for admin'));
        siem.ingest(log('web', 'sshd', 'Accepted password for admin'));

        const results = siem.query({ messageContains: 'Failed' });
        expect(results.length).toBe(1);
    });

    it('queries by tick range', () => {
        const siem = createSIEMEngine();
        siem.ingest(log('web', 'sshd', 'A', 5));
        siem.ingest(log('web', 'sshd', 'B', 15));
        siem.ingest(log('web', 'sshd', 'C', 25));

        const results = siem.query({ fromTick: 10, toTick: 20 });
        expect(results.length).toBe(1);
    });

    it('query with limit', () => {
        const siem = createSIEMEngine();
        for (let i = 0; i < 10; i++) {
            siem.ingest(log('web', 'sshd', `Log ${i}`));
        }
        expect(siem.query({ limit: 3 }).length).toBe(3);
    });

    // ── Detection Rules ────────────────────────────────────────

    it('adds and lists rules', () => {
        const siem = createSIEMEngine();
        siem.addRule(failedLoginRule());
        expect(siem.getRules().length).toBe(1);
    });

    it('removes rules', () => {
        const siem = createSIEMEngine();
        siem.addRule(failedLoginRule());
        expect(siem.removeRule('failed-logins')).toBe(true);
        expect(siem.removeRule('nonexistent')).toBe(false);
        expect(siem.getRules().length).toBe(0);
    });

    it('generates alerts when threshold reached', () => {
        const siem = createSIEMEngine();
        siem.addRule(failedLoginRule());

        siem.ingest(log('web', 'sshd', 'Failed password for admin', 1));
        siem.ingest(log('web', 'sshd', 'Failed password for admin', 2));
        siem.ingest(log('web', 'sshd', 'Failed password for admin', 3));

        const alerts = siem.tick(5);
        expect(alerts.length).toBeGreaterThan(0);
        expect(siem.getAlerts().length).toBeGreaterThan(0);
    });

    it('does not alert below threshold', () => {
        const siem = createSIEMEngine();
        siem.addRule(failedLoginRule());

        siem.ingest(log('web', 'sshd', 'Failed password for admin', 1));
        siem.ingest(log('web', 'sshd', 'Failed password for admin', 2));
        // Only 2, threshold is 3

        const alerts = siem.tick(5);
        expect(alerts.length).toBe(0);
    });

    // ── Alert Management ───────────────────────────────────────

    it('acknowledges an alert', () => {
        const siem = createSIEMEngine();
        siem.addRule(failedLoginRule());

        siem.ingest(log('web', 'sshd', 'Failed password', 1));
        siem.ingest(log('web', 'sshd', 'Failed password', 2));
        siem.ingest(log('web', 'sshd', 'Failed password', 3));
        siem.tick(5);

        const alertId = siem.getAlerts()[0]!.id;
        expect(siem.acknowledgeAlert(alertId)).toBe(true);
        expect(siem.getPendingAlerts().length).toBe(0);
    });

    it('acknowledgeAlert returns false for unknown ID', () => {
        const siem = createSIEMEngine();
        expect(siem.acknowledgeAlert('nonexistent')).toBe(false);
    });

    it('marks alert as false positive', () => {
        const siem = createSIEMEngine();
        siem.addRule(failedLoginRule());

        siem.ingest(log('web', 'sshd', 'Failed password', 1));
        siem.ingest(log('web', 'sshd', 'Failed password', 2));
        siem.ingest(log('web', 'sshd', 'Failed password', 3));
        siem.tick(5);

        const alertId = siem.getAlerts()[0]!.id;
        expect(siem.markFalsePositive(alertId)).toBe(true);
    });

    it('adds notes to alerts', () => {
        const siem = createSIEMEngine();
        siem.addRule(failedLoginRule());

        siem.ingest(log('web', 'sshd', 'Failed password', 1));
        siem.ingest(log('web', 'sshd', 'Failed password', 2));
        siem.ingest(log('web', 'sshd', 'Failed password', 3));
        siem.tick(5);

        const alertId = siem.getAlerts()[0]!.id;
        expect(siem.addAlertNote(alertId, 'Investigating')).toBe(true);
    });

    // ── Timeline ───────────────────────────────────────────────

    it('timeline returns logs in tick range sorted', () => {
        const siem = createSIEMEngine();
        siem.ingest(log('web', 'sshd', 'C', 30));
        siem.ingest(log('web', 'sshd', 'A', 10));
        siem.ingest(log('web', 'sshd', 'B', 20));

        const tl = siem.timeline(5, 25);
        expect(tl.length).toBe(2);
        expect(tl[0]!.tick).toBeLessThanOrEqual(tl[1]!.tick);
    });

    // ── Stats ──────────────────────────────────────────────────

    it('getStats returns breakdown', () => {
        const siem = createSIEMEngine();
        siem.addRule(failedLoginRule());
        siem.ingest(log('web', 'sshd', 'Info', 0, 'info'));
        siem.ingest(log('web', 'sshd', 'Error', 0, 'error'));

        const stats = siem.getStats();
        expect(stats.totalLogs).toBe(2);
        expect(stats.rulesActive).toBe(1);
    });

    // ── Export ──────────────────────────────────────────────────

    it('exports logs as JSON', () => {
        const siem = createSIEMEngine();
        siem.ingest(log('web', 'sshd', 'Test'));

        const json = siem.export('json');
        expect(json.length).toBeGreaterThan(0);
        const parsed = JSON.parse(json);
        expect(Array.isArray(parsed)).toBe(true);
    });

    it('exports logs as CSV', () => {
        const siem = createSIEMEngine();
        siem.ingest(log('web', 'sshd', 'Test'));

        const csv = siem.export('csv');
        expect(csv).toContain('timestamp');
    });
});
