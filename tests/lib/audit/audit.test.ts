import { describe, it, expect, beforeEach } from 'vitest';
import { createAuditEngine } from '../../../src/lib/audit';
import type { AuditEngine } from '../../../src/lib/audit';

describe('Audit Engine', () => {
    let engine: AuditEngine;

    beforeEach(() => {
        engine = createAuditEngine();
    });

    function logLogin(actor: string, ip?: string, tick = 1) {
        const base = {
            tick, source: 'auth-service', actor, action: 'login' as const,
            target: 'system', result: 'success' as const, severity: 'info' as const,
            details: {},
        };
        return engine.log(ip !== undefined ? { ...base, sourceIP: ip } : base);
    }

    function logFailedLogin(actor: string, ip?: string, tick = 1) {
        const base = {
            tick, source: 'auth-service', actor, action: 'login_failed' as const,
            target: 'system', result: 'failure' as const, severity: 'medium' as const,
            details: { reason: 'invalid_password' },
        };
        return engine.log(ip !== undefined ? { ...base, sourceIP: ip } : base);
    }

    // ── Event Logging ────────────────────────────────────────

    it('logs events with auto-generated IDs and hashes', () => {
        const event = logLogin('admin');
        expect(event.id).toBeTruthy();
        expect(event.hash).toBeTruthy();
        expect(event.timestamp).toBeGreaterThan(0);
    });

    it('getEvent retrieves by ID', () => {
        const event = logLogin('admin');
        expect(engine.getEvent(event.id)).not.toBeNull();
        expect(engine.getEvent(event.id)!.actor).toBe('admin');
    });

    it('getEvent returns null for unknown ID', () => {
        expect(engine.getEvent('nonexistent')).toBeNull();
    });

    // ── Querying ─────────────────────────────────────────────

    it('query by actor', () => {
        logLogin('admin');
        logLogin('user1');
        logLogin('admin');
        expect(engine.query({ actor: 'admin' })).toHaveLength(2);
    });

    it('query by action', () => {
        logLogin('admin');
        logFailedLogin('attacker');
        expect(engine.query({ action: 'login' })).toHaveLength(1);
        expect(engine.query({ action: 'login_failed' })).toHaveLength(1);
    });

    it('query by result', () => {
        logLogin('admin');
        logFailedLogin('attacker');
        expect(engine.query({ result: 'success' })).toHaveLength(1);
        expect(engine.query({ result: 'failure' })).toHaveLength(1);
    });

    it('query by severity', () => {
        logLogin('admin'); // info
        logFailedLogin('attacker'); // medium
        expect(engine.query({ severity: 'info' })).toHaveLength(1);
        expect(engine.query({ severity: 'medium' })).toHaveLength(1);
    });

    it('query by tick range', () => {
        logLogin('a', undefined, 1);
        logLogin('b', undefined, 5);
        logLogin('c', undefined, 10);
        expect(engine.query({ fromTick: 3, toTick: 7 })).toHaveLength(1);
    });

    it('query by sourceIP', () => {
        logLogin('admin', '10.0.0.1');
        logLogin('admin', '10.0.0.2');
        expect(engine.query({ sourceIP: '10.0.0.1' })).toHaveLength(1);
    });

    it('getActorEvents', () => {
        logLogin('admin');
        logFailedLogin('admin');
        logLogin('other');
        expect(engine.getActorEvents('admin')).toHaveLength(2);
    });

    it('getActionEvents', () => {
        logLogin('a');
        logLogin('b');
        logFailedLogin('c');
        expect(engine.getActionEvents('login')).toHaveLength(2);
    });

    // ── Log Integrity ────────────────────────────────────────

    it('integrity is valid when no tampering', () => {
        logLogin('admin');
        logLogin('user1');
        const check = engine.checkIntegrity();
        expect(check.valid).toBe(true);
        expect(check.tamperedEvents).toHaveLength(0);
        expect(check.missingEvents).toBe(0);
    });

    it('tamperEvent marks event as tampered', () => {
        const event = logLogin('admin');
        expect(engine.tamperEvent(event.id)).toBe(true);
        const check = engine.checkIntegrity();
        expect(check.valid).toBe(false);
        expect(check.tamperedEvents).toContain(event.id);
    });

    it('tamperEvent returns false for unknown event', () => {
        expect(engine.tamperEvent('nonexistent')).toBe(false);
    });

    it('deleteEvent creates gaps in integrity', () => {
        logLogin('a');
        const e2 = logLogin('b');
        logLogin('c');
        engine.deleteEvent(e2.id);
        const check = engine.checkIntegrity();
        expect(check.valid).toBe(false);
        expect(check.missingEvents).toBe(1);
        expect(check.gaps).toHaveLength(1);
    });

    it('deleteEvent returns false for unknown event', () => {
        expect(engine.deleteEvent('nonexistent')).toBe(false);
    });

    it('deleted events excluded from queries', () => {
        const e1 = logLogin('admin');
        logLogin('admin');
        engine.deleteEvent(e1.id);
        expect(engine.query({ actor: 'admin' })).toHaveLength(1);
    });

    it('clearLogs marks all events as deleted', () => {
        logLogin('a');
        logLogin('b');
        logLogin('c');
        const count = engine.clearLogs();
        expect(count).toBe(3);
        expect(engine.query({})).toHaveLength(0);
    });

    // ── Anomaly Detection ────────────────────────────────────

    it('detects brute force (5+ failed logins)', () => {
        for (let i = 0; i < 6; i++) {
            logFailedLogin('attacker', '10.0.0.99', i + 1);
        }
        const anomalies = engine.detectAnomalies();
        const brute = anomalies.find(a => a.type === 'brute_force');
        expect(brute).toBeDefined();
        expect(brute!.severity).toBe('high');
        expect(brute!.mitre).toBe('T1110');
    });

    it('no brute force for fewer than 5 failures', () => {
        for (let i = 0; i < 4; i++) {
            logFailedLogin('attacker', '10.0.0.99', i + 1);
        }
        const anomalies = engine.detectAnomalies();
        expect(anomalies.find(a => a.type === 'brute_force')).toBeUndefined();
    });

    it('detects impossible travel', () => {
        logLogin('admin', '10.0.0.1', 1);
        logLogin('admin', '192.168.1.1', 2); // Different IP, 1 tick apart
        const anomalies = engine.detectAnomalies();
        const travel = anomalies.find(a => a.type === 'impossible_travel');
        expect(travel).toBeDefined();
        expect(travel!.mitre).toBe('T1078');
    });

    it('no impossible travel when IPs are same', () => {
        logLogin('admin', '10.0.0.1', 1);
        logLogin('admin', '10.0.0.1', 2);
        const anomalies = engine.detectAnomalies();
        expect(anomalies.find(a => a.type === 'impossible_travel')).toBeUndefined();
    });

    it('detects log tampering', () => {
        const event = logLogin('admin');
        engine.tamperEvent(event.id);
        const anomalies = engine.detectAnomalies();
        const tamper = anomalies.find(a => a.type === 'log_tampering');
        expect(tamper).toBeDefined();
        expect(tamper!.severity).toBe('critical');
    });

    it('detects mass deletion', () => {
        for (let i = 0; i < 8; i++) {
            const e = logLogin('user', undefined, i);
            engine.deleteEvent(e.id);
        }
        const anomalies = engine.detectAnomalies();
        const mass = anomalies.find(a => a.type === 'mass_deletion');
        expect(mass).toBeDefined();
        expect(mass!.severity).toBe('critical');
    });

    it('detects privilege escalation events', () => {
        engine.log({
            tick: 1, source: 'auth', actor: 'attacker', action: 'privilege_escalation',
            target: 'root', result: 'success', severity: 'high', details: {},
        });
        const anomalies = engine.detectAnomalies();
        const priv = anomalies.find(a => a.type === 'privilege_abuse');
        expect(priv).toBeDefined();
        expect(priv!.mitre).toBe('T1548');
    });

    // ── Compliance ───────────────────────────────────────────

    it('generates compliance report with auth events', () => {
        logLogin('admin');
        logFailedLogin('attacker');
        engine.log({
            tick: 3, source: 'acl', actor: 'admin', action: 'access_granted',
            target: '/data', result: 'success', severity: 'info', details: {},
        });

        const report = engine.generateComplianceReport('SOX');
        expect(report.framework).toBe('SOX');
        expect(report.controls.length).toBeGreaterThanOrEqual(3);
        const authControl = report.controls.find(c => c.id === 'SOX-AUTH-01');
        expect(authControl).toBeDefined();
        expect(authControl!.status).toBe('pass');
        expect(report.overallScore).toBeGreaterThan(0);
    });

    it('compliance report fails when no auth events', () => {
        engine.log({
            tick: 1, source: 'system', actor: 'admin', action: 'config_change',
            target: 'firewall', result: 'success', severity: 'info', details: {},
        });
        const report = engine.generateComplianceReport('HIPAA');
        const authControl = report.controls.find(c => c.id === 'HIPAA-AUTH-01');
        expect(authControl!.status).toBe('fail');
    });

    it('compliance report detects integrity failure', () => {
        const e = logLogin('admin');
        engine.tamperEvent(e.id);
        const report = engine.generateComplianceReport('PCI');
        const intControl = report.controls.find(c => c.id === 'PCI-INT-01');
        expect(intControl!.status).toBe('fail');
    });

    // ── Stats ────────────────────────────────────────────────

    it('getStats returns accurate counts', () => {
        logLogin('admin');
        logLogin('user1');
        logFailedLogin('attacker');
        logFailedLogin('attacker');
        const e = logLogin('other');
        engine.tamperEvent(e.id);
        engine.deleteEvent(e.id);

        const stats = engine.getStats();
        expect(stats.totalEvents).toBe(4); // 5 - 1 deleted
        expect(stats.uniqueActors).toBe(3); // admin, user1, attacker (other deleted)
        expect(stats.failedLogins).toBe(2);
        expect(stats.tamperedEvents).toBe(1);
        expect(stats.deletedEvents).toBe(1);
        expect(stats.eventsByAction['login']).toBe(2); // 3 - 1 deleted
        expect(stats.eventsBySeverity['info']).toBe(2);
    });
});
