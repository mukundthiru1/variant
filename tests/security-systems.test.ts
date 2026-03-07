/**
 * VARIANT — Firewall, Process Tree, and SIEM Tests
 *
 * Tests for:
 *   - Firewall rule evaluation engine
 *   - Process tree system
 *   - SIEM log aggregation, detection, and correlation
 */

import { describe, it, expect } from 'vitest';
import { createFirewallEngine } from '../src/lib/firewall/firewall-engine';
import type { FirewallPacket } from '../src/lib/firewall/firewall-engine';
import { createProcessTree, bootstrapLinuxProcessTree } from '../src/lib/process/process-tree';
import { createSIEMEngine, createBuiltinDetectionRules, createBuiltinCorrelationRules } from '../src/lib/siem/siem-engine';
import type { SIEMLogEntry } from '../src/lib/siem/siem-engine';

// ── Firewall Tests ─────────────────────────────────────────────

describe('FirewallEngine', () => {
    const inboundHTTP: FirewallPacket = {
        protocol: 'tcp',
        sourceIP: '203.0.113.42',
        destinationIP: '10.0.1.20',
        sourcePort: 54321,
        destinationPort: 80,
        direction: 'inbound',
    };

    const inboundSSH: FirewallPacket = {
        protocol: 'tcp',
        sourceIP: '203.0.113.42',
        destinationIP: '10.0.1.20',
        sourcePort: 54322,
        destinationPort: 22,
        direction: 'inbound',
    };

    const outboundDNS: FirewallPacket = {
        protocol: 'udp',
        sourceIP: '10.0.1.20',
        destinationIP: '8.8.8.8',
        sourcePort: 1234,
        destinationPort: 53,
        direction: 'outbound',
    };

    it('allows all traffic with no rules and default ACCEPT policy', () => {
        const fw = createFirewallEngine('server-01', []);
        const result = fw.evaluate(inboundHTTP);
        expect(result.allowed).toBe(true);
        expect(result.action).toBe('ACCEPT');
        expect(result.matchedRuleIndex).toBe(-1); // default policy
    });

    it('drops traffic matching a DROP rule', () => {
        const fw = createFirewallEngine('server-01', [
            { chain: 'INPUT', action: 'DROP', protocol: 'tcp', port: 22 },
        ]);

        const httpResult = fw.evaluate(inboundHTTP);
        expect(httpResult.allowed).toBe(true);

        const sshResult = fw.evaluate(inboundSSH);
        expect(sshResult.allowed).toBe(false);
        expect(sshResult.action).toBe('DROP');
        expect(sshResult.matchedRuleIndex).toBe(0);
    });

    it('matches source IP', () => {
        const fw = createFirewallEngine('server-01', [
            { chain: 'INPUT', action: 'DROP', source: '203.0.113.42' },
        ]);

        const result = fw.evaluate(inboundHTTP);
        expect(result.allowed).toBe(false);
    });

    it('matches CIDR ranges', () => {
        const fw = createFirewallEngine('server-01', [
            { chain: 'INPUT', action: 'DROP', source: '203.0.113.0/24' },
        ]);

        const result = fw.evaluate(inboundHTTP);
        expect(result.allowed).toBe(false);

        // Different subnet — should pass
        const differentSubnet: FirewallPacket = {
            ...inboundHTTP,
            sourceIP: '10.0.1.5',
        };
        const result2 = fw.evaluate(differentSubnet);
        expect(result2.allowed).toBe(true);
    });

    it('first matching rule wins', () => {
        const fw = createFirewallEngine('server-01', [
            { chain: 'INPUT', action: 'ACCEPT', protocol: 'tcp', port: 80 },
            { chain: 'INPUT', action: 'DROP' }, // drop everything else
        ]);

        expect(fw.evaluate(inboundHTTP).allowed).toBe(true);
        expect(fw.evaluate(inboundSSH).allowed).toBe(false);
    });

    it('respects default policy change', () => {
        const fw = createFirewallEngine('server-01', []);
        fw.setPolicy('INPUT', 'DROP');

        const result = fw.evaluate(inboundHTTP);
        expect(result.allowed).toBe(false);
        expect(result.action).toBe('DROP');
    });

    it('tracks statistics', () => {
        const fw = createFirewallEngine('server-01', [
            { chain: 'INPUT', action: 'DROP', protocol: 'tcp', port: 22 },
        ]);

        fw.evaluate(inboundHTTP); // allowed
        fw.evaluate(inboundSSH);  // dropped
        fw.evaluate(inboundHTTP); // allowed

        const stats = fw.getStats();
        expect(stats.packetsEvaluated).toBe(3);
        expect(stats.packetsAllowed).toBe(2);
        expect(stats.packetsDropped).toBe(1);
    });

    it('evaluates OUTPUT chain for outbound traffic', () => {
        const fw = createFirewallEngine('server-01', [
            { chain: 'OUTPUT', action: 'DROP', protocol: 'udp', port: 53 },
        ]);

        const result = fw.evaluate(outboundDNS);
        expect(result.allowed).toBe(false);
        expect(result.chain).toBe('OUTPUT');
    });

    it('adds and removes rules dynamically', () => {
        const fw = createFirewallEngine('server-01', []);

        fw.addRule({ chain: 'INPUT', action: 'DROP', protocol: 'tcp', port: 22 });
        expect(fw.evaluate(inboundSSH).allowed).toBe(false);

        fw.removeRule(0);
        expect(fw.evaluate(inboundSSH).allowed).toBe(true);
    });

    it('inserts rules at specific position', () => {
        const fw = createFirewallEngine('server-01', [
            { chain: 'INPUT', action: 'DROP' }, // drop all
        ]);

        // Insert ACCEPT for HTTP before the DROP ALL
        fw.insertRule(0, { chain: 'INPUT', action: 'ACCEPT', protocol: 'tcp', port: 80 });

        expect(fw.evaluate(inboundHTTP).allowed).toBe(true);
        expect(fw.evaluate(inboundSSH).allowed).toBe(false);
    });

    it('formats as iptables output', () => {
        const fw = createFirewallEngine('server-01', [
            { chain: 'INPUT', action: 'ACCEPT', protocol: 'tcp', port: 80 },
            { chain: 'INPUT', action: 'DROP', source: '203.0.113.0/24' },
        ]);

        const output = fw.formatAsIptables();
        expect(output).toContain('Chain INPUT');
        expect(output).toContain('policy ACCEPT');
        expect(output).toContain('ACCEPT');
        expect(output).toContain('dpt:80');
    });

    it('handles REJECT action', () => {
        const fw = createFirewallEngine('server-01', [
            { chain: 'INPUT', action: 'REJECT', protocol: 'tcp', port: 22 },
        ]);

        const result = fw.evaluate(inboundSSH);
        expect(result.allowed).toBe(false);
        expect(result.action).toBe('REJECT');
        expect(fw.getStats().packetsRejected).toBe(1);
    });
});

// ── Process Tree Tests ─────────────────────────────────────────

describe('ProcessTree', () => {
    it('starts with init process (PID 1)', () => {
        const tree = createProcessTree('server-01');
        const init = tree.get(1);
        expect(init).not.toBeNull();
        expect(init?.name).toBe('init');
        expect(init?.pid).toBe(1);
        expect(init?.ppid).toBe(0);
    });

    it('spawns processes with unique PIDs', () => {
        const tree = createProcessTree('server-01');
        const pid1 = tree.spawn({ name: 'bash', command: '/bin/bash' });
        const pid2 = tree.spawn({ name: 'nginx', command: '/usr/sbin/nginx' });

        expect(pid1).not.toBe(pid2);
        expect(tree.get(pid1)?.name).toBe('bash');
        expect(tree.get(pid2)?.name).toBe('nginx');
    });

    it('sets parent-child relationships', () => {
        const tree = createProcessTree('server-01');
        const parentPid = tree.spawn({ name: 'sshd', command: '/usr/sbin/sshd' });
        const childPid = tree.spawn({ name: 'bash', command: '/bin/bash', ppid: parentPid });

        expect(tree.get(childPid)?.ppid).toBe(parentPid);

        const children = tree.children(parentPid);
        expect(children.length).toBe(1);
        expect(children[0]?.pid).toBe(childPid);
    });

    it('reparents orphans to init on kill', () => {
        const tree = createProcessTree('server-01');
        const parentPid = tree.spawn({ name: 'parent', command: '/usr/bin/parent' });
        const childPid = tree.spawn({ name: 'child', command: '/usr/bin/child', ppid: parentPid });

        tree.kill(parentPid);

        const child = tree.get(childPid);
        expect(child?.ppid).toBe(1); // reparented to init
    });

    it('cannot kill init (PID 1)', () => {
        const tree = createProcessTree('server-01');
        const result = tree.kill(1);
        expect(result).toBe(false);
        expect(tree.get(1)).not.toBeNull();
    });

    it('traces ancestry', () => {
        const tree = createProcessTree('server-01');
        const sshdPid = tree.spawn({ name: 'sshd', command: '/usr/sbin/sshd' });
        const bashPid = tree.spawn({ name: 'bash', command: '/bin/bash', ppid: sshdPid });
        const catPid = tree.spawn({ name: 'cat', command: '/bin/cat', ppid: bashPid });

        const ancestry = tree.ancestry(catPid);
        expect(ancestry.length).toBe(4); // cat → bash → sshd → init
        expect(ancestry[0]?.name).toBe('cat');
        expect(ancestry[1]?.name).toBe('bash');
        expect(ancestry[2]?.name).toBe('sshd');
        expect(ancestry[3]?.name).toBe('init');
    });

    it('finds processes by name', () => {
        const tree = createProcessTree('server-01');
        tree.spawn({ name: 'nginx', command: '/usr/sbin/nginx' });
        tree.spawn({ name: 'nginx', command: '/usr/sbin/nginx', args: 'worker' });

        expect(tree.findByName('nginx')?.name).toBe('nginx');
        expect(tree.findAllByName('nginx').length).toBe(2);
    });

    it('finds processes by user', () => {
        const tree = createProcessTree('server-01');
        tree.spawn({ name: 'nginx', command: 'nginx', user: 'www-data' });
        tree.spawn({ name: 'php-fpm', command: 'php-fpm', user: 'www-data' });
        tree.spawn({ name: 'sshd', command: 'sshd', user: 'root' });

        expect(tree.findByUser('www-data').length).toBe(2);
    });

    it('detects suspicious lineage', () => {
        const tree = createProcessTree('server-01');
        const nginxPid = tree.spawn({ name: 'nginx', command: 'nginx', user: 'www-data' });
        // Suspicious: bash spawned from nginx (web shell!)
        tree.spawn({ name: 'bash', command: '/bin/bash', ppid: nginxPid, user: 'www-data' });

        const anomalies = tree.detectAnomalies();
        expect(anomalies.length).toBeGreaterThanOrEqual(1);
        expect(anomalies.some(a => a.type === 'suspicious-parent')).toBe(true);
    });

    it('detects privilege escalation', () => {
        const tree = createProcessTree('server-01');
        const userPid = tree.spawn({ name: 'bash', command: '/bin/bash', user: 'webuser' });
        tree.spawn({ name: 'su', command: '/bin/su', ppid: userPid, user: 'root' });

        const anomalies = tree.detectAnomalies();
        expect(anomalies.some(a => a.type === 'privilege-escalation')).toBe(true);
    });

    it('generates ps aux output', () => {
        const tree = createProcessTree('server-01');
        tree.spawn({ name: 'nginx', command: '/usr/sbin/nginx', user: 'www-data' });

        const output = tree.formatPsAux();
        expect(output).toContain('USER');
        expect(output).toContain('PID');
        expect(output).toContain('nginx');
    });

    it('bootstrapLinuxProcessTree creates a realistic tree', () => {
        const tree = bootstrapLinuxProcessTree('web-01', ['ssh', 'http', 'mysql']);

        // Should have init + kernel threads + systemd + services
        expect(tree.count()).toBeGreaterThan(10);

        // Should have init
        expect(tree.get(1)?.name).toBe('init');

        // Should have nginx (from http service)
        expect(tree.findByName('nginx')).not.toBeNull();

        // Should have sshd
        expect(tree.findByName('sshd')).not.toBeNull();

        // Should have mysqld
        expect(tree.findByName('mysqld')).not.toBeNull();

        // ps aux should work
        const psOutput = tree.formatPsAux();
        expect(psOutput.split('\n').length).toBeGreaterThan(10);
    });
});

// ── SIEM Tests ─────────────────────────────────────────────────

describe('SIEMEngine', () => {
    function makeLogEntry(overrides: Partial<SIEMLogEntry> & { id: string }): SIEMLogEntry {
        return {
            timestamp: Date.now(),
            tick: 0,
            source: { machine: 'web-01', service: 'http', logFile: '/var/log/access.log' },
            severity: 'info',
            category: 'access',
            message: 'GET / HTTP/1.1 200',
            raw: '10.0.1.5 - - [05/Mar/2026:22:00:00 +0000] "GET / HTTP/1.1" 200 1234',
            fields: {},
            tags: [],
            ...overrides,
        };
    }

    it('ingests and queries logs', () => {
        const siem = createSIEMEngine();

        siem.ingest(makeLogEntry({ id: 'log-1', message: 'hello world' }));
        siem.ingest(makeLogEntry({ id: 'log-2', message: 'test message' }));

        const results = siem.query({ messageContains: 'hello' });
        expect(results.length).toBe(1);
        expect(results[0]?.message).toBe('hello world');
    });

    it('queries by source', () => {
        const siem = createSIEMEngine();

        siem.ingest(makeLogEntry({
            id: 'log-1',
            source: { machine: 'web-01', service: 'http', logFile: '/var/log/access.log' },
        }));
        siem.ingest(makeLogEntry({
            id: 'log-2',
            source: { machine: 'db-01', service: 'mysql', logFile: '/var/log/mysql.log' },
        }));

        expect(siem.query({ source: { machine: 'web-01' } }).length).toBe(1);
        expect(siem.query({ source: { service: 'mysql' } }).length).toBe(1);
    });

    it('queries by severity', () => {
        const siem = createSIEMEngine();

        siem.ingest(makeLogEntry({ id: 'log-1', severity: 'info' }));
        siem.ingest(makeLogEntry({ id: 'log-2', severity: 'warning' }));
        siem.ingest(makeLogEntry({ id: 'log-3', severity: 'critical' }));

        const results = siem.query({ severity: 'warning' });
        expect(results.length).toBe(2); // warning + critical
    });

    it('queries by tick range', () => {
        const siem = createSIEMEngine();

        siem.ingest(makeLogEntry({ id: 'log-1', tick: 5 }));
        siem.ingest(makeLogEntry({ id: 'log-2', tick: 15 }));
        siem.ingest(makeLogEntry({ id: 'log-3', tick: 25 }));

        const results = siem.query({ fromTick: 10, toTick: 20 });
        expect(results.length).toBe(1);
    });

    it('detection rules fire alerts', () => {
        const siem = createSIEMEngine();

        siem.addRule({
            id: 'test-rule',
            name: 'Test Alert',
            description: 'Test',
            severity: 'warning',
            conditions: [{ type: 'message-contains', substring: 'Failed password' }],
            threshold: 3,
            windowTicks: 100,
            cooldownTicks: 0,
            enabled: true,
        });

        // Ingest 3 matching logs
        for (let i = 0; i < 3; i++) {
            siem.ingest(makeLogEntry({
                id: `log-${i}`,
                tick: i,
                category: 'auth',
                message: `Failed password for admin from 10.0.1.5`,
            }));
        }

        const alerts = siem.tick(3);
        expect(alerts.length).toBe(1);
        expect(alerts[0]?.ruleName).toBe('Test Alert');
    });

    it('detection rules respect threshold', () => {
        const siem = createSIEMEngine();

        siem.addRule({
            id: 'threshold-rule',
            name: 'Threshold',
            description: 'Test',
            severity: 'info',
            conditions: [{ type: 'message-contains', substring: 'test' }],
            threshold: 5,
            windowTicks: 100,
            cooldownTicks: 0,
            enabled: true,
        });

        // Only 3 matches — below threshold
        for (let i = 0; i < 3; i++) {
            siem.ingest(makeLogEntry({ id: `log-${i}`, message: 'test event' }));
        }

        const alerts = siem.tick(0);
        expect(alerts.length).toBe(0);
    });

    it('detection rules respect cooldown', () => {
        const siem = createSIEMEngine();

        siem.addRule({
            id: 'cooldown-rule',
            name: 'Cooldown',
            description: 'Test',
            severity: 'info',
            conditions: [{ type: 'message-contains', substring: 'x' }],
            threshold: 1,
            windowTicks: 100,
            cooldownTicks: 50,
            enabled: true,
        });

        siem.ingest(makeLogEntry({ id: 'log-1', message: 'x', tick: 0 }));
        const alerts1 = siem.tick(0);
        expect(alerts1.length).toBe(1);

        // Within cooldown — should not fire
        siem.ingest(makeLogEntry({ id: 'log-2', message: 'x', tick: 10 }));
        const alerts2 = siem.tick(10);
        expect(alerts2.length).toBe(0);
    });

    it('disabled rules do not fire', () => {
        const siem = createSIEMEngine();

        siem.addRule({
            id: 'disabled-rule',
            name: 'Disabled',
            description: 'Test',
            severity: 'info',
            conditions: [{ type: 'message-contains', substring: 'test' }],
            threshold: 1,
            windowTicks: 100,
            cooldownTicks: 0,
            enabled: false,
        });

        siem.ingest(makeLogEntry({ id: 'log-1', message: 'test' }));
        expect(siem.tick(0).length).toBe(0);
    });

    it('manages alert lifecycle', () => {
        const siem = createSIEMEngine();

        siem.addRule({
            id: 'lifecycle-rule',
            name: 'Alert',
            description: 'Test',
            severity: 'warning',
            conditions: [{ type: 'message-contains', substring: 'alarm' }],
            threshold: 1,
            windowTicks: 100,
            cooldownTicks: 0,
            enabled: true,
        });

        siem.ingest(makeLogEntry({ id: 'log-1', message: 'alarm' }));
        siem.tick(0);

        expect(siem.getPendingAlerts().length).toBe(1);

        const alertId = siem.getAlerts()[0]?.id;
        expect(alertId).toBeDefined();

        siem.acknowledgeAlert(alertId!);
        expect(siem.getPendingAlerts().length).toBe(0);
    });

    it('marks alerts as false positive', () => {
        const siem = createSIEMEngine();

        siem.addRule({
            id: 'fp-rule',
            name: 'FP',
            description: 'Test',
            severity: 'info',
            conditions: [{ type: 'message-contains', substring: 'trigger' }],
            threshold: 1,
            windowTicks: 100,
            cooldownTicks: 0,
            enabled: true,
        });

        siem.ingest(makeLogEntry({ id: 'log-1', message: 'trigger' }));
        siem.tick(0);

        const alertId = siem.getAlerts()[0]?.id;
        siem.markFalsePositive(alertId!);

        expect(siem.getPendingAlerts().length).toBe(0);
    });

    it('tracks statistics', () => {
        const siem = createSIEMEngine();

        siem.ingest(makeLogEntry({ id: 'log-1', severity: 'info', source: { machine: 'web-01', service: 'http', logFile: '/log' } }));
        siem.ingest(makeLogEntry({ id: 'log-2', severity: 'warning', source: { machine: 'db-01', service: 'mysql', logFile: '/log' } }));

        const stats = siem.getStats();
        expect(stats.totalLogs).toBe(2);
        expect(stats.bySeverity.info).toBe(1);
        expect(stats.bySeverity.warning).toBe(1);
        expect(stats.byMachine['web-01']).toBe(1);
        expect(stats.byMachine['db-01']).toBe(1);
    });

    it('reconstructs timeline', () => {
        const siem = createSIEMEngine();

        siem.ingest(makeLogEntry({ id: 'log-1', tick: 5 }));
        siem.ingest(makeLogEntry({ id: 'log-3', tick: 25 }));
        siem.ingest(makeLogEntry({ id: 'log-2', tick: 15 }));

        const timeline = siem.timeline(0, 30);
        expect(timeline.length).toBe(3);
        // Should be sorted by tick
        expect(timeline[0]?.tick).toBe(5);
        expect(timeline[1]?.tick).toBe(15);
        expect(timeline[2]?.tick).toBe(25);
    });

    it('exports in JSON format', () => {
        const siem = createSIEMEngine();
        siem.ingest(makeLogEntry({ id: 'log-1', message: 'test' }));

        const json = siem.export('json');
        const parsed = JSON.parse(json);
        expect(Array.isArray(parsed)).toBe(true);
        expect(parsed.length).toBe(1);
    });

    it('exports in CEF format', () => {
        const siem = createSIEMEngine();
        siem.ingest(makeLogEntry({ id: 'log-1', category: 'auth', message: 'login' }));

        const cef = siem.export('cef');
        expect(cef).toContain('CEF:0');
        expect(cef).toContain('auth');
    });

    it('exports in CSV format', () => {
        const siem = createSIEMEngine();
        siem.ingest(makeLogEntry({ id: 'log-1' }));

        const csv = siem.export('csv');
        expect(csv).toContain('timestamp,tick');
    });

    it('evicts oldest logs when max size exceeded', () => {
        const siem = createSIEMEngine(10); // max 10 logs

        for (let i = 0; i < 15; i++) {
            siem.ingest(makeLogEntry({ id: `log-${i}`, tick: i }));
        }

        // Should have evicted and not exceed max
        expect(siem.logCount()).toBeLessThanOrEqual(15);
    });

    it('rejects duplicate rule IDs', () => {
        const siem = createSIEMEngine();
        siem.addRule({
            id: 'dup',
            name: 'A',
            description: 'a',
            severity: 'info',
            conditions: [],
            threshold: 1,
            windowTicks: 1,
            cooldownTicks: 0,
            enabled: true,
        });

        expect(() => {
            siem.addRule({
                id: 'dup',
                name: 'B',
                description: 'b',
                severity: 'info',
                conditions: [],
                threshold: 1,
                windowTicks: 1,
                cooldownTicks: 0,
                enabled: true,
            });
        }).toThrow(/already exists/);
    });

    it('createBuiltinDetectionRules returns valid rules', () => {
        const rules = createBuiltinDetectionRules();
        expect(rules.length).toBeGreaterThanOrEqual(5);

        // All rules should have required fields
        for (const rule of rules) {
            expect(rule.id).toBeTruthy();
            expect(rule.name).toBeTruthy();
            expect(rule.conditions.length).toBeGreaterThan(0);
            expect(rule.threshold).toBeGreaterThan(0);
        }
    });

    it('createBuiltinCorrelationRules returns valid rules', () => {
        const rules = createBuiltinCorrelationRules();
        expect(rules.length).toBeGreaterThanOrEqual(1);

        for (const rule of rules) {
            expect(rule.id).toBeTruthy();
            expect(rule.patterns.length).toBeGreaterThanOrEqual(2);
        }
    });

    it('field-regex condition works', () => {
        const siem = createSIEMEngine();

        siem.addRule({
            id: 'regex-rule',
            name: 'Regex',
            description: 'Test',
            severity: 'warning',
            conditions: [{ type: 'field-regex', field: 'ip', pattern: '^10\\.0\\.1\\.' }],
            threshold: 1,
            windowTicks: 100,
            cooldownTicks: 0,
            enabled: true,
        });

        siem.ingest(makeLogEntry({
            id: 'log-1',
            fields: { ip: '10.0.1.42' },
        }));

        const alerts = siem.tick(0);
        expect(alerts.length).toBe(1);
    });

    it('tag-present condition works', () => {
        const siem = createSIEMEngine();

        siem.addRule({
            id: 'tag-rule',
            name: 'Tag',
            description: 'Test',
            severity: 'info',
            conditions: [{ type: 'tag-present', tag: 'suspicious' }],
            threshold: 1,
            windowTicks: 100,
            cooldownTicks: 0,
            enabled: true,
        });

        siem.ingest(makeLogEntry({ id: 'log-1', tags: ['suspicious', 'auth'] }));

        const alerts = siem.tick(0);
        expect(alerts.length).toBe(1);
    });
});
