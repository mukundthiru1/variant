import { describe, it, expect } from 'vitest';
import { createEventBus } from '../../src/core/event-bus';
import { createVFS } from '../../src/lib/vfs/vfs';
import {
    createForensicsModule,
    buildTimeline,
    parseAuthLog,
    parseApacheLog,
    parseNginxLog,
    parseSyslog,
    detectBruteForce,
    detectPrivilegeEscalation,
    detectLateralMovement,
    detectDataExfiltration,
    detectWebAttacks,
    collectEvidence,
    generateIncidentReport,
} from '../../src/modules/forensics-module';
import type { EventBus, EngineEvent } from '../../src/core/events';
import type { SimulationContext } from '../../src/core/modules';
import { createServiceLocator } from '../../src/core/modules';
import type { WorldSpec } from '../../src/core/world/types';
import { stubFabric } from '../helpers';

function createTestContext(events: EventBus): SimulationContext {
    return {
        vms: new Map(),
        fabric: stubFabric(),
        events,
        world: {
            id: 'test-world',
            name: 'Test',
            version: '1.0.0',
            description: 'Test world',
            machines: [],
            objectives: [],
            scoring: {
                maxScore: 1000,
                hintPenalty: 50,
                timeBonus: false,
                stealthBonus: false,
                tiers: [],
            },
        } as unknown as WorldSpec,
        tick: 0,
        services: createServiceLocator(),
    };
}

function createAuthLine(message: string): string {
    return `Jan 12 10:22:11 web-01 sshd[1234]: ${message}`;
}

function createApacheLine(parts: {
    ip: string;
    method: string;
    url: string;
    status: number;
    size: number;
    user?: string;
}): string {
    const user = parts.user ?? '-';
    return `${parts.ip} - ${user} [10/Oct/2025:13:55:36 -0700] "${parts.method} ${parts.url} HTTP/1.1" ${parts.status} ${parts.size} "-" "curl/8.0"`;
}

describe('Forensics Module', () => {
    it('creates module with required metadata and capabilities', () => {
        const bus = createEventBus();
        const mod = createForensicsModule(bus);

        expect(mod.id).toBe('forensics');
        expect(mod.provides.map(p => p.name)).toEqual(expect.arrayContaining(['forensics', 'timeline', 'log-analysis']));
    });

    it('registers forensics service on init', () => {
        const bus = createEventBus();
        const mod = createForensicsModule(bus);
        const ctx = createTestContext(bus);

        mod.init(ctx);
        expect(ctx.services.has('forensics')).toBe(true);
        mod.destroy();
    });

    it('builds timeline from mixed events in chronological order', () => {
        const events: EngineEvent[] = [
            { type: 'auth:login', user: 'alice', machine: 'web-01', service: 'ssh', success: false, timestamp: 3000 },
            { type: 'fs:exec', machine: 'web-01', path: '/bin/bash', args: ['-c', 'id'], user: 'alice', timestamp: 2000 },
            { type: 'defense:alert', machine: 'web-01', ruleId: 'bf', severity: 'high', detail: 'many failures', timestamp: 4000 },
        ];

        const timeline = buildTimeline(events);
        expect(timeline).toHaveLength(3);
        expect(timeline[0]?.eventType).toBe('fs:exec');
        expect(timeline[1]?.eventType).toBe('auth:login');
        expect(timeline[2]?.severity).toBe('high');
    });

    it('supports timeline filtering by machine, actor, severity and event type', () => {
        const events: EngineEvent[] = [
            { type: 'auth:login', user: 'alice', machine: 'web-01', service: 'ssh', success: false, timestamp: 1000 },
            { type: 'auth:login', user: 'bob', machine: 'db-01', service: 'ssh', success: true, timestamp: 2000 },
            { type: 'defense:alert', machine: 'web-01', ruleId: 'x', severity: 'critical', detail: 'boom', timestamp: 3000 },
        ];

        const filtered = buildTimeline(events, {
            machine: 'web-01',
            actor: 'x',
            severity: 'critical',
            eventType: 'defense:alert',
            startTime: 2500,
            endTime: 3500,
        });

        expect(filtered).toHaveLength(1);
        expect(filtered[0]?.eventType).toBe('defense:alert');
    });

    it('parses auth.log failed and successful login lines', () => {
        const content = [
            createAuthLine('Failed password for invalid user admin from 203.0.113.10 port 5022 ssh2'),
            createAuthLine('Accepted password for alice from 203.0.113.10 port 5022 ssh2'),
        ].join('\n');

        const entries = parseAuthLog(content);

        expect(entries).toHaveLength(2);
        expect(entries[0]?.action).toBe('login');
        expect(entries[0]?.success).toBe(false);
        expect(entries[0]?.sourceIP).toBe('203.0.113.10');
        expect(entries[1]?.success).toBe(true);
        expect(entries[1]?.user).toBe('alice');
    });

    it('parses auth.log sudo and su lines', () => {
        const content = [
            createAuthLine('bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash'),
            createAuthLine('pam_unix(su:session): session opened for user root by bob(uid=1000)'),
        ].join('\n');

        const entries = parseAuthLog(content);

        expect(entries).toHaveLength(2);
        expect(entries[0]?.action).toBe('sudo');
        expect(entries[0]?.targetUser).toBe('root');
        expect(entries[1]?.action).toBe('su');
        expect(entries[1]?.user).toBe('bob(uid=1000)');
    });

    it('parses syslog format lines', () => {
        const content = [
            'Jan 12 10:22:11 web-01 kernel[12]: warning CPU temperature high',
            'Jan 12 10:22:12 web-01 systemd[1]: info Started app.service',
        ].join('\n');

        const entries = parseSyslog(content);
        expect(entries).toHaveLength(2);
        expect(entries[0]?.service).toBe('kernel');
        expect(entries[0]?.severity).toBe('warning');
        expect(entries[1]?.severity).toBe('info');
    });

    it('parses apache combined logs with GET and POST', () => {
        const content = [
            createApacheLine({ ip: '198.51.100.1', method: 'GET', url: '/index.html', status: 200, size: 512 }),
            createApacheLine({ ip: '198.51.100.2', method: 'POST', url: '/login', status: 401, size: 128 }),
        ].join('\n');

        const entries = parseApacheLog(content);

        expect(entries).toHaveLength(2);
        expect(entries[0]?.method).toBe('GET');
        expect(entries[1]?.method).toBe('POST');
        expect(entries[1]?.statusCode).toBe(401);
        expect(entries[1]?.sourceIP).toBe('198.51.100.2');
    });

    it('parses nginx access log format', () => {
        const content = createApacheLine({ ip: '203.0.113.5', method: 'GET', url: '/api/v1/health', status: 200, size: 64 });
        const entries = parseNginxLog(content);

        expect(entries).toHaveLength(1);
        expect(entries[0]?.url).toBe('/api/v1/health');
        expect(entries[0]?.statusCode).toBe(200);
    });

    it('detects brute force attempts by threshold within time window', () => {
        const content = [
            createAuthLine('Failed password for admin from 203.0.113.10 port 5000 ssh2'),
            createAuthLine('Failed password for admin from 203.0.113.10 port 5001 ssh2'),
            createAuthLine('Failed password for root from 203.0.113.10 port 5002 ssh2'),
            createAuthLine('Failed password for guest from 203.0.113.10 port 5003 ssh2'),
            createAuthLine('Failed password for app from 203.0.113.10 port 5004 ssh2'),
        ].join('\n');

        const indicators = detectBruteForce(parseAuthLog(content), 5, 10 * 60_000);

        expect(indicators).toHaveLength(1);
        expect(indicators[0]?.sourceIP).toBe('203.0.113.10');
        expect(indicators[0]?.failures).toBeGreaterThanOrEqual(5);
    });

    it('does not detect brute force below threshold', () => {
        const content = [
            createAuthLine('Failed password for admin from 203.0.113.10 port 5000 ssh2'),
            createAuthLine('Failed password for root from 203.0.113.10 port 5001 ssh2'),
            createAuthLine('Failed password for guest from 203.0.113.10 port 5002 ssh2'),
        ].join('\n');

        const indicators = detectBruteForce(parseAuthLog(content), 5, 10 * 60_000);
        expect(indicators).toHaveLength(0);
    });

    it('detects privilege escalation via sudo and su to root', () => {
        const content = [
            createAuthLine('bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash'),
            createAuthLine('pam_unix(su:session): session opened for user root by alice(uid=1001)'),
        ].join('\n');

        const indicators = detectPrivilegeEscalation(parseAuthLog(content));
        expect(indicators).toHaveLength(2);
        expect(indicators[0]?.method).toBe('sudo');
        expect(indicators[1]?.method).toBe('su');
    });

    it('detects lateral movement from internal IP across machines', () => {
        const logs = parseAuthLog([
            'Jan 12 10:20:00 web-01 sshd[123]: Accepted password for alice from 10.1.1.50 port 5500 ssh2',
            'Jan 12 10:25:00 db-01 sshd[123]: Accepted password for alice from 10.1.1.50 port 5501 ssh2',
            'Jan 12 10:26:00 app-01 sshd[123]: Accepted password for root from 10.1.1.50 port 5502 ssh2',
        ].join('\n'));

        const indicators = detectLateralMovement(logs);
        expect(indicators).toHaveLength(1);
        expect(indicators[0]?.sourceIP).toBe('10.1.1.50');
        expect(indicators[0]?.machines.length).toBeGreaterThanOrEqual(2);
    });

    it('does not flag external IP as lateral movement', () => {
        const logs = parseAuthLog([
            'Jan 12 10:20:00 web-01 sshd[123]: Accepted password for alice from 198.51.100.9 port 5500 ssh2',
            'Jan 12 10:25:00 db-01 sshd[123]: Accepted password for alice from 198.51.100.9 port 5501 ssh2',
        ].join('\n'));

        const indicators = detectLateralMovement(logs);
        expect(indicators).toHaveLength(0);
    });

    it('detects data exfiltration by large response size', () => {
        const accessLogs = parseApacheLog([
            createApacheLine({ ip: '203.0.113.9', method: 'GET', url: '/backup.sql', status: 200, size: 2_500_000 }),
            createApacheLine({ ip: '203.0.113.9', method: 'GET', url: '/home', status: 200, size: 128 }),
        ].join('\n'));

        const indicators = detectDataExfiltration(accessLogs, 1_000_000);

        expect(indicators).toHaveLength(1);
        expect(indicators[0]?.url).toBe('/backup.sql');
        expect(indicators[0]?.reason).toContain('Large outbound response size');
    });

    it('detects web attack patterns including SQLi in URL', () => {
        const accessLogs = parseApacheLog([
            createApacheLine({ ip: '203.0.113.20', method: 'GET', url: '/search?q=1%27%20OR%201=1--', status: 200, size: 10 }),
            createApacheLine({ ip: '203.0.113.21', method: 'GET', url: '/download?file=../../etc/passwd', status: 404, size: 0 }),
            createApacheLine({ ip: '203.0.113.22', method: 'GET', url: '/?x=%3Cscript%3Ealert(1)%3C/script%3E', status: 200, size: 10 }),
        ].join('\n'));

        const indicators = detectWebAttacks(accessLogs);

        expect(indicators).toHaveLength(3);
        expect(indicators.some(i => i.attackType === 'sqli')).toBe(true);
        expect(indicators.some(i => i.attackType === 'path-traversal')).toBe(true);
        expect(indicators.some(i => i.attackType === 'xss')).toBe(true);
    });

    it('collects evidence from VFS with hashes and metadata', () => {
        const vfs = createVFS();
        vfs.writeFile('/var/log/auth.log', createAuthLine('Accepted password for alice from 10.0.0.9 port 22 ssh2'));
        vfs.writeFile('/root/.bash_history', 'cat /etc/shadow\n');
        vfs.writeFile('/tmp/dropper.sh', '#!/bin/sh\necho pwned\n');
        vfs.writeFile('/etc/crontab', '* * * * * root /tmp/dropper.sh\n');
        vfs.writeFile('/root/.ssh/authorized_keys', 'ssh-rsa AAAAB3Nza... attacker@host');
        vfs.writeFile('/proc/123/cmdline', '/usr/bin/python3 /tmp/dropper.py');

        const bundle = collectEvidence(vfs, 'web-01');

        expect(bundle.machine).toBe('web-01');
        expect(bundle.fileCount).toBeGreaterThanOrEqual(6);
        expect(bundle.files.every(f => f.sha256.length === 64)).toBe(true);
        expect(bundle.hashes['/var/log/auth.log']).toBeDefined();
    });

    it('generateIncidentReport returns required sections and classifies incident', () => {
        const timeline = buildTimeline([
            { type: 'auth:login', user: 'admin', machine: 'web-01', service: 'ssh', success: false, timestamp: 1000 },
            { type: 'auth:login', user: 'admin', machine: 'web-01', service: 'ssh', success: false, timestamp: 1100 },
            { type: 'auth:login', user: 'admin', machine: 'web-01', service: 'ssh', success: false, timestamp: 1200 },
            { type: 'auth:login', user: 'admin', machine: 'web-01', service: 'ssh', success: false, timestamp: 1300 },
            { type: 'auth:login', user: 'admin', machine: 'web-01', service: 'ssh', success: false, timestamp: 1400 },
        ]);

        const vfs = createVFS();
        vfs.writeFile('/var/log/auth.log', [
            createAuthLine('Failed password for admin from 203.0.113.10 port 5000 ssh2'),
            createAuthLine('Failed password for admin from 203.0.113.10 port 5001 ssh2'),
            createAuthLine('Failed password for admin from 203.0.113.10 port 5002 ssh2'),
            createAuthLine('Failed password for admin from 203.0.113.10 port 5003 ssh2'),
            createAuthLine('Failed password for admin from 203.0.113.10 port 5004 ssh2'),
        ].join('\n'));

        const evidence = collectEvidence(vfs, 'web-01');
        const report = generateIncidentReport(timeline, evidence);

        expect(report.executiveSummary.length).toBeGreaterThan(0);
        expect(report.timeline.length).toBe(5);
        expect(report.indicatorsOfCompromise.length).toBeGreaterThan(0);
        expect(report.affectedSystems).toContain('web-01');
        expect(report.recommendations.length).toBeGreaterThan(0);
        expect(report.incidentType).toBe('brute-force');
    });

    it('module emits custom timeline result event', () => {
        const bus = createEventBus(1000);
        const mod = createForensicsModule(bus);
        const ctx = createTestContext(bus);
        mod.init(ctx);

        bus.emit({ type: 'auth:login', user: 'alice', machine: 'web-01', service: 'ssh', success: true, timestamp: 1000 });
        bus.emit({ type: 'custom:forensics-build-timeline', data: {}, timestamp: 2000 });

        const result = bus.getLog().find(e => e.type === 'custom:forensics-timeline-result');
        expect(result).toBeDefined();

        mod.destroy();
    });

    it('module emits anomaly analysis result from auth content', () => {
        const bus = createEventBus(1000);
        const mod = createForensicsModule(bus);
        const ctx = createTestContext(bus);
        mod.init(ctx);

        const content = [
            createAuthLine('Failed password for admin from 203.0.113.10 port 5000 ssh2'),
            createAuthLine('Failed password for admin from 203.0.113.10 port 5001 ssh2'),
            createAuthLine('Failed password for admin from 203.0.113.10 port 5002 ssh2'),
            createAuthLine('Failed password for admin from 203.0.113.10 port 5003 ssh2'),
            createAuthLine('Failed password for admin from 203.0.113.10 port 5004 ssh2'),
        ].join('\n');

        bus.emit({
            type: 'custom:forensics-analyze-auth',
            data: { content },
            timestamp: 1000,
        });

        const result = bus.getLog().find(e => e.type === 'custom:forensics-anomalies-result');
        expect(result).toBeDefined();

        mod.destroy();
    });
});
