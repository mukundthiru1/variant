import { describe, expect, it } from 'vitest';
import { createEventBus } from '../../src/core/event-bus';
import type { EngineEvent, EventBus } from '../../src/core/events';
import { createServiceLocator } from '../../src/core/modules';
import type { SimulationContext } from '../../src/core/modules';
import type { WorldSpec } from '../../src/core/world/types';
import {
    createThreatIntelModule,
    type ThreatIntelService,
} from '../../src/modules/threat-intel-module';
import { stubFabric } from '../helpers';

function createTestEventBus(): EventBus & { emitted: EngineEvent[] } {
    const inner = createEventBus(20_000);
    const emitted: EngineEvent[] = [];

    return {
        emitted,
        emit(event: EngineEvent): void {
            emitted.push(event);
            inner.emit(event);
        },
        on: inner.on.bind(inner),
        once: inner.once.bind(inner),
        waitFor: inner.waitFor.bind(inner),
        onPrefix: inner.onPrefix.bind(inner),
        getLog: inner.getLog.bind(inner),
        clearLog: inner.clearLog.bind(inner),
        removeAllListeners: inner.removeAllListeners.bind(inner),
    };
}

function createTestContext(events: EventBus): SimulationContext {
    return {
        vms: new Map(),
        fabric: stubFabric(),
        events,
        world: {
            id: 'test-world',
            name: 'Test',
            version: '1.0.0',
            description: 'threat-intel tests',
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

function setup() {
    const events = createTestEventBus();
    const ctx = createTestContext(events);
    const module = createThreatIntelModule(events);
    module.init(ctx);

    const service = ctx.services.get<ThreatIntelService>('threat-intel');
    if (service === undefined) {
        throw new Error('threat-intel service was not registered');
    }

    return { events, ctx, module, service };
}

describe('Threat Intel Module', () => {
    it('initializes module metadata and capabilities', () => {
        const { module } = setup();
        expect(module.id).toBe('threat-intel');
        expect(module.provides.some((capability) => capability.name === 'threat-intel')).toBe(true);
        expect(module.provides.some((capability) => capability.name === 'mitre-att&ck')).toBe(true);
        module.destroy();
    });

    it('loads built-in ATT&CK catalog with 50+ techniques', () => {
        const { module, service } = setup();
        expect(service.getKnownTechniques().length).toBeGreaterThanOrEqual(50);
        module.destroy();
    });

    it('loads CVE catalog with 20+ entries', () => {
        const { module, service } = setup();
        expect(service.getKnownCVEs().length).toBeGreaterThanOrEqual(20);
        module.destroy();
    });

    it('detects T1078 valid accounts after credential discovery', () => {
        const { events, module, service } = setup();
        const ts = Date.now();

        events.emit({
            type: 'auth:credential-found',
            credentialId: 'cred-1',
            machine: 'web-01',
            location: '/tmp/leaked.txt',
            timestamp: ts,
        });

        events.emit({
            type: 'auth:login',
            user: 'admin',
            machine: 'web-01',
            service: 'ssh',
            success: true,
            timestamp: ts + 100,
        });

        const chain = service.getTechniqueChain();
        expect(chain.some((detection) => detection.technique.id === 'T1078')).toBe(true);
        expect(events.emitted.some((event) => event.type === 'custom:technique-detected')).toBe(true);

        module.destroy();
    });

    it('detects T1021 for successful SSH remote service login', () => {
        const { events, module, service } = setup();

        events.emit({
            type: 'auth:login',
            user: 'ops',
            machine: 'db-01',
            service: 'ssh',
            success: true,
            timestamp: Date.now(),
        });

        expect(service.getTechniqueChain().some((entry) => entry.technique.id === 'T1021')).toBe(true);
        module.destroy();
    });

    it('detects T1110 brute force from repeated failed logins', () => {
        const { events, module, service } = setup();
        const ts = Date.now();

        for (let i = 0; i < 5; i++) {
            events.emit({
                type: 'auth:login',
                user: 'root',
                machine: 'mail-01',
                service: 'ssh',
                success: false,
                timestamp: ts + i * 1000,
            });
        }

        expect(service.getTechniqueChain().some((entry) => entry.technique.id === 'T1110')).toBe(true);
        module.destroy();
    });

    it('detects T1190 exploit public-facing application from suspicious URL patterns', () => {
        const { events, module, service } = setup();

        events.emit({
            type: 'net:request',
            method: 'GET',
            url: 'https://target.example/search?q=1%27%20OR%20%271%27=%271',
            source: 'attacker',
            destination: 'web-01',
            timestamp: Date.now(),
        });

        expect(service.getTechniqueChain().some((entry) => entry.technique.id === 'T1190')).toBe(true);
        module.destroy();
    });

    it('detects T1071 application-layer C2 traffic', () => {
        const { events, module, service } = setup();

        events.emit({
            type: 'net:request',
            method: 'GET',
            url: 'https://cdn.example.com/api/ping?command=checkin',
            source: 'victim',
            destination: 'internet',
            timestamp: Date.now(),
        });

        expect(service.getTechniqueChain().some((entry) => entry.technique.id === 'T1071')).toBe(true);
        module.destroy();
    });

    it('detects T1003 OS credential dumping when reading shadow/SAM style paths', () => {
        const { events, module, service } = setup();

        events.emit({
            type: 'fs:read',
            machine: 'linux-01',
            path: '/etc/shadow',
            user: 'attacker',
            timestamp: Date.now(),
        });

        expect(service.getTechniqueChain().some((entry) => entry.technique.id === 'T1003')).toBe(true);
        module.destroy();
    });

    it('detects T1053 scheduled task persistence from cron writes', () => {
        const { events, module, service } = setup();

        events.emit({
            type: 'fs:write',
            machine: 'linux-01',
            path: '/etc/cron.d/backdoor',
            user: 'root',
            timestamp: Date.now(),
        });

        expect(service.getTechniqueChain().some((entry) => entry.technique.id === 'T1053')).toBe(true);
        module.destroy();
    });

    it('detects T1098 account manipulation from SSH key injection path', () => {
        const { events, module, service } = setup();

        events.emit({
            type: 'fs:write',
            machine: 'linux-01',
            path: '/home/dev/.ssh/authorized_keys',
            user: 'attacker',
            timestamp: Date.now(),
        });

        expect(service.getTechniqueChain().some((entry) => entry.technique.id === 'T1098')).toBe(true);
        module.destroy();
    });

    it('detects T1059 command interpreter execution from shell command events', () => {
        const { events, module, service } = setup();

        events.emit({
            type: 'fs:exec',
            machine: 'linux-01',
            path: '/bin/bash',
            args: ['-c', 'id'],
            user: 'attacker',
            timestamp: Date.now(),
        });

        expect(service.getTechniqueChain().some((entry) => entry.technique.id === 'T1059')).toBe(true);
        module.destroy();
    });

    it('detects T1046 scanning after connections to multiple ports', () => {
        const { events, module, service } = setup();
        const ts = Date.now();
        const ports = [21, 22, 80, 135, 443, 445];

        for (const [index, port] of ports.entries()) {
            events.emit({
                type: 'net:connect',
                host: '10.0.0.5',
                port,
                source: 'attacker',
                protocol: 'tcp',
                timestamp: ts + index * 100,
            });
        }

        expect(service.getTechniqueChain().some((entry) => entry.technique.id === 'T1046')).toBe(true);
        module.destroy();
    });

    it('tracks kill chain progression across technique detections', () => {
        const { events, module, service } = setup();
        const ts = Date.now();

        events.emit({
            type: 'net:request',
            method: 'GET',
            url: 'https://target/search?q=../../etc/passwd',
            source: 'attacker',
            destination: 'web-01',
            timestamp: ts,
        }); // Initial Access

        events.emit({
            type: 'fs:exec',
            machine: 'web-01',
            path: '/bin/sh',
            args: ['-c', 'whoami'],
            user: 'www-data',
            timestamp: ts + 10,
        }); // Execution

        events.emit({
            type: 'fs:read',
            machine: 'web-01',
            path: '/etc/shadow',
            user: 'root',
            timestamp: ts + 20,
        }); // Credential Access

        const phases = service.getKillChainProgress();
        expect(phases.find((phase) => phase.name === 'Initial Access')?.observed).toBe(true);
        expect(phases.find((phase) => phase.name === 'Execution')?.observed).toBe(true);
        expect(phases.find((phase) => phase.name === 'Credential Access')?.observed).toBe(true);

        module.destroy();
    });

    it('matches CVEs by software and exact version', () => {
        const { module, service } = setup();

        const matches = service.matchCVE('apache http server', '2.4.49');
        expect(matches.some((entry) => entry.id === 'CVE-2021-41773')).toBe(true);

        module.destroy();
    });

    it('matches CVEs by version ranges', () => {
        const { module, service } = setup();

        const vulnerable = service.matchCVE('log4j', '2.14.1');
        expect(vulnerable.some((entry) => entry.id === 'CVE-2021-44228')).toBe(true);

        const patched = service.matchCVE('log4j', '2.17.1');
        expect(patched.some((entry) => entry.id === 'CVE-2021-44228')).toBe(false);

        module.destroy();
    });

    it('returns no CVE match for unknown software', () => {
        const { module, service } = setup();
        expect(service.matchCVE('totally-unknown-product', '1.0.0')).toHaveLength(0);
        module.destroy();
    });

    it('responds to custom threat-intel query events', () => {
        const { events, module } = setup();

        events.emit({
            type: 'custom:threat-intel-query',
            data: null,
            timestamp: Date.now(),
        });

        expect(events.emitted.some((event) => event.type === 'custom:threat-intel-query-result')).toBe(true);
        module.destroy();
    });

    it('responds to custom CVE match query events', () => {
        const { events, module } = setup();

        events.emit({
            type: 'custom:threat-intel-cve-match',
            data: {
                software: 'openssl',
                version: '1.0.1f',
            },
            timestamp: Date.now(),
        });

        const result = events.emitted.find((event) => event.type === 'custom:threat-intel-cve-match-result');
        expect(result).toBeDefined();

        module.destroy();
    });

    it('captures multiple techniques in detection chain order', () => {
        const { events, module, service } = setup();
        const ts = Date.now();

        events.emit({
            type: 'net:request',
            method: 'GET',
            url: 'https://target/site?q=../',
            source: 'attacker',
            destination: 'web',
            timestamp: ts,
        });

        events.emit({
            type: 'auth:login',
            user: 'admin',
            machine: 'web',
            service: 'ssh',
            success: true,
            timestamp: ts + 100,
        });

        events.emit({
            type: 'fs:exec',
            machine: 'web',
            path: '/bin/bash',
            args: ['-c', 'uname -a'],
            user: 'admin',
            timestamp: ts + 200,
        });

        const chain = service.getTechniqueChain();
        expect(chain.length).toBeGreaterThanOrEqual(3);
        expect(chain[0]?.timestamp).toBe(ts);
        expect(chain[1]?.timestamp).toBe(ts + 100);
        expect(chain[2]?.timestamp).toBe(ts + 200);

        module.destroy();
    });

    it('tracks event processing stats while subscribed to all events', () => {
        const { events, module, service } = setup();

        events.emit({ type: 'sim:tick', tick: 1, timestamp: Date.now() });
        events.emit({ type: 'lens:open', lensType: 'map', target: 'web', timestamp: Date.now() });
        events.emit({ type: 'lens:close', lensType: 'map', timestamp: Date.now() });

        const stats = service.getStats();
        expect(stats.eventsProcessed).toBeGreaterThanOrEqual(3);

        module.destroy();
    });
});
