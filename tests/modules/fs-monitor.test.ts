/**
 * VARIANT — Filesystem Monitor Tests
 *
 * Tests marker parsing and event emission.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createFilesystemMonitor, parseMarker } from '../../src/modules/fs-monitor';
import { createEventBus } from '../../src/core/event-bus';
import type { SimulationContext } from '../../src/core/modules';
import { createServiceLocator } from '../../src/core/modules';
import type { EventBus, EngineEvent } from '../../src/core/events';
import type { WorldSpec } from '../../src/core/world/types';

// ── Helpers ────────────────────────────────────────────────────

function makeContext(events: EventBus): SimulationContext {
    return {
        vms: new Map(),
        fabric: {
            getTrafficLog: () => [],
            getStats: () => ({ totalFrames: 0, droppedFrames: 0, bytesRouted: 0, dnsQueries: 0, activeConnections: 0 }),
            tap: () => () => { },
            addDNSRecord: () => { },
            registerExternal: () => { },
            getExternalHandler: () => undefined,
            getExternalDomains: () => [],
        },
        events,
        world: {
            version: '2.0',
            trust: 'community',
            meta: { title: 'test', scenario: 'test', briefing: [], difficulty: 'beginner', mode: 'attack', vulnClasses: [], tags: [], estimatedMinutes: 5, author: { name: 'test', id: 'test', type: 'santh' } },
            machines: {},
            startMachine: 'player',
            network: { segments: [], edges: [] },
            credentials: [],
            objectives: [],
            modules: [],
            scoring: { maxScore: 1000, timeBonus: false, stealthBonus: false, hintPenalty: 50, tiers: [] },
            hints: [],
        } as unknown as WorldSpec,
        tick: 0,
        services: createServiceLocator(),
    };
}

// ── Tests ──────────────────────────────────────────────────────

describe('Filesystem Monitor', () => {
    describe('parseMarker', () => {
        it('parses a READ marker', () => {
            const result = parseMarker('%%FS:READ:/etc/shadow:root%%');
            expect(result).toEqual({ operation: 'READ', path: '/etc/shadow', user: 'root' });
        });

        it('parses a WRITE marker', () => {
            const result = parseMarker('%%FS:WRITE:/tmp/exploit:www-data%%');
            expect(result).toEqual({ operation: 'WRITE', path: '/tmp/exploit', user: 'www-data' });
        });

        it('parses an EXEC marker', () => {
            const result = parseMarker('%%FS:EXEC:/usr/bin/python3:admin%%');
            expect(result).toEqual({ operation: 'EXEC', path: '/usr/bin/python3', user: 'admin' });
        });

        it('returns null for non-marker strings', () => {
            expect(parseMarker('hello world')).toBeNull();
            expect(parseMarker('%%FS:INVALID:/path:user%%')).toBeNull();
            expect(parseMarker('')).toBeNull();
        });
    });

    describe('Module lifecycle', () => {
        let events: EventBus;
        let monitor: ReturnType<typeof createFilesystemMonitor>;

        beforeEach(() => {
            events = createEventBus();
            monitor = createFilesystemMonitor();
        });

        afterEach(() => {
            monitor.destroy();
        });

        it('emits fs:read event on custom:fs-marker (legacy string data)', () => {
            const ctx = makeContext(events);
            monitor.init(ctx);

            const emitted: EngineEvent[] = [];
            events.on('fs:read', (e) => emitted.push(e));

            events.emit({
                type: 'custom:fs-marker',
                data: '%%FS:READ:/etc/passwd:root%%',
                timestamp: Date.now(),
            });

            expect(emitted.length).toBe(1);
            expect(emitted[0]!.type).toBe('fs:read');
            const readEvent = emitted[0] as Extract<EngineEvent, { type: 'fs:read' }>;
            expect(readEvent.machine).toBe('unknown');
        });

        it('propagates machine ID from { machine, marker } format', () => {
            const ctx = makeContext(events);
            monitor.init(ctx);

            const emitted: EngineEvent[] = [];
            events.on('fs:read', (e) => emitted.push(e));

            events.emit({
                type: 'custom:fs-marker',
                data: { machine: 'web-server', marker: '%%FS:READ:/etc/shadow:www-data%%' },
                timestamp: Date.now(),
            });

            expect(emitted.length).toBe(1);
            const readEvent = emitted[0] as Extract<EngineEvent, { type: 'fs:read' }>;
            expect(readEvent.machine).toBe('web-server');
            expect(readEvent.path).toBe('/etc/shadow');
            expect(readEvent.user).toBe('www-data');
        });

        it('emits fs:write event on WRITE marker', () => {
            const ctx = makeContext(events);
            monitor.init(ctx);

            const emitted: EngineEvent[] = [];
            events.on('fs:write', (e) => emitted.push(e));

            events.emit({
                type: 'custom:fs-marker',
                data: '%%FS:WRITE:/tmp/malware:attacker%%',
                timestamp: Date.now(),
            });

            expect(emitted.length).toBe(1);
        });

        it('emits fs:exec event on EXEC marker', () => {
            const ctx = makeContext(events);
            monitor.init(ctx);

            const emitted: EngineEvent[] = [];
            events.on('fs:exec', (e) => emitted.push(e));

            events.emit({
                type: 'custom:fs-marker',
                data: '%%FS:EXEC:/bin/sh:root%%',
                timestamp: Date.now(),
            });

            expect(emitted.length).toBe(1);
        });

        it('ignores non-marker custom events', () => {
            const ctx = makeContext(events);
            monitor.init(ctx);

            const emitted: EngineEvent[] = [];
            events.on('fs:read', (e) => emitted.push(e));
            events.on('fs:write', (e) => emitted.push(e));

            events.emit({
                type: 'custom:fs-marker',
                data: 'not a marker',
                timestamp: Date.now(),
            });

            expect(emitted.length).toBe(0);
        });

        it('stops emitting after destroy', () => {
            const ctx = makeContext(events);
            monitor.init(ctx);
            monitor.destroy();

            const emitted: EngineEvent[] = [];
            events.on('fs:read', (e) => emitted.push(e));

            events.emit({
                type: 'custom:fs-marker',
                data: '%%FS:READ:/etc/shadow:root%%',
                timestamp: Date.now(),
            });

            expect(emitted.length).toBe(0);
        });
    });
});
