/**
 * VARIANT — Objective Detector Tests
 *
 * Tests the objective detection module's ability to listen for
 * events and complete objectives automatically.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createObjectiveDetector } from '../../src/modules/objective-detector';
import { createEventBus } from '../../src/core/event-bus';
import type { SimulationContext } from '../../src/core/modules';
import { createServiceLocator } from '../../src/core/modules';
import type { EventBus } from '../../src/core/events';
import type { WorldSpec, ObjectiveSpec } from '../../src/core/world/types';

// ── Helpers ────────────────────────────────────────────────────

function makeContext(objectives: ObjectiveSpec[], events: EventBus): SimulationContext {
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
            meta: {
                title: 'test',
                scenario: 'test',
                briefing: [],
                difficulty: 'beginner',
                mode: 'attack',
                vulnClasses: [],
                tags: [],
                estimatedMinutes: 5,
                author: { name: 'test', id: 'test', type: 'santh' },
            },
            machines: {},
            startMachine: 'player',
            network: { segments: [], edges: [] },
            credentials: [],
            objectives,
            modules: [],
            scoring: { maxScore: 1000, timeBonus: false, stealthBonus: false, hintPenalty: 50, tiers: [] },
            hints: [],
        } as unknown as WorldSpec,
        tick: 0,
        services: createServiceLocator(),
    };
}

function makeFindFileObjective(id: string, machine: string, path: string): ObjectiveSpec {
    return {
        id,
        title: `Find ${path}`,
        description: '',
        type: 'find-file',
        required: true,
        details: { kind: 'find-file', machine, path },
    };
}

// ── Tests ──────────────────────────────────────────────────────

describe('ObjectiveDetector', () => {
    let events: EventBus;
    let detector: ReturnType<typeof createObjectiveDetector>;

    beforeEach(() => {
        events = createEventBus();
        detector = createObjectiveDetector();
    });

    afterEach(() => {
        detector.destroy();
    });

    it('completes find-file objective on fs:read', () => {
        const ctx = makeContext([
            makeFindFileObjective('obj-1', 'web', '/etc/shadow'),
        ], events);

        detector.init(ctx);

        const completed: string[] = [];
        events.on('objective:complete', (e) => completed.push(e.objectiveId));

        events.emit({
            type: 'fs:read',
            path: '/etc/shadow',
            machine: 'web',
            user: 'root',
            timestamp: Date.now(),
        });

        expect(completed).toEqual(['obj-1']);
    });

    it('completes credential-find objective on auth:credential-found', () => {
        const ctx = makeContext([
            {
                id: 'obj-2',
                title: 'Find SSH key',
                description: '',
                type: 'credential-find',
                required: true,
                details: { kind: 'credential-find', credentialId: 'ssh-key-admin' },
            },
        ], events);

        detector.init(ctx);

        const completed: string[] = [];
        events.on('objective:complete', (e) => completed.push(e.objectiveId));

        events.emit({
            type: 'auth:credential-found',
            credentialId: 'ssh-key-admin',
            location: '/home/admin/.ssh/id_rsa',
            machine: 'web',
            timestamp: Date.now(),
        });

        expect(completed).toEqual(['obj-2']);
    });

    it('completes escalate objective on auth:escalate', () => {
        const ctx = makeContext([
            {
                id: 'obj-3',
                title: 'Get root',
                description: '',
                type: 'escalate',
                required: true,
                details: { kind: 'escalate', machine: 'web', fromUser: 'www-data', toUser: 'root' },
            },
        ], events);

        detector.init(ctx);

        const completed: string[] = [];
        events.on('objective:complete', (e) => completed.push(e.objectiveId));

        events.emit({
            type: 'auth:escalate',
            from: 'www-data',
            to: 'root',
            method: 'sudo',
            machine: 'web',
            timestamp: Date.now(),
        });

        expect(completed).toEqual(['obj-3']);
    });

    it('completes exfiltrate objective on net:request from source machine', () => {
        const ctx = makeContext([
            {
                id: 'obj-4',
                title: 'Exfil data',
                description: '',
                type: 'exfiltrate',
                required: true,
                details: { kind: 'exfiltrate', data: 'customer-db', fromMachine: 'web' },
            },
        ], events);

        detector.init(ctx);

        const completed: string[] = [];
        events.on('objective:complete', (e) => completed.push(e.objectiveId));

        events.emit({
            type: 'net:request',
            url: 'http://evil.local/upload',
            method: 'POST',
            source: 'web',
            destination: 'evil.local',
            timestamp: Date.now(),
        });

        expect(completed).toEqual(['obj-4']);
    });

    it('completes lateral-move objective on auth:login', () => {
        const ctx = makeContext([
            {
                id: 'obj-5',
                title: 'Pivot to DB',
                description: '',
                type: 'lateral-move',
                required: true,
                details: { kind: 'lateral-move', fromMachine: 'web', toMachine: 'db-server' },
            },
        ], events);

        detector.init(ctx);

        const completed: string[] = [];
        events.on('objective:complete', (e) => completed.push(e.objectiveId));

        events.emit({
            type: 'auth:login',
            user: 'admin',
            machine: 'db-server',
            service: 'ssh',
            success: true,
            timestamp: Date.now(),
        });

        expect(completed).toEqual(['obj-5']);
    });

    it('does not double-complete objectives', () => {
        const ctx = makeContext([
            makeFindFileObjective('obj-1', 'web', '/etc/shadow'),
        ], events);

        detector.init(ctx);

        const completed: string[] = [];
        events.on('objective:complete', (e) => completed.push(e.objectiveId));

        events.emit({ type: 'fs:read', path: '/etc/shadow', machine: 'web', user: 'root', timestamp: Date.now() });
        events.emit({ type: 'fs:read', path: '/etc/shadow', machine: 'web', user: 'root', timestamp: Date.now() });

        expect(completed).toEqual(['obj-1']); // Only once
    });

    it('cleans up listeners on destroy', () => {
        const ctx = makeContext([
            makeFindFileObjective('obj-1', 'web', '/etc/shadow'),
        ], events);

        detector.init(ctx);
        detector.destroy();

        const completed: string[] = [];
        events.on('objective:complete', (e) => completed.push(e.objectiveId));

        events.emit({ type: 'fs:read', path: '/etc/shadow', machine: 'web', user: 'root', timestamp: Date.now() });

        expect(completed).toEqual([]); // No completion after destroy
    });

    it('tracks multiple objectives independently', () => {
        const ctx = makeContext([
            makeFindFileObjective('obj-1', 'web', '/etc/shadow'),
            {
                id: 'obj-2',
                title: 'Get root',
                description: '',
                type: 'escalate',
                required: true,
                details: { kind: 'escalate', machine: 'web', fromUser: 'www', toUser: 'root' },
            },
        ], events);

        detector.init(ctx);

        const completed: string[] = [];
        events.on('objective:complete', (e) => completed.push(e.objectiveId));

        events.emit({ type: 'fs:read', path: '/etc/shadow', machine: 'web', user: 'root', timestamp: Date.now() });
        expect(completed).toEqual(['obj-1']); // Only first one

        events.emit({ type: 'auth:escalate', from: 'www', to: 'root', method: 'exploit', machine: 'web', timestamp: Date.now() });
        expect(completed).toEqual(['obj-1', 'obj-2']); // Both
    });

    it('completes survive objective after N ticks', () => {
        const ctx = makeContext([
            {
                id: 'obj-survive',
                title: 'Survive 3 ticks',
                description: '',
                type: 'survive',
                required: true,
                details: { kind: 'survive', ticks: 3 },
            },
        ], events);

        detector.init(ctx);

        const completed: string[] = [];
        events.on('objective:complete', (e) => completed.push(e.objectiveId));

        events.emit({ type: 'sim:tick', tick: 1, timestamp: Date.now() });
        expect(completed.length).toBe(0);

        events.emit({ type: 'sim:tick', tick: 2, timestamp: Date.now() });
        expect(completed.length).toBe(0);

        events.emit({ type: 'sim:tick', tick: 3, timestamp: Date.now() });
        expect(completed).toEqual(['obj-survive']);
    });
});
