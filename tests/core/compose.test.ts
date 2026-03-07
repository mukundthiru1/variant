/**
 * VARIANT — WorldSpec Composition Tests
 *
 * Tests for composeWorldSpec and patchMachine.
 */

import { describe, it, expect } from 'vitest';
import { composeWorldSpec } from '../../src/core/world/compose';
import type { WorldSpec, MachineSpec, ObjectiveSpec } from '../../src/core/world/types';

// ── Minimal base WorldSpec for testing ────────────────────────

function createBaseWorld(): WorldSpec {
    return {
        version: '1.0.0',
        trust: 'local',
        meta: {
            title: 'Base Level',
            scenario: 'A base level for testing',
            briefing: ['Welcome to the base level.'],
            difficulty: 'medium',
            mode: 'attack',
            vulnClasses: ['injection'],
            tags: ['test'],
            estimatedMinutes: 30,
            author: { name: 'test', url: 'https://example.com' },
        },
        machines: {
            'web-01': {
                hostname: 'web-01',
                image: 'ubuntu:22.04',
                memoryMB: 512,
                role: 'server',
                interfaces: [{ segment: 'dmz', ip: '10.0.1.10' }],
                services: [
                    { name: 'http', command: 'nginx', ports: [80], autostart: true },
                    { name: 'ssh', command: 'sshd', ports: [22], autostart: true },
                ],
                files: {
                    '/etc/passwd': { type: 'text', content: 'root:x:0:0:root:/root:/bin/bash' },
                    '/var/www/index.html': { type: 'text', content: '<h1>Hello</h1>' },
                },
            } as unknown as MachineSpec,
            'db-01': {
                hostname: 'db-01',
                image: 'ubuntu:22.04',
                memoryMB: 1024,
                role: 'server',
                interfaces: [{ segment: 'internal', ip: '10.0.2.10' }],
                services: [
                    { name: 'mysql', command: 'mysqld', ports: [3306], autostart: true },
                ],
            } as unknown as MachineSpec,
        },
        startMachine: 'web-01',
        network: {
            segments: [
                { id: 'dmz', subnet: '10.0.1.0/24' },
                { id: 'internal', subnet: '10.0.2.0/24' },
            ],
            edges: [
                { from: 'dmz', to: 'internal', protocol: 'tcp' },
            ],
        },
        credentials: [
            { id: 'cred-admin', type: 'password', value: 'admin123', foundAt: { machine: 'web-01' }, validAt: { machine: 'web-01', service: 'ssh', user: 'admin' } },
            { id: 'cred-db', type: 'password', value: 'dbpass', foundAt: { machine: 'db-01' }, validAt: { machine: 'db-01', service: 'mysql', user: 'root' } },
        ],
        objectives: [
            { id: 'obj-1', title: 'Gain access', points: 100, details: { kind: 'detect-command', machine: 'web-01', pattern: 'whoami' } },
            { id: 'obj-2', title: 'Read secret', points: 200, details: { kind: 'detect-file-read', machine: 'db-01', path: '/secret' } },
        ] as unknown as ObjectiveSpec[],
        modules: ['process-monitor', 'siem'],
        scoring: {
            maxScore: 1000,
            hintPenalty: 50,
            timeBonus: true,
            stealthBonus: false,
            tiers: [
                { name: 'Gold', minScore: 800 },
                { name: 'Silver', minScore: 500 },
            ],
        },
        hints: ['Try scanning the network', 'Look for misconfigurations'],
    } as unknown as WorldSpec;
}

// ── Tests ────────────────────────────────────────────────────

describe('composeWorldSpec', () => {
    it('returns base unchanged when patch is empty', () => {
        const base = createBaseWorld();
        const result = composeWorldSpec(base, {});

        expect(result.version).toBe('1.0.0');
        expect(result.meta.title).toBe('Base Level');
        expect(Object.keys(result.machines)).toEqual(['web-01', 'db-01']);
        expect(result.objectives.length).toBe(2);
        expect(result.modules.length).toBe(2);
    });

    it('overrides meta fields', () => {
        const base = createBaseWorld();
        const result = composeWorldSpec(base, {
            meta: { title: 'Hard Mode', difficulty: 'hard' },
        });

        expect(result.meta.title).toBe('Hard Mode');
        expect(result.meta.difficulty).toBe('hard');
        // Unmodified fields preserved
        expect(result.meta.scenario).toBe('A base level for testing');
    });

    it('patches existing machine files', () => {
        const base = createBaseWorld();
        const result = composeWorldSpec(base, {
            machines: {
                'web-01': {
                    files: {
                        '/etc/shadow': { type: 'text', content: 'root:$6$hash:...' },
                    },
                },
            },
        });

        const webFiles = (result.machines['web-01'] as any).files;
        // New file added
        expect(webFiles['/etc/shadow'].content).toBe('root:$6$hash:...');
        // Existing files preserved
        expect(webFiles['/etc/passwd']).toBeDefined();
        expect(webFiles['/var/www/index.html']).toBeDefined();
    });

    it('removes files from machines', () => {
        const base = createBaseWorld();
        const result = composeWorldSpec(base, {
            machines: {
                'web-01': {
                    removeFiles: ['/var/www/index.html'],
                },
            },
        });

        const webFiles = (result.machines['web-01'] as any).files;
        expect(webFiles['/var/www/index.html']).toBeUndefined();
        expect(webFiles['/etc/passwd']).toBeDefined();
    });

    it('adds new machines', () => {
        const base = createBaseWorld();
        const result = composeWorldSpec(base, {
            addMachines: {
                'honeypot-01': {
                    hostname: 'honeypot-01',
                    image: 'ubuntu:22.04',
                    memoryMB: 256,
                    role: 'server',
                    interfaces: [{ segment: 'dmz', ip: '10.0.1.20' }],
                } as unknown as MachineSpec,
            },
        });

        expect(result.machines['honeypot-01']).toBeDefined();
        expect((result.machines['honeypot-01'] as any).hostname).toBe('honeypot-01');
        // Original machines still present
        expect(result.machines['web-01']).toBeDefined();
        expect(result.machines['db-01']).toBeDefined();
    });

    it('removes machines', () => {
        const base = createBaseWorld();
        const result = composeWorldSpec(base, {
            removeMachines: ['db-01'],
        });

        expect(result.machines['db-01']).toBeUndefined();
        expect(result.machines['web-01']).toBeDefined();
    });

    it('overrides startMachine', () => {
        const base = createBaseWorld();
        const result = composeWorldSpec(base, {
            startMachine: 'db-01',
        });

        expect(result.startMachine).toBe('db-01');
    });

    it('adds and removes credentials', () => {
        const base = createBaseWorld();
        const result = composeWorldSpec(base, {
            removeCredentials: ['cred-admin'],
            addCredentials: [
                { id: 'cred-new', type: 'password', value: 'p4ss', foundAt: { machine: 'web-01' }, validAt: { machine: 'web-01', service: 'ssh', user: 'hacker' } } as any,
            ],
        });

        const credIds = result.credentials.map((c: any) => c.id);
        expect(credIds).not.toContain('cred-admin');
        expect(credIds).toContain('cred-db');
        expect(credIds).toContain('cred-new');
    });

    it('replaces objectives entirely when objectives field is set', () => {
        const base = createBaseWorld();
        const newObjs = [
            { id: 'obj-new', title: 'New objective', points: 500, details: { kind: 'detect-command', machine: 'web-01', pattern: 'id' } },
        ] as unknown as ObjectiveSpec[];

        const result = composeWorldSpec(base, {
            objectives: newObjs,
        });

        expect(result.objectives.length).toBe(1);
        expect(result.objectives[0]!.id).toBe('obj-new');
    });

    it('adds and removes objectives incrementally', () => {
        const base = createBaseWorld();
        const result = composeWorldSpec(base, {
            removeObjectives: ['obj-1'],
            addObjectives: [
                { id: 'obj-3', title: 'Bonus', points: 50, details: { kind: 'detect-command', machine: 'web-01', pattern: 'ls' } },
            ] as unknown as ObjectiveSpec[],
        });

        const objIds = result.objectives.map((o: any) => o.id);
        expect(objIds).not.toContain('obj-1');
        expect(objIds).toContain('obj-2');
        expect(objIds).toContain('obj-3');
    });

    it('adds and removes modules', () => {
        const base = createBaseWorld();
        const result = composeWorldSpec(base, {
            removeModules: ['siem'],
            addModules: ['correlation-module', 'traffic-generator'],
        });

        expect(result.modules).not.toContain('siem');
        expect(result.modules).toContain('process-monitor');
        expect(result.modules).toContain('correlation-module');
        expect(result.modules).toContain('traffic-generator');
    });

    it('appends hints', () => {
        const base = createBaseWorld();
        const result = composeWorldSpec(base, {
            addHints: ['Check port 3306'],
        });

        expect(result.hints.length).toBe(3);
        expect(result.hints).toContain('Check port 3306');
    });

    it('overrides scoring config with deep merge', () => {
        const base = createBaseWorld();
        const result = composeWorldSpec(base, {
            scoring: { maxScore: 2000, stealthBonus: true },
        });

        expect(result.scoring.maxScore).toBe(2000);
        expect(result.scoring.stealthBonus).toBe(true);
        // Preserved from base
        expect(result.scoring.hintPenalty).toBe(50);
        expect(result.scoring.timeBonus).toBe(true);
    });

    it('overrides tickIntervalMs', () => {
        const base = createBaseWorld();
        const result = composeWorldSpec(base, {
            tickIntervalMs: 500,
        });

        expect(result.tickIntervalMs).toBe(500);
    });

    it('merges extensions', () => {
        const base = createBaseWorld();
        (base as any).extensions = { 'base-key': 'base-value' };

        const result = composeWorldSpec(base, {
            extensions: { 'patch-key': 'patch-value' },
        });

        expect((result as any).extensions['base-key']).toBe('base-value');
        expect((result as any).extensions['patch-key']).toBe('patch-value');
    });

    it('merges dynamics timed and reactive events', () => {
        const base = createBaseWorld();
        (base as any).dynamics = {
            timedEvents: [{ tick: 10, action: { type: 'alert', severity: 'info', message: 'base event' } }],
            reactiveEvents: [],
        };

        const result = composeWorldSpec(base, {
            dynamics: {
                timedEvents: [{ tick: 20, action: { type: 'alert', severity: 'warning', message: 'patch event' } }],
                reactiveEvents: [{ trigger: 'auth:login', action: { type: 'alert', severity: 'info', message: 'reactive' } }],
            },
        });

        const dynamics = (result as any).dynamics;
        expect(dynamics.timedEvents.length).toBe(2);
        expect(dynamics.reactiveEvents.length).toBe(1);
    });

    it('does not mutate the base WorldSpec', () => {
        const base = createBaseWorld();
        const originalMachineKeys = Object.keys(base.machines);
        const originalModules = [...base.modules];

        composeWorldSpec(base, {
            addMachines: { 'new-machine': { hostname: 'new' } as unknown as MachineSpec },
            addModules: ['new-module'],
            removeMachines: ['db-01'],
        });

        // Base should be unchanged
        expect(Object.keys(base.machines)).toEqual(originalMachineKeys);
        expect([...base.modules]).toEqual(originalModules);
    });

    it('patches machine hostname and memory', () => {
        const base = createBaseWorld();
        const result = composeWorldSpec(base, {
            machines: {
                'web-01': {
                    hostname: 'web-primary',
                    memoryMB: 2048,
                },
            },
        });

        const web = result.machines['web-01'] as any;
        expect(web.hostname).toBe('web-primary');
        expect(web.memoryMB).toBe(2048);
        // Image preserved from base
        expect(web.image).toBe('ubuntu:22.04');
    });

    it('ignores machine patches for non-existent machines', () => {
        const base = createBaseWorld();
        const result = composeWorldSpec(base, {
            machines: {
                'nonexistent': { hostname: 'ghost' },
            },
        });

        // No crash, non-existent machine not added
        expect(result.machines['nonexistent']).toBeUndefined();
    });

    it('overrides network segments', () => {
        const base = createBaseWorld();
        const result = composeWorldSpec(base, {
            network: {
                segments: [{ id: 'flat', subnet: '192.168.0.0/16' }],
            },
        });

        expect(result.network.segments.length).toBe(1);
        expect(result.network.segments[0]!.id).toBe('flat');
        // Edges preserved from base when not specified in patch
        expect(result.network.edges.length).toBe(1);
    });
});
