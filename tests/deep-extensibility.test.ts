/**
 * VARIANT — Deep Extensibility Tests
 *
 * Tests for:
 *   - Dynamics Engine v2 (new action types, repeat, once, custom registry)
 *   - Objective Evaluator Registry (registration, built-in evaluators)
 *   - NPC Extensions (new action types, template registry)
 *   - Service Handler Registration (SSH, SMTP, DNS factory registration)
 */

import { describe, it, expect, vi } from 'vitest';
import { createDynamicsEngine, createDynamicActionHandlerRegistry } from '../src/modules/dynamics-engine';
import { createObjectiveEvaluatorRegistry, registerBuiltinEvaluators } from '../src/modules/objective-evaluators';
import { expandNPCSchedule, NPC_TEMPLATES } from '../src/lib/npc/types';
import type { NPCDefinition } from '../src/lib/npc/types';
import { createEventBus } from '../src/core/event-bus';
import { createServiceLocator } from '../src/core/modules';

// ── Dynamic Action Handler Registry Tests ──────────────────────

describe('DynamicActionHandlerRegistry', () => {
    it('registers and retrieves a handler', () => {
        const registry = createDynamicActionHandlerRegistry();
        const handler = vi.fn();

        registry.register('deploy-honeypot', handler);

        expect(registry.has('deploy-honeypot')).toBe(true);
        expect(registry.get('deploy-honeypot')).toBe(handler);
    });

    it('rejects duplicate registrations', () => {
        const registry = createDynamicActionHandlerRegistry();
        registry.register('test-action', vi.fn());

        expect(() => {
            registry.register('test-action', vi.fn());
        }).toThrow(/already registered/);
    });

    it('rejects empty action names', () => {
        const registry = createDynamicActionHandlerRegistry();

        expect(() => {
            registry.register('', vi.fn());
        }).toThrow(/non-empty/);
    });

    it('lists all registered actions', () => {
        const registry = createDynamicActionHandlerRegistry();
        registry.register('action-a', vi.fn());
        registry.register('action-b', vi.fn());

        const list = registry.list();
        expect(list).toContain('action-a');
        expect(list).toContain('action-b');
    });

    it('returns undefined for unregistered actions', () => {
        const registry = createDynamicActionHandlerRegistry();
        expect(registry.get('nonexistent')).toBeUndefined();
    });
});

// ── Dynamics Engine v2 Tests ───────────────────────────────────

describe('Dynamics Engine v2', () => {
    it('handles send-email action', () => {
        const events = createEventBus();
        const engine = createDynamicsEngine();
        const emitted: any[] = [];

        events.onPrefix('custom:', (e) => emitted.push(e));

        engine.init({
            vms: new Map(),
            fabric: {} as any,
            events,
            services: createServiceLocator(),
            world: {
                dynamics: {
                    timedEvents: [{
                        tick: 0,
                        action: {
                            type: 'send-email' as const,
                            to: 'victim@corp.local',
                            template: 'password-reset',
                        },
                    }],
                },
            } as any,
            tick: 0,
        });

        events.emit({ type: 'sim:tick', tick: 0, timestamp: Date.now() });

        expect(emitted.length).toBe(1);
        expect(emitted[0].type).toBe('custom:dynamics-send-email');
        expect(emitted[0].data.to).toBe('victim@corp.local');

        engine.destroy();
    });

    it('handles custom action with registered handler', () => {
        const registry = createDynamicActionHandlerRegistry();
        const handler = vi.fn();
        registry.register('deploy-decoy', handler);

        const events = createEventBus();
        const engine = createDynamicsEngine(registry);

        engine.init({
            vms: new Map(),
            fabric: {} as any,
            events,
            services: createServiceLocator(),
            world: {
                dynamics: {
                    timedEvents: [{
                        tick: 0,
                        action: {
                            type: 'custom' as const,
                            action: 'deploy-decoy',
                            params: { target: 'honeypot-01' },
                        },
                    }],
                },
            } as any,
            tick: 0,
        });

        events.emit({ type: 'sim:tick', tick: 0, timestamp: Date.now() });

        expect(handler).toHaveBeenCalledTimes(1);
        expect(handler).toHaveBeenCalledWith(
            'deploy-decoy',
            { target: 'honeypot-01' },
            events,
        );

        engine.destroy();
    });

    it('handles custom action without registered handler (emits generic event)', () => {
        const events = createEventBus();
        const engine = createDynamicsEngine();
        const emitted: any[] = [];

        events.onPrefix('custom:', (e) => emitted.push(e));

        engine.init({
            vms: new Map(),
            fabric: {} as any,
            events,
            services: createServiceLocator(),
            world: {
                dynamics: {
                    timedEvents: [{
                        tick: 0,
                        action: {
                            type: 'custom' as const,
                            action: 'unknown-action',
                            params: { x: 1 },
                        },
                    }],
                },
            } as any,
            tick: 0,
        });

        events.emit({ type: 'sim:tick', tick: 0, timestamp: Date.now() });

        expect(emitted.length).toBe(1);
        expect(emitted[0].type).toBe('custom:dynamics-unknown-action');

        engine.destroy();
    });

    it('handles start-service action', () => {
        const events = createEventBus();
        const engine = createDynamicsEngine();
        const emitted: any[] = [];

        events.onPrefix('custom:', (e) => emitted.push(e));

        engine.init({
            vms: new Map(),
            fabric: {} as any,
            events,
            services: createServiceLocator(),
            world: {
                dynamics: {
                    timedEvents: [{
                        tick: 0,
                        action: {
                            type: 'start-service' as const,
                            machine: 'web-01',
                            service: 'nginx',
                        },
                    }],
                },
            } as any,
            tick: 0,
        });

        events.emit({ type: 'sim:tick', tick: 0, timestamp: Date.now() });

        expect(emitted[0].data.machine).toBe('web-01');
        expect(emitted[0].data.service).toBe('nginx');

        engine.destroy();
    });

    it('handles open-lens action', () => {
        const events = createEventBus();
        const engine = createDynamicsEngine();
        const emitted: any[] = [];

        events.onPrefix('custom:', (e) => emitted.push(e));

        engine.init({
            vms: new Map(),
            fabric: {} as any,
            events,
            services: createServiceLocator(),
            world: {
                dynamics: {
                    timedEvents: [{
                        tick: 0,
                        action: {
                            type: 'open-lens' as const,
                            lensType: 'browser',
                            targetMachine: 'web-01',
                        },
                    }],
                },
            } as any,
            tick: 0,
        });

        events.emit({ type: 'sim:tick', tick: 0, timestamp: Date.now() });

        expect(emitted[0].data.lensType).toBe('browser');
        expect(emitted[0].data.targetMachine).toBe('web-01');

        engine.destroy();
    });

    it('supports repeating timed events', () => {
        const events = createEventBus();
        const engine = createDynamicsEngine();
        const emitted: any[] = [];

        events.on('sim:alert', (e) => emitted.push(e));

        engine.init({
            vms: new Map(),
            fabric: {} as any,
            events,
            services: createServiceLocator(),
            world: {
                dynamics: {
                    timedEvents: [{
                        tick: 5,
                        repeatInterval: 10,
                        action: {
                            type: 'alert' as const,
                            severity: 'info',
                            message: 'heartbeat',
                        },
                    }],
                },
            } as any,
            tick: 0,
        });

        // Before fire tick — no event
        events.emit({ type: 'sim:tick', tick: 3, timestamp: Date.now() });
        expect(emitted.length).toBe(0);

        // At fire tick — fires
        events.emit({ type: 'sim:tick', tick: 5, timestamp: Date.now() });
        expect(emitted.length).toBe(1);

        // Not yet at next repeat
        events.emit({ type: 'sim:tick', tick: 10, timestamp: Date.now() });
        expect(emitted.length).toBe(1);

        // At next repeat (5 + 10 = 15)
        events.emit({ type: 'sim:tick', tick: 15, timestamp: Date.now() });
        expect(emitted.length).toBe(2);

        // Next repeat (15 + 10 = 25)
        events.emit({ type: 'sim:tick', tick: 25, timestamp: Date.now() });
        expect(emitted.length).toBe(3);

        engine.destroy();
    });

    it('supports once flag on reactive events', () => {
        const events = createEventBus();
        const engine = createDynamicsEngine();
        const emitted: any[] = [];

        events.on('sim:alert', (e) => emitted.push(e));

        engine.init({
            vms: new Map(),
            fabric: {} as any,
            events,
            services: createServiceLocator(),
            world: {
                dynamics: {
                    reactiveEvents: [{
                        trigger: 'custom:auth-login-failed',
                        once: true,
                        action: {
                            type: 'alert' as const,
                            severity: 'warning',
                            message: 'first failed login detected',
                        },
                    }],
                },
            } as any,
            tick: 0,
        });

        // First trigger
        events.emit({ type: 'custom:auth-login-failed', data: {}, timestamp: Date.now() });
        expect(emitted.length).toBe(1);

        // Second trigger — should NOT fire (once=true)
        events.emit({ type: 'custom:auth-login-failed', data: {}, timestamp: Date.now() });
        expect(emitted.length).toBe(1);

        engine.destroy();
    });
});

// ── Objective Evaluator Registry Tests ─────────────────────────

describe('ObjectiveEvaluatorRegistry', () => {
    it('registers and retrieves an evaluator', () => {
        const registry = createObjectiveEvaluatorRegistry();

        registry.register({
            id: 'test-evaluator',
            displayName: 'Test',
            description: 'test evaluator',
            start: () => { },
        });

        expect(registry.has('test-evaluator')).toBe(true);
        expect(registry.get('test-evaluator')?.displayName).toBe('Test');
    });

    it('rejects duplicate evaluator registrations', () => {
        const registry = createObjectiveEvaluatorRegistry();

        registry.register({
            id: 'dup-eval',
            displayName: 'Dup',
            description: 'dup',
            start: () => { },
        });

        expect(() => {
            registry.register({
                id: 'dup-eval',
                displayName: 'Dup2',
                description: 'dup2',
                start: () => { },
            });
        }).toThrow(/already registered/);
    });

    it('rejects empty evaluator IDs', () => {
        const registry = createObjectiveEvaluatorRegistry();

        expect(() => {
            registry.register({
                id: '',
                displayName: 'Empty',
                description: 'empty',
                start: () => { },
            });
        }).toThrow(/non-empty/);
    });

    it('lists all registered evaluator IDs', () => {
        const registry = createObjectiveEvaluatorRegistry();

        registry.register({ id: 'eval-a', displayName: 'A', description: 'a', start: () => { } });
        registry.register({ id: 'eval-b', displayName: 'B', description: 'b', start: () => { } });

        expect(registry.list()).toContain('eval-a');
        expect(registry.list()).toContain('eval-b');
    });

    it('getAll returns all evaluators', () => {
        const registry = createObjectiveEvaluatorRegistry();

        registry.register({ id: 'eval-x', displayName: 'X', description: 'x', start: () => { } });

        const all = registry.getAll();
        expect(all).toHaveLength(1);
        expect(all[0]?.id).toBe('eval-x');
    });

    it('registerBuiltinEvaluators adds all built-in evaluators', () => {
        const registry = createObjectiveEvaluatorRegistry();
        registerBuiltinEvaluators(registry);

        expect(registry.has('detect-file-read')).toBe(true);
        expect(registry.has('detect-command')).toBe(true);
        expect(registry.has('detect-traffic')).toBe(true);
        expect(registry.has('collect-items')).toBe(true);
        expect(registry.has('survive-clean')).toBe(true);
        expect(registry.has('phishing-detection')).toBe(true);

        // Should be exactly 6 built-in evaluators
        expect(registry.list().length).toBe(6);
    });
});

// ── NPC Extensions Tests ───────────────────────────────────────

describe('NPC Extensions', () => {
    it('NPC definitions support extensions field', () => {
        const npc: NPCDefinition = {
            id: 'npc-custom-1',
            name: 'Custom NPC',
            username: 'bot',
            role: 'threat-actor',  // custom role — open union
            machine: 'server-01',
            schedule: [],
            extensions: {
                'vendor/threat-model': { attackPattern: 'apt29-like', persistence: 'registry' },
            },
        };

        expect(npc.role).toBe('threat-actor');
        expect(npc.extensions?.['vendor/threat-model']).toBeDefined();
    });

    it('NPC supports send-email action type', () => {
        const npc: NPCDefinition = {
            id: 'npc-phisher',
            name: 'Phishing Bot',
            username: 'internal',
            role: 'attacker',
            machine: 'mail-01',
            schedule: [
                {
                    tick: 30,
                    type: {
                        kind: 'send-email',
                        to: 'victim@corp.local',
                        from: 'it-support@corp.local',
                        subject: 'Password Reset Required',
                        body: 'Please click here to reset: http://evil.corp.local/reset',
                        malicious: true,
                        maliciousAction: 'credential-harvest',
                    },
                },
            ],
        };

        expect(npc.schedule[0]?.type.kind).toBe('send-email');
    });

    it('NPC supports network action type', () => {
        const npc: NPCDefinition = {
            id: 'npc-scanner',
            name: 'Network Scanner',
            username: 'recon',
            role: 'attacker',
            machine: 'kali-01',
            schedule: [
                {
                    tick: 10,
                    type: {
                        kind: 'network',
                        target: '10.0.1.20',
                        port: 22,
                        protocol: 'tcp',
                        activity: 'scan',
                    },
                },
            ],
        };

        expect(npc.schedule[0]?.type.kind).toBe('network');
    });

    it('NPC supports custom action type', () => {
        const npc: NPCDefinition = {
            id: 'npc-lateral',
            name: 'Lateral Mover',
            username: 'admin',
            role: 'attacker',
            machine: 'dc-01',
            schedule: [
                {
                    tick: 100,
                    type: {
                        kind: 'custom',
                        action: 'kerberoast',
                        params: { targetSPN: 'MSSQLSvc/db01.corp.local:1433' },
                    },
                },
            ],
        };

        expect(npc.schedule[0]?.type.kind).toBe('custom');
    });

    it('expandNPCSchedule works with new action types', () => {
        const npc: NPCDefinition = {
            id: 'npc-phisher',
            name: 'Phisher',
            username: 'attacker',
            role: 'attacker',
            machine: 'mail',
            schedule: [
                {
                    tick: 10,
                    type: {
                        kind: 'send-email',
                        to: 'admin@corp.local',
                        from: 'ceo@corp.local',
                        subject: 'Urgent',
                        body: 'Wire transfer needed',
                        malicious: true,
                    },
                },
                {
                    tick: 20,
                    type: {
                        kind: 'network',
                        target: '10.0.1.5',
                        port: 445,
                        protocol: 'tcp',
                        activity: 'exfiltrate',
                        bytes: 1048576,
                    },
                },
            ],
            recurring: [
                {
                    intervalTicks: 50,
                    action: {
                        kind: 'custom',
                        action: 'beacon-callback',
                        params: { c2: 'https://c2.evil.local/api' },
                    },
                },
            ],
        };

        const expanded = expandNPCSchedule(npc, 200);

        // 2 scheduled + (200/50 + 1 = 5) recurring = 7
        expect(expanded.length).toBe(7);
        // Recurring start at tick 0, scheduled at 10 and 20
        // Sort is by tick, so recurring (tick 0, 50, 100, 150, 200) come first
        // then scheduled at tick 10 and 20 are interleaved
        const kinds = expanded.map(e => e.action.kind);
        expect(kinds).toContain('send-email');
        expect(kinds).toContain('network');
        expect(kinds).toContain('custom');
    });

    it('NPC templates still work correctly', () => {
        const admin = NPC_TEMPLATES.sysadmin('alice', 'server-01');
        expect(admin.id).toBe('npc-sysadmin-alice');
        expect(admin.role).toBe('admin');
        expect(admin.schedule.length).toBeGreaterThan(0);

        const employee = NPC_TEMPLATES.employee('bob', 'workstation-01');
        expect(employee.role).toBe('employee');

        const attacker = NPC_TEMPLATES.bruteForceAttacker('server-01', '203.0.113.42');
        expect(attacker.role).toBe('attacker');
        expect(attacker.recurring?.length).toBeGreaterThan(0);

        const cron = NPC_TEMPLATES.cronService('server-01', 'logrotate', 300);
        expect(cron.role).toBe('service-account');
    });
});
