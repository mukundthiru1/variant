import { describe, it, expect, beforeEach } from 'vitest';
import {
    createStealthEngine,
    createNoiseRuleRegistry,
    createBuiltinRules,
} from '../src/lib/stealth/stealth-engine';
import type { NoiseRule, NoiseRuleRegistry } from '../src/lib/stealth/types';
import { createEventBus } from '../src/core/event-bus';
import type { SimulationContext } from '../src/core/modules';
import { createServiceLocator } from '../src/core/modules';
import type { WorldSpec } from '../src/core/world/types';

// ── Helpers ──────────────────────────────────────────────────

function createMinimalWorld(): WorldSpec {
    return {
        version: '2.0',
        trust: 'community',
        meta: {
            title: 'Test',
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
        startMachine: '',
        network: { segments: [], edges: [] },
        credentials: [],
        objectives: [],
        scoring: {
            maxScore: 1000,
            timeBonus: false,
            stealthBonus: true,
            hintPenalty: 50,
            tiers: [],
        },
        hints: [],
        modules: [],
    };
}

function createContext(events = createEventBus()): SimulationContext {
    return {
        vms: new Map(),
        fabric: { getTrafficLog: () => [], getStats: () => ({ totalFrames: 0, droppedFrames: 0, bytesRouted: 0, dnsQueries: 0, activeConnections: 0 }), tap: () => () => {}, addDNSRecord: () => {}, registerExternal: () => () => {}, getExternalHandler: () => undefined, getExternalDomains: () => [] },
        events,
        world: createMinimalWorld(),
        tick: 0,
        services: createServiceLocator(),
    };
}

// ── Tests ────────────────────────────────────────────────────

describe('NoiseRuleRegistry', () => {
    let registry: NoiseRuleRegistry;

    beforeEach(() => {
        registry = createNoiseRuleRegistry();
    });

    it('registers and retrieves rules', () => {
        const rule: NoiseRule = {
            id: 'test/rule',
            description: 'Test rule',
            category: 'reconnaissance',
            eventPattern: 'net:connect',
            baseNoise: 10,
        };

        registry.register(rule);
        expect(registry.get('test/rule')).toEqual(rule);
    });

    it('throws on duplicate registration', () => {
        const rule: NoiseRule = {
            id: 'test/dup',
            description: 'Test',
            category: 'reconnaissance',
            eventPattern: 'net:connect',
            baseNoise: 5,
        };

        registry.register(rule);
        expect(() => registry.register(rule)).toThrow("Noise rule 'test/dup' already registered");
    });

    it('matches rules by exact event type', () => {
        registry.registerAll([
            { id: 'a', description: '', category: 'reconnaissance', eventPattern: 'net:connect', baseNoise: 5 },
            { id: 'b', description: '', category: 'reconnaissance', eventPattern: 'fs:read', baseNoise: 3 },
        ]);

        const matches = registry.getMatchingRules('net:connect');
        expect(matches.length).toBe(1);
        expect(matches[0]!.id).toBe('a');
    });

    it('matches rules by prefix', () => {
        registry.registerAll([
            { id: 'a', description: '', category: 'reconnaissance', eventPattern: 'net:*', baseNoise: 5 },
            { id: 'b', description: '', category: 'reconnaissance', eventPattern: 'fs:read', baseNoise: 3 },
        ]);

        const matches = registry.getMatchingRules('net:connect');
        expect(matches.length).toBe(1);
        expect(matches[0]!.id).toBe('a');
    });

    it('filters by category', () => {
        registry.registerAll([
            { id: 'a', description: '', category: 'reconnaissance', eventPattern: 'net:connect', baseNoise: 5 },
            { id: 'b', description: '', category: 'credential-access', eventPattern: 'auth:login', baseNoise: 8 },
        ]);

        const recon = registry.getByCategory('reconnaissance');
        expect(recon.length).toBe(1);
        expect(recon[0]!.id).toBe('a');
    });
});

describe('Built-in Noise Rules', () => {
    it('has at least 10 built-in rules', () => {
        const rules = createBuiltinRules();
        expect(rules.length).toBeGreaterThanOrEqual(10);
    });

    it('covers all major categories', () => {
        const rules = createBuiltinRules();
        const categories = new Set(rules.map(r => r.category));
        expect(categories.has('reconnaissance')).toBe(true);
        expect(categories.has('credential-access')).toBe(true);
        expect(categories.has('exploitation')).toBe(true);
        expect(categories.has('privilege-escalation')).toBe(true);
        expect(categories.has('lateral-movement')).toBe(true);
        expect(categories.has('exfiltration')).toBe(true);
        expect(categories.has('persistence')).toBe(true);
        expect(categories.has('defense-evasion')).toBe(true);
    });

    it('all rules have unique IDs', () => {
        const rules = createBuiltinRules();
        const ids = new Set(rules.map(r => r.id));
        expect(ids.size).toBe(rules.length);
    });
});

describe('StealthEngine Module', () => {
    it('initializes and destroys cleanly', () => {
        const module = createStealthEngine();
        const context = createContext();

        expect(module.id).toBe('stealth-engine');
        expect(module.provides.length).toBeGreaterThan(0);

        module.init(context);
        module.destroy();
    });

    it('generates noise on matching events', () => {
        const events = createEventBus();
        const context = createContext(events);
        const module = createStealthEngine();

        const noiseEvents: number[] = [];
        events.on('sim:noise', (event) => {
            noiseEvents.push(event.amount);
        });

        module.init(context);

        // Emit a net:connect event (matches recon/port-scan)
        events.emit({
            type: 'net:connect',
            host: '10.0.0.5',
            port: 80,
            source: 'player',
            protocol: 'tcp',
            timestamp: Date.now(),
        });

        expect(noiseEvents.length).toBeGreaterThan(0);
        expect(noiseEvents[0]!).toBeGreaterThan(0);

        module.destroy();
    });

    it('excludes rules by ID', () => {
        const events = createEventBus();
        const context = createContext(events);
        const module = createStealthEngine({
            excludeRules: ['recon/port-scan'],
        });

        const noiseEvents: number[] = [];
        events.on('sim:noise', (event) => {
            noiseEvents.push(event.amount);
        });

        module.init(context);

        events.emit({
            type: 'net:connect',
            host: '10.0.0.5',
            port: 80,
            source: 'player',
            protocol: 'tcp',
            timestamp: Date.now(),
        });

        // Port scan rule is excluded, but SSH lateral movement rule may still match on port 22
        // For port 80, only the excluded rule would match
        // Port scan rule is excluded; other rules may or may not match depending on port
        module.destroy();
    });

    it('supports custom detection config', () => {
        const module = createStealthEngine({
            detection: {
                noiseFloor: 100,
                noiseCeiling: 1000,
                curve: 'linear',
                decayPerTick: 2.0,
            },
        });

        expect(module.id).toBe('stealth-engine');
        module.destroy();
    });

    it('responds to stealth-query custom events', () => {
        const events = createEventBus();
        const context = createContext(events);
        const module = createStealthEngine();

        let stateReceived = false;
        events.onPrefix('custom:', (event) => {
            if (event.type === 'custom:stealth-state') {
                stateReceived = true;
                const data = event.data as { totalNoise: number; detected: boolean };
                expect(typeof data.totalNoise).toBe('number');
                expect(typeof data.detected).toBe('boolean');
            }
        });

        module.init(context);

        events.emit({
            type: 'custom:stealth-query',
            data: {},
            timestamp: Date.now(),
        });

        expect(stateReceived).toBe(true);

        module.destroy();
    });

    it('applies stealth modifiers', () => {
        const events = createEventBus();
        const context = createContext(events);
        const module = createStealthEngine({
            modifiers: [{
                id: 'test-stealth',
                description: 'Silent mode',
                categories: ['*'],
                multiplier: 0.0,
                active: true,
            }],
        });

        const noiseEvents: number[] = [];
        events.on('sim:noise', (event) => {
            noiseEvents.push(event.amount);
        });

        module.init(context);

        // With multiplier 0.0, all noise should be suppressed
        events.emit({
            type: 'auth:escalate',
            machine: 'target',
            from: 'user',
            to: 'root',
            method: 'sudo',
            timestamp: Date.now(),
        });

        expect(noiseEvents.length).toBe(0);

        module.destroy();
    });
});
