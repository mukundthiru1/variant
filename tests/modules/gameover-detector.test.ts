/**
 * VARIANT — Game Over Detector Tests
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createGameOverDetector, createGameOverConditionHandlerRegistry } from '../../src/modules/gameover-detector';
import type { GameOverConditionHandlerRegistry } from '../../src/modules/gameover-detector';
import { createEventBus } from '../../src/core/event-bus';
import type { SimulationContext } from '../../src/core/modules';
import { createServiceLocator } from '../../src/core/modules';
import type { EventBus } from '../../src/core/events';
import type { WorldSpec, GameOverSpec } from '../../src/core/world/types';

// ── Helpers ────────────────────────────────────────────────────

function makeContext(gameOver: GameOverSpec | undefined, events: EventBus): SimulationContext {
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
            meta: { title: 'test', scenario: 'test', briefing: [], difficulty: 'beginner', mode: 'defense', vulnClasses: [], tags: [], estimatedMinutes: 5, author: { name: 'test', id: 'test', type: 'santh' } },
            machines: {},
            startMachine: 'player',
            network: { segments: [], edges: [] },
            credentials: [],
            objectives: [],
            gameOver,
            modules: [],
            scoring: { maxScore: 1000, timeBonus: false, stealthBonus: false, hintPenalty: 50, tiers: [] },
            hints: [],
        } as unknown as WorldSpec,
        tick: 0,
        services: createServiceLocator(),
    };
}

// ── Tests ──────────────────────────────────────────────────────

describe('GameOverDetector', () => {
    let events: EventBus;
    let detector: ReturnType<typeof createGameOverDetector>;

    beforeEach(() => {
        events = createEventBus();
        detector = createGameOverDetector();
    });

    afterEach(() => {
        detector.destroy();
    });

    it('fires gameover on machine compromise', () => {
        const ctx = makeContext({
            conditions: [{ type: 'machine-compromised', machine: 'web-server' }],
            message: 'Server compromised!',
        }, events);

        detector.init(ctx);

        const reasons: string[] = [];
        events.on('sim:gameover', (e) => reasons.push(e.reason));

        events.emit({
            type: 'auth:escalate',
            machine: 'web-server',
            from: 'www-data',
            to: 'root',
            method: 'exploit',
            timestamp: Date.now(),
        });

        expect(reasons.length).toBe(1);
        expect(reasons[0]).toContain('compromised');
    });

    it('fires gameover on credential leak', () => {
        const ctx = makeContext({
            conditions: [{ type: 'credential-leaked', credentialId: 'admin-key' }],
            message: 'Credential leaked!',
        }, events);

        detector.init(ctx);

        const reasons: string[] = [];
        events.on('sim:gameover', (e) => reasons.push(e.reason));

        events.emit({
            type: 'auth:credential-found',
            credentialId: 'admin-key',
            machine: 'attacker',
            location: '/tmp/loot',
            timestamp: Date.now(),
        });

        expect(reasons.length).toBe(1);
        expect(reasons[0]).toContain('admin-key');
    });

    it('fires gameover on data exfiltration', () => {
        const ctx = makeContext({
            conditions: [{ type: 'data-exfiltrated', data: 'customer-db' }],
            message: 'Data stolen!',
        }, events);

        detector.init(ctx);

        const reasons: string[] = [];
        events.on('sim:gameover', (e) => reasons.push(e.reason));

        events.emit({
            type: 'net:request',
            url: 'http://evil.local/exfil?data=customer-db',
            method: 'POST',
            source: 'attacker',
            destination: 'evil.local',
            timestamp: Date.now(),
        });

        expect(reasons.length).toBe(1);
        expect(reasons[0]).toContain('customer-db');
    });

    it('does not double-fire gameover', () => {
        const ctx = makeContext({
            conditions: [{ type: 'machine-compromised', machine: 'web' }],
            message: 'Compromised!',
        }, events);

        detector.init(ctx);

        const reasons: string[] = [];
        events.on('sim:gameover', (e) => reasons.push(e.reason));

        events.emit({ type: 'auth:escalate', machine: 'web', from: 'www', to: 'root', method: 'a', timestamp: Date.now() });
        events.emit({ type: 'auth:escalate', machine: 'web', from: 'www', to: 'root', method: 'b', timestamp: Date.now() });

        expect(reasons.length).toBe(1);
    });

    it('does nothing without gameOver spec', () => {
        const ctx = makeContext(undefined, events);
        detector.init(ctx);

        const reasons: string[] = [];
        events.on('sim:gameover', (e) => reasons.push(e.reason));

        events.emit({ type: 'auth:escalate', machine: 'web', from: 'www', to: 'root', method: 'a', timestamp: Date.now() });

        expect(reasons.length).toBe(0);
    });

    it('cleans up on destroy', () => {
        const ctx = makeContext({
            conditions: [{ type: 'machine-compromised', machine: 'web' }],
            message: 'Compromised!',
        }, events);

        detector.init(ctx);
        detector.destroy();

        const reasons: string[] = [];
        events.on('sim:gameover', (e) => reasons.push(e.reason));

        events.emit({ type: 'auth:escalate', machine: 'web', from: 'www', to: 'root', method: 'a', timestamp: Date.now() });

        expect(reasons.length).toBe(0);
    });

    // ── Custom Condition Handler Registry ──────────────────────

    describe('GameOverConditionHandlerRegistry', () => {
        let registry: GameOverConditionHandlerRegistry;

        beforeEach(() => {
            registry = createGameOverConditionHandlerRegistry();
        });

        it('registers and retrieves a handler', () => {
            const handler = () => {};
            registry.register('custom-check', handler);
            expect(registry.get('custom-check')).toBe(handler);
            expect(registry.has('custom-check')).toBe(true);
        });

        it('returns undefined for unknown handler', () => {
            expect(registry.get('nonexistent')).toBeUndefined();
            expect(registry.has('nonexistent')).toBe(false);
        });

        it('lists registered handlers', () => {
            registry.register('a', () => {});
            registry.register('b', () => {});
            expect(registry.list()).toContain('a');
            expect(registry.list()).toContain('b');
        });

        it('rejects duplicate registration', () => {
            registry.register('dup', () => {});
            expect(() => registry.register('dup', () => {})).toThrow('already registered');
        });

        it('rejects empty name', () => {
            expect(() => registry.register('', () => {})).toThrow('non-empty');
        });
    });

    // ── Custom Condition Integration ──────────────────────────

    describe('custom game-over condition', () => {
        it('fires gameover via custom handler', () => {
            const registry = createGameOverConditionHandlerRegistry();
            let triggerFn: ((reason: string) => void) | null = null;

            registry.register('latency-check', (_params, _events, trigger) => {
                triggerFn = trigger;
            });

            const detectorWithRegistry = createGameOverDetector(registry);
            const ctx = makeContext({
                conditions: [{
                    type: 'custom' as const,
                    handler: 'latency-check',
                    params: { maxMs: 500 },
                }],
                message: 'Custom game over!',
            }, events);

            detectorWithRegistry.init(ctx);

            const reasons: string[] = [];
            events.on('sim:gameover', (e) => reasons.push(e.reason));

            // Simulate the custom handler detecting the condition
            expect(triggerFn).not.toBeNull();
            triggerFn!('Latency exceeded 500ms');

            expect(reasons.length).toBe(1);
            expect(reasons[0]).toContain('Latency exceeded');

            detectorWithRegistry.destroy();
        });

        it('ignores custom condition when no registry provided', () => {
            const detectorNoRegistry = createGameOverDetector();
            const ctx = makeContext({
                conditions: [{
                    type: 'custom' as const,
                    handler: 'nonexistent',
                    params: {},
                }],
                message: 'Custom game over!',
            }, events);

            // Should not throw
            detectorNoRegistry.init(ctx);

            const reasons: string[] = [];
            events.on('sim:gameover', (e) => reasons.push(e.reason));
            expect(reasons.length).toBe(0);

            detectorNoRegistry.destroy();
        });

        it('custom handler cleanup runs on destroy', () => {
            const registry = createGameOverConditionHandlerRegistry();
            let cleaned = false;

            registry.register('cleanup-test', () => {
                return () => { cleaned = true; };
            });

            const detectorWithRegistry = createGameOverDetector(registry);
            const ctx = makeContext({
                conditions: [{
                    type: 'custom' as const,
                    handler: 'cleanup-test',
                    params: {},
                }],
                message: 'Test',
            }, events);

            detectorWithRegistry.init(ctx);
            expect(cleaned).toBe(false);
            detectorWithRegistry.destroy();
            expect(cleaned).toBe(true);
        });
    });
});
