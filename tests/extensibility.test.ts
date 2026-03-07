/**
 * VARIANT — Service Factory, Protocol Handler & Resource Estimator Tests
 */

import { describe, it, expect } from 'vitest';
import { createServiceHandlerFactory } from '../src/lib/services/factory';
import { createProtocolHandlerRegistry } from '../src/lib/services/protocol-handler';
import { estimateResources, fitsWithinBudget, resourceSummary } from '../src/lib/resource-estimator';
import type { ServiceHandler, ServiceContext } from '../src/lib/services/types';
import type { ServiceHandlerMeta } from '../src/lib/services/factory';
import type { ProtocolHandler } from '../src/lib/services/protocol-handler';
import type { WorldSpec } from '../src/core/world/types';

// ── Helpers ────────────────────────────────────────────────────

function makeMockServiceHandler(name: string, port: number): ServiceHandler {
    return {
        name,
        port,
        protocol: 'tcp' as const,
        handle: () => null,
    };
}

function makeMockProtocolHandler(name: string, port: number): ProtocolHandler {
    return {
        name,
        defaultPort: port,
        handleConnection: () => undefined,
    };
}

function makeMinimalWorldSpec(machines: Record<string, { backend?: string; memoryMB: number; role: string; services?: readonly { name: string; command: string; ports: readonly number[]; autostart: boolean }[] }>): WorldSpec {
    const machineSpecs: Record<string, any> = {};
    for (const [id, m] of Object.entries(machines)) {
        machineSpecs[id] = {
            hostname: id,
            backend: m.backend,
            image: 'test.img',
            memoryMB: m.memoryMB,
            role: m.role,
            interfaces: [{ ip: '10.0.0.1', segment: 'lan' }],
            services: m.services,
        };
    }

    return {
        version: '2.0',
        trust: 'community',
        meta: {
            title: 'Test',
            scenario: 'Test',
            briefing: [],
            difficulty: 'beginner',
            mode: 'attack',
            vulnClasses: [],
            tags: [],
            estimatedMinutes: 5,
            author: { name: 'test', id: 'test', type: 'santh' },
        },
        machines: machineSpecs,
        startMachine: Object.keys(machineSpecs)[0] ?? '',
        network: { segments: [], edges: [] },
        credentials: [],
        objectives: [],
        modules: [],
        scoring: { maxScore: 100, timeBonus: false, stealthBonus: false, hintPenalty: 10, tiers: [] },
        hints: [],
    } as unknown as WorldSpec;
}

// ── ServiceHandlerFactory Tests ────────────────────────────────

describe('ServiceHandlerFactory', () => {
    it('registers and creates a service handler', () => {
        const factory = createServiceHandlerFactory();

        const meta: ServiceHandlerMeta = {
            name: 'http',
            displayName: 'HTTP Server',
            description: 'Web server',
            defaultPort: 80,
            defaultProtocol: 'tcp',
            requiresTcpStack: false,
            compatibleBackends: null,
        };

        factory.register(meta, (_config, _ctx) => makeMockServiceHandler('http', 80));

        expect(factory.has('http')).toBe(true);
        expect(factory.getMeta('http')?.displayName).toBe('HTTP Server');

        const handler = factory.create(
            { name: 'http', command: '', ports: [80], autostart: true },
            {} as ServiceContext,
        );
        expect(handler).not.toBeNull();
        expect(handler?.name).toBe('http');
    });

    it('rejects duplicate registrations', () => {
        const factory = createServiceHandlerFactory();
        const meta: ServiceHandlerMeta = {
            name: 'ssh',
            displayName: 'SSH',
            description: 'SSH server',
            defaultPort: 22,
            defaultProtocol: 'tcp',
            requiresTcpStack: true,
            compatibleBackends: ['simulacrum+'],
        };

        factory.register(meta, () => makeMockServiceHandler('ssh', 22));

        expect(() => {
            factory.register(meta, () => makeMockServiceHandler('ssh', 22));
        }).toThrow(/already registered/);
    });

    it('rejects empty service names', () => {
        const factory = createServiceHandlerFactory();

        expect(() => {
            factory.register({
                name: '',
                displayName: 'Empty',
                description: 'x',
                defaultPort: 0,
                defaultProtocol: 'tcp',
                requiresTcpStack: false,
                compatibleBackends: null,
            }, () => makeMockServiceHandler('', 0));
        }).toThrow(/non-empty/);
    });

    it('returns null for unregistered service types', () => {
        const factory = createServiceHandlerFactory();
        const handler = factory.create(
            { name: 'nonexistent', command: '', ports: [9999], autostart: false },
            {} as ServiceContext,
        );
        expect(handler).toBeNull();
    });

    it('getAllMeta returns all registered metadata', () => {
        const factory = createServiceHandlerFactory();

        factory.register({
            name: 'http',
            displayName: 'HTTP',
            description: 'Web',
            defaultPort: 80,
            defaultProtocol: 'tcp',
            requiresTcpStack: false,
            compatibleBackends: null,
        }, () => makeMockServiceHandler('http', 80));

        factory.register({
            name: 'dns',
            displayName: 'DNS',
            description: 'Name resolution',
            defaultPort: 53,
            defaultProtocol: 'udp',
            requiresTcpStack: false,
            compatibleBackends: null,
        }, () => makeMockServiceHandler('dns', 53));

        const all = factory.getAllMeta();
        expect(all).toHaveLength(2);
        expect(all.map(m => m.name)).toContain('http');
        expect(all.map(m => m.name)).toContain('dns');
    });

    it('getNames returns all registered names', () => {
        const factory = createServiceHandlerFactory();

        factory.register({
            name: 'smtp',
            displayName: 'SMTP',
            description: 'Mail',
            defaultPort: 25,
            defaultProtocol: 'tcp',
            requiresTcpStack: true,
            compatibleBackends: ['simulacrum+'],
        }, () => makeMockServiceHandler('smtp', 25));

        expect(factory.getNames()).toContain('smtp');
    });

    it('supports namespaced third-party service types', () => {
        const factory = createServiceHandlerFactory();

        factory.register({
            name: 'vendor/custom-db',
            displayName: 'Custom DB',
            description: 'Third-party database',
            defaultPort: 5432,
            defaultProtocol: 'tcp',
            requiresTcpStack: true,
            compatibleBackends: null,
        }, () => makeMockServiceHandler('vendor/custom-db', 5432));

        expect(factory.has('vendor/custom-db')).toBe(true);
    });
});

// ── ProtocolHandlerRegistry Tests ──────────────────────────────

describe('ProtocolHandlerRegistry', () => {
    it('registers and retrieves a protocol handler', () => {
        const registry = createProtocolHandlerRegistry();
        const handler = makeMockProtocolHandler('ssh', 22);
        registry.register(handler);

        expect(registry.hasHandler(22)).toBe(true);
        expect(registry.getHandler(22)?.name).toBe('ssh');
    });

    it('registers on custom port', () => {
        const registry = createProtocolHandlerRegistry();
        const handler = makeMockProtocolHandler('ssh', 22);
        registry.register(handler, 2222);

        expect(registry.hasHandler(2222)).toBe(true);
        expect(registry.hasHandler(22)).toBe(false);
    });

    it('rejects duplicate port registrations', () => {
        const registry = createProtocolHandlerRegistry();
        registry.register(makeMockProtocolHandler('ssh', 22));

        expect(() => {
            registry.register(makeMockProtocolHandler('ftp', 22), 22);
        }).toThrow(/port 22 is already registered/);
    });

    it('returns null for unregistered ports', () => {
        const registry = createProtocolHandlerRegistry();
        expect(registry.getHandler(9999)).toBeNull();
    });

    it('getAll returns all handlers', () => {
        const registry = createProtocolHandlerRegistry();
        registry.register(makeMockProtocolHandler('ssh', 22));
        registry.register(makeMockProtocolHandler('mysql', 3306));

        const all = registry.getAll();
        expect(all).toHaveLength(2);
    });

    it('getPortMap returns the full port mapping', () => {
        const registry = createProtocolHandlerRegistry();
        registry.register(makeMockProtocolHandler('ssh', 22));
        registry.register(makeMockProtocolHandler('smtp', 25));

        const portMap = registry.getPortMap();
        expect(portMap.size).toBe(2);
        expect(portMap.get(22)?.name).toBe('ssh');
        expect(portMap.get(25)?.name).toBe('smtp');
    });
});

// ── Resource Estimator Tests ───────────────────────────────────

describe('Resource Estimator', () => {
    it('estimates a single Simulacrum machine at ~18MB total', () => {
        const world = makeMinimalWorldSpec({
            target: { backend: 'simulacrum', memoryMB: 32, role: 'target' },
        });

        const est = estimateResources(world);
        // ENGINE_OVERHEAD (15) + Simulacrum overhead (3) = ~18
        expect(est.estimatedRAMMB).toBe(18);
        expect(est.minimumTier).toBe('chromebook');
    });

    it('estimates a single v86 player at ~155MB total', () => {
        const world = makeMinimalWorldSpec({
            player: { backend: 'v86', memoryMB: 128, role: 'player' },
        });

        const est = estimateResources(world);
        // ENGINE (15) + v86_fixed (12) + memoryMB (128) + overhead (0) = 155
        expect(est.estimatedRAMMB).toBe(155);
        expect(est.minimumTier).toBe('chromebook');
    });

    it('estimates a beginner level (player v86 + 2 simulacra) as chromebook-tier', () => {
        const world = makeMinimalWorldSpec({
            player: { backend: 'v86', memoryMB: 64, role: 'player' },
            target1: { backend: 'simulacrum', memoryMB: 32, role: 'target' },
            target2: { backend: 'simulacrum', memoryMB: 32, role: 'target' },
        });

        const est = estimateResources(world);
        // ENGINE (15) + v86 (64+12) + sim (3) + sim (3) = 97
        expect(est.estimatedRAMMB).toBe(97);
        expect(est.minimumTier).toBe('chromebook');
    });

    it('estimates a heavy level as laptop-tier', () => {
        const world = makeMinimalWorldSpec({
            player: { backend: 'v86', memoryMB: 128, role: 'player' },
            server1: { backend: 'v86', memoryMB: 128, role: 'target' },
            server2: { backend: 'simulacrum+', memoryMB: 32, role: 'target' },
            server3: { backend: 'simulacrum+', memoryMB: 32, role: 'target' },
            server4: { backend: 'simulacrum+', memoryMB: 32, role: 'target' },
            server5: { backend: 'simulacrum+', memoryMB: 32, role: 'target' },
        });

        const est = estimateResources(world);
        // ENGINE (15) + v86 (128+12) + v86 (128+12) + 4*sim+ (4*8) = 327
        expect(est.estimatedRAMMB).toBe(327);
        expect(est.minimumTier).toBe('laptop');
    });

    it('infers v86 for player machines when backend not specified', () => {
        const world = makeMinimalWorldSpec({
            player: { memoryMB: 64, role: 'player' },
        });

        const est = estimateResources(world);
        // ENGINE (15) + v86 fixed (12) + 64 = 91
        expect(est.estimatedRAMMB).toBe(91);
    });

    it('infers simulacrum for target machines when backend not specified', () => {
        const world = makeMinimalWorldSpec({
            target: { memoryMB: 32, role: 'target' },
        });

        const est = estimateResources(world);
        // ENGINE (15) + simulacrum (3) = 18
        expect(est.estimatedRAMMB).toBe(18);
    });

    it('accounts for service overhead', () => {
        const world = makeMinimalWorldSpec({
            target: {
                backend: 'simulacrum',
                memoryMB: 32,
                role: 'target',
                services: [
                    { name: 'http', command: '', ports: [80], autostart: true },
                    { name: 'ssh', command: '', ports: [22], autostart: true },
                    { name: 'mysql', command: '', ports: [3306], autostart: true },
                ],
            },
        });

        const est = estimateResources(world);
        // ENGINE (15) + sim (3) + 3 services * 0.5 = 19.5 → 20
        expect(est.estimatedRAMMB).toBe(20);
    });

    it('fitsWithinBudget returns correct boolean', () => {
        const world = makeMinimalWorldSpec({
            player: { backend: 'v86', memoryMB: 64, role: 'player' },
        });

        expect(fitsWithinBudget(world, 200)).toBe(true);
        expect(fitsWithinBudget(world, 50)).toBe(false);
    });

    it('resourceSummary returns human-readable output', () => {
        const est = { estimatedRAMMB: 150, estimatedBootSeconds: 3.5, minimumTier: 'chromebook' as const };
        const summary = resourceSummary(est);

        expect(summary).toContain('150 MB');
        expect(summary).toContain('3.5s');
        expect(summary).toContain('chromebook');
    });
});
