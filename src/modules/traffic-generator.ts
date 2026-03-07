/**
 * VARIANT — Traffic Generator Module
 *
 * Generates realistic background network traffic to make
 * the simulation feel alive. Without background noise, the
 * player's actions stand out like a flashlight in a dark room.
 *
 * Traffic patterns:
 *   - Web browsing: periodic HTTP requests to random URLs
 *   - DNS queries: name resolution for common domains
 *   - Internal comms: service-to-service API calls
 *   - Mail traffic: SMTP connections between mail servers
 *   - Heartbeat: periodic health check connections
 *   - Custom: extensible pattern definitions
 *
 * EXTENSIBILITY:
 *   - Custom traffic patterns via TrafficPattern definitions
 *   - Configurable intensity, machines, timing
 *   - Random jitter to avoid predictable patterns
 *
 * SWAPPABILITY: Implements Module interface. Replace this file.
 */

import type { Module, SimulationContext, Capability } from '../core/modules';
import type { EventBus } from '../core/events';

// ── Module ID ──────────────────────────────────────────────

const MODULE_ID = 'traffic-generator';
const MODULE_VERSION = '1.0.0';

// ── Types ──────────────────────────────────────────────────

export type TrafficPatternType =
    | 'web-browse'
    | 'dns-query'
    | 'internal-api'
    | 'mail'
    | 'heartbeat'
    | 'ssh-session'
    | (string & {}); // open union

export interface TrafficPattern {
    /** Pattern identifier. */
    readonly id: string;
    /** Pattern type. */
    readonly type: TrafficPatternType;
    /** Source machine ID. */
    readonly sourceMachine: string;
    /** Destination machine ID or external host. */
    readonly destination: string;
    /** Fire every N ticks. */
    readonly intervalTicks: number;
    /** Random jitter in ticks (±). Default: 0. */
    readonly jitterTicks?: number;
    /** Start tick. Default: 0. */
    readonly startTick?: number;
    /** Stop tick. Default: never. */
    readonly stopTick?: number;
    /** Protocol. Default: 'tcp'. */
    readonly protocol?: 'tcp' | 'udp';
    /** Destination port. */
    readonly port?: number;
    /** Custom data for the pattern. */
    readonly data?: Readonly<Record<string, unknown>>;
}

export interface TrafficGeneratorConfig {
    /** Traffic patterns to generate. */
    readonly patterns?: readonly TrafficPattern[];
    /** Whether to auto-generate common patterns. Default: true. */
    readonly autoGenerate?: boolean;
    /** Intensity multiplier (1.0 = normal, 0.5 = half, 2.0 = double). Default: 1.0. */
    readonly intensity?: number;
}

// ── Common Domains for DNS ──────────────────────────────────

const COMMON_DOMAINS = [
    'google.com', 'github.com', 'stackoverflow.com', 'npmjs.com',
    'slack.com', 'office.com', 'microsoft.com', 'aws.amazon.com',
    'cloudflare.com', 'ubuntu.com', 'docker.com', 'elastic.co',
];

const WEB_PATHS = [
    '/', '/api/status', '/health', '/metrics', '/login', '/dashboard',
    '/api/v1/users', '/api/v1/data', '/static/app.js', '/favicon.ico',
];

// ── Factory ────────────────────────────────────────────────

export function createTrafficGenerator(generatorConfig?: TrafficGeneratorConfig): Module {
    const cfg = generatorConfig ?? {};
    const intensity = cfg.intensity ?? 1.0;

    // Track next fire tick per pattern
    const nextFire = new Map<string, number>();
    // Seeded PRNG for deterministic jitter
    let seed = 42;

    function pseudoRandom(): number {
        seed = (seed * 1103515245 + 12345) & 0x7fffffff;
        return seed / 0x7fffffff;
    }

    function pickRandom<T>(arr: readonly T[]): T {
        return arr[Math.floor(pseudoRandom() * arr.length)]!;
    }

    function generatePatternEvents(pattern: TrafficPattern, events: EventBus): void {
        switch (pattern.type) {
            case 'web-browse':
                events.emit({
                    type: 'net:request',
                    method: 'GET',
                    url: `http://${pattern.destination}${pickRandom(WEB_PATHS)}`,
                    source: pattern.sourceMachine,
                    destination: pattern.destination,
                    timestamp: Date.now(),
                });
                break;

            case 'dns-query':
                events.emit({
                    type: 'net:dns',
                    query: pickRandom(COMMON_DOMAINS),
                    result: `${Math.floor(pseudoRandom() * 256)}.${Math.floor(pseudoRandom() * 256)}.${Math.floor(pseudoRandom() * 256)}.${Math.floor(pseudoRandom() * 256)}`,
                    source: pattern.sourceMachine,
                    timestamp: Date.now(),
                });
                break;

            case 'internal-api':
                events.emit({
                    type: 'net:request',
                    method: pseudoRandom() > 0.7 ? 'POST' : 'GET',
                    url: `http://${pattern.destination}/api/v1/${pseudoRandom() > 0.5 ? 'health' : 'data'}`,
                    source: pattern.sourceMachine,
                    destination: pattern.destination,
                    timestamp: Date.now(),
                });
                break;

            case 'mail':
                events.emit({
                    type: 'net:connect',
                    host: pattern.destination,
                    port: pattern.port ?? 25,
                    source: pattern.sourceMachine,
                    protocol: 'tcp',
                    timestamp: Date.now(),
                });
                break;

            case 'heartbeat':
                events.emit({
                    type: 'net:connect',
                    host: pattern.destination,
                    port: pattern.port ?? 443,
                    source: pattern.sourceMachine,
                    protocol: 'tcp',
                    timestamp: Date.now(),
                });
                break;

            case 'ssh-session':
                events.emit({
                    type: 'net:connect',
                    host: pattern.destination,
                    port: 22,
                    source: pattern.sourceMachine,
                    protocol: 'tcp',
                    timestamp: Date.now(),
                });
                break;

            default:
                // Custom pattern — emit as custom event
                events.emit({
                    type: `custom:traffic-${pattern.type}`,
                    data: {
                        patternId: pattern.id,
                        source: pattern.sourceMachine,
                        destination: pattern.destination,
                        ...(pattern.data ?? {}),
                    },
                    timestamp: Date.now(),
                });
                break;
        }
    }

    function autoGeneratePatterns(context: SimulationContext): readonly TrafficPattern[] {
        const patterns: TrafficPattern[] = [];
        const machineIds = [...context.vms.keys()];

        if (machineIds.length === 0) return patterns;

        // Each machine does some DNS queries
        for (const machineId of machineIds) {
            patterns.push({
                id: `auto-dns-${machineId}`,
                type: 'dns-query',
                sourceMachine: machineId,
                destination: 'dns-server',
                intervalTicks: Math.round(15 / intensity),
                jitterTicks: 3,
            });
        }

        // Inter-machine heartbeats
        for (let i = 0; i < machineIds.length; i++) {
            for (let j = i + 1; j < machineIds.length; j++) {
                const src = machineIds[i]!;
                const dst = machineIds[j]!;
                patterns.push({
                    id: `auto-heartbeat-${src}-${dst}`,
                    type: 'heartbeat',
                    sourceMachine: src,
                    destination: dst,
                    intervalTicks: Math.round(30 / intensity),
                    jitterTicks: 5,
                    port: 8080,
                });
            }
        }

        // Web browsing from first machine (workstation)
        const workstation = machineIds[0]!;
        patterns.push({
            id: `auto-web-${workstation}`,
            type: 'web-browse',
            sourceMachine: workstation,
            destination: pickRandom(COMMON_DOMAINS),
            intervalTicks: Math.round(10 / intensity),
            jitterTicks: 4,
        });

        return patterns;
    }

    const module: Module = {
        id: MODULE_ID,
        type: 'actor',
        version: MODULE_VERSION,
        description: 'Generates realistic background network traffic patterns for simulation realism',

        provides: [
            { name: 'traffic-generation' },
            { name: 'background-noise' },
        ] as readonly Capability[],
        requires: [] as readonly Capability[],

        init(context: SimulationContext): void {
            nextFire.clear();
            seed = 42;

            // Collect all patterns
            let allPatterns: TrafficPattern[] = [...(cfg.patterns ?? [])];

            if (cfg.autoGenerate !== false) {
                allPatterns = [...allPatterns, ...autoGeneratePatterns(context)];
            }

            // Initialize next fire ticks
            for (const pattern of allPatterns) {
                nextFire.set(pattern.id, pattern.startTick ?? 0);
            }

            // Store patterns on the module for onTick access
            (module as unknown as { _patterns: TrafficPattern[] })._patterns = allPatterns;
        },

        onTick(tick: number, context: SimulationContext): void {
            const patterns = (module as unknown as { _patterns: TrafficPattern[] | null })._patterns;
            if (patterns === null) return;

            for (const pattern of patterns) {
                const stopTick = pattern.stopTick ?? Infinity;
                if (tick > stopTick) continue;

                const next = nextFire.get(pattern.id);
                if (next === undefined || tick < next) continue;

                generatePatternEvents(pattern, context.events);

                // Schedule next fire with jitter
                const jitter = pattern.jitterTicks ?? 0;
                const jitterAmount = jitter > 0 ? Math.round((pseudoRandom() - 0.5) * 2 * jitter) : 0;
                const nextTick = tick + pattern.intervalTicks + jitterAmount;
                nextFire.set(pattern.id, Math.max(tick + 1, nextTick));
            }
        },

        destroy(): void {
            nextFire.clear();
            (module as unknown as { _patterns: TrafficPattern[] | null })._patterns = null;
        },
    };

    return module;
}
