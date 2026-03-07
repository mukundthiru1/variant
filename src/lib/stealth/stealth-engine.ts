/**
 * VARIANT — Stealth Engine
 *
 * Computes noise from player actions. Every event is evaluated
 * against registered noise rules. Noise accumulates, decays
 * over time, and drives the detection probability.
 *
 * CONFIGURABILITY:
 *   - Detection thresholds are fully configurable per-level
 *   - Noise rules are registered via NoiseRuleRegistry (extensible)
 *   - Stealth modifiers can be added/removed at runtime
 *   - Detection curve is selectable (linear, quadratic, logarithmic)
 *   - Decay rate, floor, ceiling — all configurable
 *
 * SWAPPABILITY: Implements Module interface. Replace this file.
 * Nothing else changes. The event bus contract is the only coupling.
 *
 * SECURITY: Read-only event bus access. Cannot mutate simulation state.
 */

import type { Module, SimulationContext, Capability } from '../../core/modules';
import type { Unsubscribe, EngineEvent } from '../../core/events';
import type {
    NoiseRule,
    NoiseCondition,
    NoiseEntry,
    NoiseState,
    StealthModifier,
    DetectionConfig,
    NoiseCategory,
    NoiseRuleRegistry,
} from './types';

// ── Module ID ──────────────────────────────────────────────

const MODULE_ID = 'stealth-engine';
const MODULE_VERSION = '1.0.0';

// ── Default Detection Config ──────────────────────────────

const DEFAULT_DETECTION_CONFIG: DetectionConfig = {
    noiseFloor: 50,
    noiseCeiling: 500,
    curve: 'quadratic',
    decayPerTick: 1.0,
    maxHistory: 1000,
};

// ── Built-in Noise Rules ──────────────────────────────────

function createBuiltinRules(): readonly NoiseRule[] {
    return [
        // ── Reconnaissance ────────────────────────────────
        {
            id: 'recon/port-scan',
            description: 'Port scanning generates significant network noise',
            category: 'reconnaissance',
            eventPattern: 'net:connect',
            scalable: true,
            scaleFactor: 1.5,
            windowMs: 30_000,
            baseNoise: 5,
            cooldownMs: 1000,
        },
        {
            id: 'recon/dns-enum',
            description: 'Rapid DNS queries suggest enumeration',
            category: 'reconnaissance',
            eventPattern: 'net:dns',
            scalable: true,
            scaleFactor: 1.0,
            windowMs: 60_000,
            baseNoise: 2,
        },
        {
            id: 'recon/dir-traversal',
            description: 'Reading many files in rapid succession',
            category: 'reconnaissance',
            eventPattern: 'fs:read',
            scalable: true,
            scaleFactor: 0.5,
            windowMs: 10_000,
            baseNoise: 1,
        },
        {
            id: 'recon/http-enum',
            description: 'HTTP requests to discover endpoints',
            category: 'reconnaissance',
            eventPattern: 'net:request',
            scalable: true,
            scaleFactor: 1.0,
            windowMs: 30_000,
            baseNoise: 3,
        },

        // ── Credential Access ─────────────────────────────
        {
            id: 'cred/brute-force',
            description: 'Failed login attempts generate auth noise',
            category: 'credential-access',
            eventPattern: 'auth:login',
            condition: ((data: Readonly<Record<string, unknown>>) =>
                data['success'] === false) as NoiseCondition,
            scalable: true,
            scaleFactor: 2.0,
            windowMs: 60_000,
            baseNoise: 8,
        },
        {
            id: 'cred/shadow-read',
            description: 'Reading /etc/shadow is suspicious',
            category: 'credential-access',
            eventPattern: 'fs:read',
            condition: ((data: Readonly<Record<string, unknown>>) =>
                typeof data['path'] === 'string' && (
                    data['path'] === '/etc/shadow' ||
                    (data['path'] as string).includes('.ssh/') ||
                    (data['path'] as string).endsWith('.pem') ||
                    (data['path'] as string).endsWith('.key')
                )) as NoiseCondition,
            baseNoise: 15,
            cooldownMs: 5000,
        },
        {
            id: 'cred/credential-found',
            description: 'Finding credentials indicates active intrusion',
            category: 'credential-access',
            eventPattern: 'auth:credential-found',
            baseNoise: 10,
        },

        // ── Exploitation ──────────────────────────────────
        {
            id: 'exploit/web-request',
            description: 'HTTP requests with suspicious patterns',
            category: 'exploitation',
            eventPattern: 'net:request',
            condition: ((data: Readonly<Record<string, unknown>>) => {
                const url = typeof data['url'] === 'string' ? data['url'] : '';
                return /['";<>]|union\s+select|script|\.\.\/|%00/i.test(url);
            }) as NoiseCondition,
            baseNoise: 20,
            cooldownMs: 2000,
        },

        // ── Privilege Escalation ──────────────────────────
        {
            id: 'privesc/escalate',
            description: 'Privilege escalation is always noisy',
            category: 'privilege-escalation',
            eventPattern: 'auth:escalate',
            baseNoise: 25,
        },
        {
            id: 'privesc/suid-read',
            description: 'Reading SUID binaries or sudo config',
            category: 'privilege-escalation',
            eventPattern: 'fs:read',
            condition: ((data: Readonly<Record<string, unknown>>) =>
                typeof data['path'] === 'string' && (
                    data['path'] === '/etc/sudoers' ||
                    (data['path'] as string).includes('/sudoers.d/')
                )) as NoiseCondition,
            baseNoise: 5,
            cooldownMs: 10_000,
        },

        // ── Lateral Movement ──────────────────────────────
        {
            id: 'lateral/ssh-connect',
            description: 'SSH connections to new hosts',
            category: 'lateral-movement',
            eventPattern: 'net:connect',
            condition: ((data: Readonly<Record<string, unknown>>) =>
                data['port'] === 22) as NoiseCondition,
            baseNoise: 15,
            cooldownMs: 5000,
        },

        // ── Exfiltration ──────────────────────────────────
        {
            id: 'exfil/large-transfer',
            description: 'Large data transfers suggest exfiltration',
            category: 'exfiltration',
            eventPattern: 'net:request',
            condition: ((data: Readonly<Record<string, unknown>>) =>
                data['method'] === 'POST' || data['method'] === 'PUT') as NoiseCondition,
            baseNoise: 12,
            scalable: true,
            scaleFactor: 1.5,
            windowMs: 30_000,
        },

        // ── Persistence ───────────────────────────────────
        {
            id: 'persist/cron-write',
            description: 'Writing to cron directories',
            category: 'persistence',
            eventPattern: 'fs:write',
            condition: ((data: Readonly<Record<string, unknown>>) =>
                typeof data['path'] === 'string' && (
                    (data['path'] as string).includes('/cron') ||
                    (data['path'] as string).includes('/init.d/') ||
                    (data['path'] as string).includes('/systemd/')
                )) as NoiseCondition,
            baseNoise: 18,
        },

        // ── Defense Evasion ───────────────────────────────
        {
            id: 'evasion/log-delete',
            description: 'Deleting or modifying logs is highly suspicious',
            category: 'defense-evasion',
            eventPattern: 'fs:write',
            condition: ((data: Readonly<Record<string, unknown>>) =>
                typeof data['path'] === 'string' && (
                    (data['path'] as string).includes('/var/log/') ||
                    (data['path'] as string).endsWith('.log')
                )) as NoiseCondition,
            baseNoise: 30,
        },

        // ── Defense alerts (game generates noise too) ─────
        {
            id: 'defense/alert-triggered',
            description: 'Defense systems detecting activity generates noise feedback',
            category: 'reconnaissance',
            eventPattern: 'defense:alert',
            baseNoise: 5,
        },
    ];
}

// ── Noise Rule Registry Implementation ────────────────────

export function createNoiseRuleRegistry(): NoiseRuleRegistry {
    const rules = new Map<string, NoiseRule>();
    let prefixCache: Map<string, NoiseRule[]> | null = null;

    function invalidateCache(): void {
        prefixCache = null;
    }

    function buildPrefixCache(): Map<string, NoiseRule[]> {
        const cache = new Map<string, NoiseRule[]>();
        for (const rule of rules.values()) {
            const pattern = rule.eventPattern;
            if (pattern.endsWith('*')) {
                const prefix = pattern.slice(0, -1);
                const existing = cache.get(prefix) ?? [];
                existing.push(rule);
                cache.set(prefix, existing);
            } else {
                const existing = cache.get(pattern) ?? [];
                existing.push(rule);
                cache.set(pattern, existing);
            }
        }
        return cache;
    }

    return {
        register(rule: NoiseRule): void {
            if (rules.has(rule.id)) {
                throw new Error(`Noise rule '${rule.id}' already registered`);
            }
            rules.set(rule.id, rule);
            invalidateCache();
        },

        registerAll(newRules: readonly NoiseRule[]): void {
            for (const rule of newRules) {
                if (rules.has(rule.id)) {
                    throw new Error(`Noise rule '${rule.id}' already registered`);
                }
                rules.set(rule.id, rule);
            }
            invalidateCache();
        },

        get(id: string): NoiseRule | undefined {
            return rules.get(id);
        },

        getAll(): readonly NoiseRule[] {
            return [...rules.values()];
        },

        getMatchingRules(eventType: string): readonly NoiseRule[] {
            if (prefixCache === null) {
                prefixCache = buildPrefixCache();
            }

            const result: NoiseRule[] = [];

            // Exact matches
            const exact = prefixCache.get(eventType);
            if (exact !== undefined) {
                result.push(...exact);
            }

            // Prefix matches: for 'net:connect', check 'net:' prefix
            const colonIdx = eventType.indexOf(':');
            if (colonIdx >= 0) {
                const prefix = eventType.slice(0, colonIdx + 1);
                const prefixRules = prefixCache.get(prefix);
                if (prefixRules !== undefined) {
                    result.push(...prefixRules);
                }
            }

            return result;
        },

        getByCategory(category: NoiseCategory): readonly NoiseRule[] {
            return [...rules.values()].filter(r => r.category === category);
        },
    };
}

// ── Stealth Engine Module ─────────────────────────────────

export interface StealthEngineConfig {
    /** Detection thresholds. Merged with defaults. */
    readonly detection?: Partial<DetectionConfig>;

    /** Additional noise rules beyond built-ins. */
    readonly additionalRules?: readonly NoiseRule[];

    /** Rules to exclude by ID (e.g., disable port scan detection). */
    readonly excludeRules?: readonly string[];

    /** Initial stealth modifiers. */
    readonly modifiers?: readonly StealthModifier[];

    /** Override built-in rules entirely. */
    readonly replaceBuiltinRules?: boolean;
}

export function createStealthEngine(engineConfig?: StealthEngineConfig): Module {
    const config = engineConfig ?? {};
    const unsubscribers: Unsubscribe[] = [];
    const registry = createNoiseRuleRegistry();

    // ── State ─────────────────────────────────────────────
    let totalNoise = 0;
    const noiseByCat = new Map<string, number>();
    const noiseByMachine = new Map<string, number>();
    const history: NoiseEntry[] = [];
    const modifiers = new Map<string, StealthModifier>();
    let detected = false;

    // ── Cooldown tracking ─────────────────────────────────
    const lastFired = new Map<string, number>();

    // ── Scalable rule event counting ──────────────────────
    const eventWindows = new Map<string, number[]>();

    // ── Detection config ──────────────────────────────────
    const detectionConfig: DetectionConfig = {
        ...DEFAULT_DETECTION_CONFIG,
        ...config.detection,
    };

    // ── Register rules ────────────────────────────────────

    function registerRules(): void {
        const excludeSet = new Set(config.excludeRules ?? []);

        if (config.replaceBuiltinRules !== true) {
            const builtins = createBuiltinRules();
            for (const rule of builtins) {
                if (!excludeSet.has(rule.id)) {
                    registry.register(rule);
                }
            }
        }

        if (config.additionalRules !== undefined) {
            for (const rule of config.additionalRules) {
                if (!excludeSet.has(rule.id)) {
                    registry.register(rule);
                }
            }
        }
    }

    // ── Noise calculation ─────────────────────────────────

    function computeDetectionProbability(noise: number): number {
        if (noise <= detectionConfig.noiseFloor) return 0;
        if (noise >= detectionConfig.noiseCeiling) return 1;

        const range = detectionConfig.noiseCeiling - detectionConfig.noiseFloor;
        const normalized = (noise - detectionConfig.noiseFloor) / range;

        switch (detectionConfig.curve) {
            case 'linear':
                return normalized;
            case 'quadratic':
                return normalized * normalized;
            case 'logarithmic':
                return Math.log2(1 + normalized) / Math.log2(2);
        }
    }

    function getStealthMultiplier(category: NoiseCategory): number {
        let multiplier = 1.0;
        for (const mod of modifiers.values()) {
            if (!mod.active) continue;
            if (mod.categories.includes('*') || mod.categories.includes(category)) {
                multiplier *= mod.multiplier;
            }
        }
        return Math.max(0, multiplier);
    }

    function getScalableCount(ruleId: string, windowMs: number, now: number): number {
        const window = eventWindows.get(ruleId);
        if (window === undefined) return 1;

        // Prune old entries
        const cutoff = now - windowMs;
        const pruned = window.filter(t => t >= cutoff);
        eventWindows.set(ruleId, pruned);

        return pruned.length;
    }

    function recordScalableEvent(ruleId: string, now: number): void {
        const window = eventWindows.get(ruleId) ?? [];
        window.push(now);
        eventWindows.set(ruleId, window);
    }

    function processEvent(event: EngineEvent, context: SimulationContext): void {
        if (detected) return;

        const now = Date.now();
        const matchingRules = registry.getMatchingRules(event.type);

        for (const rule of matchingRules) {
            // Check cooldown
            if (rule.cooldownMs !== undefined) {
                const lastTime = lastFired.get(rule.id) ?? 0;
                if (now - lastTime < rule.cooldownMs) continue;
            }

            // Check condition
            if (rule.condition !== undefined) {
                if (!rule.condition(event as unknown as Readonly<Record<string, unknown>>)) {
                    continue;
                }
            }

            // Calculate noise
            let noise = rule.baseNoise;

            if (rule.scalable === true) {
                recordScalableEvent(rule.id, now);
                const count = getScalableCount(
                    rule.id,
                    rule.windowMs ?? 60_000,
                    now,
                );
                const factor = rule.scaleFactor ?? 1.0;
                noise = rule.baseNoise * Math.log2(1 + count) * factor;
            }

            // Apply stealth modifiers
            const multiplier = getStealthMultiplier(rule.category);
            const adjustedNoise = noise * multiplier;

            if (adjustedNoise <= 0) continue;

            // Extract machine from event
            const machine = extractMachine(event);

            // Accumulate
            totalNoise += adjustedNoise;
            noiseByCat.set(rule.category, (noiseByCat.get(rule.category) ?? 0) + adjustedNoise);
            if (machine !== '') {
                noiseByMachine.set(machine, (noiseByMachine.get(machine) ?? 0) + adjustedNoise);
            }

            // Record history
            const entry: NoiseEntry = {
                timestamp: now,
                ruleId: rule.id,
                category: rule.category,
                rawNoise: noise,
                adjustedNoise,
                machine,
                eventType: event.type,
            };
            history.push(entry);
            while (history.length > detectionConfig.maxHistory) {
                history.shift();
            }

            // Update cooldown
            lastFired.set(rule.id, now);

            // Emit noise event
            context.events.emit({
                type: 'sim:noise',
                source: rule.id,
                machine,
                amount: adjustedNoise,
                timestamp: now,
            });
        }

        // Check detection
        const prob = computeDetectionProbability(totalNoise);
        if (prob >= 1.0) {
            detected = true;
        }
    }

    function extractMachine(event: EngineEvent): string {
        if ('machine' in event && typeof event.machine === 'string') {
            return event.machine;
        }
        if ('source' in event && typeof event.source === 'string') {
            return event.source;
        }
        if ('destination' in event && typeof event.destination === 'string') {
            return event.destination;
        }
        return '';
    }

    function onTick(): void {
        // Noise decay
        if (totalNoise > 0 && detectionConfig.decayPerTick > 0) {
            totalNoise = Math.max(0, totalNoise - detectionConfig.decayPerTick);
        }
    }

    // ── Public API (exposed via custom events) ────────────

    function getState(): NoiseState {
        return {
            totalNoise,
            byCategory: Object.fromEntries(noiseByCat),
            byMachine: Object.fromEntries(noiseByMachine),
            detectionProbability: computeDetectionProbability(totalNoise),
            detected,
            activeModifiers: [...modifiers.values()].filter(m => m.active),
            history: [...history],
        };
    }

    // ── Module interface ──────────────────────────────────

    const module: Module = {
        id: MODULE_ID,
        type: 'engine',
        version: MODULE_VERSION,
        description: 'Tracks player stealth via noise accumulation and detection probability',

        provides: [{ name: 'stealth' }, { name: 'noise-tracking' }] as readonly Capability[],
        requires: [] as readonly Capability[],

        init(context: SimulationContext): void {
            registerRules();

            // Load initial modifiers
            if (config.modifiers !== undefined) {
                for (const mod of config.modifiers) {
                    modifiers.set(mod.id, mod);
                }
            }

            // Subscribe to all events
            const allUnsub = context.events.onPrefix('*', (event: EngineEvent) => {
                // Don't process our own noise events (infinite loop)
                if (event.type === 'sim:noise') return;
                // Don't process tick events (handled separately)
                if (event.type === 'sim:tick') return;

                processEvent(event, context);
            });
            unsubscribers.push(allUnsub);

            // Subscribe to tick for decay
            const tickUnsub = context.events.on('sim:tick', () => {
                onTick();
            });
            unsubscribers.push(tickUnsub);

            // Handle stealth modifier requests via custom events
            const modUnsub = context.events.onPrefix('custom:', (event) => {
                if (event.type === 'custom:stealth-add-modifier') {
                    const mod = (event.data as { modifier: StealthModifier }).modifier;
                    if (mod !== undefined) {
                        modifiers.set(mod.id, mod);
                    }
                } else if (event.type === 'custom:stealth-remove-modifier') {
                    const id = (event.data as { id: string }).id;
                    if (id !== undefined) {
                        modifiers.delete(id);
                    }
                } else if (event.type === 'custom:stealth-query') {
                    context.events.emit({
                        type: 'custom:stealth-state',
                        data: getState(),
                        timestamp: Date.now(),
                    });
                }
            });
            unsubscribers.push(modUnsub);
        },

        onTick(_tick: number, _context: SimulationContext): void {
            onTick();
        },

        destroy(): void {
            for (const unsub of unsubscribers) {
                unsub();
            }
            unsubscribers.length = 0;
            totalNoise = 0;
            noiseByCat.clear();
            noiseByMachine.clear();
            history.length = 0;
            modifiers.clear();
            detected = false;
            lastFired.clear();
            eventWindows.clear();
        },
    };

    return module;
}

// ── Exported utilities ────────────────────────────────────

/**
 * Get the noise state from a stealth engine module.
 * Requires emitting a custom:stealth-query event and
 * listening for custom:stealth-state response.
 *
 * For direct access in tests, cast the module.
 */
export { createBuiltinRules };
