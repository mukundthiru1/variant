/**
 * VARIANT — Correlation Module
 *
 * Bridges the EventBus into the correlation engine. Translates
 * simulation events into CorrelationEvents and evaluates registered
 * correlation rules on each event. Fires defense:alert events
 * when patterns are matched.
 *
 * EXTENSIBILITY:
 *   - Rules added via config or at runtime via custom events
 *   - Custom action handlers registered via config
 *   - All correlation strategies available (sequence, threshold, unique)
 *
 * SWAPPABILITY: Implements Module interface. Replace this file.
 *
 * SECURITY: Read-only event bus access. Cannot mutate simulation state.
 */

import type { Module, SimulationContext, Capability } from '../core/modules';
import type { Unsubscribe, EngineEvent } from '../core/events';
import { createCorrelationEngine } from '../lib/correlation/correlation-engine';
import type {
    CorrelationEngine,
    CorrelationRule,
    CorrelationEvent,
    CorrelationMatch,
} from '../lib/correlation/types';

// ── Module ID ──────────────────────────────────────────────

const MODULE_ID = 'correlation-module';
const MODULE_VERSION = '1.0.0';

// ── Config ────────────────────────────────────────────────

export interface CorrelationModuleConfig {
    /** Initial correlation rules. */
    readonly rules?: readonly CorrelationRule[];
    /** Whether to load built-in attack chain rules. Default: true. */
    readonly loadBuiltinRules?: boolean;
}

// ── Built-in Correlation Rules ────────────────────────────

function createBuiltinCorrelationRules(): readonly CorrelationRule[] {
    return [
        {
            id: 'attack-chain/recon-exploit-escalate',
            name: 'Full Attack Chain',
            strategy: {
                type: 'sequence',
                steps: [
                    { eventType: 'net:connect' },
                    { eventType: 'auth:login', conditions: [{ field: 'success', operator: '==', value: true }] },
                    { eventType: 'auth:escalate' },
                ],
            },
            windowMs: 300_000,
            actions: [{ type: 'alert', params: { message: 'Full attack chain detected: recon → login → escalate' } }],
            severity: 'critical',
            tags: ['attack-chain'],
        },
        {
            id: 'brute-force/ssh',
            name: 'SSH Brute Force',
            strategy: {
                type: 'threshold',
                eventType: 'auth:login',
                threshold: 5,
                conditions: [{ field: 'success', operator: '==', value: false }],
                groupBy: 'machine',
            },
            windowMs: 60_000,
            actions: [{ type: 'alert', params: { message: 'SSH brute force detected' } }],
            severity: 'high',
            cooldownMs: 120_000,
            tags: ['brute-force'],
        },
        {
            id: 'port-scan/rapid',
            name: 'Rapid Port Scan',
            strategy: {
                type: 'unique',
                eventType: 'net:connect',
                uniqueField: 'port',
                threshold: 10,
            },
            windowMs: 30_000,
            actions: [{ type: 'alert', params: { message: 'Rapid port scan detected' } }],
            severity: 'medium',
            cooldownMs: 60_000,
            tags: ['reconnaissance'],
        },
        {
            id: 'lateral-movement/credential-reuse',
            name: 'Credential Reuse Across Machines',
            strategy: {
                type: 'sequence',
                steps: [
                    { eventType: 'auth:credential-found' },
                    { eventType: 'auth:login', conditions: [{ field: 'success', operator: '==', value: true }] },
                ],
            },
            windowMs: 120_000,
            actions: [{ type: 'alert', params: { message: 'Credential found and reused for login' } }],
            severity: 'high',
            tags: ['lateral-movement'],
        },
    ];
}

// ── Event Translation ──────────────────────────────────────

function engineEventToCorrelationEvent(event: EngineEvent): CorrelationEvent | null {
    switch (event.type) {
        case 'auth:login':
            return {
                type: event.type,
                timestamp: event.timestamp,
                fields: { user: event.user, machine: event.machine, service: event.service, success: event.success },
            };
        case 'auth:escalate':
            return {
                type: event.type,
                timestamp: event.timestamp,
                fields: { machine: event.machine, from: event.from, to: event.to, method: event.method },
            };
        case 'auth:credential-found':
            return {
                type: event.type,
                timestamp: event.timestamp,
                fields: { credentialId: event.credentialId, machine: event.machine, location: event.location },
            };
        case 'net:connect':
            return {
                type: event.type,
                timestamp: event.timestamp,
                fields: { host: event.host, port: event.port, source: event.source, protocol: event.protocol },
            };
        case 'net:request':
            return {
                type: event.type,
                timestamp: event.timestamp,
                fields: { method: event.method, url: event.url, source: event.source, destination: event.destination },
            };
        case 'net:dns':
            return {
                type: event.type,
                timestamp: event.timestamp,
                fields: { query: event.query, result: event.result, source: event.source },
            };
        case 'fs:read':
        case 'fs:write':
            return {
                type: event.type,
                timestamp: event.timestamp,
                fields: { path: event.path, user: event.user, machine: event.machine },
            };
        case 'fs:exec':
            return {
                type: event.type,
                timestamp: event.timestamp,
                fields: { path: event.path, user: event.user, machine: event.machine, args: event.args.join(' ') },
            };
        case 'defense:breach':
            return {
                type: event.type,
                timestamp: event.timestamp,
                fields: { machine: event.machine, vector: event.vector, attacker: event.attacker },
            };
        case 'defense:alert':
            return {
                type: event.type,
                timestamp: event.timestamp,
                fields: { machine: event.machine, ruleId: event.ruleId, severity: event.severity },
            };
        default:
            return null;
    }
}

// ── Factory ────────────────────────────────────────────────

export function createCorrelationModule(moduleConfig?: CorrelationModuleConfig): Module {
    const cfg = moduleConfig ?? {};
    const unsubscribers: Unsubscribe[] = [];
    let engine: CorrelationEngine | null = null;

    const module: Module = {
        id: MODULE_ID,
        type: 'defense',
        version: MODULE_VERSION,
        description: 'Correlation engine — detects multi-event attack patterns via sequence, threshold, and unique strategies',

        provides: [
            { name: 'correlation' },
            { name: 'attack-chain-detection' },
        ] as readonly Capability[],
        requires: [] as readonly Capability[],

        init(context: SimulationContext): void {
            engine = createCorrelationEngine();

            // Register built-in alert action handler
            engine.registerActionHandler('alert', (params, match) => {
                const message = typeof params['message'] === 'string' ? params['message'] : `Correlation match: ${match.ruleId}`;
                context.events.emit({
                    type: 'defense:alert',
                    machine: extractMachineFromMatch(match),
                    ruleId: match.ruleId,
                    severity: mapSeverity(match.severity),
                    detail: message,
                    timestamp: Date.now(),
                });
            });

            // Load built-in rules
            if (cfg.loadBuiltinRules !== false) {
                for (const rule of createBuiltinCorrelationRules()) {
                    engine.addRule(rule);
                }
            }

            // Load custom rules
            if (cfg.rules !== undefined) {
                for (const rule of cfg.rules) {
                    engine.addRule(rule);
                }
            }

            // Subscribe to all relevant events
            const allUnsub = context.events.onPrefix('', (event: EngineEvent) => {
                if (engine === null) return;
                // Don't process tick, noise, or custom events
                if (event.type === 'sim:tick' || event.type === 'sim:noise') return;
                if (event.type.startsWith('custom:')) return;

                const correlationEvent = engineEventToCorrelationEvent(event);
                if (correlationEvent !== null) {
                    engine.processEvent(correlationEvent);
                }
            });
            unsubscribers.push(allUnsub);

            // Handle runtime rule management via custom events
            const customUnsub = context.events.onPrefix('custom:', (event) => {
                if (engine === null) return;

                if (event.type === 'custom:correlation-add-rule') {
                    const rule = (event.data as { rule: CorrelationRule }).rule;
                    if (rule !== undefined) {
                        engine.addRule(rule);
                    }
                } else if (event.type === 'custom:correlation-remove-rule') {
                    const id = (event.data as { id: string }).id;
                    if (id !== undefined) {
                        engine.removeRule(id);
                    }
                } else if (event.type === 'custom:correlation-query') {
                    context.events.emit({
                        type: 'custom:correlation-query-result',
                        data: {
                            rules: engine.getRules(),
                            recentMatches: engine.getRecentMatches(),
                        },
                        timestamp: Date.now(),
                    });
                }
            });
            unsubscribers.push(customUnsub);
        },

        destroy(): void {
            for (const unsub of unsubscribers) {
                unsub();
            }
            unsubscribers.length = 0;
            engine = null;
        },
    };

    return module;
}

function extractMachineFromMatch(match: CorrelationMatch): string {
    for (const event of match.matchedEvents) {
        const machine = event.fields['machine'];
        if (typeof machine === 'string') return machine;
    }
    return 'unknown';
}

function mapSeverity(severity: string): 'low' | 'medium' | 'high' | 'critical' {
    switch (severity) {
        case 'info':
        case 'low':
            return 'low';
        case 'medium':
            return 'medium';
        case 'high':
            return 'high';
        case 'critical':
            return 'critical';
        default:
            return 'medium';
    }
}
