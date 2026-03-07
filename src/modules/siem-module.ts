/**
 * VARIANT — SIEM Module
 *
 * Bridges the EventBus into the SIEM engine. Every simulation event
 * is translated into a structured SIEM log entry and ingested.
 * Detection rules and correlation rules fire on each tick, producing
 * defense:alert events that other modules can react to.
 *
 * EXTENSIBILITY:
 *   - Custom detection rules via SIEMModuleConfig.additionalRules
 *   - Custom correlation rules via SIEMModuleConfig.additionalCorrelationRules
 *   - Custom log parsers via SIEMModuleConfig.logTransformers
 *   - Configurable max log size, severity thresholds
 *   - Third-party can register rules at runtime via custom events
 *
 * SWAPPABILITY: Implements Module interface. Replace this file.
 *
 * SECURITY: Read-only event bus access. Cannot mutate simulation state.
 * All rules are declarative — no code execution.
 */

import type { Module, SimulationContext, Capability } from '../core/modules';
import type { Unsubscribe, EngineEvent } from '../core/events';
import {
    createSIEMEngine,
    createBuiltinDetectionRules,
    createBuiltinCorrelationRules,
} from '../lib/siem/siem-engine';
import type {
    SIEMEngine,
    SIEMLogEntry,
    SIEMDetectionRule,
    SIEMCorrelationRule,
    SIEMSeverity,
} from '../lib/siem/siem-engine';

// ── Module ID ──────────────────────────────────────────────

const MODULE_ID = 'siem-module';
const MODULE_VERSION = '1.0.0';

// ── Config ────────────────────────────────────────────────

export interface SIEMModuleConfig {
    /** Maximum log entries to retain. Default: 100000. */
    readonly maxLogSize?: number;
    /** Whether to load built-in detection rules. Default: true. */
    readonly loadBuiltinRules?: boolean;
    /** Whether to load built-in correlation rules. Default: true. */
    readonly loadBuiltinCorrelationRules?: boolean;
    /** Additional detection rules. */
    readonly additionalRules?: readonly SIEMDetectionRule[];
    /** Additional correlation rules. */
    readonly additionalCorrelationRules?: readonly SIEMCorrelationRule[];
    /** Minimum severity to emit defense:alert events. Default: 'warning'. */
    readonly alertThreshold?: SIEMSeverity;
}

// ── Event → Log Entry Translation ──────────────────────────

let nextLogId = 1;

function eventToLogEntry(event: EngineEvent, tick: number): SIEMLogEntry | null {
    const id = `log-${nextLogId++}`;

    switch (event.type) {
        case 'auth:login':
            return {
                id,
                timestamp: event.timestamp,
                tick,
                source: { machine: event.machine, service: 'sshd', logFile: '/var/log/auth.log' },
                severity: event.success ? 'info' : 'warning',
                category: 'auth',
                message: event.success
                    ? `Accepted password for ${event.user} from (${event.service})`
                    : `Failed password for ${event.user} from (${event.service})`,
                raw: `${new Date(event.timestamp).toISOString()} ${event.machine} sshd: ${event.success ? 'Accepted' : 'Failed'} password for ${event.user}`,
                fields: { user: event.user, machine: event.machine, service: event.service, success: event.success },
                tags: event.success ? ['auth', 'login-success'] : ['auth', 'login-failure'],
            };

        case 'auth:escalate':
            return {
                id,
                timestamp: event.timestamp,
                tick,
                source: { machine: event.machine, service: 'sudo', logFile: '/var/log/auth.log' },
                severity: 'warning',
                category: 'auth',
                message: `sudo command: user ${event.from} escalated to ${event.to} via ${event.method}`,
                raw: `${new Date(event.timestamp).toISOString()} ${event.machine} sudo: ${event.from} : TTY=pts/0 ; PWD=/home/${event.from} ; USER=${event.to} ; COMMAND=${event.method}`,
                fields: { from: event.from, to: event.to, method: event.method, machine: event.machine },
                tags: ['auth', 'privilege-escalation'],
            };

        case 'auth:credential-found':
            return {
                id,
                timestamp: event.timestamp,
                tick,
                source: { machine: event.machine, service: 'variant', logFile: '/var/log/variant.log' },
                severity: 'notice',
                category: 'credential',
                message: `Credential found: ${event.credentialId} at ${event.location}`,
                raw: `Credential ${event.credentialId} found at ${event.location} on ${event.machine}`,
                fields: { credentialId: event.credentialId, location: event.location, machine: event.machine },
                tags: ['credential', 'found'],
            };

        case 'net:connect':
            return {
                id,
                timestamp: event.timestamp,
                tick,
                source: { machine: event.source, service: 'netfilter', logFile: '/var/log/kern.log' },
                severity: 'debug',
                category: 'network',
                message: `${event.protocol.toUpperCase()} connection to ${event.host}:${event.port}`,
                raw: `${event.source} -> ${event.host}:${event.port} (${event.protocol})`,
                fields: { host: event.host, port: event.port, protocol: event.protocol, source: event.source },
                tags: ['network', 'connection'],
            };

        case 'net:request':
            return {
                id,
                timestamp: event.timestamp,
                tick,
                source: { machine: event.destination, service: 'http', logFile: '/var/log/nginx/access.log' },
                severity: 'info',
                category: 'network',
                message: `${event.method} ${event.url} from ${event.source}`,
                raw: `${event.source} - - [${new Date(event.timestamp).toISOString()}] "${event.method} ${event.url} HTTP/1.1"`,
                fields: { method: event.method, url: event.url, source: event.source, destination: event.destination },
                tags: ['network', 'http'],
            };

        case 'fs:read':
            return {
                id,
                timestamp: event.timestamp,
                tick,
                source: { machine: event.machine, service: 'audit', logFile: '/var/log/audit/audit.log' },
                severity: 'debug',
                category: 'filesystem',
                message: `File read: ${event.path} by ${event.user}`,
                raw: `type=SYSCALL msg=audit(${event.timestamp}): arch=x86_64 syscall=open path="${event.path}" uid=${event.user}`,
                fields: { path: event.path, user: event.user, machine: event.machine },
                tags: ['filesystem', 'read'],
            };

        case 'fs:write':
            return {
                id,
                timestamp: event.timestamp,
                tick,
                source: { machine: event.machine, service: 'audit', logFile: '/var/log/audit/audit.log' },
                severity: 'info',
                category: 'filesystem',
                message: `File write: ${event.path} by ${event.user}`,
                raw: `type=SYSCALL msg=audit(${event.timestamp}): arch=x86_64 syscall=write path="${event.path}" uid=${event.user}`,
                fields: { path: event.path, user: event.user, machine: event.machine },
                tags: ['filesystem', 'write'],
            };

        case 'fs:exec':
            return {
                id,
                timestamp: event.timestamp,
                tick,
                source: { machine: event.machine, service: 'audit', logFile: '/var/log/audit/audit.log' },
                severity: 'info',
                category: 'execution',
                message: `Execution: ${event.path} ${event.args.join(' ')} by ${event.user}`,
                raw: `type=EXECVE msg=audit(${event.timestamp}): argc=${event.args.length} a0="${event.path}"`,
                fields: { path: event.path, user: event.user, machine: event.machine },
                tags: ['filesystem', 'exec'],
            };

        case 'defense:breach':
            return {
                id,
                timestamp: event.timestamp,
                tick,
                source: { machine: event.machine, service: 'ids', logFile: '/var/log/ids.log' },
                severity: 'critical',
                category: 'defense',
                message: `Breach detected: ${event.vector} by ${event.attacker}`,
                raw: `ALERT: breach on ${event.machine} via ${event.vector} by ${event.attacker}`,
                fields: { vector: event.vector, attacker: event.attacker, machine: event.machine },
                tags: ['defense', 'breach'],
            };

        case 'defense:alert':
            return {
                id,
                timestamp: event.timestamp,
                tick,
                source: { machine: event.machine, service: 'ids', logFile: '/var/log/ids.log' },
                severity: event.severity === 'critical' ? 'critical' : event.severity === 'high' ? 'alert' : event.severity === 'medium' ? 'warning' : 'notice',
                category: 'defense',
                message: `Defense alert [${event.ruleId}]: ${event.detail}`,
                raw: `ALERT: [${event.severity}] ${event.ruleId} on ${event.machine}: ${event.detail}`,
                fields: { ruleId: event.ruleId, severity: event.severity, machine: event.machine },
                tags: ['defense', 'alert', event.severity],
            };

        // Skip sim events, lens events, custom events — not SIEM relevant
        default:
            return null;
    }
}

// ── Factory ────────────────────────────────────────────────

export function createSIEMModule(moduleConfig?: SIEMModuleConfig): Module {
    const cfg = moduleConfig ?? {};
    const unsubscribers: Unsubscribe[] = [];
    let siem: SIEMEngine | null = null;
    let currentTick = 0;

    const module: Module = {
        id: MODULE_ID,
        type: 'defense',
        version: MODULE_VERSION,
        description: 'SIEM engine — aggregates simulation events into structured logs, evaluates detection and correlation rules',

        provides: [
            { name: 'siem' },
            { name: 'log-aggregation' },
            { name: 'detection-rules' },
        ] as readonly Capability[],
        requires: [] as readonly Capability[],

        init(context: SimulationContext): void {
            nextLogId = 1;
            currentTick = context.tick;
            siem = createSIEMEngine(cfg.maxLogSize ?? 100_000);

            // Load built-in rules
            if (cfg.loadBuiltinRules !== false) {
                for (const rule of createBuiltinDetectionRules()) {
                    siem.addRule(rule);
                }
            }
            if (cfg.loadBuiltinCorrelationRules !== false) {
                for (const rule of createBuiltinCorrelationRules()) {
                    siem.addCorrelationRule(rule);
                }
            }

            // Load additional rules
            if (cfg.additionalRules !== undefined) {
                for (const rule of cfg.additionalRules) {
                    siem.addRule(rule);
                }
            }
            if (cfg.additionalCorrelationRules !== undefined) {
                for (const rule of cfg.additionalCorrelationRules) {
                    siem.addCorrelationRule(rule);
                }
            }

            // Subscribe to all non-custom events
            const allUnsub = context.events.onPrefix('*', (event: EngineEvent) => {
                if (siem === null) return;
                // Don't ingest our own custom events
                if (event.type.startsWith('custom:siem-')) return;
                // Don't ingest tick events (too noisy)
                if (event.type === 'sim:tick') return;

                const logEntry = eventToLogEntry(event, currentTick);
                if (logEntry !== null) {
                    siem.ingest(logEntry);
                }
            });
            unsubscribers.push(allUnsub);

            // Handle SIEM query/control via custom events
            const siemUnsub = context.events.onPrefix('custom:', (event) => {
                if (siem === null) return;

                if (event.type === 'custom:siem-query') {
                    const data = event.data as { query?: Record<string, unknown> } | null;
                    const results = siem.query(data?.query as Parameters<SIEMEngine['query']>[0] ?? {});
                    context.events.emit({
                        type: 'custom:siem-query-result',
                        data: { results },
                        timestamp: Date.now(),
                    });
                } else if (event.type === 'custom:siem-stats') {
                    context.events.emit({
                        type: 'custom:siem-stats-result',
                        data: siem.getStats(),
                        timestamp: Date.now(),
                    });
                } else if (event.type === 'custom:siem-add-rule') {
                    const rule = (event.data as { rule: SIEMDetectionRule }).rule;
                    if (rule !== undefined) {
                        siem.addRule(rule);
                    }
                } else if (event.type === 'custom:siem-acknowledge') {
                    const alertId = (event.data as { alertId: string }).alertId;
                    if (alertId !== undefined) {
                        siem.acknowledgeAlert(alertId);
                    }
                } else if (event.type === 'custom:siem-export') {
                    const format = (event.data as { format: 'json' | 'cef' | 'csv' }).format ?? 'json';
                    context.events.emit({
                        type: 'custom:siem-export-result',
                        data: { content: siem.export(format) },
                        timestamp: Date.now(),
                    });
                }
            });
            unsubscribers.push(siemUnsub);
        },

        onTick(tick: number, context: SimulationContext): void {
            currentTick = tick;
            if (siem === null) return;

            const newAlerts = siem.tick(tick);

            // Emit defense:alert events for each new SIEM alert
            for (const alert of newAlerts) {
                const severity = mapSIEMSeverityToAlertSeverity(alert.severity);
                context.events.emit({
                    type: 'defense:alert',
                    machine: alert.evidence[0]?.source.machine ?? 'unknown',
                    ruleId: alert.ruleId,
                    severity,
                    detail: alert.description,
                    timestamp: Date.now(),
                });
            }
        },

        destroy(): void {
            for (const unsub of unsubscribers) {
                unsub();
            }
            unsubscribers.length = 0;
            siem = null;
        },
    };

    return module;
}

function mapSIEMSeverityToAlertSeverity(severity: SIEMSeverity): 'low' | 'medium' | 'high' | 'critical' {
    switch (severity) {
        case 'debug':
        case 'info':
        case 'notice':
            return 'low';
        case 'warning':
            return 'medium';
        case 'error':
        case 'critical':
            return 'high';
        case 'alert':
        case 'emergency':
            return 'critical';
    }
}
