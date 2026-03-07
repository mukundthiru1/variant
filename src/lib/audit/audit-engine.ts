/**
 * VARIANT — Audit Log Engine
 *
 * Simulates enterprise audit logging with:
 * - Hash-chained log integrity
 * - Tamper detection
 * - Brute-force / impossible-travel anomaly detection
 * - Basic compliance report generation
 *
 * All operations are synchronous and pure-data.
 */

import type {
    AuditEngine,
    AuditEvent,
    AuditQuery,
    AuditAnomaly,
    LogIntegrityCheck,
    ComplianceReport,
    ComplianceControl,
} from './types';

// ── Helpers ───────────────────────────────────────────────

let eventCounter = 0;

function generateEventId(): string {
    return `audit-${++eventCounter}`;
}

function simpleHash(input: string): string {
    let hash = 0;
    for (let i = 0; i < input.length; i++) {
        const c = input.charCodeAt(i);
        hash = ((hash << 5) - hash + c) | 0;
    }
    return `h${Math.abs(hash).toString(16).padStart(8, '0')}`;
}

// ── Factory ──────────────────────────────────────────────

export function createAuditEngine(): AuditEngine {
    const events: AuditEvent[] = [];
    const deletedIds = new Set<string>();
    const tamperedIds = new Set<string>();
    let prevHash = '0';

    const engine: AuditEngine = {
        log(input) {
            const id = generateEventId();
            const timestamp = Date.now();
            const chainData = `${prevHash}|${id}|${input.tick}|${input.actor}|${input.action}|${input.target}`;
            const hash = simpleHash(chainData);
            prevHash = hash;

            const event: AuditEvent = Object.freeze({
                ...input,
                id,
                timestamp,
                hash,
            });
            events.push(event);
            return event;
        },

        getEvent(id) {
            return events.find(e => e.id === id) ?? null;
        },

        query(filter: AuditQuery) {
            let result = events.filter(e => !deletedIds.has(e.id));

            if (filter.actor) result = result.filter(e => e.actor === filter.actor);
            if (filter.action) result = result.filter(e => e.action === filter.action);
            if (filter.target) result = result.filter(e => e.target === filter.target);
            if (filter.result) result = result.filter(e => e.result === filter.result);
            if (filter.severity) result = result.filter(e => e.severity === filter.severity);
            if (filter.sourceIP) result = result.filter(e => e.sourceIP === filter.sourceIP);
            if (filter.fromTick !== undefined) result = result.filter(e => e.tick >= filter.fromTick!);
            if (filter.toTick !== undefined) result = result.filter(e => e.tick <= filter.toTick!);

            return Object.freeze(result);
        },

        getActorEvents(actor) {
            return Object.freeze(events.filter(e => e.actor === actor && !deletedIds.has(e.id)));
        },

        getActionEvents(action) {
            return Object.freeze(events.filter(e => e.action === action && !deletedIds.has(e.id)));
        },

        checkIntegrity(): LogIntegrityCheck {
            const tamperedList: string[] = [];
            const gaps: Array<{ afterId: string; beforeId: string; missingCount: number }> = [];
            let missing = 0;

            // Check for tampered events
            for (const id of tamperedIds) {
                tamperedList.push(id);
            }

            // Check for gaps (deleted events)
            const remaining = events.filter(e => !deletedIds.has(e.id));
            for (let i = 1; i < remaining.length; i++) {
                const prevNum = parseInt(remaining[i - 1]!.id.replace('audit-', ''));
                const currNum = parseInt(remaining[i]!.id.replace('audit-', ''));
                if (currNum - prevNum > 1) {
                    const gapSize = currNum - prevNum - 1;
                    missing += gapSize;
                    gaps.push({
                        afterId: remaining[i - 1]!.id,
                        beforeId: remaining[i]!.id,
                        missingCount: gapSize,
                    });
                }
            }

            return Object.freeze({
                valid: tamperedList.length === 0 && missing === 0,
                totalEvents: remaining.length,
                missingEvents: missing,
                tamperedEvents: Object.freeze(tamperedList),
                gaps: Object.freeze(gaps),
            });
        },

        tamperEvent(id) {
            const event = events.find(e => e.id === id);
            if (!event) return false;
            tamperedIds.add(id);
            // Replace with a tampered version (modified hash)
            const idx = events.indexOf(event);
            events[idx] = { ...event, hash: 'TAMPERED' };
            return true;
        },

        deleteEvent(id) {
            const exists = events.some(e => e.id === id);
            if (!exists) return false;
            deletedIds.add(id);
            return true;
        },

        clearLogs() {
            const count = events.length;
            for (const e of events) deletedIds.add(e.id);
            return count;
        },

        detectAnomalies(): readonly AuditAnomaly[] {
            const anomalies: AuditAnomaly[] = [];
            const active = events.filter(e => !deletedIds.has(e.id));

            // Brute force: >5 failed logins from same actor
            const failedByActor = new Map<string, string[]>();
            for (const e of active) {
                if (e.action === 'login_failed') {
                    const list = failedByActor.get(e.actor) ?? [];
                    list.push(e.id);
                    failedByActor.set(e.actor, list);
                }
            }
            for (const [actor, ids] of failedByActor) {
                if (ids.length >= 5) {
                    anomalies.push({
                        type: 'brute_force',
                        severity: 'high',
                        description: `${ids.length} failed login attempts by ${actor}`,
                        events: Object.freeze(ids),
                        mitre: 'T1110',
                    });
                }
            }

            // Impossible travel: same actor from different IPs within short time
            const actorIPs = new Map<string, Array<{ ip: string; tick: number; id: string }>>();
            for (const e of active) {
                if (e.sourceIP && (e.action === 'login' || e.action === 'access_granted')) {
                    const list = actorIPs.get(e.actor) ?? [];
                    list.push({ ip: e.sourceIP, tick: e.tick, id: e.id });
                    actorIPs.set(e.actor, list);
                }
            }
            for (const [actor, entries] of actorIPs) {
                for (let i = 1; i < entries.length; i++) {
                    const prev = entries[i - 1]!;
                    const curr = entries[i]!;
                    if (prev.ip !== curr.ip && Math.abs(curr.tick - prev.tick) <= 2) {
                        anomalies.push({
                            type: 'impossible_travel',
                            severity: 'high',
                            description: `${actor} accessed from ${prev.ip} and ${curr.ip} within ${Math.abs(curr.tick - prev.tick)} ticks`,
                            events: Object.freeze([prev.id, curr.id]),
                            mitre: 'T1078',
                        });
                    }
                }
            }

            // Log tampering detection
            if (tamperedIds.size > 0) {
                anomalies.push({
                    type: 'log_tampering',
                    severity: 'critical',
                    description: `${tamperedIds.size} log entries have been tampered with`,
                    events: Object.freeze(Array.from(tamperedIds)),
                    mitre: 'T1070.001',
                });
            }

            // Mass deletion
            if (deletedIds.size > 5) {
                anomalies.push({
                    type: 'mass_deletion',
                    severity: 'critical',
                    description: `${deletedIds.size} log entries have been deleted`,
                    events: Object.freeze(Array.from(deletedIds)),
                    mitre: 'T1070.001',
                });
            }

            // Privilege escalation events
            const privEsc = active.filter(e => e.action === 'privilege_escalation');
            if (privEsc.length > 0) {
                anomalies.push({
                    type: 'privilege_abuse',
                    severity: 'high',
                    description: `${privEsc.length} privilege escalation events detected`,
                    events: Object.freeze(privEsc.map(e => e.id)),
                    mitre: 'T1548',
                });
            }

            return Object.freeze(anomalies);
        },

        generateComplianceReport(framework: string): ComplianceReport {
            const active = events.filter(e => !deletedIds.has(e.id));
            const controls: ComplianceControl[] = [];

            // Authentication logging
            const hasAuthLogs = active.some(e => e.action === 'login' || e.action === 'login_failed');
            controls.push({
                id: `${framework}-AUTH-01`,
                name: 'Authentication Event Logging',
                status: hasAuthLogs ? 'pass' : 'fail',
                evidence: hasAuthLogs ? ['Authentication events are being logged'] : ['No authentication events found'],
            });

            // Access control logging
            const hasAccessLogs = active.some(e => e.action === 'access_granted' || e.action === 'access_denied');
            controls.push({
                id: `${framework}-AC-01`,
                name: 'Access Control Logging',
                status: hasAccessLogs ? 'pass' : 'fail',
                evidence: hasAccessLogs ? ['Access control events are being logged'] : ['No access control events found'],
            });

            // Log integrity
            const integrity = engine.checkIntegrity();
            controls.push({
                id: `${framework}-INT-01`,
                name: 'Log Integrity',
                status: integrity.valid ? 'pass' : 'fail',
                evidence: integrity.valid
                    ? ['Log chain is intact']
                    : [`${integrity.tamperedEvents.length} tampered, ${integrity.missingEvents} missing`],
            });

            // Privilege monitoring
            const hasPrivLogs = active.some(e => e.action === 'privilege_escalation' || e.action === 'user_modify');
            controls.push({
                id: `${framework}-PM-01`,
                name: 'Privileged Action Monitoring',
                status: hasPrivLogs ? 'pass' : 'partial',
                evidence: hasPrivLogs
                    ? ['Privileged actions are monitored']
                    : ['No privileged action events — may not be configured'],
            });

            const passCount = controls.filter(c => c.status === 'pass').length;
            const score = Math.round((passCount / controls.length) * 100);

            return Object.freeze({
                framework,
                generatedAt: Date.now(),
                controls: Object.freeze(controls),
                overallScore: score,
            });
        },

        getStats() {
            const active = events.filter(e => !deletedIds.has(e.id));
            const byAction: Record<string, number> = {};
            const bySeverity: Record<string, number> = {};
            const actors = new Set<string>();
            let failedLogins = 0;

            for (const e of active) {
                byAction[e.action] = (byAction[e.action] ?? 0) + 1;
                bySeverity[e.severity] = (bySeverity[e.severity] ?? 0) + 1;
                actors.add(e.actor);
                if (e.action === 'login_failed') failedLogins++;
            }

            return Object.freeze({
                totalEvents: active.length,
                eventsByAction: Object.freeze(byAction),
                eventsBySeverity: Object.freeze(bySeverity),
                uniqueActors: actors.size,
                failedLogins,
                tamperedEvents: tamperedIds.size,
                deletedEvents: deletedIds.size,
            });
        },
    };

    return engine;
}
