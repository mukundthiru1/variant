/**
 * VARIANT — EDR Engine
 *
 * Simulates endpoint detection and response with:
 * - Behavioral detection rules (process, file, network, registry)
 * - Automated response actions (isolate, kill, quarantine)
 * - Alert investigation workflow
 * - Host isolation management
 * - Built-in detection rules for common attack techniques
 *
 * All operations are synchronous and pure-data.
 */

import type {
    EDREngine,
    EDREvent,
    EDRDetectionRule,
    EDRAlert,
    EDRSeverity,
    EDRCondition,
    EDRResponseAction,
    EDRHostStatus,
    EDRStats,
} from './types';

// ── Helpers ───────────────────────────────────────────────

let eventCounter = 0;
let alertCounter = 0;

function generateEventId(): string {
    return `edr-evt-${++eventCounter}`;
}

function generateAlertId(): string {
    return `edr-alert-${++alertCounter}`;
}

function matchCondition(event: EDREvent, condition: EDRCondition): boolean {
    const fieldValue = String((event as any)[condition.field] ?? '');

    switch (condition.operator) {
        case 'equals':
            return fieldValue === condition.value;
        case 'notEquals':
            return fieldValue !== condition.value;
        case 'contains':
            return fieldValue.toLowerCase().includes(String(condition.value).toLowerCase());
        case 'startsWith':
            return fieldValue.toLowerCase().startsWith(String(condition.value).toLowerCase());
        case 'endsWith':
            return fieldValue.toLowerCase().endsWith(String(condition.value).toLowerCase());
        case 'regex':
            try { return new RegExp(String(condition.value), 'i').test(fieldValue); }
            catch { return false; }
        case 'in':
            if (Array.isArray(condition.value)) {
                return (condition.value as readonly string[]).some(v => v.toLowerCase() === fieldValue.toLowerCase());
            }
            return false;
        default:
            return false;
    }
}

// ── Factory ──────────────────────────────────────────────

export function createEDREngine(): EDREngine {
    const rules = new Map<string, EDRDetectionRule>();
    const alerts: EDRAlert[] = [];
    const hosts = new Map<string, {
        isolated: boolean;
        lastSeen: number;
        blockedProcesses: string[];
        quarantinedFiles: string[];
        suspendedUsers: string[];
    }>();
    let totalEvents = 0;

    function ensureHost(machine: string, tick: number): void {
        if (!hosts.has(machine)) {
            hosts.set(machine, {
                isolated: false,
                lastSeen: tick,
                blockedProcesses: [],
                quarantinedFiles: [],
                suspendedUsers: [],
            });
        }
    }

    function evaluateRules(event: EDREvent): EDRAlert[] {
        const newAlerts: EDRAlert[] = [];

        for (const rule of rules.values()) {
            if (!rule.enabled) continue;

            const matches = rule.logic === 'all'
                ? rule.conditions.every(c => matchCondition(event, c))
                : rule.conditions.some(c => matchCondition(event, c));

            if (matches) {
                const responsesApplied: EDRResponseAction[] = [];
                const host = hosts.get(event.machine);

                for (const action of rule.responseActions) {
                    responsesApplied.push(action);
                    if (host) {
                        switch (action) {
                            case 'isolate_host':
                                host.isolated = true;
                                break;
                            case 'kill_process':
                                if (!host.blockedProcesses.includes(event.processName)) {
                                    host.blockedProcesses.push(event.processName);
                                }
                                break;
                            case 'quarantine_file':
                                if (event.filePath && !host.quarantinedFiles.includes(event.filePath)) {
                                    host.quarantinedFiles.push(event.filePath);
                                }
                                break;
                            case 'suspend_user':
                                if (!host.suspendedUsers.includes(event.user)) {
                                    host.suspendedUsers.push(event.user);
                                }
                                break;
                        }
                    }
                }

                const alert: EDRAlert = Object.freeze({
                    id: generateAlertId(),
                    ruleId: rule.id,
                    ruleName: rule.name,
                    severity: rule.severity,
                    event,
                    tick: event.tick,
                    mitreTechnique: rule.mitreTechnique,
                    mitreTactic: rule.mitreTactic,
                    responsesTaken: Object.freeze(responsesApplied),
                    investigated: false,
                    falsePositive: false,
                });

                alerts.push(alert);
                newAlerts.push(alert);
            }
        }

        return newAlerts;
    }

    const engine: EDREngine = {
        ingestEvent(input: Omit<EDREvent, 'id'>): EDRAlert[] {
            totalEvents++;
            const event: EDREvent = Object.freeze({ ...input, id: generateEventId() });
            ensureHost(event.machine, event.tick);
            const host = hosts.get(event.machine)!;
            host.lastSeen = event.tick;
            return evaluateRules(event);
        },

        addRule(rule: EDRDetectionRule): void {
            rules.set(rule.id, rule);
        },

        removeRule(id: string): boolean {
            return rules.delete(id);
        },

        setRuleEnabled(id: string, enabled: boolean): boolean {
            const rule = rules.get(id);
            if (!rule) return false;
            rules.set(id, { ...rule, enabled });
            return true;
        },

        getRules(): readonly EDRDetectionRule[] {
            return Object.freeze(Array.from(rules.values()));
        },

        getAlerts(): readonly EDRAlert[] {
            return Object.freeze([...alerts]);
        },

        getAlertsBySeverity(severity: EDRSeverity): readonly EDRAlert[] {
            return Object.freeze(alerts.filter(a => a.severity === severity));
        },

        getAlertsByMachine(machine: string): readonly EDRAlert[] {
            return Object.freeze(alerts.filter(a => a.event.machine === machine));
        },

        investigateAlert(alertId: string, falsePositive: boolean): boolean {
            const idx = alerts.findIndex(a => a.id === alertId);
            if (idx === -1) return false;
            alerts[idx] = { ...alerts[idx]!, investigated: true, falsePositive };
            return true;
        },

        isolateHost(machine: string): void {
            ensureHost(machine, Date.now());
            hosts.get(machine)!.isolated = true;
        },

        unisolateHost(machine: string): void {
            const host = hosts.get(machine);
            if (host) host.isolated = false;
        },

        getHostStatus(machine: string): EDRHostStatus {
            ensureHost(machine, Date.now());
            const host = hosts.get(machine)!;
            return Object.freeze({
                machine,
                isolated: host.isolated,
                agentVersion: '7.4.2',
                lastSeen: host.lastSeen,
                blockedProcesses: Object.freeze([...host.blockedProcesses]),
                quarantinedFiles: Object.freeze([...host.quarantinedFiles]),
                suspendedUsers: Object.freeze([...host.suspendedUsers]),
            });
        },

        getHosts(): readonly EDRHostStatus[] {
            return Object.freeze(
                Array.from(hosts.keys()).map(m => engine.getHostStatus(m))
            );
        },

        resetAlerts(): void {
            alerts.length = 0;
        },

        getStats(): EDRStats {
            const bySeverity: Record<string, number> = {};
            let investigated = 0;
            let falsePositives = 0;

            for (const alert of alerts) {
                bySeverity[alert.severity] = (bySeverity[alert.severity] ?? 0) + 1;
                if (alert.investigated) investigated++;
                if (alert.falsePositive) falsePositives++;
            }

            let isolated = 0;
            for (const host of hosts.values()) {
                if (host.isolated) isolated++;
            }

            return Object.freeze({
                totalEvents,
                totalAlerts: alerts.length,
                alertsBySeverity: Object.freeze(bySeverity),
                totalRules: rules.size,
                enabledRules: Array.from(rules.values()).filter(r => r.enabled).length,
                hostsMonitored: hosts.size,
                hostsIsolated: isolated,
                investigatedAlerts: investigated,
                falsePositives,
            });
        },
    };

    return engine;
}

/** Create built-in EDR detection rules. */
export function createBuiltinEDRRules(): readonly EDRDetectionRule[] {
    return Object.freeze([
        {
            id: 'edr-001', name: 'Suspicious PowerShell Execution', description: 'Encoded PowerShell command detected',
            severity: 'high' as EDRSeverity, logic: 'all' as const,
            conditions: [
                { field: 'type', operator: 'equals' as const, value: 'process_create' },
                { field: 'processName', operator: 'in' as const, value: ['powershell.exe', 'pwsh.exe', 'powershell'] },
                { field: 'commandLine', operator: 'regex' as const, value: '-[eE]nc|-[Ee]ncodedCommand|-[Ww]indowStyle\\s+[Hh]idden' },
            ],
            mitreTechnique: 'T1059.001', mitreTactic: 'execution',
            responseActions: ['alert', 'collect_forensics'], enabled: true, falsePositiveRate: 'medium',
        },
        {
            id: 'edr-002', name: 'LSASS Memory Access', description: 'Process accessing LSASS memory (credential dumping)',
            severity: 'critical' as EDRSeverity, logic: 'all' as const,
            conditions: [
                { field: 'type', operator: 'equals' as const, value: 'memory_injection' },
                { field: 'commandLine', operator: 'contains' as const, value: 'lsass' },
            ],
            mitreTechnique: 'T1003.001', mitreTactic: 'credential-access',
            responseActions: ['alert', 'kill_process', 'isolate_host'], enabled: true, falsePositiveRate: 'low',
        },
        {
            id: 'edr-003', name: 'Reverse Shell Detection', description: 'Outbound shell connection detected',
            severity: 'critical' as EDRSeverity, logic: 'all' as const,
            conditions: [
                { field: 'type', operator: 'equals' as const, value: 'network_connect' },
                { field: 'processName', operator: 'in' as const, value: ['bash', 'sh', 'cmd.exe', 'nc', 'ncat', 'socat'] },
            ],
            mitreTechnique: 'T1059', mitreTactic: 'execution',
            responseActions: ['alert', 'kill_process', 'block_network'], enabled: true, falsePositiveRate: 'low',
        },
        {
            id: 'edr-004', name: 'Mimikatz Execution', description: 'Known credential dumping tool',
            severity: 'critical' as EDRSeverity, logic: 'any' as const,
            conditions: [
                { field: 'commandLine', operator: 'contains' as const, value: 'mimikatz' },
                { field: 'commandLine', operator: 'contains' as const, value: 'sekurlsa::logonpasswords' },
                { field: 'commandLine', operator: 'contains' as const, value: 'kerberos::golden' },
            ],
            mitreTechnique: 'T1003', mitreTactic: 'credential-access',
            responseActions: ['alert', 'kill_process', 'quarantine_file', 'isolate_host'], enabled: true, falsePositiveRate: 'none',
        },
        {
            id: 'edr-005', name: 'Suspicious Binary in Temp Directory', description: 'Executable created in temp directory',
            severity: 'medium' as EDRSeverity, logic: 'all' as const,
            conditions: [
                { field: 'type', operator: 'equals' as const, value: 'file_create' },
                { field: 'filePath', operator: 'regex' as const, value: '(/tmp/|/var/tmp/|\\\\Temp\\\\).*\\.(exe|dll|ps1|bat|vbs|sh)$' },
            ],
            mitreTechnique: 'T1204', mitreTactic: 'execution',
            responseActions: ['alert', 'quarantine_file'], enabled: true, falsePositiveRate: 'medium',
        },
        {
            id: 'edr-006', name: 'Lateral Movement via PsExec', description: 'PsExec or similar remote execution',
            severity: 'high' as EDRSeverity, logic: 'any' as const,
            conditions: [
                { field: 'processName', operator: 'equals' as const, value: 'psexec.exe' },
                { field: 'processName', operator: 'equals' as const, value: 'psexesvc.exe' },
                { field: 'commandLine', operator: 'contains' as const, value: 'psexec' },
            ],
            mitreTechnique: 'T1570', mitreTactic: 'lateral-movement',
            responseActions: ['alert', 'collect_forensics'], enabled: true, falsePositiveRate: 'low',
        },
        {
            id: 'edr-007', name: 'Scheduled Task Creation', description: 'Persistence via scheduled task',
            severity: 'medium' as EDRSeverity, logic: 'all' as const,
            conditions: [
                { field: 'type', operator: 'equals' as const, value: 'process_create' },
                { field: 'commandLine', operator: 'regex' as const, value: 'schtasks|at\\s+\\d|crontab' },
            ],
            mitreTechnique: 'T1053', mitreTactic: 'persistence',
            responseActions: ['alert'], enabled: true, falsePositiveRate: 'high',
        },
        {
            id: 'edr-008', name: 'DNS Tunneling Detected', description: 'Unusual DNS query patterns',
            severity: 'high' as EDRSeverity, logic: 'all' as const,
            conditions: [
                { field: 'type', operator: 'equals' as const, value: 'network_dns' },
                { field: 'networkDest', operator: 'regex' as const, value: '.{60,}\\.' },
            ],
            mitreTechnique: 'T1071.004', mitreTactic: 'command-and-control',
            responseActions: ['alert', 'block_network'], enabled: true, falsePositiveRate: 'low',
        },
    ]);
}
