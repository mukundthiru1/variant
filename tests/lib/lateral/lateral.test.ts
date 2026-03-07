import { describe, it, expect, beforeEach } from 'vitest';
import { createLateralMovementEngine } from '../../../src/lib/lateral';
import type { LateralMovementEngine, HostCredential } from '../../../src/lib/lateral';

describe('Lateral Movement Engine', () => {
    let engine: LateralMovementEngine;

    const sshCred: HostCredential = { username: 'admin', credType: 'password' };
    const hashCred: HostCredential = { username: 'admin', credType: 'ntlm_hash', hash: 'aad3b435...' };
    beforeEach(() => {
        engine = createLateralMovementEngine();
        engine.addHost({
            hostname: 'attacker', ip: '10.0.0.1', os: 'linux',
            openPorts: [22], services: [], credentials: [sshCred],
        });
        engine.addHost({
            hostname: 'webserver', ip: '10.0.0.2', os: 'linux',
            openPorts: [22, 80, 443],
            services: [{ port: 22, protocol: 'tcp', name: 'ssh', authenticated: true }],
            credentials: [sshCred],
        });
        engine.addHost({
            hostname: 'dc01', ip: '10.0.0.10', os: 'windows', domain: 'corp.local',
            openPorts: [135, 445, 3389, 5985],
            services: [{ port: 445, protocol: 'tcp', name: 'smb', authenticated: true }],
            credentials: [hashCred],
        });
    });

    // ── Host Management ──────────────────────────────────────

    it('adds and retrieves hosts by hostname', () => {
        expect(engine.getHost('webserver')).not.toBeNull();
        expect(engine.getHost('webserver')!.ip).toBe('10.0.0.2');
    });

    it('retrieves hosts by IP', () => {
        expect(engine.getHost('10.0.0.10')!.hostname).toBe('dc01');
    });

    it('returns null for unknown host', () => {
        expect(engine.getHost('nonexistent')).toBeNull();
    });

    it('lists all hosts', () => {
        expect(engine.listHosts()).toHaveLength(3);
    });

    it('new hosts are not compromised', () => {
        const host = engine.getHost('webserver')!;
        expect(host.compromised).toBe(false);
        expect(host.adminAccess).toBe(false);
    });

    // ── Compromise ───────────────────────────────────────────

    it('compromiseHost marks host as compromised', () => {
        expect(engine.compromiseHost('attacker')).toBe(true);
        expect(engine.getHost('attacker')!.compromised).toBe(true);
    });

    it('compromiseHost returns false for unknown host', () => {
        expect(engine.compromiseHost('ghost')).toBe(false);
    });

    // ── Credential Management ────────────────────────────────

    it('addCredential adds credentials to a host', () => {
        engine.addCredential('webserver', { username: 'root', credType: 'ssh_key', key: 'id_rsa...' });
        const hosts = engine.listHosts();
        const ws = hosts.find(h => h.hostname === 'webserver')!;
        expect(ws.credentials.length).toBeGreaterThanOrEqual(2);
    });

    it('addCredential returns false for unknown host', () => {
        expect(engine.addCredential('ghost', sshCred)).toBe(false);
    });

    // ── Pivoting ─────────────────────────────────────────────

    it('SSH pivot succeeds when source is compromised and port open', () => {
        engine.compromiseHost('attacker');
        const result = engine.pivot({
            sourceMachine: 'attacker', targetMachine: 'webserver',
            technique: 'ssh', credential: sshCred, tick: 1,
        });
        expect(result.success).toBe(true);
        expect(result.mitreTechnique).toBe('T1021.004');
        expect(result.artifacts.length).toBeGreaterThan(0);
        expect(engine.getHost('webserver')!.compromised).toBe(true);
    });

    it('pivot fails when source is not compromised', () => {
        const result = engine.pivot({
            sourceMachine: 'attacker', targetMachine: 'webserver',
            technique: 'ssh', credential: sshCred, tick: 1,
        });
        expect(result.success).toBe(false);
        expect(result.reason).toContain('not compromised');
    });

    it('pivot fails when target does not exist', () => {
        engine.compromiseHost('attacker');
        const result = engine.pivot({
            sourceMachine: 'attacker', targetMachine: 'ghost',
            technique: 'ssh', credential: sshCred, tick: 1,
        });
        expect(result.success).toBe(false);
        expect(result.reason).toContain('not found');
    });

    it('pivot fails when required port is not open', () => {
        engine.compromiseHost('attacker');
        const result = engine.pivot({
            sourceMachine: 'attacker', targetMachine: 'webserver',
            technique: 'rdp', credential: sshCred, tick: 1,
        });
        expect(result.success).toBe(false);
        expect(result.reason).toContain('Port 3389');
    });

    it('pivot fails with incompatible credential type', () => {
        engine.compromiseHost('attacker');
        const result = engine.pivot({
            sourceMachine: 'attacker', targetMachine: 'webserver',
            technique: 'pass_the_hash', credential: sshCred, tick: 1,
        });
        expect(result.success).toBe(false);
        expect(result.reason).toContain('does not accept');
    });

    it('pass-the-hash pivot succeeds with NTLM hash on open port 445', () => {
        engine.compromiseHost('attacker');
        // First hop to webserver
        engine.pivot({ sourceMachine: 'attacker', targetMachine: 'webserver', technique: 'ssh', credential: sshCred, tick: 1 });
        // Then PTH to dc01
        const result = engine.pivot({
            sourceMachine: 'webserver', targetMachine: 'dc01',
            technique: 'pass_the_hash', credential: hashCred, tick: 2,
        });
        expect(result.success).toBe(true);
        expect(result.mitreTechnique).toBe('T1550.002');
        expect(result.detectionRisk).toBe('high');
    });

    it('PSExec pivot generates service artifacts', () => {
        engine.compromiseHost('attacker');
        engine.pivot({ sourceMachine: 'attacker', targetMachine: 'webserver', technique: 'ssh', credential: sshCred, tick: 1 });
        const result = engine.pivot({
            sourceMachine: 'webserver', targetMachine: 'dc01',
            technique: 'psexec', credential: hashCred, tick: 2,
        });
        expect(result.success).toBe(true);
        expect(result.artifacts.some(a => a.description.includes('PSEXESVC'))).toBe(true);
    });

    it('admin obtained for Administrator username', () => {
        engine.compromiseHost('attacker');
        const adminCred: HostCredential = { username: 'Administrator', credType: 'password' };
        const result = engine.pivot({
            sourceMachine: 'attacker', targetMachine: 'webserver',
            technique: 'ssh', credential: adminCred, tick: 1,
        });
        expect(result.success).toBe(true);
        expect(result.adminObtained).toBe(true);
        expect(engine.getHost('webserver')!.adminAccess).toBe(true);
    });

    // ── Attack Path ──────────────────────────────────────────

    it('getAttackPath tracks successful pivots', () => {
        engine.compromiseHost('attacker');
        engine.pivot({ sourceMachine: 'attacker', targetMachine: 'webserver', technique: 'ssh', credential: sshCred, tick: 1 });
        engine.pivot({ sourceMachine: 'webserver', targetMachine: 'dc01', technique: 'psexec', credential: hashCred, tick: 2 });

        const path = engine.getAttackPath();
        expect(path.startHost).toBe('attacker');
        expect(path.currentHost).toBe('dc01');
        expect(path.totalHops).toBe(2);
    });

    it('attack path detected flag when high-risk technique used', () => {
        engine.compromiseHost('attacker');
        engine.pivot({ sourceMachine: 'attacker', targetMachine: 'webserver', technique: 'ssh', credential: sshCred, tick: 1 });
        engine.pivot({ sourceMachine: 'webserver', targetMachine: 'dc01', technique: 'psexec', credential: hashCred, tick: 2 });

        const path = engine.getAttackPath();
        expect(path.detected).toBe(true); // psexec is high risk
    });

    // ── Reachable Hosts ──────────────────────────────────────

    it('getReachableHosts returns other hosts when compromised', () => {
        engine.compromiseHost('attacker');
        const reachable = engine.getReachableHosts('attacker');
        expect(reachable).toHaveLength(2);
        expect(reachable.map(h => h.hostname)).toContain('webserver');
    });

    it('getReachableHosts returns empty when not compromised', () => {
        expect(engine.getReachableHosts('webserver')).toHaveLength(0);
    });

    // ── MITRE Mapping ────────────────────────────────────────

    it('getMitreMapping returns correct technique IDs', () => {
        expect(engine.getMitreMapping('ssh')).toBe('T1021.004');
        expect(engine.getMitreMapping('rdp')).toBe('T1021.001');
        expect(engine.getMitreMapping('wmi')).toBe('T1047');
        expect(engine.getMitreMapping('pass_the_hash')).toBe('T1550.002');
        expect(engine.getMitreMapping('golden_ticket')).toBe('T1558.001');
    });

    it('getMitreMapping returns default for unknown technique', () => {
        expect(engine.getMitreMapping('custom_exploit')).toBe('T1570');
    });

    // ── Stats ────────────────────────────────────────────────

    it('getStats returns accurate counts', () => {
        engine.compromiseHost('attacker');
        engine.pivot({ sourceMachine: 'attacker', targetMachine: 'webserver', technique: 'ssh', credential: sshCred, tick: 1 });
        // Fail a pivot (ssh_key not accepted by pass_the_hash)
        engine.pivot({ sourceMachine: 'attacker', targetMachine: 'dc01', technique: 'pass_the_hash', credential: { username: 'admin', credType: 'ssh_key' }, tick: 2 });

        const stats = engine.getStats();
        expect(stats.totalHosts).toBe(3);
        expect(stats.compromisedHosts).toBe(2);
        expect(stats.pivotAttempts).toBe(2);
        expect(stats.successfulPivots).toBe(1);
        expect(stats.failedPivots).toBe(1);
        expect(stats.techniquesUsed).toContain('ssh');
        expect(stats.credentialsHarvested).toBeGreaterThanOrEqual(3);
    });

    // ── Pivot History ────────────────────────────────────────

    it('getPivotHistory includes all attempts', () => {
        engine.compromiseHost('attacker');
        engine.pivot({ sourceMachine: 'attacker', targetMachine: 'webserver', technique: 'ssh', credential: sshCred, tick: 1 });
        engine.pivot({ sourceMachine: 'attacker', targetMachine: 'dc01', technique: 'rdp', credential: sshCred, tick: 2 });
        expect(engine.getPivotHistory()).toHaveLength(2);
    });
});
