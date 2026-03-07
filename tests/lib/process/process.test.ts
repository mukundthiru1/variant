/**
 * VARIANT — Process Tree tests
 */
import { describe, it, expect } from 'vitest';
import { createProcessTree } from '../../../src/lib/process/process-tree';

describe('ProcessTree', () => {
    it('starts with init process (PID 1)', () => {
        const tree = createProcessTree('web-server');
        const init = tree.get(1);
        expect(init).not.toBeNull();
        expect(init!.name).toBe('init');
        expect(init!.pid).toBe(1);
        expect(init!.user).toBe('root');
    });

    it('spawns processes with incrementing PIDs', () => {
        const tree = createProcessTree('srv');
        const pid1 = tree.spawn({ name: 'sshd', command: '/usr/sbin/sshd' });
        const pid2 = tree.spawn({ name: 'httpd', command: '/usr/sbin/httpd' });
        expect(pid1).toBe(2);
        expect(pid2).toBe(3);
    });

    it('retrieves spawned process', () => {
        const tree = createProcessTree('srv');
        const pid = tree.spawn({ name: 'sshd', command: '/usr/sbin/sshd', user: 'root' });
        const proc = tree.get(pid);
        expect(proc).not.toBeNull();
        expect(proc!.name).toBe('sshd');
        expect(proc!.user).toBe('root');
    });

    it('returns null for unknown PID', () => {
        const tree = createProcessTree('srv');
        expect(tree.get(999)).toBeNull();
    });

    it('kills a process', () => {
        const tree = createProcessTree('srv');
        const pid = tree.spawn({ name: 'bash', command: '/bin/bash' });
        expect(tree.kill(pid)).toBe(true);
        expect(tree.get(pid)).toBeNull();
    });

    it('cannot kill init (PID 1)', () => {
        const tree = createProcessTree('srv');
        expect(tree.kill(1)).toBe(false);
        expect(tree.get(1)).not.toBeNull();
    });

    it('kill returns false for unknown PID', () => {
        const tree = createProcessTree('srv');
        expect(tree.kill(999)).toBe(false);
    });

    it('reparents children to init when parent is killed', () => {
        const tree = createProcessTree('srv');
        const parent = tree.spawn({ name: 'sshd', command: '/usr/sbin/sshd' });
        const child = tree.spawn({ name: 'bash', command: '/bin/bash', ppid: parent });

        tree.kill(parent);

        const orphan = tree.get(child);
        expect(orphan).not.toBeNull();
        expect(orphan!.ppid).toBe(1); // Reparented to init
    });

    it('lists children of a process', () => {
        const tree = createProcessTree('srv');
        const parent = tree.spawn({ name: 'sshd', command: '/usr/sbin/sshd' });
        tree.spawn({ name: 'bash', command: '/bin/bash', ppid: parent });
        tree.spawn({ name: 'bash', command: '/bin/bash', ppid: parent });

        const kids = tree.children(parent);
        expect(kids.length).toBe(2);
    });

    it('lists ancestry chain', () => {
        const tree = createProcessTree('srv');
        const pid1 = tree.spawn({ name: 'sshd', command: '/usr/sbin/sshd' });
        const pid2 = tree.spawn({ name: 'bash', command: '/bin/bash', ppid: pid1 });
        const pid3 = tree.spawn({ name: 'vi', command: '/usr/bin/vi', ppid: pid2 });

        const chain = tree.ancestry(pid3);
        expect(chain.length).toBeGreaterThanOrEqual(3); // vi → bash → sshd → init
        expect(chain[0]!.name).toBe('vi');
    });

    it('findByName returns first match', () => {
        const tree = createProcessTree('srv');
        tree.spawn({ name: 'bash', command: '/bin/bash' });
        tree.spawn({ name: 'bash', command: '/bin/bash' });

        const found = tree.findByName('bash');
        expect(found).not.toBeNull();
        expect(found!.name).toBe('bash');
    });

    it('findByName returns null for no match', () => {
        const tree = createProcessTree('srv');
        expect(tree.findByName('nonexistent')).toBeNull();
    });

    it('findAllByName returns all matches', () => {
        const tree = createProcessTree('srv');
        tree.spawn({ name: 'worker', command: '/usr/bin/worker' });
        tree.spawn({ name: 'worker', command: '/usr/bin/worker' });
        tree.spawn({ name: 'other', command: '/usr/bin/other' });

        expect(tree.findAllByName('worker').length).toBe(2);
    });

    it('findByUser returns processes owned by user', () => {
        const tree = createProcessTree('srv');
        tree.spawn({ name: 'sshd', command: '/usr/sbin/sshd', user: 'root' });
        tree.spawn({ name: 'httpd', command: '/usr/sbin/httpd', user: 'www-data' });
        tree.spawn({ name: 'worker', command: '/usr/bin/worker', user: 'www-data' });

        expect(tree.findByUser('www-data').length).toBe(2);
        // root owns init + sshd
        expect(tree.findByUser('root').length).toBe(2);
    });

    it('all() returns all processes including init', () => {
        const tree = createProcessTree('srv');
        tree.spawn({ name: 'a', command: '/a' });
        tree.spawn({ name: 'b', command: '/b' });

        expect(tree.all().length).toBe(3); // init + a + b
    });

    it('count returns total process count', () => {
        const tree = createProcessTree('srv');
        expect(tree.count()).toBe(1); // just init
        tree.spawn({ name: 'a', command: '/a' });
        expect(tree.count()).toBe(2);
    });

    it('formatPsAux produces output', () => {
        const tree = createProcessTree('srv');
        tree.spawn({ name: 'sshd', command: '/usr/sbin/sshd' });
        const output = tree.formatPsAux();
        expect(output).toContain('USER');
        expect(output).toContain('sshd');
    });

    it('formatPsAuxForest produces tree output', () => {
        const tree = createProcessTree('srv');
        tree.spawn({ name: 'sshd', command: '/usr/sbin/sshd' });
        const output = tree.formatPsAuxForest();
        expect(output.length).toBeGreaterThan(0);
    });

    it('formatPstree produces tree output', () => {
        const tree = createProcessTree('srv');
        const parent = tree.spawn({ name: 'sshd', command: '/usr/sbin/sshd' });
        tree.spawn({ name: 'bash', command: '/bin/bash', ppid: parent });
        const output = tree.formatPstree();
        expect(output).toContain('init');
    });

    it('detectAnomalies finds suspicious lineage', () => {
        const tree = createProcessTree('srv');
        const httpd = tree.spawn({ name: 'httpd', command: '/usr/sbin/httpd' });
        tree.spawn({ name: 'bash', command: '/bin/bash', ppid: httpd });

        const anomalies = tree.detectAnomalies();
        expect(anomalies.length).toBeGreaterThan(0);
        expect(anomalies.some(a => a.type === 'suspicious-parent')).toBe(true);
    });

    it('detectAnomalies returns empty for clean tree', () => {
        const tree = createProcessTree('srv');
        tree.spawn({ name: 'sshd', command: '/usr/sbin/sshd' });
        tree.spawn({ name: 'crond', command: '/usr/sbin/crond' });

        const anomalies = tree.detectAnomalies();
        expect(anomalies.length).toBe(0);
    });

    it('defaults ppid to 1 (init) when parent not specified', () => {
        const tree = createProcessTree('srv');
        const pid = tree.spawn({ name: 'daemon', command: '/usr/sbin/daemon' });
        expect(tree.get(pid)!.ppid).toBe(1);
    });

    it('reparents to init if specified parent does not exist', () => {
        const tree = createProcessTree('srv');
        const pid = tree.spawn({ name: 'orphan', command: '/usr/bin/orphan', ppid: 9999 });
        expect(tree.get(pid)!.ppid).toBe(1);
    });
});
