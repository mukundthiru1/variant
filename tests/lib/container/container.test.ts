import { describe, it, expect, beforeEach } from 'vitest';
import { createContainerEngine } from '../../../src/lib/container';
import type { ContainerEngine, ContainerCreateConfig } from '../../../src/lib/container';

describe('Container Engine', () => {
    let engine: ContainerEngine;

    beforeEach(() => {
        engine = createContainerEngine();
    });

    function defaultConfig(overrides: Partial<ContainerCreateConfig> = {}): ContainerCreateConfig {
        return {
            name: 'test-container',
            image: 'nginx:latest',
            ...overrides,
        };
    }

    // ── Container Lifecycle ──────────────────────────────────

    it('creates a container with correct defaults', () => {
        const c = engine.create(defaultConfig());
        expect(c.id).toBeTruthy();
        expect(c.name).toBe('test-container');
        expect(c.image).toBe('nginx:latest');
        expect(c.status).toBe('created');
        expect(c.privileged).toBe(false);
        expect(c.user).toBe('root');
        expect(c.readOnly).toBe(false);
        expect(c.restartPolicy).toBe('no');
        expect(c.networkMode).toBe('bridge');
    });

    it('starts a container', () => {
        const c = engine.create(defaultConfig());
        expect(engine.start(c.id)).toBe(true);
        const updated = engine.get(c.id)!;
        expect(updated.status).toBe('running');
        expect(updated.pid).toBeDefined();
    });

    it('cannot start an already-running container', () => {
        const c = engine.create(defaultConfig());
        engine.start(c.id);
        expect(engine.start(c.id)).toBe(false);
    });

    it('stops a running container', () => {
        const c = engine.create(defaultConfig());
        engine.start(c.id);
        expect(engine.stop(c.id)).toBe(true);
        expect(engine.get(c.id)!.status).toBe('exited');
    });

    it('cannot stop a non-running container', () => {
        const c = engine.create(defaultConfig());
        expect(engine.stop(c.id)).toBe(false);
    });

    it('removes a stopped container', () => {
        const c = engine.create(defaultConfig());
        expect(engine.remove(c.id)).toBe(true);
        expect(engine.get(c.id)).toBeNull();
    });

    it('cannot remove a running container', () => {
        const c = engine.create(defaultConfig());
        engine.start(c.id);
        expect(engine.remove(c.id)).toBe(false);
    });

    it('returns null for nonexistent container', () => {
        expect(engine.get('nonexistent')).toBeNull();
    });

    // ── Container Lookup ─────────────────────────────────────

    it('finds container by name', () => {
        const c = engine.create(defaultConfig({ name: 'my-app' }));
        expect(engine.get('my-app')).not.toBeNull();
        expect(engine.get('my-app')!.id).toBe(c.id);
    });

    it('finds container by id prefix', () => {
        const c = engine.create(defaultConfig());
        const prefix = c.id.slice(0, 4);
        expect(engine.get(prefix)!.id).toBe(c.id);
    });

    // ── Container Listing ────────────────────────────────────

    it('list without all only shows running containers', () => {
        engine.create(defaultConfig({ name: 'c1' }));
        const c2 = engine.create(defaultConfig({ name: 'c2' }));
        engine.start(c2.id);
        expect(engine.list().length).toBe(1);
        expect(engine.list()[0]!.name).toBe('c2');
    });

    it('list with all=true shows all containers', () => {
        engine.create(defaultConfig({ name: 'c1' }));
        engine.create(defaultConfig({ name: 'c2' }));
        expect(engine.list(true)).toHaveLength(2);
    });

    // ── Container Exec ───────────────────────────────────────

    it('exec fails on non-running container', () => {
        const c = engine.create(defaultConfig());
        const result = engine.exec(c.id, ['whoami']);
        expect(result.exitCode).toBe(1);
        expect(result.stderr).toContain('not running');
    });

    it('exec whoami returns container user', () => {
        const c = engine.create(defaultConfig({ user: 'appuser' }));
        engine.start(c.id);
        const result = engine.exec(c.id, ['whoami']);
        expect(result.exitCode).toBe(0);
        expect(result.stdout).toBe('appuser');
    });

    it('exec hostname returns container id prefix', () => {
        const c = engine.create(defaultConfig());
        engine.start(c.id);
        const result = engine.exec(c.id, ['hostname']);
        expect(result.exitCode).toBe(0);
        expect(result.stdout).toBe(c.id.slice(0, 12));
    });

    it('exec env returns environment variables', () => {
        const c = engine.create(defaultConfig({ env: { FOO: 'bar', BAZ: '123' } }));
        engine.start(c.id);
        const result = engine.exec(c.id, ['env']);
        expect(result.exitCode).toBe(0);
        expect(result.stdout).toContain('FOO=bar');
        expect(result.stdout).toContain('BAZ=123');
    });

    it('exec id returns user info', () => {
        const c = engine.create(defaultConfig());
        engine.start(c.id);
        const result = engine.exec(c.id, ['id']);
        expect(result.exitCode).toBe(0);
        expect(result.stdout).toContain('root');
    });

    it('exec mount shows volume mounts', () => {
        const c = engine.create(defaultConfig({
            volumes: [{ source: '/data', destination: '/mnt/data', mode: 'rw', type: 'bind' }],
        }));
        engine.start(c.id);
        const result = engine.exec(c.id, ['mount']);
        expect(result.stdout).toContain('/data');
        expect(result.stdout).toContain('/mnt/data');
    });

    it('exec cat /proc/1/cgroup shows docker cgroup for non-privileged', () => {
        const c = engine.create(defaultConfig());
        engine.start(c.id);
        const result = engine.exec(c.id, ['cat', '/proc/1/cgroup']);
        expect(result.stdout).toContain(`/docker/${c.id}`);
    });

    it('exec cat /proc/1/cgroup shows root cgroup for privileged', () => {
        const c = engine.create(defaultConfig({ privileged: true }));
        engine.start(c.id);
        const result = engine.exec(c.id, ['cat', '/proc/1/cgroup']);
        expect(result.stdout).toBe('0::/\n');
    });

    // ── Image Management ─────────────────────────────────────

    it('pullImage creates and returns an image', () => {
        const img = engine.pullImage('ubuntu', '22.04');
        expect(img.repository).toBe('ubuntu');
        expect(img.tag).toBe('22.04');
        expect(img.id).toContain('sha256:');
        expect(img.layers.length).toBeGreaterThan(0);
        expect(img.digest).toContain('sha256:');
    });

    it('pullImage defaults to latest tag', () => {
        const img = engine.pullImage('alpine');
        expect(img.tag).toBe('latest');
    });

    it('listImages returns pulled images', () => {
        engine.pullImage('nginx', '1.24');
        engine.pullImage('redis', '7');
        expect(engine.listImages().length).toBeGreaterThanOrEqual(2);
    });

    it('creating a container auto-creates its image', () => {
        engine.create(defaultConfig({ image: 'postgres:15' }));
        const images = engine.listImages();
        const pg = images.find(i => i.repository === 'postgres' && i.tag === '15');
        expect(pg).toBeDefined();
    });

    // ── Security Scan ────────────────────────────────────────

    it('scan detects privileged container', () => {
        const c = engine.create(defaultConfig({ privileged: true }));
        const scan = engine.securityScan(c.id);
        expect(scan.riskLevel).toBe('critical');
        const finding = scan.findings.find(f => f.type === 'privileged_container');
        expect(finding).toBeDefined();
        expect(finding!.severity).toBe('critical');
        expect(finding!.mitre).toBe('T1611');
    });

    it('scan detects docker socket mount', () => {
        const c = engine.create(defaultConfig({
            volumes: [{ source: '/var/run/docker.sock', destination: '/var/run/docker.sock', mode: 'rw', type: 'bind' }],
        }));
        const scan = engine.securityScan(c.id);
        const finding = scan.findings.find(f => f.type === 'docker_socket_mount');
        expect(finding).toBeDefined();
        expect(finding!.severity).toBe('critical');
    });

    it('scan detects sensitive mount', () => {
        const c = engine.create(defaultConfig({
            volumes: [{ source: '/etc/shadow', destination: '/mnt/shadow', mode: 'ro', type: 'bind' }],
        }));
        const scan = engine.securityScan(c.id);
        const finding = scan.findings.find(f => f.type === 'sensitive_mount');
        expect(finding).toBeDefined();
        expect(finding!.severity).toBe('high');
    });

    it('scan detects CAP_SYS_ADMIN', () => {
        const c = engine.create(defaultConfig({ capabilities: ['SYS_ADMIN'] }));
        const scan = engine.securityScan(c.id);
        const finding = scan.findings.find(f => f.type === 'cap_sys_admin');
        expect(finding).toBeDefined();
        expect(finding!.severity).toBe('critical');
    });

    it('scan detects CAP_NET_RAW', () => {
        const c = engine.create(defaultConfig({ capabilities: ['NET_RAW'] }));
        const scan = engine.securityScan(c.id);
        const finding = scan.findings.find(f => f.type === 'cap_net_raw');
        expect(finding).toBeDefined();
        expect(finding!.severity).toBe('medium');
    });

    it('scan detects root user', () => {
        const c = engine.create(defaultConfig());
        const scan = engine.securityScan(c.id);
        const finding = scan.findings.find(f => f.type === 'root_user');
        expect(finding).toBeDefined();
    });

    it('scan detects writable rootfs', () => {
        const c = engine.create(defaultConfig());
        const scan = engine.securityScan(c.id);
        const finding = scan.findings.find(f => f.type === 'writable_rootfs');
        expect(finding).toBeDefined();
    });

    it('scan detects no seccomp profile', () => {
        const c = engine.create(defaultConfig());
        const scan = engine.securityScan(c.id);
        const finding = scan.findings.find(f => f.type === 'no_seccomp');
        expect(finding).toBeDefined();
    });

    it('scan detects env secrets', () => {
        const c = engine.create(defaultConfig({
            env: { DATABASE_PASSWORD: 'supersecret', APP_NAME: 'myapp' },
        }));
        const scan = engine.securityScan(c.id);
        const finding = scan.findings.find(f => f.type === 'env_secret');
        expect(finding).toBeDefined();
        expect(finding!.severity).toBe('high');
    });

    it('scan detects host network mode', () => {
        const c = engine.create(defaultConfig({ networkMode: 'host' }));
        const scan = engine.securityScan(c.id);
        const finding = scan.findings.find(f => f.type === 'host_network');
        expect(finding).toBeDefined();
        expect(finding!.severity).toBe('high');
    });

    it('scan returns safe for hardened container', () => {
        const c = engine.create(defaultConfig({
            user: 'appuser',
            readOnly: true,
            securityOpt: ['seccomp=default'],
            networkMode: 'bridge',
        }));
        const scan = engine.securityScan(c.id);
        expect(scan.riskLevel).toBe('safe');
        expect(scan.findings).toHaveLength(0);
    });

    it('scan returns safe for nonexistent container', () => {
        const scan = engine.securityScan('nonexistent');
        expect(scan.riskLevel).toBe('safe');
        expect(scan.findings).toHaveLength(0);
    });

    // ── Network Management ───────────────────────────────────

    it('default bridge network exists', () => {
        const nets = engine.listNetworks();
        const bridge = nets.find(n => n.name === 'bridge');
        expect(bridge).toBeDefined();
        expect(bridge!.driver).toBe('bridge');
    });

    it('createNetwork creates a new network', () => {
        const net = engine.createNetwork('mynet', 'overlay', '10.0.0.0/24');
        expect(net.name).toBe('mynet');
        expect(net.driver).toBe('overlay');
        expect(net.subnet).toBe('10.0.0.0/24');
        expect(net.gateway).toBe('10.0.0.1');
    });

    it('started container is added to its network', () => {
        const c = engine.create(defaultConfig());
        engine.start(c.id);
        const nets = engine.listNetworks();
        const bridge = nets.find(n => n.name === 'bridge')!;
        expect(bridge.containers).toContain(c.id);
    });

    it('stopped container is removed from its network', () => {
        const c = engine.create(defaultConfig());
        engine.start(c.id);
        engine.stop(c.id);
        const nets = engine.listNetworks();
        const bridge = nets.find(n => n.name === 'bridge')!;
        expect(bridge.containers).not.toContain(c.id);
    });

    // ── Logs ─────────────────────────────────────────────────

    it('logs captures start and stop events', () => {
        const c = engine.create(defaultConfig({ name: 'log-test' }));
        engine.start(c.id);
        engine.stop(c.id);
        const logs = engine.logs(c.id);
        expect(logs.length).toBeGreaterThanOrEqual(2);
        expect(logs.some(l => l.includes('started'))).toBe(true);
        expect(logs.some(l => l.includes('stopped'))).toBe(true);
    });

    it('logs captures exec commands', () => {
        const c = engine.create(defaultConfig());
        engine.start(c.id);
        engine.exec(c.id, ['whoami']);
        const logs = engine.logs(c.id);
        expect(logs.some(l => l.includes('exec: whoami'))).toBe(true);
    });

    it('logs tail returns last N entries', () => {
        const c = engine.create(defaultConfig());
        engine.start(c.id);
        engine.exec(c.id, ['whoami']);
        engine.exec(c.id, ['hostname']);
        engine.exec(c.id, ['id']);
        const tail = engine.logs(c.id, 2);
        expect(tail).toHaveLength(2);
    });

    it('logs returns empty for nonexistent container', () => {
        expect(engine.logs('nonexistent')).toHaveLength(0);
    });

    // ── Stats ────────────────────────────────────────────────

    it('getStats returns accurate counts', () => {
        const c1 = engine.create(defaultConfig({ name: 'c1', privileged: true }));
        engine.create(defaultConfig({ name: 'c2' }));
        engine.start(c1.id);
        engine.createNetwork('custom');

        const stats = engine.getStats();
        expect(stats.totalContainers).toBe(2);
        expect(stats.runningContainers).toBe(1);
        expect(stats.stoppedContainers).toBe(1);
        expect(stats.privilegedContainers).toBe(1);
        expect(stats.totalNetworks).toBeGreaterThanOrEqual(2);
        expect(stats.totalImages).toBeGreaterThanOrEqual(1);
    });

    // ── Config Propagation ───────────────────────────────────

    it('container inherits config options', () => {
        const c = engine.create(defaultConfig({
            ports: [{ containerPort: 80, hostPort: 8080, protocol: 'tcp' }],
            labels: { app: 'web' },
            capabilities: ['NET_ADMIN'],
            securityOpt: ['apparmor=docker-default'],
            entrypoint: ['/bin/sh'],
            command: ['-c', 'echo hello'],
            readOnly: true,
            restartPolicy: 'always',
        }));
        expect(c.ports).toHaveLength(1);
        expect(c.ports[0]!.containerPort).toBe(80);
        expect(c.labels['app']).toBe('web');
        expect(c.capabilities).toContain('NET_ADMIN');
        expect(c.securityOpt).toContain('apparmor=docker-default');
        expect(c.entrypoint).toEqual(['/bin/sh']);
        expect(c.command).toEqual(['-c', 'echo hello']);
        expect(c.readOnly).toBe(true);
        expect(c.restartPolicy).toBe('always');
    });

    it('image tag defaults to latest when not specified', () => {
        const c = engine.create(defaultConfig({ image: 'ubuntu' }));
        expect(c.image).toBe('ubuntu');
        const images = engine.listImages();
        const ubuntuImg = images.find(i => i.repository === 'ubuntu' && i.tag === 'latest');
        expect(ubuntuImg).toBeDefined();
    });
});
