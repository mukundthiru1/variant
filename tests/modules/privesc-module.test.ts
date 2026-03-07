import { describe, it, expect } from 'vitest';
import { createVFS } from '../../src/lib/vfs/vfs';
import { createPrivescModule, findPathEscalation, findSuidBinaries, parseSudoers, findSudoEscalation, findCronEscalation, findCapabilityEscalation, matchKernelExploits } from '../../src/modules/privesc-module';
import type { VMInstance } from '../../src/core/vm/types';
import type { SimulationContext, Capability } from '../../src/core/modules';
import type { EventBus, EngineEvent } from '../../src/core/events';
import { createEventBus, stubFabric, stubServices } from '../helpers';
import type { VirtualFilesystem } from '../../src/lib/vfs/types';
import type { WorldSpec } from '../../src/core/world/types';

interface TestEventBus extends EventBus {
    emitted: EngineEvent[];
}

function createTestEventBus(): TestEventBus {
    const emitted: EngineEvent[] = [];
    const inner = createEventBus(5000);

    return {
        emitted,
        emit(event): void {
            emitted.push(event);
            inner.emit(event);
        },
        on: inner.on.bind(inner),
        once: inner.once.bind(inner),
        waitFor: inner.waitFor.bind(inner),
        onPrefix: inner.onPrefix.bind(inner),
        getLog: inner.getLog.bind(inner),
        clearLog: inner.clearLog.bind(inner),
        removeAllListeners: inner.removeAllListeners.bind(inner),
    };
}

function createTestContext(vfs: VirtualFilesystem, machine = 'target-01'): {
    context: SimulationContext;
    bus: TestEventBus;
} {
    const bus = createTestEventBus();

    const vm = {
        id: machine,
        config: {
            imageUrl: 'file://test',
            memoryMB: 256,
            networkMAC: '52:54:00:12:34:56',
            biosUrl: 'file://bios',
            vgaBiosUrl: 'file://vga',
            enableVGA: false,
        },
        state: 'running' as const,
        shell: {
            getVFS(): VirtualFilesystem {
                return vfs;
            },
        },
    } as unknown as VMInstance;

    const context: SimulationContext = {
        vms: new Map([[machine, vm]]),
        fabric: stubFabric(),
        events: bus,
        world: {
            name: 'Privilege Escalation Test',
            version: '2.0',
            description: 'Integration tests',
            machines: {} as any,
            objectives: [],
            scoring: {
                maxScore: 1000,
                hintPenalty: 50,
                timeBonus: false,
                stealthBonus: false,
                tiers: [],
            },
        } as unknown as WorldSpec,
        tick: 0,
        services: stubServices(),
    };

    return { context, bus };
}

describe('Privilege Escalation module primitives', () => {
    it('findSuidBinaries detects known setuid binaries', () => {
        const vfs = createVFS();
        vfs.writeFile('/usr/bin/bash', '', { mode: 0o4755, owner: 'root' });
        vfs.writeFile('/usr/bin/python3', '', { mode: 0o4755, owner: 'root' });
        vfs.writeFile('/usr/bin/unknown', '', { mode: 0o4755, owner: 'root' });

        const suid = findSuidBinaries(vfs);
        const binaries = suid.map(entry => entry.binary);

        expect(binaries).toContain('bash');
        expect(binaries).toContain('python3');
        expect(binaries).not.toContain('unknown');
        expect(suid.find(entry => entry.binary === 'bash')?.shell).toBe(true);
    });

    it('findSuidBinaries ignores files without setuid permission', () => {
        const vfs = createVFS();
        vfs.writeFile('/usr/bin/bash', '', { mode: 0o755, owner: 'root' });

        const suid = findSuidBinaries(vfs);
        expect(suid.length).toBe(0);
    });

    it('parseSudoers parses NOPASSWD and wildcard rules', () => {
        const raw = 'alice ALL=(root) NOPASSWD: ALL';
        const entries = parseSudoers(raw);

        expect(entries).toHaveLength(1);
        expect(entries[0]).toMatchObject({
            user: 'alice',
            host: 'ALL',
            runAs: 'root',
            noPasswd: true,
            commands: ['ALL'],
        });
    });

    it('parseSudoers merges global env_keep values', () => {
        const raw = [
            'Defaults env_keep += "LD_PRELOAD,LD_LIBRARY_PATH"',
            'alice ALL=(root) NOPASSWD: /usr/bin/bash',
        ].join('\n');

        const entries = parseSudoers(raw);
        expect(entries).toHaveLength(1);
        expect(entries[0]!.envKeep).toContain('LD_PRELOAD');
        expect(entries[0]!.envKeep).toContain('LD_LIBRARY_PATH');
    });

    it('findSudoEscalation identifies wildcard escalation vector', () => {
        const entries = parseSudoers('alice ALL=(root) NOPASSWD: ALL');
        const paths = findSudoEscalation(entries, 'alice');

        expect(paths).toHaveLength(1);
        expect(paths[0]).toMatchObject({
            fromUser: 'alice',
            toUser: 'root',
            noPasswd: true,
            vector: 'wildcard-command',
        });
    });

    it('findSudoEscalation detects env_keep abuse vector', () => {
        const raw = [
            'Defaults env_keep += "LD_PRELOAD"',
            'alice ALL=(root) NOPASSWD: /usr/bin/env',
        ].join('\n');

        const entries = parseSudoers(raw);
        const paths = findSudoEscalation(entries, 'alice');

        expect(paths).toHaveLength(1);
        expect(paths[0]).toMatchObject({
            method: 'sudo',
            vector: 'env-keep-abuse',
            toUser: 'root',
        });
    });

    it('findSudoEscalation flags script reference commands', () => {
        const raw = 'alice ALL=(root) NOPASSWD: /tmp/pwn.sh';
        const entries = parseSudoers(raw);
        const paths = findSudoEscalation(entries, 'alice');

        expect(paths).toHaveLength(1);
        expect(paths[0]).toMatchObject({
            fromUser: 'alice',
            toUser: 'root',
            vector: 'script-ref',
        });
    });

    it('findCronEscalation detects writable /etc/crontab entry', () => {
        const vfs = createVFS();
        vfs.writeFile('/etc/crontab', '* * * * * root /usr/bin/pwn.sh', { mode: 0o666, owner: 'attacker' });
        vfs.mkdir('/usr/bin', { mode: 0o777, owner: 'root', recursive: true });
        vfs.writeFile('/usr/bin/pwn.sh', '', { mode: 0o755, owner: 'root' });

        const entries = findCronEscalation(vfs, 'attacker');
        expect(entries.some(entry => entry.mechanism === 'writable-script' && entry.file === '/etc/crontab')).toBe(true);
        expect(entries.some(entry => entry.mechanism === 'root-job')).toBe(true);
    });

    it('findCronEscalation detects writable /etc/cron.d file', () => {
        const vfs = createVFS();
        vfs.mkdir('/etc/cron.d', { mode: 0o755, owner: 'root', recursive: true });
        vfs.writeFile('/etc/cron.d/cleanup', '* * * * * root /usr/bin/cleanup.sh', { mode: 0o666, owner: 'attacker' });

        const entries = findCronEscalation(vfs, 'attacker');
        expect(entries.some(entry => entry.mechanism === 'writable-script' && entry.file === '/etc/cron.d/cleanup')).toBe(true);
    });

    it('findCronEscalation detects writable /var/spool/cron file', () => {
        const vfs = createVFS();
        vfs.writeFile('/var/spool/cron/alice', '* * * * * /usr/bin/spool-job', { mode: 0o666, owner: 'attacker' });

        const entries = findCronEscalation(vfs, 'attacker');
        expect(entries.some(entry => entry.file === '/var/spool/cron/alice' && entry.mechanism === 'writable-script')).toBe(true);
    });

    it('findCronEscalation flags PATH manipulation inside cron file', () => {
        const vfs = createVFS();
        vfs.mkdir('/etc', { mode: 0o755, owner: 'root', recursive: true });
        vfs.mkdir('/tmp/cron-bin', { mode: 0o777, owner: 'attacker', recursive: true });
        vfs.writeFile('/etc/crontab', 'PATH=/tmp/cron-bin:/usr/bin\n* * * * * root pwn', { mode: 0o644, owner: 'root' });

        const entries = findCronEscalation(vfs, 'attacker');
        expect(entries.some(entry => entry.mechanism === 'path-manipulation' && entry.command === '/tmp/cron-bin')).toBe(true);
    });

    it('findPathEscalation detects writable PATH entries', () => {
        const vfs = createVFS();
        vfs.mkdir('/tmp/attacker/bin', { mode: 0o777, owner: 'alice', recursive: true });
        const env = new Map<string, string>([
            ['PATH', '/tmp/attacker/bin:/usr/bin'],
            ['USER', 'alice'],
            ['HOME', '/home/alice'],
        ]);

        const escalations = findPathEscalation(vfs, env);
        expect(escalations.some(entry => entry.variable === 'PATH' && entry.path === '/tmp/attacker/bin')).toBe(true);
    });

    it('findPathEscalation detects writable LD_PRELOAD path', () => {
        const vfs = createVFS();
        vfs.writeFile('/tmp/libevil.so', '', { mode: 0o666, owner: 'alice' });
        const env = new Map<string, string>([
            ['LD_PRELOAD', '/tmp/libevil.so'],
            ['USER', 'alice'],
            ['HOME', '/home/alice'],
        ]);

        const escalations = findPathEscalation(vfs, env);
        expect(escalations.some(entry => entry.variable === 'LD_PRELOAD' && entry.path === '/tmp/libevil.so')).toBe(true);
    });

    it('findPathEscalation detects writable shell startup scripts', () => {
        const vfs = createVFS();
        vfs.mkdir('/home/alice', { mode: 0o755, owner: 'alice', recursive: true });
        vfs.writeFile('/home/alice/.bashrc', 'export PATH=/usr/bin', { mode: 0o666, owner: 'alice' });
        const env = new Map<string, string>([
            ['USER', 'alice'],
            ['HOME', '/home/alice'],
        ]);

        const escalations = findPathEscalation(vfs, env);
        expect(escalations.some(entry => entry.variable === 'PERSISTENCE' && entry.path === '/home/alice/.bashrc')).toBe(true);
    });

    it('findCapabilityEscalation finds binaries carrying privilege capabilities', () => {
        const vfs = createVFS();
        vfs.writeFile('/usr/bin/ping', 'cap_setuid,cap_net_raw', { mode: 0o755, owner: 'root' });

        const caps = findCapabilityEscalation(vfs);
        expect(caps.some(entry => entry.path === '/usr/bin/ping' && entry.capability === 'cap_setuid')).toBe(true);
        expect(caps.some(entry => entry.path === '/usr/bin/ping' && entry.capability === 'cap_net_raw')).toBe(true);
    });

    it('findCapabilityEscalation ignores files without capability markers', () => {
        const vfs = createVFS();
        vfs.writeFile('/usr/bin/normal', 'safe binary', { mode: 0o755, owner: 'root' });

        const caps = findCapabilityEscalation(vfs);
        expect(caps.some(entry => entry.path === '/usr/bin/normal')).toBe(false);
    });

    it('matchKernelExploits matches DirtyPipe-capable versions', () => {
        const matches = matchKernelExploits('5.15.10');
        expect(matches.some(entry => entry.cve === 'CVE-2022-0847')).toBe(true);
    });

    it('matchKernelExploits returns no match for patched kernels', () => {
        const matches = matchKernelExploits('99.0.0');
        expect(matches.length).toBe(0);
    });

    it('module validates two-step sudo chain escalation', () => {
        const vfs = createVFS();
        vfs.writeFile('/etc/sudoers', [
            'alice ALL=(www-data) NOPASSWD: /bin/echo',
            'www-data ALL=(root) NOPASSWD: /bin/bash',
        ].join('\n'));

        const { context, bus } = createTestContext(vfs);
        const mod = createPrivescModule(bus);
        mod.init(context);

        bus.emit({
            type: 'auth:escalate',
            machine: 'target-01',
            from: 'alice',
            to: 'www-data',
            method: 'sudo',
            timestamp: Date.now(),
        });

        bus.emit({
            type: 'auth:escalate',
            machine: 'target-01',
            from: 'www-data',
            to: 'root',
            method: 'sudo',
            timestamp: Date.now(),
        });

        const progress = bus.emitted.filter((event: any) => event.type === 'objective:progress');
        expect(progress.length).toBeGreaterThanOrEqual(2);
        expect(progress.some((event: any) => event.objectiveId === 'privesc-engine:target-01')).toBe(true);

        mod.destroy();
    });

    it('module does not emit progress for invalid auth:escalate', () => {
        const vfs = createVFS();
        const { context, bus } = createTestContext(vfs);
        const mod = createPrivescModule(bus);
        mod.init(context);

        bus.emit({
            type: 'auth:escalate',
            machine: 'target-01',
            from: 'intruder',
            to: 'root',
            method: 'sudo',
            timestamp: Date.now(),
        });

        expect(bus.emitted.some(event => event.type === 'objective:progress')).toBe(false);
        mod.destroy();
    });

    it('module deduplicates repeated identical escalation chains', () => {
        const vfs = createVFS();
        vfs.writeFile('/etc/sudoers', 'alice ALL=(www-data) NOPASSWD: /bin/echo');
        const { context, bus } = createTestContext(vfs);
        const mod = createPrivescModule(bus);
        mod.init(context);

        bus.emit({ type: 'auth:escalate', machine: 'target-01', from: 'alice', to: 'www-data', method: 'sudo', timestamp: Date.now() });
        bus.emit({ type: 'auth:escalate', machine: 'target-01', from: 'alice', to: 'www-data', method: 'sudo', timestamp: Date.now() });

        const progress = bus.emitted.filter(event => event.type === 'objective:progress');
        expect(progress).toHaveLength(1);
        mod.destroy();
    });

    it('module id and capabilities are registered', () => {
        const module = createPrivescModule();
        expect(module.id).toBe('privesc-engine');
        const names = module.provides.map((value: Capability) => value.name);
        expect(names).toContain('privilege-escalation');
        expect(names).toContain('privesc');
    });
});
