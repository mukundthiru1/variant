/**
 * VARIANT — Sandbox Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createSandboxEngine } from '../../../src/lib/sandbox/sandbox-engine';
import type { SandboxConfig } from '../../../src/lib/sandbox/types';

function makeConfig(overrides?: Partial<SandboxConfig>): SandboxConfig {
    return {
        id: 'sandbox-1',
        label: 'Test Sandbox',
        owner: 'test-user',
        permissions: {
            vfs: { read: true, write: true, allowedPaths: [], blockedPaths: [] },
            network: { outbound: false, inbound: false, allowedHosts: [], allowedPorts: [] },
            shell: { enabled: true, allowedCommands: [], blockedCommands: [] },
            events: { emit: true, listen: true, allowedPrefixes: [] },
            canSpawnChildren: false,
        },
        limits: {
            maxFileOpsPerTick: 100,
            maxShellOpsPerTick: 10,
            maxEventsPerTick: 50,
            maxTotalOps: 10000,
        },
        ttlTicks: 0,
        ...overrides,
    };
}

describe('SandboxEngine', () => {
    it('creates and retrieves sandboxes', () => {
        const engine = createSandboxEngine();
        const state = engine.create(makeConfig(), 0);

        expect(state.id).toBe('sandbox-1');
        expect(state.status).toBe('active');
        expect(engine.get('sandbox-1')).not.toBeNull();
        expect(engine.get('nonexistent')).toBeNull();
    });

    it('throws on duplicate sandbox', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig(), 0);
        expect(() => engine.create(makeConfig(), 0)).toThrow();
    });

    it('lists all sandboxes', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig({ id: 's1' }), 0);
        engine.create(makeConfig({ id: 's2' }), 0);
        expect(engine.list().length).toBe(2);
    });

    // ── VFS Permissions ───────────────────────────────────────────

    it('allows VFS read when permitted', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig(), 0);
        expect(engine.check('sandbox-1', 'vfs:read', '/var/log/syslog', 1)).toBe(true);
    });

    it('blocks VFS read when not permitted', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig({
            permissions: {
                vfs: { read: false, write: false, allowedPaths: [], blockedPaths: [] },
                network: { outbound: false, inbound: false, allowedHosts: [], allowedPorts: [] },
                shell: { enabled: false, allowedCommands: [], blockedCommands: [] },
                events: { emit: false, listen: false, allowedPrefixes: [] },
                canSpawnChildren: false,
            },
        }), 0);

        expect(engine.check('sandbox-1', 'vfs:read', '/etc/passwd', 1)).toBe(false);
    });

    it('respects blockedPaths over allowedPaths', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig({
            permissions: {
                vfs: {
                    read: true, write: true,
                    allowedPaths: ['/var/'],
                    blockedPaths: ['/var/secret/'],
                },
                network: { outbound: false, inbound: false, allowedHosts: [], allowedPorts: [] },
                shell: { enabled: false, allowedCommands: [], blockedCommands: [] },
                events: { emit: false, listen: false, allowedPrefixes: [] },
                canSpawnChildren: false,
            },
        }), 0);

        expect(engine.check('sandbox-1', 'vfs:read', '/var/log/test', 1)).toBe(true);
        expect(engine.check('sandbox-1', 'vfs:read', '/var/secret/keys', 1)).toBe(false);
        expect(engine.check('sandbox-1', 'vfs:read', '/etc/passwd', 1)).toBe(false);
    });

    // ── Shell Permissions ─────────────────────────────────────────

    it('allows shell commands when permitted', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig(), 0);
        expect(engine.check('sandbox-1', 'shell:exec', 'ls -la', 1)).toBe(true);
    });

    it('blocks shell when disabled', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig({
            permissions: {
                vfs: { read: true, write: true, allowedPaths: [], blockedPaths: [] },
                network: { outbound: false, inbound: false, allowedHosts: [], allowedPorts: [] },
                shell: { enabled: false, allowedCommands: [], blockedCommands: [] },
                events: { emit: true, listen: true, allowedPrefixes: [] },
                canSpawnChildren: false,
            },
        }), 0);
        expect(engine.check('sandbox-1', 'shell:exec', 'ls', 1)).toBe(false);
    });

    it('respects blockedCommands', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig({
            permissions: {
                vfs: { read: true, write: true, allowedPaths: [], blockedPaths: [] },
                network: { outbound: false, inbound: false, allowedHosts: [], allowedPorts: [] },
                shell: { enabled: true, allowedCommands: [], blockedCommands: ['rm', 'dd'] },
                events: { emit: true, listen: true, allowedPrefixes: [] },
                canSpawnChildren: false,
            },
        }), 0);

        expect(engine.check('sandbox-1', 'shell:exec', 'ls -la', 1)).toBe(true);
        expect(engine.check('sandbox-1', 'shell:exec', 'rm -rf /', 1)).toBe(false);
        expect(engine.check('sandbox-1', 'shell:exec', 'dd if=/dev/zero', 1)).toBe(false);
    });

    // ── Network Permissions ───────────────────────────────────────

    it('blocks network by default', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig(), 0);
        expect(engine.check('sandbox-1', 'network:connect', '10.0.0.1:80', 1)).toBe(false);
        expect(engine.check('sandbox-1', 'network:listen', ':8080', 1)).toBe(false);
    });

    it('allows network when permitted', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig({
            permissions: {
                vfs: { read: true, write: true, allowedPaths: [], blockedPaths: [] },
                network: { outbound: true, inbound: true, allowedHosts: [], allowedPorts: [] },
                shell: { enabled: true, allowedCommands: [], blockedCommands: [] },
                events: { emit: true, listen: true, allowedPrefixes: [] },
                canSpawnChildren: false,
            },
        }), 0);

        expect(engine.check('sandbox-1', 'network:connect', '10.0.0.1:80', 1)).toBe(true);
    });

    // ── Resource Limits ───────────────────────────────────────────

    it('enforces per-tick file ops limit', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig({
            limits: { maxFileOpsPerTick: 2, maxShellOpsPerTick: 10, maxEventsPerTick: 50, maxTotalOps: 10000 },
        }), 0);

        expect(engine.check('sandbox-1', 'vfs:read', '/a', 1)).toBe(true);
        expect(engine.check('sandbox-1', 'vfs:read', '/b', 1)).toBe(true);
        expect(engine.check('sandbox-1', 'vfs:read', '/c', 1)).toBe(false); // limit reached
    });

    it('resets per-tick counters on tick', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig({
            limits: { maxFileOpsPerTick: 1, maxShellOpsPerTick: 10, maxEventsPerTick: 50, maxTotalOps: 10000 },
        }), 0);

        expect(engine.check('sandbox-1', 'vfs:read', '/a', 1)).toBe(true);
        expect(engine.check('sandbox-1', 'vfs:read', '/b', 1)).toBe(false);

        engine.tick('sandbox-1', 2);
        expect(engine.check('sandbox-1', 'vfs:read', '/c', 2)).toBe(true);
    });

    it('enforces total ops limit', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig({
            limits: { maxFileOpsPerTick: 100, maxShellOpsPerTick: 100, maxEventsPerTick: 100, maxTotalOps: 3 },
        }), 0);

        expect(engine.check('sandbox-1', 'vfs:read', '/a', 1)).toBe(true);
        expect(engine.check('sandbox-1', 'vfs:read', '/b', 1)).toBe(true);
        expect(engine.check('sandbox-1', 'vfs:read', '/c', 1)).toBe(true);
        expect(engine.check('sandbox-1', 'vfs:read', '/d', 1)).toBe(false);
    });

    // ── TTL ───────────────────────────────────────────────────────

    it('expires sandbox after TTL', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig({ ttlTicks: 10 }), 0);

        engine.tick('sandbox-1', 5);
        expect(engine.get('sandbox-1')!.status).toBe('active');

        engine.tick('sandbox-1', 10);
        expect(engine.get('sandbox-1')!.status).toBe('expired');

        expect(engine.check('sandbox-1', 'vfs:read', '/a', 11)).toBe(false);
    });

    // ── Suspend/Resume/Terminate ──────────────────────────────────

    it('suspends and resumes sandbox', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig(), 0);

        expect(engine.suspend('sandbox-1')).toBe(true);
        expect(engine.get('sandbox-1')!.status).toBe('suspended');
        expect(engine.check('sandbox-1', 'vfs:read', '/a', 1)).toBe(false);

        expect(engine.resume('sandbox-1')).toBe(true);
        expect(engine.get('sandbox-1')!.status).toBe('active');
        expect(engine.check('sandbox-1', 'vfs:read', '/a', 2)).toBe(true);
    });

    it('terminates sandbox permanently', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig(), 0);

        expect(engine.terminate('sandbox-1')).toBe(true);
        expect(engine.get('sandbox-1')!.status).toBe('terminated');
        expect(engine.resume('sandbox-1')).toBe(false);
    });

    it('suspend/resume/terminate return false for unknown', () => {
        const engine = createSandboxEngine();
        expect(engine.suspend('nope')).toBe(false);
        expect(engine.resume('nope')).toBe(false);
        expect(engine.terminate('nope')).toBe(false);
    });

    // ── Audit Log ─────────────────────────────────────────────────

    it('records all operations in audit log', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig(), 0);

        engine.check('sandbox-1', 'vfs:read', '/a', 1);
        engine.check('sandbox-1', 'shell:exec', 'ls', 2);

        const log = engine.getAuditLog('sandbox-1');
        expect(log.length).toBe(2);
        expect(log[0]!.operation).toBe('vfs:read');
        expect(log[0]!.allowed).toBe(true);
    });

    it('records violations', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig({
            permissions: {
                vfs: { read: false, write: false, allowedPaths: [], blockedPaths: [] },
                network: { outbound: false, inbound: false, allowedHosts: [], allowedPorts: [] },
                shell: { enabled: false, allowedCommands: [], blockedCommands: [] },
                events: { emit: false, listen: false, allowedPrefixes: [] },
                canSpawnChildren: false,
            },
        }), 0);

        engine.check('sandbox-1', 'vfs:read', '/etc/shadow', 1);
        engine.check('sandbox-1', 'shell:exec', 'rm -rf /', 2);

        const violations = engine.getViolations('sandbox-1');
        expect(violations.length).toBe(2);
        expect(violations[0]!.operation).toBe('vfs:read');
    });

    it('onViolation handler fires', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig({
            permissions: {
                vfs: { read: false, write: false, allowedPaths: [], blockedPaths: [] },
                network: { outbound: false, inbound: false, allowedHosts: [], allowedPorts: [] },
                shell: { enabled: false, allowedCommands: [], blockedCommands: [] },
                events: { emit: false, listen: false, allowedPrefixes: [] },
                canSpawnChildren: false,
            },
        }), 0);

        const received: string[] = [];
        engine.onViolation((v) => received.push(v.operation));

        engine.check('sandbox-1', 'vfs:read', '/etc/shadow', 1);
        expect(received).toEqual(['vfs:read']);
    });

    it('onViolation unsubscribe', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig({
            permissions: {
                vfs: { read: false, write: false, allowedPaths: [], blockedPaths: [] },
                network: { outbound: false, inbound: false, allowedHosts: [], allowedPorts: [] },
                shell: { enabled: false, allowedCommands: [], blockedCommands: [] },
                events: { emit: false, listen: false, allowedPrefixes: [] },
                canSpawnChildren: false,
            },
        }), 0);

        const received: string[] = [];
        const unsub = engine.onViolation((v) => received.push(v.operation));

        engine.check('sandbox-1', 'vfs:read', '/a', 1);
        unsub();
        engine.check('sandbox-1', 'vfs:read', '/b', 2);

        expect(received.length).toBe(1);
    });

    // ── Capability Tokens ─────────────────────────────────────────

    it('issues and validates tokens', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig(), 0);

        const token = engine.issueToken('sandbox-1', 'vfs:read', '/secret/', 100);
        expect(token).not.toBeNull();
        expect(engine.checkToken(token!.id, 50)).toBe(true);
    });

    it('token expires', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig(), 0);

        const token = engine.issueToken('sandbox-1', 'vfs:read', '/secret/', 10);
        expect(engine.checkToken(token!.id, 5)).toBe(true);
        expect(engine.checkToken(token!.id, 10)).toBe(false);
    });

    it('token revocation', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig(), 0);

        const token = engine.issueToken('sandbox-1', 'vfs:read', '/secret/', 0);
        expect(engine.checkToken(token!.id, 50)).toBe(true);
        expect(engine.revokeToken(token!.id)).toBe(true);
        expect(engine.checkToken(token!.id, 50)).toBe(false);
        expect(engine.revokeToken(token!.id)).toBe(false); // already revoked
    });

    it('issueToken returns null for unknown sandbox', () => {
        const engine = createSandboxEngine();
        expect(engine.issueToken('nonexistent', 'vfs:read', '/', 0)).toBeNull();
    });

    // ── Event Permissions ─────────────────────────────────────────

    it('allows events with matching prefix', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig({
            permissions: {
                vfs: { read: true, write: true, allowedPaths: [], blockedPaths: [] },
                network: { outbound: false, inbound: false, allowedHosts: [], allowedPorts: [] },
                shell: { enabled: true, allowedCommands: [], blockedCommands: [] },
                events: { emit: true, listen: true, allowedPrefixes: ['scenario:', 'player:'] },
                canSpawnChildren: false,
            },
        }), 0);

        expect(engine.check('sandbox-1', 'event:emit', 'scenario:start', 1)).toBe(true);
        expect(engine.check('sandbox-1', 'event:emit', 'system:shutdown', 1)).toBe(false);
    });

    // ── Spawn Permission ──────────────────────────────────────────

    it('blocks child spawning by default', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig(), 0);
        expect(engine.check('sandbox-1', 'spawn:child', '', 1)).toBe(false);
    });

    it('allows child spawning when permitted', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig({
            permissions: {
                vfs: { read: true, write: true, allowedPaths: [], blockedPaths: [] },
                network: { outbound: false, inbound: false, allowedHosts: [], allowedPorts: [] },
                shell: { enabled: true, allowedCommands: [], blockedCommands: [] },
                events: { emit: true, listen: true, allowedPrefixes: [] },
                canSpawnChildren: true,
            },
        }), 0);

        expect(engine.check('sandbox-1', 'spawn:child', '', 1)).toBe(true);
    });

    // ── Clear ─────────────────────────────────────────────────────

    it('clear removes everything', () => {
        const engine = createSandboxEngine();
        engine.create(makeConfig(), 0);
        engine.clear();
        expect(engine.list().length).toBe(0);
    });
});
