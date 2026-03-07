import { describe, it, expect } from 'vitest';
import { createMigrationRegistry } from '../../src/core/index';

describe('WorldSpec Migration', () => {
    it('migrates basic 1.0.0 spec to 2.0', () => {
        const registry = createMigrationRegistry();
        const oldSpec = {
            version: '1.0.0',
            meta: {
                title: 'Test',
                description: 'A test scenario',
                author: { name: 'Alice', id: 'alice' }
            },
            credentials: [
                { id: 'cred1', type: 'password', value: 'secret', machine: 'db', path: '/etc/passwd', service: 'ssh', user: 'admin' }
            ]
        };

        const { result, steps } = registry.migrate(oldSpec, '2.0');
        
        expect(steps.length).toBe(1);
        expect(steps[0]).toMatch(/Upgrade to 2.0/);
        
        const migrated = result as any;
        expect(migrated.version).toBe('2.0');
        expect(migrated.meta.scenario).toBe('A test scenario');
        expect(migrated.meta.description).toBeUndefined();
        expect(migrated.trust).toBe('community');
        expect(migrated.scoring).toBeDefined();
        
        expect(migrated.credentials[0].foundAt.machine).toBe('db');
        expect(migrated.credentials[0].foundAt.path).toBe('/etc/passwd');
        expect(migrated.credentials[0].validAt.machine).toBe('db');
        expect(migrated.credentials[0].validAt.service).toBe('ssh');
        expect(migrated.credentials[0].validAt.user).toBe('admin');
        
        // Input is not mutated
        expect(oldSpec.version).toBe('1.0.0');
        expect((oldSpec.meta as any).description).toBe('A test scenario');
    });

    it('returns no-op if versions match', () => {
        const registry = createMigrationRegistry();
        const spec = { version: '2.0', trust: 'curated' };
        
        const { result, steps } = registry.migrate(spec, '2.0');
        
        expect(steps.length).toBe(0);
        expect(result).toEqual(spec);
    });

    it('throws on unknown version or missing path', () => {
        const registry = createMigrationRegistry();
        const spec = { version: '0.9.0' };
        
        expect(() => registry.migrate(spec, '2.0')).toThrow(/No migration path found/);
    });

    it('finds multi-step migration path', () => {
        const registry = createMigrationRegistry();
        
        registry.register({
            fromVersion: '2.0',
            toVersion: '2.1',
            description: '2.0 to 2.1',
            migrate: (s: any) => ({ ...s, version: '2.1', field21: true })
        });
        
        registry.register({
            fromVersion: '2.1',
            toVersion: '3.0',
            description: '2.1 to 3.0',
            migrate: (s: any) => ({ ...s, version: '3.0', field30: true })
        });

        const spec = { version: '2.0' };
        const { result, steps } = registry.migrate(spec, '3.0');
        
        expect(steps.length).toBe(2);
        expect(steps[0]).toBe('2.0 to 2.1');
        expect(steps[1]).toBe('2.1 to 3.0');
        
        const res = result as any;
        expect(res.version).toBe('3.0');
        expect(res.field21).toBe(true);
        expect(res.field30).toBe(true);
    });

    it('preserves data during migration', () => {
        const registry = createMigrationRegistry();
        const oldSpec = {
            version: '1.0.0',
            meta: { title: 'T' },
            machines: { 'm1': { image: 'ubuntu' } },
            network: { segments: [] }
        };

        const { result } = registry.migrate(oldSpec, '2.0');
        const res = result as any;
        expect(res.machines.m1.image).toBe('ubuntu');
        expect(res.network.segments).toEqual([]);
    });

    it('rejects duplicate steps', () => {
        const registry = createMigrationRegistry();
        
        expect(() => {
            registry.register({
                fromVersion: '1.0.0',
                toVersion: '2.0',
                description: 'duplicate',
                migrate: s => s
            });
        }).toThrow(/already registered/);
    });

    it('canMigrate returns true for valid path and false otherwise', () => {
        const registry = createMigrationRegistry();
        expect(registry.canMigrate('1.0.0', '2.0')).toBe(true);
        expect(registry.canMigrate('0.9.0', '2.0')).toBe(false);
    });
});
