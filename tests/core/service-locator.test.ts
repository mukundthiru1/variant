/**
 * VARIANT — Service Locator Tests
 *
 * Tests for inter-module service registry.
 */

import { describe, it, expect } from 'vitest';
import { createServiceLocator } from '../../src/core/modules';

describe('ServiceLocator', () => {
    it('registers and retrieves a service', () => {
        const locator = createServiceLocator();
        const svc = { query: (sql: string) => sql };

        locator.register('sql-engine', svc);

        expect(locator.has('sql-engine')).toBe(true);
        expect(locator.get('sql-engine')).toBe(svc);
    });

    it('returns undefined for unregistered services', () => {
        const locator = createServiceLocator();

        expect(locator.has('nonexistent')).toBe(false);
        expect(locator.get('nonexistent')).toBeUndefined();
    });

    it('throws on duplicate registration', () => {
        const locator = createServiceLocator();
        locator.register('svc', { a: 1 });

        expect(() => locator.register('svc', { a: 2 })).toThrow(/already registered/);
    });

    it('throws on empty service name', () => {
        const locator = createServiceLocator();

        expect(() => locator.register('', {})).toThrow(/non-empty/);
    });

    it('lists all registered service names', () => {
        const locator = createServiceLocator();
        locator.register('alpha', { x: 1 });
        locator.register('beta', { x: 2 });
        locator.register('gamma', { x: 3 });

        const names = locator.list();
        expect(names).toContain('alpha');
        expect(names).toContain('beta');
        expect(names).toContain('gamma');
        expect(names.length).toBe(3);
    });

    it('list returns a frozen array', () => {
        const locator = createServiceLocator();
        locator.register('svc', {});

        const list = locator.list();
        expect(() => {
            (list as string[]).push('injected');
        }).toThrow();
    });

    it('supports typed retrieval via generics', () => {
        interface SQLEngine {
            query(sql: string): string[];
        }

        const locator = createServiceLocator();
        const engine: SQLEngine = { query: (sql) => [sql] };
        locator.register('sql', engine);

        const retrieved = locator.get<SQLEngine>('sql');
        expect(retrieved).toBeDefined();
        expect(retrieved!.query('SELECT 1')).toEqual(['SELECT 1']);
    });

    it('allows registering different value types', () => {
        const locator = createServiceLocator();

        locator.register('string-svc', 'hello');
        locator.register('number-svc', 42);
        locator.register('fn-svc', () => 'result');
        locator.register('null-svc', null);

        expect(locator.get('string-svc')).toBe('hello');
        expect(locator.get('number-svc')).toBe(42);
        expect(typeof locator.get('fn-svc')).toBe('function');
        expect(locator.get('null-svc')).toBeNull();
    });
});
