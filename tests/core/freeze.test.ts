/**
 * VARIANT — Deep Freeze Tests
 *
 * Verifies that deepFreeze makes the entire object graph immutable.
 */

import { describe, it, expect } from 'vitest';
import { deepFreeze } from '../../src/core/freeze';

describe('deepFreeze', () => {
    it('freezes a simple object', () => {
        const obj = deepFreeze({ a: 1, b: 'hello' });
        expect(Object.isFrozen(obj)).toBe(true);
        expect(() => { (obj as Record<string, unknown>)['a'] = 999; }).toThrow();
    });

    it('deeply freezes nested objects', () => {
        const obj = deepFreeze({
            meta: { title: 'test', tags: ['a', 'b'] },
            machines: { vm1: { hostname: 'test', files: { '/etc/passwd': { content: 'root' } } } },
        });

        expect(Object.isFrozen(obj.meta)).toBe(true);
        expect(Object.isFrozen(obj.meta.tags)).toBe(true);
        expect(Object.isFrozen(obj.machines)).toBe(true);
        expect(Object.isFrozen(obj.machines['vm1'])).toBe(true);
        expect(Object.isFrozen(obj.machines['vm1']?.files)).toBe(true);

        expect(() => {
            (obj.meta as Record<string, unknown>)['title'] = 'hacked';
        }).toThrow();

        expect(() => {
            (obj.machines as Record<string, unknown>)['vm2'] = {};
        }).toThrow();
    });

    it('handles arrays', () => {
        const obj = deepFreeze([{ a: 1 }, { b: 2 }]);
        expect(Object.isFrozen(obj)).toBe(true);
        expect(Object.isFrozen(obj[0])).toBe(true);
        expect(() => { (obj as unknown[]).push({ c: 3 }); }).toThrow();
    });

    it('returns primitives as-is', () => {
        expect(deepFreeze(42)).toBe(42);
        expect(deepFreeze('hello')).toBe('hello');
        expect(deepFreeze(null)).toBe(null);
        expect(deepFreeze(undefined)).toBe(undefined);
        expect(deepFreeze(true)).toBe(true);
    });

    it('handles circular references without infinite loop', () => {
        const a: Record<string, unknown> = { name: 'a' };
        const b: Record<string, unknown> = { name: 'b', ref: a };
        a['ref'] = b;

        const frozen = deepFreeze(a);
        expect(Object.isFrozen(frozen)).toBe(true);
        expect(Object.isFrozen(b)).toBe(true);
    });

    it('does not freeze ArrayBuffers', () => {
        const buf = new ArrayBuffer(16);
        const obj = deepFreeze({ data: buf });

        expect(Object.isFrozen(obj)).toBe(true);
        // ArrayBuffer should NOT be frozen (v86 snapshots need mutable buffers)
        expect(Object.isFrozen(buf)).toBe(false);
    });

    it('does not freeze Uint8Arrays', () => {
        const arr = new Uint8Array([1, 2, 3]);
        const obj = deepFreeze({ bytes: arr });

        expect(Object.isFrozen(obj)).toBe(true);
        expect(Object.isFrozen(arr)).toBe(false);
    });
});
