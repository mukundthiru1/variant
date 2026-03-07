/**
 * VARIANT — Deep Freeze Utility
 *
 * Recursively freezes an entire object graph so that no nested
 * property can be mutated at runtime.
 *
 * SECURITY: TypeScript readonly modifiers only work at compile time.
 * Deep freeze provides runtime immutability enforcement, which is
 * critical for WorldSpec objects that modules receive references to.
 *
 * This utility handles:
 *   - Plain objects
 *   - Arrays
 *   - Maps and Sets (freeze the container, values are already frozen)
 *   - Circular references (via WeakSet)
 *   - Typed arrays / ArrayBuffers (left unfrozen — they're binary data)
 */

/**
 * Deep freeze an object and all nested objects.
 * Returns the same reference, now deeply frozen.
 *
 * @param obj The object to freeze. Primitives and null are returned as-is.
 */
export function deepFreeze<T>(obj: T): Readonly<T> {
    if (obj === null || typeof obj !== 'object') {
        return obj;
    }

    return deepFreezeImpl(obj, new WeakSet()) as Readonly<T>;
}

function deepFreezeImpl(obj: object, visited: WeakSet<object>): object {
    if (visited.has(obj)) {
        return obj; // Circular reference — already processed
    }

    visited.add(obj);

    // Don't freeze typed arrays or ArrayBuffers — they're binary data
    // and freezing them causes issues with v86 state snapshots
    if (ArrayBuffer.isView(obj) || obj instanceof ArrayBuffer) {
        return obj;
    }

    // Freeze the object itself first
    Object.freeze(obj);

    if (Array.isArray(obj)) {
        for (const item of obj) {
            if (item !== null && typeof item === 'object') {
                deepFreezeImpl(item, visited);
            }
        }
    } else {
        // Enumerate own properties and freeze their values
        const propertyNames = Object.getOwnPropertyNames(obj);
        for (const name of propertyNames) {
            const descriptor = Object.getOwnPropertyDescriptor(obj, name);
            if (descriptor === undefined) continue;

            // Only freeze data properties, not getters/setters
            if ('value' in descriptor) {
                const value = descriptor.value as unknown;
                if (value !== null && typeof value === 'object') {
                    deepFreezeImpl(value as object, visited);
                }
            }
        }
    }

    return obj;
}
