/**
 * VARIANT — WorldSpec Validator Tests
 *
 * Tests the security gate. Every WorldSpec passes through
 * the validator before entering the engine.
 */

import { describe, it, expect } from 'vitest';
import { validateWorldSpec } from '../../src/core/world/validator';

/** Minimal valid WorldSpec for testing. */
function minimalWorldSpec(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
        version: '2.0',
        trust: 'community',
        meta: {
            title: 'Test Level',
            scenario: 'A test scenario',
            briefing: ['You are testing.'],
            difficulty: 'beginner',
            mode: 'attack',
            vulnClasses: ['test'],
            tags: ['test'],
            estimatedMinutes: 10,
            author: { name: 'Tester', id: 'test-01', type: 'santh' },
        },
        machines: {
            'attacker': {
                hostname: 'kali',
                image: 'alpine-kali-tools',
                memoryMB: 64,
                role: 'player',
                interfaces: [{ ip: '10.0.1.5', segment: 'corporate' }],
            },
        },
        startMachine: 'attacker',
        network: {
            segments: [{ id: 'corporate', subnet: '10.0.1.0/24' }],
            edges: [],
        },
        credentials: [],
        objectives: [{
            id: 'obj-1',
            title: 'Test Objective',
            description: 'Complete the test',
            type: 'find-file',
            required: true,
            details: { kind: 'find-file', machine: 'attacker', path: '/root/flag.txt' },
        }],
        modules: [],
        scoring: {
            maxScore: 100,
            timeBonus: false,
            stealthBonus: false,
            hintPenalty: 10,
            tiers: [{ name: 'COMPLETE', minScore: 50, color: '#00ff41' }],
        },
        hints: ['Check the /root directory.'],
        ...overrides,
    };
}

describe('WorldSpec Validator', () => {
    // ── Valid specs ──────────────────────────────────────────────

    it('accepts a minimal valid WorldSpec', () => {
        const result = validateWorldSpec(minimalWorldSpec());
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
    });

    // ── Structural validation ───────────────────────────────────

    it('rejects null input', () => {
        const result = validateWorldSpec(null);
        expect(result.valid).toBe(false);
        expect(result.errors[0]?.code).toBe('INVALID_TYPE');
    });

    it('rejects non-object input', () => {
        const result = validateWorldSpec('not an object');
        expect(result.valid).toBe(false);
    });

    it('rejects wrong version', () => {
        const result = validateWorldSpec(minimalWorldSpec({ version: '1.0' }));
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.path === '$.version')).toBe(true);
    });

    it('rejects invalid trust level', () => {
        const result = validateWorldSpec(minimalWorldSpec({ trust: 'superadmin' }));
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.path === '$.trust')).toBe(true);
    });

    // ── Machine validation ──────────────────────────────────────

    it('rejects machines with no entries', () => {
        const result = validateWorldSpec(minimalWorldSpec({ machines: {} }));
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.code === 'MISSING_FIELD')).toBe(true);
    });

    it('rejects invalid hostname', () => {
        const result = validateWorldSpec(minimalWorldSpec({
            machines: {
                'bad': {
                    hostname: 'UPPERCASE-BAD!',
                    image: 'alpine',
                    memoryMB: 64,
                    role: 'player',
                    interfaces: [],
                },
            },
        }));
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.path.includes('hostname'))).toBe(true);
    });

    it('rejects memory outside bounds', () => {
        const result = validateWorldSpec(minimalWorldSpec({
            machines: {
                'attacker': {
                    hostname: 'kali',
                    image: 'alpine',
                    memoryMB: 1024, // too high
                    role: 'player',
                    interfaces: [],
                },
            },
        }));
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.code === 'RESOURCE_LIMIT')).toBe(true);
    });

    it('rejects invalid role', () => {
        const result = validateWorldSpec(minimalWorldSpec({
            machines: {
                'attacker': {
                    hostname: 'kali',
                    image: 'alpine',
                    memoryMB: 64,
                    role: 'god-mode', // invalid
                    interfaces: [],
                },
            },
        }));
        expect(result.valid).toBe(false);
    });

    // ── startMachine validation ─────────────────────────────────

    it('rejects startMachine referencing nonexistent machine', () => {
        const result = validateWorldSpec(minimalWorldSpec({ startMachine: 'nonexistent' }));
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.code === 'INVALID_REFERENCE')).toBe(true);
    });

    // ── Security: code injection ────────────────────────────────

    it('rejects functions in WorldSpec', () => {
        const spec = minimalWorldSpec();
        // Inject a function into the spec
        (spec as Record<string, unknown>)['malicious'] = function exploit() { /* steal data */ };

        const result = validateWorldSpec(spec);
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.code === 'SECURITY_VIOLATION')).toBe(true);
    });

    it('rejects __proto__ keys (prototype pollution)', () => {
        // JSON.parse correctly creates an own property named '__proto__'
        // (unlike direct assignment which triggers the __proto__ setter).
        // This test simulates what happens when a malicious WorldSpec
        // arrives as JSON with a __proto__ key.
        const spec = JSON.parse(JSON.stringify(minimalWorldSpec()));
        Object.defineProperty(spec, '__proto__', {
            value: { isAdmin: true },
            enumerable: true,
            writable: true,
            configurable: true,
        });

        const result = validateWorldSpec(spec);
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.code === 'SECURITY_VIOLATION')).toBe(true);
    });

    it('rejects constructor keys', () => {
        const spec = minimalWorldSpec();
        (spec as Record<string, unknown>)['constructor'] = { prototype: {} };

        const result = validateWorldSpec(spec);
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.code === 'SECURITY_VIOLATION')).toBe(true);
    });

    // ── Security: path traversal ────────────────────────────────

    it('rejects file paths with ..', () => {
        const result = validateWorldSpec(minimalWorldSpec({
            machines: {
                'attacker': {
                    hostname: 'kali',
                    image: 'alpine',
                    memoryMB: 64,
                    role: 'player',
                    interfaces: [],
                    files: {
                        '/../../etc/shadow': { content: 'stolen' },
                    },
                },
            },
        }));
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.code === 'PATH_TRAVERSAL')).toBe(true);
    });

    it('rejects file paths with null bytes', () => {
        const result = validateWorldSpec(minimalWorldSpec({
            machines: {
                'attacker': {
                    hostname: 'kali',
                    image: 'alpine',
                    memoryMB: 64,
                    role: 'player',
                    interfaces: [],
                    files: {
                        '/root/flag.txt\0.jpg': { content: 'trick' },
                    },
                },
            },
        }));
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.code === 'SECURITY_VIOLATION' || e.code === 'PATH_TRAVERSAL')).toBe(true);
    });

    it('rejects relative file paths', () => {
        const result = validateWorldSpec(minimalWorldSpec({
            machines: {
                'attacker': {
                    hostname: 'kali',
                    image: 'alpine',
                    memoryMB: 64,
                    role: 'player',
                    interfaces: [],
                    files: {
                        'relative/path': { content: 'bad' },
                    },
                },
            },
        }));
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.code === 'SECURITY_VIOLATION')).toBe(true);
    });

    // ── Trust boundary ──────────────────────────────────────────

    it('rejects invariant-live payloads in community levels', () => {
        const result = validateWorldSpec(minimalWorldSpec({
            trust: 'community',
            objectives: [{
                id: 'obj-1',
                title: 'Write Rule',
                description: 'Write a defense rule',
                type: 'write-rule',
                required: true,
                details: {
                    kind: 'write-rule',
                    vulnClass: 'sqli',
                    minDetection: 0.8,
                    maxFalsePositive: 0.05,
                    payloadSource: 'invariant-live',
                },
            }],
        }));
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.code === 'TRUST_VIOLATION')).toBe(true);
    });

    it('allows invariant-live payloads in curated levels', () => {
        const result = validateWorldSpec(minimalWorldSpec({
            trust: 'curated',
            objectives: [{
                id: 'obj-1',
                title: 'Write Rule',
                description: 'Write a defense rule',
                type: 'write-rule',
                required: true,
                details: {
                    kind: 'write-rule',
                    vulnClass: 'sqli',
                    minDetection: 0.8,
                    maxFalsePositive: 0.05,
                    payloadSource: 'invariant-live',
                },
            }],
        }));
        // Should not have trust violations
        expect(result.errors.filter(e => e.code === 'TRUST_VIOLATION')).toHaveLength(0);
    });

    // ── Resource limits ─────────────────────────────────────────

    it('rejects too many machines', () => {
        const machines: Record<string, unknown> = {};
        for (let i = 0; i < 25; i++) {
            machines[`vm-${i}`] = {
                hostname: `vm${i}`,
                image: 'alpine',
                memoryMB: 32,
                role: 'target',
                interfaces: [],
            };
        }
        machines['player'] = {
            hostname: 'kali',
            image: 'alpine',
            memoryMB: 64,
            role: 'player',
            interfaces: [],
        };

        const result = validateWorldSpec(minimalWorldSpec({
            machines,
            startMachine: 'player',
        }));
        expect(result.errors.some(e => e.code === 'RESOURCE_LIMIT')).toBe(true);
    });

    // ── Network validation ──────────────────────────────────────

    it('rejects missing network field', () => {
        const spec = minimalWorldSpec();
        delete (spec as Record<string, unknown>)['network'];
        const result = validateWorldSpec(spec);
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.path === '$.network')).toBe(true);
    });

    it('rejects network without segments', () => {
        const result = validateWorldSpec(minimalWorldSpec({
            network: { edges: [] },
        }));
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.path === '$.network.segments')).toBe(true);
    });

    it('rejects segment with invalid subnet', () => {
        const result = validateWorldSpec(minimalWorldSpec({
            network: {
                segments: [{ id: 'corporate', subnet: 'not-a-cidr' }],
                edges: [],
            },
        }));
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.path.includes('subnet'))).toBe(true);
    });

    it('rejects segment with invalid gateway', () => {
        const result = validateWorldSpec(minimalWorldSpec({
            network: {
                segments: [{ id: 'corporate', subnet: '10.0.1.0/24', gateway: 'not-an-ip' }],
                edges: [],
            },
        }));
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.path.includes('gateway'))).toBe(true);
    });

    it('rejects duplicate segment IDs', () => {
        const result = validateWorldSpec(minimalWorldSpec({
            network: {
                segments: [
                    { id: 'same', subnet: '10.0.1.0/24' },
                    { id: 'same', subnet: '10.0.2.0/24' },
                ],
                edges: [],
            },
        }));
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.message.includes('Duplicate segment'))).toBe(true);
    });

    // ── Scoring validation ──────────────────────────────────────

    it('rejects missing scoring field', () => {
        const spec = minimalWorldSpec();
        delete (spec as Record<string, unknown>)['scoring'];
        const result = validateWorldSpec(spec);
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.path === '$.scoring')).toBe(true);
    });

    it('rejects scoring without maxScore', () => {
        const result = validateWorldSpec(minimalWorldSpec({
            scoring: { hintPenalty: 10, tiers: [] },
        }));
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.path === '$.scoring.maxScore')).toBe(true);
    });

    it('rejects scoring with negative hintPenalty', () => {
        const result = validateWorldSpec(minimalWorldSpec({
            scoring: { maxScore: 100, hintPenalty: -5, tiers: [] },
        }));
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.path === '$.scoring.hintPenalty')).toBe(true);
    });

    // ── Hints validation ────────────────────────────────────────

    it('rejects non-array hints', () => {
        const result = validateWorldSpec(minimalWorldSpec({
            hints: 'not-an-array',
        }));
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.path === '$.hints')).toBe(true);
    });

    it('accepts empty hints array', () => {
        const result = validateWorldSpec(minimalWorldSpec({ hints: [] }));
        // Should not fail due to hints being empty
        expect(result.errors.filter(e => e.path === '$.hints')).toHaveLength(0);
    });

    // ── Interface validation ────────────────────────────────────

    it('rejects interfaces with invalid IP', () => {
        const result = validateWorldSpec(minimalWorldSpec({
            machines: {
                'attacker': {
                    hostname: 'kali',
                    image: 'alpine',
                    memoryMB: 64,
                    role: 'player',
                    interfaces: [{ ip: 'not-an-ip', segment: 'corporate' }],
                },
            },
        }));
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.path.includes('.ip'))).toBe(true);
    });

    it('rejects interfaces with empty segment', () => {
        const result = validateWorldSpec(minimalWorldSpec({
            machines: {
                'attacker': {
                    hostname: 'kali',
                    image: 'alpine',
                    memoryMB: 64,
                    role: 'player',
                    interfaces: [{ ip: '10.0.1.5', segment: '' }],
                },
            },
        }));
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.path.includes('.segment'))).toBe(true);
    });

    // ── Cross-reference validation ──────────────────────────────

    it('rejects interface referencing nonexistent segment', () => {
        const result = validateWorldSpec(minimalWorldSpec({
            machines: {
                'attacker': {
                    hostname: 'kali',
                    image: 'alpine',
                    memoryMB: 64,
                    role: 'player',
                    interfaces: [{ ip: '10.0.1.5', segment: 'nonexistent' }],
                },
            },
            network: {
                segments: [{ id: 'corporate', subnet: '10.0.1.0/24' }],
                edges: [],
            },
        }));
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.code === 'INVALID_REFERENCE' && e.message.includes('nonexistent'))).toBe(true);
    });

    it('warns on machines without interfaces', () => {
        const result = validateWorldSpec(minimalWorldSpec({
            machines: {
                'attacker': {
                    hostname: 'kali',
                    image: 'alpine',
                    memoryMB: 64,
                    role: 'player',
                    interfaces: [],
                },
            },
        }));
        // Warning, not error
        expect(result.warnings.some(w => w.message.includes('no interfaces'))).toBe(true);
    });
});
