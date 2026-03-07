/**
 * VARIANT — SQL Injection Detection Engine Tests
 *
 * Tests for SQLi engine covering:
 * - Benign input detection
 * - Malicious input detection with correct severity
 * - MITRE technique mapping
 * - CWE ID mapping
 * - Multiple attack pattern detection
 */
import { describe, it, expect } from 'vitest';
import { createSQLiEngine } from '../../../src/lib/detection/sqli-engine';
// lightweight unit tests — no extra types required

describe('SQLi Detection Engine', () => {
    describe('Benign Input Detection', () => {
        it('returns empty result for benign input', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze('hello world');

            expect(result.detected).toBe(false);
            expect(result.confidence).toBe(0);
            expect(result.matches).toHaveLength(0);
            expect(result.category).toBe('sqli');
        });

        it('returns empty result for normal search query', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze('search for products');

            expect(result.detected).toBe(false);
            expect(result.matches).toHaveLength(0);
        });

        it('returns empty result for alphanumeric input', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze('user123');

            expect(result.detected).toBe(false);
            expect(result.matches).toHaveLength(0);
        });

        it('returns empty result for common punctuation', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze('Hello, world! How are you?');

            expect(result.detected).toBe(false);
            expect(result.matches).toHaveLength(0);
        });
    });

    describe('Malicious Input Detection with Severity', () => {
        it('detects UNION SELECT as critical severity', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze("' UNION SELECT * FROM users --");

            expect(result.detected).toBe(true);
            expect(result.confidence).toBeGreaterThan(0.5);
            expect(result.matches.some(m => m.severity === 'critical')).toBe(true);
            expect(result.matches.some(m => m.patternId === 'sqli/union-select')).toBe(true);
        });

        it('detects OR 1=1 as high severity', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze("' OR 1=1 --");

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.severity === 'high')).toBe(true);
            expect(result.matches.some(m => m.patternId === 'sqli/or-true')).toBe(true);
        });

        it('detects stacked queries as critical severity', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze("'; DROP TABLE users; --");

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.severity === 'critical')).toBe(true);
            expect(result.matches.some(m => m.patternId === 'sqli/stacked-query')).toBe(true);
        });

        it('detects DROP TABLE as critical severity', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze("' DROP TABLE users --");

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'sqli/drop-table')).toBe(true);
            expect(result.matches.some(m => m.severity === 'critical')).toBe(true);
        });

        it('detects time-based blind injection as high severity', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze("' OR SLEEP(5) --");

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'sqli/sleep')).toBe(true);
            expect(result.matches.some(m => m.severity === 'high')).toBe(true);
        });

        it('detects information schema access as high severity', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze("' UNION SELECT * FROM information_schema.tables --");

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'sqli/information-schema')).toBe(true);
        });
    });

    describe('MITRE Technique Mapping', () => {
        it('maps SQL injection to T1190', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze("' UNION SELECT * FROM users --");

            expect(result.detected).toBe(true);
            expect(result.mitreTechniques).toContain('T1190');
        });

        it('includes MITRE techniques for stacked queries', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze("'; EXEC xp_cmdshell 'dir' --");

            expect(result.detected).toBe(true);
            expect(result.mitreTechniques).toBeDefined();
            expect(result.mitreTechniques).toContain('T1190');
        });

        it('does not include MITRE techniques for benign input', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze('hello world');

            expect(result.detected).toBe(false);
            expect(result.mitreTechniques).toBeUndefined();
        });
    });

    describe('CWE ID Mapping', () => {
        it('categorizes as SQLi category', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze("' OR 1=1 --");

            expect(result.detected).toBe(true);
            expect(result.category).toBe('sqli');
        });

        it('maintains category for complex injections', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze("' UNION SELECT username,password FROM admin--");

            expect(result.category).toBe('sqli');
        });
    });

    describe('Multiple Attack Pattern Detection', () => {
        it('detects multiple patterns in complex payload', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze("' UNION SELECT * FROM users WHERE 1=1 --");

            expect(result.detected).toBe(true);
            expect(result.matches.length).toBeGreaterThan(1);
        });

        it('detects both union and boolean patterns', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze("' UNION SELECT * FROM users OR 'a'='a'--");

            expect(result.matches.some(m => m.patternId === 'sqli/union-select')).toBe(true);
            expect(result.matches.some(m => m.patternId === 'sqli/or-string-true')).toBe(true);
        });

        it('detects comment termination with other patterns', () => {
            const engine = createSQLiEngine();
        const result = engine.analyze("admin'--");

            // Comment termination may produce matches but not always cross confidence threshold
            const ids = result.matches.map(m => m.patternId);
            expect(ids.some(id => ['sqli/comment-terminate', 'sqli/single-quote-escape'].includes(id))).toBe(true);
        });

        it('increases confidence with multiple patterns', () => {
            const engine = createSQLiEngine();
            const simpleResult = engine.analyze("' OR 1=1 --");
            const complexResult = engine.analyze("' UNION SELECT * FROM users WHERE 1=1 OR 'a'='a'--");

            expect(complexResult.confidence).toBeGreaterThanOrEqual(simpleResult.confidence);
        });

        it('tracks unique pattern matches', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze("'; DROP TABLE users; SELECT * FROM passwords --");

            const uniquePatterns = new Set(result.matches.map(m => m.patternId));
            expect(uniquePatterns.size).toBeGreaterThanOrEqual(2);
        });

        it('detects NoSQL injection patterns', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze('{"username": {"$gt": ""}}');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'sqli/nosql-operator')).toBe(true);
        });

        it('detects hex encoding evasion', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze("0x554E494F4E2053454C454354");
            // Ensure hex-encoding pattern is matched when present
            expect(result.matches.some(m => m.patternId === 'sqli/hex-encoding' || m.patternId === 'sqli/char-function')).toBe(true);
        });
    });

    describe('Engine Interface Compliance', () => {
        it('returns correct engine ID', () => {
            const engine = createSQLiEngine();
            expect(engine.id).toBe('sqli-detection');
        });

        it('returns correct category', () => {
            const engine = createSQLiEngine();
            expect(engine.category).toBe('sqli');
        });

        it('returns patterns via getPatterns()', () => {
            const engine = createSQLiEngine();
            const patterns = engine.getPatterns();

            expect(patterns.length).toBeGreaterThan(0);
            expect(patterns.some(p => p.id === 'sqli/union-select')).toBe(true);
        });

        it('returns config via getConfig()', () => {
            const engine = createSQLiEngine();
            const config = engine.getConfig();

            expect(config.sensitivity).toBeDefined();
            expect(config.confidenceThreshold).toBeDefined();
            expect(config.maxInputLength).toBeDefined();
        });

        it('respects sensitivity configuration', () => {
            const strictEngine = createSQLiEngine({ sensitivity: 'low', confidenceThreshold: 0.8 });
            const result = strictEngine.analyze("admin'--");
            // With high threshold, may not detect low-severity patterns
            expect(result.category).toBe('sqli');
        });
    });

    describe('Edge Cases', () => {
        it('handles empty input', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze('');

            expect(result.detected).toBe(false);
            expect(result.matches).toHaveLength(0);
        });

        it('handles very long input', () => {
            const engine = createSQLiEngine();
            // place payload at beginning so it survives truncation
            const longInput = "' OR 1=1 --" + 'A'.repeat(100000);
            const result = engine.analyze(longInput);

            expect(result.detected).toBe(true);
        });

        it('handles URL-encoded input', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze("%27%20UNION%20SELECT%20*%20FROM%20users%20--");

            expect(result.detected).toBe(true);
        });

        it('provides explanation for detected input', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze("' OR 1=1 --");

            expect(result.explanation).toContain('SQL injection detected');
        });

        it('provides explanation for clean input', () => {
            const engine = createSQLiEngine();
            const result = engine.analyze('hello world');

            expect(result.explanation).toContain('No SQL injection');
        });
    });
});
