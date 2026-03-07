/**
 * VARIANT — Detection Engine tests (Registry + Rule Scorer + SQLi engine)
 */
import { describe, it, expect } from 'vitest';
import { createDetectionEngineRegistry, scoreDetectionRule } from '../../../src/lib/detection/registry';
import { createSQLiEngine } from '../../../src/lib/detection/sqli-engine';
import type { DetectionEngine, DetectionResult, DetectionPattern, DetectionEngineConfig, TestCorpusEntry } from '../../../src/lib/detection/types';

function mockEngine(id: string, category: string): DetectionEngine {
    return {
        id,
        category,
        version: '1.0.0',
        description: `Mock ${id}`,
        analyze(input: string): DetectionResult {
            const detected = input.includes('MALICIOUS');
            return {
                detected,
                confidence: detected ? 0.9 : 0.1,
                matches: [],
                explanation: detected ? 'Found malicious pattern' : 'Clean',
                category,
            };
        },
        getPatterns(): readonly DetectionPattern[] {
            return [];
        },
        getConfig(): DetectionEngineConfig {
            return { sensitivity: 'medium', confidenceThreshold: 0.5, maxInputLength: 65536, decodeUrl: true, normalizeWhitespace: true };
        },
    };
}

describe('DetectionEngineRegistry', () => {
    it('registers and retrieves engines', () => {
        const reg = createDetectionEngineRegistry();
        reg.register(mockEngine('sqli-1', 'sqli'));

        expect(reg.get('sqli-1')).not.toBeUndefined();
        expect(reg.get('nonexistent')).toBeUndefined();
        expect(reg.getAll().length).toBe(1);
    });

    it('throws on duplicate engine', () => {
        const reg = createDetectionEngineRegistry();
        reg.register(mockEngine('e1', 'sqli'));
        expect(() => reg.register(mockEngine('e1', 'xss'))).toThrow();
    });

    it('filters engines by category', () => {
        const reg = createDetectionEngineRegistry();
        reg.register(mockEngine('sqli-1', 'sqli'));
        reg.register(mockEngine('xss-1', 'xss'));
        reg.register(mockEngine('sqli-2', 'sqli'));

        expect(reg.getByCategory('sqli').length).toBe(2);
        expect(reg.getByCategory('xss').length).toBe(1);
        expect(reg.getByCategory('cmdi').length).toBe(0);
    });

    it('analyzeAll runs all engines', () => {
        const reg = createDetectionEngineRegistry();
        reg.register(mockEngine('e1', 'sqli'));
        reg.register(mockEngine('e2', 'xss'));

        const results = reg.analyzeAll('clean input');
        expect(results.length).toBe(2);
    });

    it('analyzeAll detects malicious input', () => {
        const reg = createDetectionEngineRegistry();
        reg.register(mockEngine('e1', 'sqli'));

        const results = reg.analyzeAll('MALICIOUS input');
        expect(results[0]!.detected).toBe(true);
    });

    it('analyzeByCategory only runs relevant engines', () => {
        const reg = createDetectionEngineRegistry();
        reg.register(mockEngine('sqli-1', 'sqli'));
        reg.register(mockEngine('xss-1', 'xss'));

        const results = reg.analyzeByCategory('test', 'sqli');
        expect(results.length).toBe(1);
    });
});

describe('scoreDetectionRule', () => {
    it('scores a perfect detector', () => {
        const corpus: TestCorpusEntry[] = [
            { input: 'SELECT * FROM users', malicious: true },
            { input: 'hello world', malicious: false },
        ];

        const result = scoreDetectionRule(
            (input) => input.includes('SELECT'),
            corpus,
        );

        expect(result.breakdown.truePositives).toBe(1);
        expect(result.breakdown.trueNegatives).toBe(1);
        expect(result.breakdown.falsePositives).toBe(0);
        expect(result.breakdown.falseNegatives).toBe(0);
        expect(result.f1Score).toBe(1);
    });

    it('scores a detector with false positives', () => {
        const corpus: TestCorpusEntry[] = [
            { input: 'DROP TABLE', malicious: true },
            { input: 'drop the beat', malicious: false },
        ];

        const result = scoreDetectionRule(
            (input) => input.toLowerCase().includes('drop'),
            corpus,
        );

        expect(result.breakdown.truePositives).toBe(1);
        expect(result.breakdown.falsePositives).toBe(1);
        expect(result.falsePositiveRate).toBe(1);
    });

    it('scores a detector that misses everything', () => {
        const corpus: TestCorpusEntry[] = [
            { input: 'SELECT 1', malicious: true },
            { input: 'hello', malicious: false },
        ];

        const result = scoreDetectionRule(
            () => false,
            corpus,
        );

        expect(result.breakdown.falseNegatives).toBe(1);
        expect(result.truePositiveRate).toBe(0);
        expect(result.f1Score).toBe(0);
    });

    it('handles empty corpus', () => {
        const result = scoreDetectionRule(() => true, []);
        expect(result.totalInputs).toBe(0);
        expect(result.f1Score).toBe(0);
    });
});

describe('SQLi Detection Engine', () => {
    it('detects basic UNION SELECT', () => {
        const engine = createSQLiEngine();
        const result = engine.analyze("' UNION SELECT * FROM users --");
        expect(result.detected).toBe(true);
        expect(result.category).toBe('sqli');
    });

    it('detects OR 1=1 pattern', () => {
        const engine = createSQLiEngine();
        const result = engine.analyze("' OR 1=1 --");
        expect(result.detected).toBe(true);
    });

    it('does not flag clean input', () => {
        const engine = createSQLiEngine();
        const result = engine.analyze('hello world');
        expect(result.detected).toBe(false);
    });

    it('has patterns available', () => {
        const engine = createSQLiEngine();
        expect(engine.getPatterns().length).toBeGreaterThan(0);
    });

    it('returns config', () => {
        const engine = createSQLiEngine();
        const config = engine.getConfig();
        expect(config.sensitivity).toBeDefined();
    });
});
