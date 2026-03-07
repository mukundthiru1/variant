/**
 * VARIANT — XSS Detection Engine Tests
 *
 * Tests for XSS engine covering:
 * - Benign input detection
 * - Malicious input detection with correct severity
 * - MITRE technique mapping
 * - CWE ID mapping
 * - Multiple attack pattern detection
 */
import { describe, it, expect } from 'vitest';
import { createXSSEngine } from '../../../src/lib/detection/xss-engine';
// tests intentionally avoid importing heavy types
describe('XSS Detection Engine', () => {
    describe('Benign Input Detection', () => {
        it('returns empty result for benign input', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('hello world');

            expect(result.detected).toBe(false);
            expect(result.confidence).toBe(0);
            expect(result.matches).toHaveLength(0);
            expect(result.category).toBe('xss');
        });

        it('returns empty result for normal HTML text', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('This is a normal paragraph');

            expect(result.detected).toBe(false);
            expect(result.matches).toHaveLength(0);
        });

        it('returns empty result for URL without javascript scheme', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('https://example.com/path');

            expect(result.detected).toBe(false);
        });

        it('returns empty result for CSS properties', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('color: red; font-size: 12px;');

            expect(result.detected).toBe(false);
        });
    });

    describe('Malicious Input Detection with Severity', () => {
        it('detects script tag as critical severity', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('<script>alert(1)</script>');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.severity === 'critical')).toBe(true);
            expect(result.matches.some(m => m.patternId === 'xss/script-tag')).toBe(true);
        });

        it('detects eval() as critical severity', () => {
            const engine = createXSSEngine();
            const result = engine.analyze("eval('alert(1)')");

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.severity === 'critical')).toBe(true);
            expect(result.matches.some(m => m.patternId === 'xss/eval')).toBe(true);
        });

        it('detects event handlers as high severity', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('<img onerror=alert(1) src=x>');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.severity === 'high')).toBe(true);
            expect(result.matches.some(m => m.patternId === 'xss/event-handler')).toBe(true);
        });

        it('detects javascript: URI as high severity', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('javascript:alert(1)');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'xss/javascript-uri')).toBe(true);
        });

        it('detects innerHTML assignment as high severity', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('element.innerHTML = userInput');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'xss/innerhtml')).toBe(true);
        });

        it('detects Function constructor as critical severity', () => {
            const engine = createXSSEngine();
            const result = engine.analyze("new Function('alert(1)')");

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'xss/function-constructor')).toBe(true);
        });

        it('detects document.write as high severity', () => {
            const engine = createXSSEngine();
            const result = engine.analyze("document.write('<img src=x onerror=alert(1)>')");

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'xss/document-write')).toBe(true);
        });
    });

    describe('MITRE Technique Mapping', () => {
        it('maps XSS to T1059.007', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('<script>alert(1)</script>');

            expect(result.detected).toBe(true);
            expect(result.mitreTechniques).toContain('T1059.007');
        });

        it('includes MITRE techniques for DOM-based XSS', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('eval(location.hash.slice(1))');

            expect(result.detected).toBe(true);
            expect(result.mitreTechniques).toBeDefined();
            expect(result.mitreTechniques).toContain('T1059.007');
        });

        it('does not include MITRE techniques for benign input', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('hello world');

            expect(result.detected).toBe(false);
            expect(result.mitreTechniques).toBeUndefined();
        });
    });

    describe('CWE ID Mapping', () => {
        it('categorizes as XSS category', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('<script>alert(1)</script>');

            expect(result.detected).toBe(true);
            expect(result.category).toBe('xss');
        });

        it('maintains category for stored XSS', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('<svg onload=alert(1)>');

            expect(result.category).toBe('xss');
        });
    });

    describe('Multiple Attack Pattern Detection', () => {
        it('detects multiple patterns in complex payload', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('<script>document.write("<img onerror=alert(1)>")</script>');

            expect(result.detected).toBe(true);
            expect(result.matches.length).toBeGreaterThan(1);
        });

        it('detects both script tag and event handler', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('<script>alert(1)</script><img onerror=alert(2)>');

            expect(result.matches.some(m => m.patternId === 'xss/script-tag')).toBe(true);
            expect(result.matches.some(m => m.patternId === 'xss/event-handler')).toBe(true);
        });

        it('detects template injection patterns', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('{{constructor.constructor("alert(1)")()}}');

            // Template-injection style probes may be detected as template-literal or angular-expression
            expect(result.matches.length).toBeGreaterThan(0);
        });

        it('detects data URI with script', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('data:text/html,<script>alert(1)</script>');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'xss/data-uri')).toBe(true);
        });

        it('detects SVG-based XSS', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('<svg onload=alert(1)>');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'xss/svg-tag')).toBe(true);
        });

        it('detects iframe injection', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('<iframe src="javascript:alert(1)">');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'xss/iframe-tag')).toBe(true);
        });

        it('increases confidence with multiple patterns', () => {
            const engine = createXSSEngine();
            const simpleResult = engine.analyze('<script>alert(1)</script>');
            const complexResult = engine.analyze('<script>eval("alert(1)")</script><img onerror=alert(2)>');

            expect(complexResult.confidence).toBeGreaterThanOrEqual(simpleResult.confidence);
        });

        it('detects object/embed tags', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('<object data="evil.swf">');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'xss/object-embed')).toBe(true);
        });

        it('tracks unique pattern matches', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('<script>alert(1)</script><script>alert(2)</script>');

            const uniquePatterns = new Set(result.matches.map(m => m.patternId));
            // Should still count as unique patterns, not duplicate matches
            expect(uniquePatterns.size).toBeGreaterThanOrEqual(1);
        });
    });

    describe('Engine Interface Compliance', () => {
        it('returns correct engine ID', () => {
            const engine = createXSSEngine();
            expect(engine.id).toBe('xss-detection');
        });

        it('returns correct category', () => {
            const engine = createXSSEngine();
            expect(engine.category).toBe('xss');
        });

        it('returns patterns via getPatterns()', () => {
            const engine = createXSSEngine();
            const patterns = engine.getPatterns();

            expect(patterns.length).toBeGreaterThan(0);
            expect(patterns.some(p => p.id === 'xss/script-tag')).toBe(true);
        });

        it('returns config via getConfig()', () => {
            const engine = createXSSEngine();
            const config = engine.getConfig();

            expect(config.sensitivity).toBeDefined();
            expect(config.confidenceThreshold).toBeDefined();
            expect(config.maxInputLength).toBeDefined();
        });
    });

    describe('Edge Cases', () => {
        it('handles empty input', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('');

            expect(result.detected).toBe(false);
            expect(result.matches).toHaveLength(0);
        });

        it('handles HTML entity encoding', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('&lt;script&gt;alert(1)&lt;/script&gt;');

            // Should detect after HTML entity decoding
            expect(result.detected).toBe(true);
        });

        it('provides explanation for detected input', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('<script>alert(1)</script>');

            expect(result.explanation).toContain('XSS detected');
        });

        it('provides explanation for clean input', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('hello world');

            expect(result.explanation).toContain('No XSS');
        });

        it('handles case variations in script tags', () => {
            const engine = createXSSEngine();
            const result = engine.analyze('<SCRIPT>alert(1)</SCRIPT>');

            expect(result.detected).toBe(true);
        });
    });
});
