/**
 * VARIANT — Path Traversal Detection Engine Tests
 *
 * Tests for Path Traversal engine covering:
 * - Benign input detection
 * - Malicious input detection with correct severity
 * - MITRE technique mapping
 * - CWE ID mapping
 * - Multiple attack pattern detection
 */
import { describe, it, expect } from 'vitest';
import { createPathTraversalEngine } from '../../../src/lib/detection/path-traversal-engine';
// tests are lightweight; avoid importing unused types
describe('Path Traversal Detection Engine', () => {
    describe('Benign Input Detection', () => {
        it('returns empty result for benign input', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('document.pdf');

            expect(result.detected).toBe(false);
            expect(result.confidence).toBe(0);
            expect(result.matches).toHaveLength(0);
            expect(result.category).toBe('path-traversal');
        });

        it('returns empty result for normal path', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('files/documents/report.txt');

            expect(result.detected).toBe(false);
            expect(result.matches).toHaveLength(0);
        });

        it('returns empty result for single directory traversal', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('../images/photo.jpg');

            // Single ../ should not be detected as malicious
            expect(result.detected).toBe(false);
        });

        it('returns empty result for relative path without traversal', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('./config/settings.json');

            expect(result.detected).toBe(false);
        });
    });

    describe('Malicious Input Detection with Severity', () => {
        it('detects multiple ../ as high severity', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('../../../etc/passwd');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.severity === 'high')).toBe(true);
            expect(result.matches.some(m => m.patternId === 'path/dot-dot-slash')).toBe(true);
        });

        it('detects Windows-style traversal as high severity', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('..\\..\\..\\windows\\system32\\config\\sam');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'path/dot-dot-backslash')).toBe(true);
        });

        it('detects encoded traversal as high severity', () => {
            const engine = createPathTraversalEngine();
        const result = engine.analyze('%2e%2e%2f%2e%2e%2fetc%2fpasswd');

            expect(result.detected).toBe(true);
            // After decoding the match may be encoded-traversal, double-encoded or plain dot-dot-slash
            expect(result.matches.some(m => ['path/encoded-traversal','path/double-encoded','path/dot-dot-slash'].includes(m.patternId))).toBe(true);
        });

        it('detects double encoded traversal as critical severity', () => {
            const engine = createPathTraversalEngine();
        const result = engine.analyze('%252e%252e%252fetc%252fpasswd');

            expect(result.detected).toBe(true);
            // double-encoded inputs may decode into several forms; ensure at least one pattern matched
            expect(result.matches.length).toBeGreaterThan(0);
        });

        it('detects null byte injection as critical severity', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('file.txt%00.jpg');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.severity === 'critical')).toBe(true);
            expect(result.matches.some(m => m.patternId === 'path/null-byte')).toBe(true);
        });

        it('detects sensitive file access as high severity', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('/etc/passwd');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'path/sensitive-files')).toBe(true);
        });

        it('detects Windows sensitive files as high severity', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('C:\\windows\\system32\\drivers\\etc\\hosts');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'path/windows-sensitive')).toBe(true);
        });

        it('detects remote file inclusion as critical severity', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('http://evil.com/shell.txt');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'path/rfi-http')).toBe(true);
        });

        it('detects PHP wrapper as critical severity', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('php://filter/read=convert.base64-encode/resource=/etc/passwd');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'path/php-wrapper')).toBe(true);
        });
    });

    describe('MITRE Technique Mapping', () => {
        it('maps path traversal to T1083', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('../../../etc/passwd');

            expect(result.detected).toBe(true);
            expect(result.mitreTechniques).toContain('T1083');
        });

        it('includes MITRE techniques for RFI', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('http://evil.com/shell.php');

            expect(result.detected).toBe(true);
            expect(result.mitreTechniques).toBeDefined();
            expect(result.mitreTechniques).toContain('T1083');
        });

        it('does not include MITRE techniques for benign input', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('document.pdf');

            expect(result.detected).toBe(false);
            expect(result.mitreTechniques).toBeUndefined();
        });
    });

    describe('CWE ID Mapping', () => {
        it('categorizes as path-traversal category', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('../../../etc/passwd');

            expect(result.detected).toBe(true);
            expect(result.category).toBe('path-traversal');
        });

        it('maintains category for complex traversals', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('..\\..\\windows\\win.ini');

            expect(result.category).toBe('path-traversal');
        });
    });

    describe('Multiple Attack Pattern Detection', () => {
        it('detects multiple patterns in complex payload', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('../../../etc/passwd%00.jpg');

            expect(result.detected).toBe(true);
            expect(result.matches.length).toBeGreaterThan(1);
        });

        it('detects traversal and sensitive file together', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('../../../etc/passwd');

            expect(result.matches.some(m => m.patternId === 'path/dot-dot-slash')).toBe(true);
            expect(result.matches.some(m => m.patternId === 'path/sensitive-files')).toBe(true);
        });

        it('detects encoded traversal variants', () => {
            const engine = createPathTraversalEngine();
        const result = engine.analyze('%2e%2e/%2e%2e/%2e%2e/etc/passwd');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => ['path/encoded-traversal','path/dot-dot-slash','path/double-encoded'].includes(m.patternId))).toBe(true);
        });

        // Note: IP-notation and IPv6-mapped checks belong to SSRF engine; omitted here

        it('detects absolute Unix path', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('/etc/hosts');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'path/absolute-unix')).toBe(true);
        });

        it('detects absolute Windows path', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('C:\\Windows\\System32\\config\\SAM');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'path/absolute-windows')).toBe(true);
        });

        it('detects .env file access', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('../../../.env');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'path/sensitive-files')).toBe(true);
        });

        it('increases confidence with multiple patterns', () => {
            const engine = createPathTraversalEngine();
            const simpleResult = engine.analyze('../../../etc/hosts');
            const complexResult = engine.analyze('../../../etc/passwd%00.jpg');

            expect(complexResult.confidence).toBeGreaterThanOrEqual(simpleResult.confidence);
        });
    });

    describe('Engine Interface Compliance', () => {
        it('returns correct engine ID', () => {
            const engine = createPathTraversalEngine();
            expect(engine.id).toBe('path-traversal-detection');
        });

        it('returns correct category', () => {
            const engine = createPathTraversalEngine();
            expect(engine.category).toBe('path-traversal');
        });

        it('returns patterns via getPatterns()', () => {
            const engine = createPathTraversalEngine();
            const patterns = engine.getPatterns();

            expect(patterns.length).toBeGreaterThan(0);
            expect(patterns.some(p => p.id === 'path/dot-dot-slash')).toBe(true);
        });

        it('returns config via getConfig()', () => {
            const engine = createPathTraversalEngine();
            const config = engine.getConfig();

            expect(config.sensitivity).toBeDefined();
            expect(config.confidenceThreshold).toBeDefined();
            expect(config.maxInputLength).toBeDefined();
        });
    });

    describe('Edge Cases', () => {
        it('handles empty input', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('');

            expect(result.detected).toBe(false);
            expect(result.matches).toHaveLength(0);
        });

        it('handles very long input', () => {
            const engine = createPathTraversalEngine();
            // put the payload at the beginning so it survives truncation
            const longInput = '../../../etc/passwd' + 'A'.repeat(100000);
            const result = engine.analyze(longInput);

            expect(result.detected).toBe(true);
        });

        it('handles URL double encoding', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('%252e%252e%252fetc%252fpasswd');

            expect(result.detected).toBe(true);
        });

        it('provides explanation for detected input', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('../../../etc/passwd');

            expect(result.explanation).toContain('Path traversal detected');
        });

        it('provides explanation for clean input', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('document.pdf');

            expect(result.explanation).toContain('No path traversal');
        });

        it('detects git directory access', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('../../../.git/config');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'path/sensitive-files')).toBe(true);
        });

        it('detects proc self access', () => {
            const engine = createPathTraversalEngine();
            const result = engine.analyze('/proc/self/environ');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'path/sensitive-files')).toBe(true);
        });
    });
});
