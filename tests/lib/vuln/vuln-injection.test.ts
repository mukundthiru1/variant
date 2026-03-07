/**
 * VARIANT — Vulnerability Injection tests
 */
import { describe, it, expect } from 'vitest';
import { injectVulnerabilities } from '../../../src/lib/vuln/types';
import type { BaseCodebase, VulnDefinition } from '../../../src/lib/vuln/types';

// ── Test fixtures ──────────────────────────────────────────────

const baseCodebase: BaseCodebase = {
    id: 'nodeapp-basic',
    name: 'Basic Node.js App',
    category: 'web-app',
    stack: ['node', 'express'],
    license: 'MIT',
    attribution: 'Based on Example App by Example Corp',
    files: new Map([
        ['/var/www/app.js', {
            content: [
                'const express = require("express");',
                'const db = require("./db");',
                'const app = express();',
                '',
                'app.get("/users/:id", async (req, res) => {',
                '    const user = await db.query("SELECT * FROM users WHERE id = $1", [req.params.id]);',
                '    res.json(user);',
                '});',
                '',
                'app.post("/login", async (req, res) => {',
                '    const { username, password } = req.body;',
                '    const user = await db.query("SELECT * FROM users WHERE username = $1 AND password = $2", [username, password]);',
                '    if (user) res.json({ token: generateToken(user) });',
                '    else res.status(401).json({ error: "Invalid credentials" });',
                '});',
                '',
                'app.listen(3000);',
            ].join('\n'),
        }],
        ['/var/www/db.js', {
            content: 'const pg = require("pg");\nconst pool = new pg.Pool();\nmodule.exports = { query: (q, p) => pool.query(q, p) };\n',
        }],
        ['/var/www/package.json', {
            content: '{"name":"app","version":"1.0.0","dependencies":{"express":"^4.18.0","pg":"^8.0.0"}}',
        }],
        ['/etc/app.conf', {
            content: 'DB_HOST=localhost\nDB_PORT=5432\nDB_NAME=appdb\nDB_USER=appuser\nDB_PASS=securepass123\n',
        }],
    ]),
};

const sqliVuln: VulnDefinition = {
    id: 'VART-0001',
    name: 'SQL Injection in User Lookup',
    description: 'The user lookup endpoint concatenates user input directly into a SQL query.',
    category: 'sqli',
    difficulty: 'beginner',
    severity: 9.8,
    compatibleBases: ['nodeapp-basic'],
    patches: [
        {
            type: 'replace',
            path: '/var/www/app.js',
            search: 'const user = await db.query("SELECT * FROM users WHERE id = $1", [req.params.id]);',
            content: 'const user = await db.query("SELECT * FROM users WHERE id = " + req.params.id);',
        },
    ],
    clues: [
        {
            location: 'log',
            path: '/var/log/app.log',
            content: '[WARN] Unparameterized query detected in user lookup',
            visibility: 3,
        },
    ],
    detection: {
        mode: 'any',
        triggers: [
            { type: 'http', method: 'GET', path: '/users/:id', bodyContains: "' OR '1'='1" },
            { type: 'http', method: 'GET', path: '/users/:id', bodyContains: 'UNION SELECT' },
        ],
    },
    tags: ['owasp-top-10', 'injection'],
};

const rceVuln: VulnDefinition = {
    id: 'VART-0002',
    name: 'RCE via Debug Endpoint',
    description: 'A hidden debug endpoint allows arbitrary code execution.',
    category: 'rce',
    difficulty: 'intermediate',
    severity: 10.0,
    compatibleBases: ['nodeapp-basic'],
    patches: [
        {
            type: 'insert',
            path: '/var/www/app.js',
            search: 'app.listen(3000);',
            content: '\n// Debug endpoint\napp.get("/debug/eval", (req, res) => {\n    const result = eval(req.query.code);\n    res.json({ result });\n});\n\n',
        },
    ],
    clues: [
        {
            location: 'file',
            path: '/var/www/.debug_notes.txt',
            content: 'TODO: Remove debug endpoint before production deploy',
            visibility: 2,
        },
    ],
    redHerrings: [
        {
            location: 'file',
            path: '/var/www/SECURITY.md',
            content: '# Security\nAll endpoints have been reviewed and hardened.\nNo unsafe eval() usage.\n',
            visibility: 4,
        },
    ],
    detection: {
        mode: 'any',
        triggers: [
            { type: 'http', method: 'GET', path: '/debug/eval' },
        ],
    },
};

const incompatibleVuln: VulnDefinition = {
    id: 'VART-9999',
    name: 'Incompatible Vuln',
    description: 'This vuln is not compatible with the test base.',
    category: 'xss',
    difficulty: 'beginner',
    severity: 5.0,
    compatibleBases: ['django-app'],
    patches: [],
    detection: { mode: 'any', triggers: [] },
};

// ── Tests ──────────────────────────────────────────────────────

describe('VulnInjection', () => {
    describe('basic injection', () => {
        it('applies a single vulnerability patch', () => {
            const result = injectVulnerabilities(baseCodebase, [sqliVuln]);
            expect(result.applied).toContain('VART-0001');
            expect(result.errors).toHaveLength(0);

            const appJs = result.overlay.files.get('/var/www/app.js');
            expect(appJs).toBeDefined();
            const content = typeof appJs!.content === 'string' ? appJs!.content : '';
            expect(content).toContain('WHERE id = " + req.params.id');
            expect(content).not.toContain('WHERE id = $1');
        });

        it('applies multiple vulnerabilities', () => {
            const result = injectVulnerabilities(baseCodebase, [sqliVuln, rceVuln]);
            expect(result.applied).toContain('VART-0001');
            expect(result.applied).toContain('VART-0002');
            expect(result.errors).toHaveLength(0);

            const appJs = result.overlay.files.get('/var/www/app.js');
            const content = typeof appJs!.content === 'string' ? appJs!.content : '';
            expect(content).toContain('WHERE id = " + req.params.id'); // SQLi
            expect(content).toContain('/debug/eval'); // RCE
        });

        it('preserves base files not targeted by patches', () => {
            const result = injectVulnerabilities(baseCodebase, [sqliVuln]);
            expect(result.overlay.files.has('/var/www/db.js')).toBe(true);
            expect(result.overlay.files.has('/var/www/package.json')).toBe(true);
        });
    });

    describe('clues and red herrings', () => {
        it('applies clues to the filesystem', () => {
            const result = injectVulnerabilities(baseCodebase, [sqliVuln]);
            const logFile = result.overlay.files.get('/var/log/app.log');
            expect(logFile).toBeDefined();
            const content = typeof logFile!.content === 'string' ? logFile!.content : '';
            expect(content).toContain('Unparameterized query');
        });

        it('applies red herrings', () => {
            const result = injectVulnerabilities(baseCodebase, [rceVuln]);
            const securityMd = result.overlay.files.get('/var/www/SECURITY.md');
            expect(securityMd).toBeDefined();
            const content = typeof securityMd!.content === 'string' ? securityMd!.content : '';
            expect(content).toContain('No unsafe eval() usage');
        });
    });

    describe('compatibility checking', () => {
        it('rejects incompatible vulnerabilities', () => {
            const result = injectVulnerabilities(baseCodebase, [incompatibleVuln]);
            expect(result.applied).toHaveLength(0);
            expect(result.errors).toHaveLength(1);
            expect(result.errors[0]!.vulnId).toBe('VART-9999');
            expect(result.errors[0]!.message).toContain('not compatible');
        });

        it('applies compatible vulns and rejects incompatible in same batch', () => {
            const result = injectVulnerabilities(baseCodebase, [sqliVuln, incompatibleVuln]);
            expect(result.applied).toContain('VART-0001');
            expect(result.applied).not.toContain('VART-9999');
            expect(result.errors).toHaveLength(1);
        });
    });

    describe('patch types', () => {
        it('handles create patch', () => {
            const createVuln: VulnDefinition = {
                id: 'VART-CREATE',
                name: 'Backdoor File',
                description: 'Creates a backdoor file.',
                category: 'rce',
                difficulty: 'beginner',
                severity: 10,
                compatibleBases: ['nodeapp-basic'],
                patches: [
                    {
                        type: 'create',
                        path: '/var/www/.backdoor.php',
                        content: '<?php system($_GET["cmd"]); ?>',
                        mode: 0o755,
                    },
                ],
                detection: { mode: 'any', triggers: [] },
            };

            const result = injectVulnerabilities(baseCodebase, [createVuln]);
            expect(result.applied).toContain('VART-CREATE');
            const backdoor = result.overlay.files.get('/var/www/.backdoor.php');
            expect(backdoor).toBeDefined();
            const content = typeof backdoor!.content === 'string' ? backdoor!.content : '';
            expect(content).toContain('system($_GET');
        });

        it('handles delete patch (remove string)', () => {
            const deleteVuln: VulnDefinition = {
                id: 'VART-DELETE',
                name: 'Remove Auth Check',
                description: 'Removes authentication check.',
                category: 'auth-bypass',
                difficulty: 'intermediate',
                severity: 8,
                compatibleBases: ['nodeapp-basic'],
                patches: [
                    {
                        type: 'delete',
                        path: '/var/www/app.js',
                        search: '    else res.status(401).json({ error: "Invalid credentials" });',
                    },
                ],
                detection: { mode: 'any', triggers: [] },
            };

            const result = injectVulnerabilities(baseCodebase, [deleteVuln]);
            expect(result.applied).toContain('VART-DELETE');
            const appJs = result.overlay.files.get('/var/www/app.js');
            const content = typeof appJs!.content === 'string' ? appJs!.content : '';
            expect(content).not.toContain('Invalid credentials');
        });

        it('handles insert patch', () => {
            const result = injectVulnerabilities(baseCodebase, [rceVuln]);
            const appJs = result.overlay.files.get('/var/www/app.js');
            const content = typeof appJs!.content === 'string' ? appJs!.content : '';
            // The debug endpoint should be inserted before app.listen
            expect(content).toContain('eval(req.query.code)');
            expect(content).toContain('app.listen(3000)');
        });
    });

    describe('error handling', () => {
        it('reports error when search string not found', () => {
            const badVuln: VulnDefinition = {
                id: 'VART-BAD',
                name: 'Bad Patch',
                description: 'Has a patch that cannot be applied.',
                category: 'sqli',
                difficulty: 'beginner',
                severity: 5,
                compatibleBases: ['nodeapp-basic'],
                patches: [
                    {
                        type: 'replace',
                        path: '/var/www/app.js',
                        search: 'THIS STRING DOES NOT EXIST',
                        content: 'replaced',
                    },
                ],
                detection: { mode: 'any', triggers: [] },
            };

            const result = injectVulnerabilities(baseCodebase, [badVuln]);
            expect(result.applied).not.toContain('VART-BAD');
            expect(result.errors).toHaveLength(1);
            expect(result.errors[0]!.message).toContain('search string not found');
        });

        it('reports error when target file not found', () => {
            const badVuln: VulnDefinition = {
                id: 'VART-NOFILE',
                name: 'Missing File',
                description: 'Targets a file that does not exist.',
                category: 'sqli',
                difficulty: 'beginner',
                severity: 5,
                compatibleBases: ['nodeapp-basic'],
                patches: [
                    {
                        type: 'replace',
                        path: '/var/www/nonexistent.js',
                        search: 'anything',
                        content: 'replaced',
                    },
                ],
                detection: { mode: 'any', triggers: [] },
            };

            const result = injectVulnerabilities(baseCodebase, [badVuln]);
            expect(result.applied).not.toContain('VART-NOFILE');
            expect(result.errors).toHaveLength(1);
            expect(result.errors[0]!.message).toContain('file not found');
        });
    });

    describe('wildcard compatibility', () => {
        it('accepts vulns with wildcard compatibility', () => {
            const wildcardVuln: VulnDefinition = {
                id: 'VART-WILD',
                name: 'Universal Vuln',
                description: 'Works with any base.',
                category: 'misconfiguration',
                difficulty: 'beginner',
                severity: 3,
                compatibleBases: ['*'],
                patches: [
                    {
                        type: 'create',
                        path: '/etc/debug.conf',
                        content: 'debug=true\nverbose_errors=true\n',
                    },
                ],
                detection: { mode: 'any', triggers: [] },
            };

            const result = injectVulnerabilities(baseCodebase, [wildcardVuln]);
            expect(result.applied).toContain('VART-WILD');
        });
    });
});
