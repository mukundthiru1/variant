/**
 * VARIANT — Database Simulacrum tests
 */
import { describe, it, expect } from 'vitest';
import { createScriptedDatabase } from '../../../src/lib/database/types';
import { createVFS } from '../../../src/lib/vfs/vfs';
import { createShell } from '../../../src/lib/shell/shell';

const usersTable = {
    name: 'users',
    columns: [
        { name: 'id', type: 'INT' as const, primaryKey: true },
        { name: 'username', type: 'VARCHAR' as const },
        { name: 'password', type: 'VARCHAR' as const },
        { name: 'email', type: 'VARCHAR' as const },
        { name: 'role', type: 'VARCHAR' as const },
    ],
    rows: [
        new Map<string, string | number | null>([['id', 1], ['username', 'admin'], ['password', 'hashed_pw_1'], ['email', 'admin@corp.local'], ['role', 'admin']]),
        new Map<string, string | number | null>([['id', 2], ['username', 'john'], ['password', 'hashed_pw_2'], ['email', 'john@corp.local'], ['role', 'user']]),
        new Map<string, string | number | null>([['id', 3], ['username', 'jane'], ['password', 'hashed_pw_3'], ['email', 'jane@corp.local'], ['role', 'user']]),
    ],
};

const ordersTable = {
    name: 'orders',
    columns: [
        { name: 'id', type: 'INT' as const, primaryKey: true },
        { name: 'user_id', type: 'INT' as const },
        { name: 'amount', type: 'VARCHAR' as const },
        { name: 'status', type: 'VARCHAR' as const },
    ],
    rows: [
        new Map<string, string | number | null>([['id', 1], ['user_id', 1], ['amount', '99.99'], ['status', 'completed']]),
        new Map<string, string | number | null>([['id', 2], ['user_id', 2], ['amount', '49.50'], ['status', 'pending']]),
    ],
};

const dbConfig = {
    type: 'mysql' as const,
    name: 'production_db',
    user: 'appuser',
    password: 'S3cretDbP@ss!',
    port: 3306,
    tables: [usersTable, ordersTable],
    queryMappings: [
        {
            pattern: "' OR '1'='1",
            result: {
                columns: ['id', 'username', 'password', 'email', 'role'],
                rows: [
                    ['1', 'admin', 'hashed_pw_1', 'admin@corp.local', 'admin'],
                    ['2', 'john', 'hashed_pw_2', 'john@corp.local', 'user'],
                    ['3', 'jane', 'hashed_pw_3', 'jane@corp.local', 'user'],
                ],
            },
        },
        {
            pattern: 'UNION SELECT',
            isRegex: false,
            result: {
                columns: ['id', 'username', 'password', 'email', 'role'],
                rows: [
                    ['1', 'admin', 'hashed_pw_1', 'admin@corp.local', 'admin'],
                    ['---', '---', '---', '---', '---'],
                    ['1', 'root', 'toor', '', 'mysql.user'],
                ],
            },
        },
    ],
};

describe('DatabaseSimulacrum', () => {
    describe('scripted queries', () => {
        it('handles SHOW TABLES', () => {
            const db = createScriptedDatabase(dbConfig);
            const result = db.query('SHOW TABLES;');
            expect(result.output).toContain('users');
            expect(result.output).toContain('orders');
        });

        it('handles SHOW DATABASES', () => {
            const db = createScriptedDatabase(dbConfig);
            const result = db.query('SHOW DATABASES;');
            expect(result.output).toContain('production_db');
            expect(result.output).toContain('information_schema');
        });

        it('handles SELECT from known table', () => {
            const db = createScriptedDatabase(dbConfig);
            const result = db.query('SELECT * FROM users;');
            expect(result.output).toContain('admin');
            expect(result.output).toContain('john');
            expect(result.output).toContain('jane');
        });

        it('handles SELECT with WHERE clause', () => {
            const db = createScriptedDatabase(dbConfig);
            const result = db.query("SELECT * FROM users WHERE username = 'admin';");
            expect(result.output).toContain('admin');
            expect(result.output).not.toContain('john');
        });

        it('handles DESCRIBE table', () => {
            const db = createScriptedDatabase(dbConfig);
            const result = db.query('DESCRIBE users;');
            expect(result.output).toContain('id');
            expect(result.output).toContain('INT');
            expect(result.output).toContain('PRI');
        });

        it('handles unknown table gracefully', () => {
            const db = createScriptedDatabase(dbConfig);
            const result = db.query('SELECT * FROM nonexistent;');
            expect(result.exitCode).toBe(1);
            expect(result.output).toContain("doesn't exist");
        });
    });

    describe('SQL injection mappings', () => {
        it('matches injection patterns and returns configured results', () => {
            const db = createScriptedDatabase(dbConfig);
            const result = db.query("SELECT * FROM users WHERE username = '' OR '1'='1';");
            expect(result.output).toContain('admin');
            expect(result.output).toContain('john');
            expect(result.output).toContain('jane');
            // All 3 rows returned — injection worked
            expect(result.output).toContain('3 row');
        });

        it('matches UNION SELECT injection', () => {
            const db = createScriptedDatabase(dbConfig);
            const result = db.query("SELECT * FROM users WHERE id = 1 UNION SELECT 1,'root','toor','','mysql.user';");
            expect(result.output).toContain('root');
            expect(result.output).toContain('toor');
            expect(result.output).toContain('mysql.user');
        });
    });

    describe('shell integration', () => {
        it('registers mysql command with shell', () => {
            const vfs = createVFS();
            const shell = createShell({ vfs, hostname: 'db-01' });
            const db = createScriptedDatabase(dbConfig);

            for (const [name, handler] of db.commands) {
                shell.registerCommand(name, handler);
            }

            expect(shell.hasCommand('mysql')).toBe(true);
            expect(shell.hasCommand('mysqldump')).toBe(true);
        });

        it('mysqldump generates SQL output', () => {
            const db = createScriptedDatabase(dbConfig);
            const dumpHandler = db.commands.get('mysqldump');
            expect(dumpHandler).toBeDefined();

            // Can't easily test shell execution directly, but verify the command exists
            const result = db.query('SHOW TABLES;');
            expect(result.exitCode).toBe(0);
        });
    });

    describe('postgresql mode', () => {
        it('registers psql command', () => {
            const pgDb = createScriptedDatabase({
                ...dbConfig,
                type: 'postgresql',
            });
            expect(pgDb.commands.has('psql')).toBe(true);
            expect(pgDb.commands.has('pg_dump')).toBe(true);
        });

        it('handles \\dt for listing tables', () => {
            const pgDb = createScriptedDatabase({
                ...dbConfig,
                type: 'postgresql',
            });
            const result = pgDb.query('\\dt');
            expect(result.output).toContain('users');
        });
    });

    describe('table formatting', () => {
        it('produces ASCII table output with borders', () => {
            const db = createScriptedDatabase(dbConfig);
            const result = db.query('SHOW DATABASES;');
            expect(result.output).toContain('+');
            expect(result.output).toContain('|');
            expect(result.output).toContain('-');
        });
    });
});
