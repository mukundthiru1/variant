/**
 * VARIANT — MySQL Service Handler
 *
 * Simulacrum-level MySQL service. Handles MySQL wire protocol
 * at the request/response level for security training scenarios
 * involving SQL injection, credential theft, and data exfiltration.
 *
 * What it does:
 *   - Username/password authentication
 *   - Responds to basic SQL queries (SELECT, SHOW, USE, DESCRIBE)
 *   - SQL injection detection via detection engine integration
 *   - Generates MySQL-format log entries
 *   - Emits events for objective detection
 *
 * EXTENSIBILITY:
 *   - Custom databases/tables via config
 *   - Query result generators
 *   - All behavior configurable through ServiceConfig.config
 *
 * SWAPPABILITY: Implements ServiceHandler. Replace this file.
 */

import type {
    ServiceHandler,
    ServiceRequest,
    ServiceResponse,
    ServiceContext,
} from './types';
import type { ServiceConfig } from '../../core/world/types';

// ── MySQL Config ────────────────────────────────────────────

interface MySQLConfig {
    readonly port: number;
    readonly version: string;
    readonly allowedUsers: readonly string[] | null;
    readonly logFile: string;
    readonly databases: readonly MySQLDatabase[];
    readonly requireAuth: boolean;
}

export interface MySQLDatabase {
    readonly name: string;
    readonly tables: readonly MySQLTable[];
}

export interface MySQLTable {
    readonly name: string;
    readonly columns: readonly string[];
    readonly rows: readonly (readonly string[])[];
}

function resolveMySQLConfig(config: ServiceConfig): MySQLConfig {
    const c = config.config ?? {};
    return {
        port: config.ports[0] ?? 3306,
        version: (c['version'] as string) ?? '8.0.36-0ubuntu0.22.04.1',
        allowedUsers: (c['allowedUsers'] as readonly string[]) ?? null,
        logFile: (c['logFile'] as string) ?? '/var/log/mysql/query.log',
        databases: (c['databases'] as readonly MySQLDatabase[]) ?? [defaultDatabase()],
        requireAuth: (c['requireAuth'] as boolean) ?? true,
    };
}

function defaultDatabase(): MySQLDatabase {
    return {
        name: 'webapp',
        tables: [
            {
                name: 'users',
                columns: ['id', 'username', 'email', 'role'],
                rows: [
                    ['1', 'admin', 'admin@corp.local', 'admin'],
                    ['2', 'jsmith', 'jsmith@corp.local', 'user'],
                    ['3', 'developer', 'dev@corp.local', 'developer'],
                ],
            },
            {
                name: 'sessions',
                columns: ['id', 'user_id', 'token', 'expires'],
                rows: [
                    ['1', '1', 'abc123def456', '2026-12-31'],
                    ['2', '2', 'xyz789ghi012', '2026-06-15'],
                ],
            },
            {
                name: 'config',
                columns: ['key', 'value'],
                rows: [
                    ['db_password', 'P@ssw0rd123!'],
                    ['api_key', 'sk-prod-a1b2c3d4e5f6'],
                    ['secret_key', 'super-secret-key-do-not-share'],
                ],
            },
        ],
    };
}

// ── MySQL Session State ─────────────────────────────────────

interface MySQLSession {
    authenticated: boolean;
    username: string;
    currentDB: string | null;
}

// ── MySQL Service Handler ───────────────────────────────────

export function createMySQLService(config: ServiceConfig): ServiceHandler {
    const mysqlConfig = resolveMySQLConfig(config);
    const sessions = new Map<string, MySQLSession>();

    function getSession(sourceIP: string): MySQLSession {
        let session = sessions.get(sourceIP);
        if (session === undefined) {
            session = {
                authenticated: !mysqlConfig.requireAuth,
                username: '',
                currentDB: null,
            };
            sessions.set(sourceIP, session);
        }
        return session;
    }

    function writeQueryLog(ctx: ServiceContext, query: string, username: string): void {
        const timestamp = new Date().toISOString();
        const line = `${timestamp}\t${username}\tQuery\t${query}`;
        try {
            const existing = ctx.vfs.readFile(mysqlConfig.logFile);
            ctx.vfs.writeFile(mysqlConfig.logFile, existing + '\n' + line);
        } catch {
            ctx.vfs.writeFile(mysqlConfig.logFile, line);
        }
    }

    function formatTable(columns: readonly string[], rows: readonly (readonly string[])[]): string {
        // MySQL tabular output format
        const widths = columns.map((col, i) => {
            const maxRow = rows.reduce((max, row) => Math.max(max, (row[i] ?? '').length), 0);
            return Math.max(col.length, maxRow);
        });

        const separator = '+' + widths.map(w => '-'.repeat(w + 2)).join('+') + '+';
        const header = '|' + columns.map((col, i) => ` ${col.padEnd(widths[i]!)} `).join('|') + '|';
        const dataRows = rows.map(row =>
            '|' + columns.map((_, i) => ` ${(row[i] ?? '').padEnd(widths[i]!)} `).join('|') + '|',
        );

        return [separator, header, separator, ...dataRows, separator].join('\n');
    }

    function findDatabase(name: string): MySQLDatabase | null {
        return mysqlConfig.databases.find(db => db.name === name) ?? null;
    }

    function findTable(dbName: string, tableName: string): MySQLTable | null {
        const db = findDatabase(dbName);
        if (db === null) return null;
        return db.tables.find(t => t.name === tableName) ?? null;
    }

    function handleQuery(query: string, session: MySQLSession, ctx: ServiceContext, sourceIP: string): string {
        const normalized = query.trim().replace(/;$/, '').trim();
        const upper = normalized.toUpperCase();

        writeQueryLog(ctx, normalized, session.username);

        // SHOW DATABASES
        if (upper === 'SHOW DATABASES') {
            const names = mysqlConfig.databases.map(db => [db.name]);
            return formatTable(['Database'], names) + `\n${names.length} rows in set`;
        }

        // SHOW TABLES
        if (upper === 'SHOW TABLES') {
            if (session.currentDB === null) return 'ERROR 1046 (3D000): No database selected';
            const db = findDatabase(session.currentDB);
            if (db === null) return `ERROR 1049 (42000): Unknown database '${session.currentDB}'`;
            const names = db.tables.map(t => [t.name]);
            return formatTable([`Tables_in_${session.currentDB}`], names) + `\n${names.length} rows in set`;
        }

        // USE <database>
        if (upper.startsWith('USE ')) {
            const dbName = normalized.slice(4).trim().replace(/[`'"]/g, '');
            const db = findDatabase(dbName);
            if (db === null) return `ERROR 1049 (42000): Unknown database '${dbName}'`;
            session.currentDB = dbName;
            return 'Database changed';
        }

        // DESCRIBE / DESC <table>
        if (upper.startsWith('DESCRIBE ') || upper.startsWith('DESC ')) {
            const tableName = normalized.split(/\s+/)[1]?.replace(/[`'"]/g, '') ?? '';
            if (session.currentDB === null) return 'ERROR 1046 (3D000): No database selected';
            const table = findTable(session.currentDB, tableName);
            if (table === null) return `ERROR 1146 (42S02): Table '${session.currentDB}.${tableName}' doesn't exist`;
            const cols = table.columns.map(c => [c, 'varchar(255)', 'YES', '', 'NULL', '']);
            return formatTable(['Field', 'Type', 'Null', 'Key', 'Default', 'Extra'], cols);
        }

        // SELECT
        if (upper.startsWith('SELECT')) {
            ctx.emit({ type: 'service:custom', service: 'mysql', action: 'query', details: { username: session.username, query: normalized, sourceIP } });

            // SELECT VERSION()
            if (upper.includes('VERSION()')) {
                return formatTable(['VERSION()'], [[mysqlConfig.version]]) + '\n1 row in set';
            }

            // SELECT DATABASE()
            if (upper.includes('DATABASE()')) {
                return formatTable(['DATABASE()'], [[session.currentDB ?? 'NULL']]) + '\n1 row in set';
            }

            // SELECT USER()
            if (upper.includes('USER()')) {
                return formatTable(['USER()'], [[`${session.username}@localhost`]]) + '\n1 row in set';
            }

            // SELECT * FROM <table>
            const fromMatch = normalized.match(/from\s+[`'"]?(\w+)[`'"]?/i);
            if (fromMatch !== null) {
                const tableName = fromMatch[1]!;
                if (session.currentDB === null) return 'ERROR 1046 (3D000): No database selected';
                const table = findTable(session.currentDB, tableName);
                if (table === null) return `ERROR 1146 (42S02): Table '${session.currentDB}.${tableName}' doesn't exist`;

                // Check for WHERE clause
                const whereMatch = normalized.match(/where\s+(.+)/i);
                let filteredRows = [...table.rows];

                if (whereMatch !== null) {
                    const whereClause = whereMatch[1]!;
                    // Simple equality filter: column = 'value'
                    const eqMatch = whereClause.match(/(\w+)\s*=\s*'([^']*)'/);
                    if (eqMatch !== null) {
                        const colName = eqMatch[1]!;
                        const colVal = eqMatch[2]!;
                        const colIdx = table.columns.indexOf(colName);
                        if (colIdx >= 0) {
                            filteredRows = filteredRows.filter(row => row[colIdx] === colVal);
                        }
                    }
                }

                return formatTable(table.columns, filteredRows) + `\n${filteredRows.length} rows in set`;
            }

            return 'Empty set';
        }

        // INSERT, UPDATE, DELETE — simulate without modifying (read-only sim)
        if (upper.startsWith('INSERT') || upper.startsWith('UPDATE') || upper.startsWith('DELETE')) {
            ctx.emit({ type: 'service:custom', service: 'mysql', action: 'query', details: { username: session.username, query: normalized, sourceIP } });
            return 'Query OK, 0 rows affected';
        }

        return `ERROR 1064 (42000): You have an error in your SQL syntax near '${normalized.slice(0, 30)}'`;
    }

    return {
        name: 'mysql',
        port: mysqlConfig.port,
        protocol: 'tcp',

        start(ctx: ServiceContext): void {
            ctx.emit({
                type: 'service:custom',
                service: 'mysql',
                action: 'started',
                details: { port: mysqlConfig.port, version: mysqlConfig.version },
            });
        },

        handle(request: ServiceRequest, ctx: ServiceContext): ServiceResponse | null {
            const text = request.payloadText.trim();
            if (text === '') {
                return {
                    payload: new TextEncoder().encode(`Welcome to the MySQL monitor. Server version: ${mysqlConfig.version}\r\nmysql> `),
                    close: false,
                };
            }

            const session = getSession(request.sourceIP);

            // Handle AUTH command (simplified wire protocol)
            if (text.toUpperCase().startsWith('AUTH ')) {
                const parts = text.split(' ');
                const username = parts[1] ?? '';
                const password = parts[2] ?? '';

                // Validate
                const valid = validateMySQLAuth(ctx, username, password);

                ctx.emit({
                    type: 'service:custom',
                    service: 'mysql',
                    action: 'login',
                    details: { username, sourceIP: request.sourceIP, success: valid },
                });

                if (valid) {
                    session.authenticated = true;
                    session.username = username;
                    return {
                        payload: new TextEncoder().encode(`Welcome to the MySQL monitor. Server version: ${mysqlConfig.version}\r\nmysql> `),
                        close: false,
                    };
                }

                return {
                    payload: new TextEncoder().encode('ERROR 1045 (28000): Access denied for user\r\n'),
                    close: true,
                };
            }

            if (!session.authenticated) {
                return {
                    payload: new TextEncoder().encode('ERROR 1045 (28000): Access denied. Please authenticate first.\r\n'),
                    close: true,
                };
            }

            // Handle SQL queries
            const result = handleQuery(text, session, ctx, request.sourceIP);

            return {
                payload: new TextEncoder().encode(result + '\r\nmysql> '),
                close: false,
            };
        },

        stop(): void {
            sessions.clear();
        },
    };
}

function validateMySQLAuth(ctx: ServiceContext, username: string, password: string): boolean {
    try {
        const shadow = ctx.vfs.readFile('/etc/shadow');
        if (shadow === null) return false;
        for (const line of shadow.split('\n')) {
            const parts = line.split(':');
            if (parts[0] === username && parts[1] === password) {
                return true;
            }
        }
    } catch {
        // No shadow file
    }
    return false;
}
