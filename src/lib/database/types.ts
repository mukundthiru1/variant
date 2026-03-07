/**
 * VARIANT — Database Simulacrum
 *
 * Provides simulated database access for Simulacra.
 * Backed by configurable tables that level designers define.
 *
 * Two modes:
 *   1. SCRIPTED: mysql/psql shell commands with pre-configured
 *      query → result mappings. Fast. Deterministic. Good for
 *      most levels.
 *   2. REAL: SQL.js (SQLite in WASM) for actual SQL execution.
 *      SQL injection literally works because it's a real SQL
 *      parser. Level designers provide table schemas and data.
 *      The backend creates a real SQLite database in-memory.
 *
 * Level designers configure:
 *   - Tables (schema + data)
 *   - Allowed queries (for scripted mode)
 *   - Injection-vulnerable queries (which queries skip parameterization)
 *   - Database credentials (which appear in app configs)
 *   - Database files (my.cnf, pg_hba.conf, etc.)
 *
 * DESIGN: Pure interface. Backend (scripted vs SQL.js) is swappable.
 * The shell commands (mysql, psql, sqlite3) are CommandHandlers
 * that use the database instance.
 */

import type { CommandHandler, ShellResult } from '../shell/types';

// ── Types ──────────────────────────────────────────────────────

export type DatabaseType = 'mysql' | 'postgresql' | 'sqlite';

export interface TableDefinition {
    /** Table name. */
    readonly name: string;
    /** Column definitions. */
    readonly columns: readonly ColumnDefinition[];
    /** Row data. Each row is a map of column name → value. */
    readonly rows: readonly ReadonlyMap<string, string | number | null>[];
}

export interface ColumnDefinition {
    readonly name: string;
    readonly type: 'INT' | 'VARCHAR' | 'TEXT' | 'BOOLEAN' | 'TIMESTAMP' | 'BLOB';
    readonly primaryKey?: boolean;
    readonly nullable?: boolean;
    readonly defaultValue?: string;
}

export interface DatabaseConfig {
    /** Database type. */
    readonly type: DatabaseType;
    /** Database name. */
    readonly name: string;
    /** Tables. */
    readonly tables: readonly TableDefinition[];
    /** Database user. */
    readonly user: string;
    /** Database password. */
    readonly password: string;
    /** Port. */
    readonly port: number;
    /**
     * Mode: 'scripted' for pre-configured results,
     * 'real' for SQL.js execution.
     * Default: 'scripted'.
     */
    readonly mode?: 'scripted' | 'real';
    /**
     * Pre-configured query → result mappings (scripted mode).
     * Each query is matched by substring or regex.
     */
    readonly queryMappings?: readonly QueryMapping[];
    /**
     * Custom shell prompt. Default: derived from type.
     */
    readonly prompt?: string;
}

export interface QueryMapping {
    /** Pattern to match against the query. Substring or regex. */
    readonly pattern: string;
    /** Whether pattern is a regex. Default: false (substring). */
    readonly isRegex?: boolean;
    /** Result to return. */
    readonly result: QueryResult;
}

export interface QueryResult {
    /** Column headers. */
    readonly columns: readonly string[];
    /** Rows. Each row is an array of string values. */
    readonly rows: readonly (readonly string[])[];
    /** Error message (if query should return an error). */
    readonly error?: string;
    /** Rows affected (for INSERT/UPDATE/DELETE). */
    readonly rowsAffected?: number;
}

// ── Scripted Database ──────────────────────────────────────────

export function createScriptedDatabase(config: DatabaseConfig): DatabaseCommands {
    const commandHandlers = new Map<string, CommandHandler>();

    // Build the query handler
    function handleQuery(query: string): ShellResult {
        const trimmed = query.trim();

        // Empty query
        if (trimmed.length === 0) return { output: '', exitCode: 0 };

        // System commands
        if (trimmed.startsWith('\\') || trimmed.startsWith('SHOW') || trimmed.startsWith('show')) {
            return handleSystemCommand(trimmed);
        }

        // Check query mappings
        if (config.queryMappings !== undefined) {
            for (const mapping of config.queryMappings) {
                const matches = mapping.isRegex === true
                    ? new RegExp(mapping.pattern, 'i').test(trimmed)
                    : trimmed.toLowerCase().includes(mapping.pattern.toLowerCase());

                if (matches) {
                    if (mapping.result.error !== undefined) {
                        return { output: `ERROR: ${mapping.result.error}\n`, exitCode: 1 };
                    }
                    return { output: formatQueryResult(mapping.result), exitCode: 0 };
                }
            }
        }

        // SELECT from known tables
        const selectMatch = /SELECT\s+(.+?)\s+FROM\s+(\w+)/i.exec(trimmed);
        if (selectMatch !== null) {
            const tableName = selectMatch[2]!;
            const table = config.tables.find(t => t.name.toLowerCase() === tableName.toLowerCase());
            if (table !== undefined) {
                return { output: formatTableData(table, trimmed), exitCode: 0 };
            }
            return { output: `ERROR: Table '${tableName}' doesn't exist\n`, exitCode: 1 };
        }

        // DESCRIBE / DESC
        const descMatch = /(?:DESCRIBE|DESC)\s+(\w+)/i.exec(trimmed);
        if (descMatch !== null) {
            const tableName = descMatch[1]!;
            const table = config.tables.find(t => t.name.toLowerCase() === tableName.toLowerCase());
            if (table !== undefined) {
                return { output: formatTableDescription(table), exitCode: 0 };
            }
            return { output: `ERROR: Table '${tableName}' doesn't exist\n`, exitCode: 1 };
        }

        // INSERT / UPDATE / DELETE — acknowledge but don't modify
        if (/^(INSERT|UPDATE|DELETE)/i.test(trimmed)) {
            return { output: 'Query OK, 1 row affected (0.01 sec)\n', exitCode: 0 };
        }

        return { output: `ERROR: Unknown query\n`, exitCode: 1 };
    }

    function handleSystemCommand(cmd: string): ShellResult {
        const lower = cmd.toLowerCase();

        if (lower === 'show databases;' || lower === '\\l') {
            return {
                output: formatQueryResult({
                    columns: ['Database'],
                    rows: [[config.name], ['information_schema'], ['performance_schema']],
                }),
                exitCode: 0,
            };
        }

        if (lower === 'show tables;' || lower === '\\dt') {
            const rows = config.tables.map(t => [t.name]);
            return {
                output: formatQueryResult({
                    columns: [`Tables_in_${config.name}`],
                    rows,
                }),
                exitCode: 0,
            };
        }

        if (lower === '\\q' || lower === 'quit' || lower === 'exit') {
            return { output: 'Bye\n', exitCode: 0 };
        }

        if (lower === 'status' || lower === '\\s') {
            return {
                output: [
                    `${config.type === 'mysql' ? 'mysql' : 'psql'} ${config.type === 'mysql' ? 'Ver 8.0.35' : '(PostgreSQL) 15.4'}`,
                    `Connection id:          42`,
                    `Current database:       ${config.name}`,
                    `Current user:           ${config.user}@localhost`,
                    `Server version:         ${config.type === 'mysql' ? '8.0.35-0ubuntu0.22.04.1' : '15.4 (Ubuntu 15.4-1.pgdg22.04+1)'}`,
                    '',
                ].join('\n'),
                exitCode: 0,
            };
        }

        return { output: `ERROR: Unknown command '${cmd}'\n`, exitCode: 1 };
    }

    function formatTableData(table: TableDefinition, query: string): string {
        // Basic WHERE clause handling for scripted mode
        const whereMatch = /WHERE\s+(.+?)(?:;|$)/i.exec(query);
        let rows = table.rows;

        if (whereMatch !== null) {
            const whereClause = whereMatch[1]!.trim();
            // Basic: column = 'value' or column = value
            const eqMatch = /(\w+)\s*=\s*'?([^';\s]+)'?/i.exec(whereClause);
            if (eqMatch !== null) {
                const col = eqMatch[1]!;
                const val = eqMatch[2]!;
                rows = rows.filter(row => {
                    const cell = row.get(col);
                    return cell !== undefined && String(cell) === val;
                });
            }
        }

        const columns = table.columns.map(c => c.name);
        const resultRows = rows.map(row =>
            columns.map(col => String(row.get(col) ?? 'NULL'))
        );

        return formatQueryResult({ columns, rows: resultRows });
    }

    function formatTableDescription(table: TableDefinition): string {
        const columns = ['Field', 'Type', 'Null', 'Key', 'Default'];
        const rows = table.columns.map(col => [
            col.name,
            col.type,
            col.nullable !== false ? 'YES' : 'NO',
            col.primaryKey === true ? 'PRI' : '',
            col.defaultValue ?? 'NULL',
        ]);
        return formatQueryResult({ columns, rows });
    }

    // ── Command handlers ──────────────────────────────────────

    const dbCommand: CommandHandler = (args) => {
        // Join all args as the query if provided inline
        const inlineQuery = args.filter(a => !a.startsWith('-')).join(' ');

        if (inlineQuery.length > 0) {
            // Direct query execution (e.g., mysql -e "SELECT * FROM users")
            if (args.includes('-e')) {
                const eIdx = args.indexOf('-e');
                const query = args.slice(eIdx + 1).join(' ');
                return handleQuery(query);
            }
        }

        // Interactive mode — show prompt
        const prompt = config.prompt ?? (config.type === 'mysql' ? `mysql> ` : `${config.name}=> `);
        return {
            output: `Welcome to the ${config.type === 'mysql' ? 'MySQL' : 'PostgreSQL'} monitor.\nType 'help;' for help. Type '\\q' to quit.\n\n${prompt}`,
            exitCode: 0,
        };
    };

    // Register commands based on type
    switch (config.type) {
        case 'mysql':
            commandHandlers.set('mysql', dbCommand);
            commandHandlers.set('mysqldump', (args) => {
                const tableName = args.find(a => !a.startsWith('-'));
                if (tableName === undefined) return { output: 'Usage: mysqldump [options] database [tables]\n', exitCode: 1 };
                const table = config.tables.find(t => t.name === tableName);
                if (table === undefined) return { output: `mysqldump: Got error: Table '${tableName}' doesn't exist\n`, exitCode: 2 };
                return { output: generateDumpOutput(table, config.name), exitCode: 0 };
            });
            break;
        case 'postgresql':
            commandHandlers.set('psql', dbCommand);
            commandHandlers.set('pg_dump', (args) => {
                const tableName = args.find(a => !a.startsWith('-'));
                if (tableName === undefined) return { output: 'pg_dump: too few command-line arguments\n', exitCode: 1 };
                return { output: `-- PostgreSQL database dump\n-- Dumped from database version 15.4\n`, exitCode: 0 };
            });
            break;
        case 'sqlite':
            commandHandlers.set('sqlite3', dbCommand);
            break;
    }

    return {
        commands: commandHandlers,
        query: handleQuery,
        getTables: () => config.tables,
        getConfig: () => config,
    };
}

// ── Result formatter ───────────────────────────────────────────

function formatQueryResult(result: QueryResult): string {
    if (result.error !== undefined) {
        return `ERROR: ${result.error}\n`;
    }

    if (result.columns.length === 0) {
        return `${result.rowsAffected ?? 0} rows affected\n`;
    }

    // Calculate column widths
    const widths = result.columns.map(c => c.length);
    for (const row of result.rows) {
        for (let i = 0; i < row.length && i < widths.length; i++) {
            widths[i] = Math.max(widths[i]!, (row[i] ?? '').length);
        }
    }

    // Build table
    const separator = '+' + widths.map(w => '-'.repeat(w! + 2)).join('+') + '+';
    const header = '| ' + result.columns.map((c, i) => c.padEnd(widths[i]!)).join(' | ') + ' |';

    const lines = [separator, header, separator];
    for (const row of result.rows) {
        const cells = result.columns.map((_c, i) =>
            (row[i] ?? 'NULL').padEnd(widths[i]!)
        );
        lines.push('| ' + cells.join(' | ') + ' |');
    }
    lines.push(separator);
    lines.push(`${result.rows.length} row${result.rows.length !== 1 ? 's' : ''} in set (0.00 sec)\n`);

    return lines.join('\n') + '\n';
}

function generateDumpOutput(table: TableDefinition, dbName: string): string {
    const lines = [
        `-- MySQL dump, Database: ${dbName}`,
        `-- Table structure for table \`${table.name}\``,
        '',
        `DROP TABLE IF EXISTS \`${table.name}\`;`,
        `CREATE TABLE \`${table.name}\` (`,
    ];

    for (let i = 0; i < table.columns.length; i++) {
        const col = table.columns[i]!;
        const comma = i < table.columns.length - 1 ? ',' : '';
        const pk = col.primaryKey === true ? ' PRIMARY KEY' : '';
        lines.push(`  \`${col.name}\` ${col.type}${pk}${comma}`);
    }
    lines.push(');');
    lines.push('');

    return lines.join('\n') + '\n';
}

// ── Return type ────────────────────────────────────────────────

export interface DatabaseCommands {
    /** Command handlers to register with the shell. */
    readonly commands: ReadonlyMap<string, CommandHandler>;
    /** Execute a query directly. */
    query(sql: string): ShellResult;
    /** Get all table definitions. */
    getTables(): readonly TableDefinition[];
    /** Get database config. */
    getConfig(): DatabaseConfig;
}
