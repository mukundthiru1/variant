/**
 * Minimal pg type declarations for CF Workers.
 * We can't use @types/pg because it pulls in @types/node
 * which conflicts with @cloudflare/workers-types.
 */
declare module 'pg' {
    export interface ClientConfig {
        connectionString?: string;
    }

    export interface QueryResult<T = Record<string, unknown>> {
        rows: T[];
        rowCount: number;
    }

    export class Client {
        constructor(config?: ClientConfig);
        connect(): Promise<void>;
        query<T = Record<string, unknown>>(text: string, values?: unknown[]): Promise<QueryResult<T>>;
        end(): Promise<void>;
    }
}
