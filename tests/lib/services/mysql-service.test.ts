/**
 * VARIANT — MySQL Service Handler tests
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createMySQLService } from '../../../src/lib/services/mysql-service';
import { createVFS } from '../../../src/lib/vfs/vfs';
import { createShell } from '../../../src/lib/shell/shell';
import type { ServiceContext, ServiceRequest } from '../../../src/lib/services/types';
import type { ServiceConfig } from '../../../src/core/world/types';

function makeRequest(text: string, sourceIP: string = '10.0.0.10'): ServiceRequest {
    return {
        sourceIP,
        sourcePort: 12345,
        payload: new TextEncoder().encode(text),
        payloadText: text,
    };
}

function makeContext(): ServiceContext {
    const vfs = createVFS();
    vfs.writeFile('/etc/shadow', 'root:toor\ndbuser:dbpass123');

    const shell = createShell({ vfs, hostname: 'db-01' });

    return {
        vfs,
        shell,
        hostname: 'db-01',
        ip: '10.0.1.30',
        emit: vi.fn(),
    };
}

function makeServiceConfig(overrides?: Record<string, unknown>): ServiceConfig {
    const base: ServiceConfig = {
        name: 'mysql',
        command: 'mysqld',
        ports: [3306],
        autostart: true,
    };
    if (overrides !== undefined) {
        return { ...base, config: overrides };
    }
    return base;
}

function decode(payload: Uint8Array): string {
    return new TextDecoder().decode(payload);
}

describe('MySQLService', () => {
    let ctx: ServiceContext;

    beforeEach(() => {
        ctx = makeContext();
    });

    it('returns welcome banner on empty request', () => {
        const service = createMySQLService(makeServiceConfig());
        const response = service.handle(makeRequest(''), ctx);
        expect(response).not.toBeNull();
        const text = decode(response!.payload);
        expect(text).toContain('Welcome to the MySQL monitor');
        expect(text).toContain('mysql>');
    });

    it('authenticates with valid AUTH command', () => {
        const service = createMySQLService(makeServiceConfig());
        const resp = service.handle(makeRequest('AUTH root toor'), ctx);
        const text = decode(resp!.payload);
        expect(text).toContain('Welcome to the MySQL monitor');
        expect(resp!.close).toBe(false);
    });

    it('rejects invalid AUTH credentials', () => {
        const service = createMySQLService(makeServiceConfig());
        const resp = service.handle(makeRequest('AUTH root wrongpass'), ctx);
        const text = decode(resp!.payload);
        expect(text).toContain('ERROR 1045');
        expect(text).toContain('Access denied');
        expect(resp!.close).toBe(true);
    });

    it('denies queries without authentication', () => {
        const service = createMySQLService(makeServiceConfig());
        const resp = service.handle(makeRequest('SELECT 1'), ctx);
        const text = decode(resp!.payload);
        expect(text).toContain('ERROR 1045');
        expect(text).toContain('Please authenticate');
    });

    it('handles SHOW DATABASES', () => {
        const service = createMySQLService(makeServiceConfig());
        service.handle(makeRequest('AUTH root toor'), ctx);

        const resp = service.handle(makeRequest('SHOW DATABASES'), ctx);
        const text = decode(resp!.payload);
        expect(text).toContain('webapp');
        expect(text).toContain('rows in set');
    });

    it('handles USE database', () => {
        const service = createMySQLService(makeServiceConfig());
        service.handle(makeRequest('AUTH root toor'), ctx);

        const resp = service.handle(makeRequest('USE webapp'), ctx);
        const text = decode(resp!.payload);
        expect(text).toContain('Database changed');
    });

    it('rejects USE for unknown database', () => {
        const service = createMySQLService(makeServiceConfig());
        service.handle(makeRequest('AUTH root toor'), ctx);

        const resp = service.handle(makeRequest('USE nonexistent'), ctx);
        const text = decode(resp!.payload);
        expect(text).toContain('ERROR 1049');
        expect(text).toContain('Unknown database');
    });

    it('handles SHOW TABLES after USE', () => {
        const service = createMySQLService(makeServiceConfig());
        service.handle(makeRequest('AUTH root toor'), ctx);
        service.handle(makeRequest('USE webapp'), ctx);

        const resp = service.handle(makeRequest('SHOW TABLES'), ctx);
        const text = decode(resp!.payload);
        expect(text).toContain('users');
        expect(text).toContain('sessions');
        expect(text).toContain('config');
    });

    it('returns error for SHOW TABLES without database selected', () => {
        const service = createMySQLService(makeServiceConfig());
        service.handle(makeRequest('AUTH root toor'), ctx);

        const resp = service.handle(makeRequest('SHOW TABLES'), ctx);
        const text = decode(resp!.payload);
        expect(text).toContain('ERROR 1046');
        expect(text).toContain('No database selected');
    });

    it('handles DESCRIBE table', () => {
        const service = createMySQLService(makeServiceConfig());
        service.handle(makeRequest('AUTH root toor'), ctx);
        service.handle(makeRequest('USE webapp'), ctx);

        const resp = service.handle(makeRequest('DESCRIBE users'), ctx);
        const text = decode(resp!.payload);
        expect(text).toContain('id');
        expect(text).toContain('username');
        expect(text).toContain('email');
        expect(text).toContain('role');
        expect(text).toContain('varchar(255)');
    });

    it('handles SELECT * FROM table', () => {
        const service = createMySQLService(makeServiceConfig());
        service.handle(makeRequest('AUTH root toor'), ctx);
        service.handle(makeRequest('USE webapp'), ctx);

        const resp = service.handle(makeRequest('SELECT * FROM users'), ctx);
        const text = decode(resp!.payload);
        expect(text).toContain('admin');
        expect(text).toContain('jsmith');
        expect(text).toContain('developer');
        expect(text).toContain('3 rows in set');
    });

    it('handles SELECT with WHERE clause', () => {
        const service = createMySQLService(makeServiceConfig());
        service.handle(makeRequest('AUTH root toor'), ctx);
        service.handle(makeRequest('USE webapp'), ctx);

        const resp = service.handle(makeRequest("SELECT * FROM users WHERE username = 'admin'"), ctx);
        const text = decode(resp!.payload);
        expect(text).toContain('admin');
        expect(text).toContain('1 rows in set');
        expect(text).not.toContain('jsmith');
    });

    it('handles SELECT VERSION()', () => {
        const service = createMySQLService(makeServiceConfig());
        service.handle(makeRequest('AUTH root toor'), ctx);

        const resp = service.handle(makeRequest('SELECT VERSION()'), ctx);
        const text = decode(resp!.payload);
        expect(text).toContain('8.0.36');
        expect(text).toContain('1 row in set');
    });

    it('handles SELECT DATABASE()', () => {
        const service = createMySQLService(makeServiceConfig());
        service.handle(makeRequest('AUTH root toor'), ctx);
        service.handle(makeRequest('USE webapp'), ctx);

        const resp = service.handle(makeRequest('SELECT DATABASE()'), ctx);
        const text = decode(resp!.payload);
        expect(text).toContain('webapp');
    });

    it('handles SELECT USER()', () => {
        const service = createMySQLService(makeServiceConfig());
        service.handle(makeRequest('AUTH root toor'), ctx);

        const resp = service.handle(makeRequest('SELECT USER()'), ctx);
        const text = decode(resp!.payload);
        expect(text).toContain('root@localhost');
    });

    it('handles INSERT/UPDATE/DELETE as read-only sim', () => {
        const service = createMySQLService(makeServiceConfig());
        service.handle(makeRequest('AUTH root toor'), ctx);
        service.handle(makeRequest('USE webapp'), ctx);

        const insertResp = service.handle(makeRequest("INSERT INTO users VALUES (4, 'test', 'test@test.com', 'user')"), ctx);
        expect(decode(insertResp!.payload)).toContain('Query OK');

        const updateResp = service.handle(makeRequest("UPDATE users SET role = 'admin' WHERE id = 2"), ctx);
        expect(decode(updateResp!.payload)).toContain('Query OK');

        const deleteResp = service.handle(makeRequest('DELETE FROM users WHERE id = 3'), ctx);
        expect(decode(deleteResp!.payload)).toContain('Query OK');
    });

    it('returns syntax error for unknown SQL', () => {
        const service = createMySQLService(makeServiceConfig());
        service.handle(makeRequest('AUTH root toor'), ctx);

        const resp = service.handle(makeRequest('DROP TABLE users'), ctx);
        const text = decode(resp!.payload);
        expect(text).toContain('ERROR 1064');
        expect(text).toContain('syntax');
    });

    it('emits login events', () => {
        const service = createMySQLService(makeServiceConfig());
        service.handle(makeRequest('AUTH root toor'), ctx);

        expect(ctx.emit).toHaveBeenCalledWith(
            expect.objectContaining({
                type: 'service:custom',
                service: 'mysql',
                action: 'login',
                details: expect.objectContaining({ username: 'root', success: true }),
            }),
        );
    });

    it('emits query events on SELECT', () => {
        const service = createMySQLService(makeServiceConfig());
        service.handle(makeRequest('AUTH root toor'), ctx);
        service.handle(makeRequest('USE webapp'), ctx);
        service.handle(makeRequest('SELECT * FROM users'), ctx);

        expect(ctx.emit).toHaveBeenCalledWith(
            expect.objectContaining({
                type: 'service:custom',
                service: 'mysql',
                action: 'query',
                details: expect.objectContaining({ query: 'SELECT * FROM users' }),
            }),
        );
    });

    it('writes query log to VFS', () => {
        const service = createMySQLService(makeServiceConfig());
        service.handle(makeRequest('AUTH root toor'), ctx);
        service.handle(makeRequest('USE webapp'), ctx);
        service.handle(makeRequest('SELECT * FROM users'), ctx);

        const log = ctx.vfs.readFile('/var/log/mysql/query.log');
        expect(log).toContain('SELECT * FROM users');
        expect(log).toContain('root');
    });

    it('maintains per-IP sessions', () => {
        const service = createMySQLService(makeServiceConfig());

        // Auth IP1
        service.handle(makeRequest('AUTH root toor', '10.0.0.1'), ctx);

        // IP2 should not be authenticated
        const resp = service.handle(makeRequest('SHOW DATABASES', '10.0.0.2'), ctx);
        const text = decode(resp!.payload);
        expect(text).toContain('ERROR 1045');
    });

    it('clears sessions on stop', () => {
        const service = createMySQLService(makeServiceConfig());
        service.handle(makeRequest('AUTH root toor'), ctx);
        service.stop?.();

        const resp = service.handle(makeRequest('SHOW DATABASES'), ctx);
        const text = decode(resp!.payload);
        expect(text).toContain('ERROR 1045');
    });

    it('uses custom version from config', () => {
        const service = createMySQLService(makeServiceConfig({ version: '5.7.42' }));
        service.handle(makeRequest('AUTH root toor'), ctx);

        const resp = service.handle(makeRequest('SELECT VERSION()'), ctx);
        expect(decode(resp!.payload)).toContain('5.7.42');
    });

    it('handles trailing semicolons in queries', () => {
        const service = createMySQLService(makeServiceConfig());
        service.handle(makeRequest('AUTH root toor'), ctx);

        const resp = service.handle(makeRequest('SHOW DATABASES;'), ctx);
        const text = decode(resp!.payload);
        expect(text).toContain('webapp');
    });

    it('config table contains sensitive training data', () => {
        const service = createMySQLService(makeServiceConfig());
        service.handle(makeRequest('AUTH root toor'), ctx);
        service.handle(makeRequest('USE webapp'), ctx);

        const resp = service.handle(makeRequest('SELECT * FROM config'), ctx);
        const text = decode(resp!.payload);
        expect(text).toContain('db_password');
        expect(text).toContain('P@ssw0rd123!');
        expect(text).toContain('api_key');
        expect(text).toContain('secret_key');
    });
});
