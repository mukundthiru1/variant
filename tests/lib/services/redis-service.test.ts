import { describe, it, expect } from 'vitest';
import { createRedisService } from '../../../src/lib/services/redis-service';

describe('Redis Service', () => {
    // ── Basic Operations ─────────────────────────────────────

    it('SET and GET a key', () => {
        const redis = createRedisService();
        expect(redis.execute('SET', 'foo', 'bar').ok).toBe(true);
        expect(redis.execute('GET', 'foo').value).toBe('bar');
    });

    it('GET returns null for missing key', () => {
        const redis = createRedisService();
        expect(redis.execute('GET', 'missing').value).toBeNull();
    });

    it('DEL removes keys', () => {
        const redis = createRedisService();
        redis.execute('SET', 'foo', 'bar');
        redis.execute('SET', 'baz', 'qux');
        const result = redis.execute('DEL', 'foo', 'baz');
        expect(result.value).toBe('2');
        expect(redis.execute('GET', 'foo').value).toBeNull();
    });

    it('EXISTS checks key existence', () => {
        const redis = createRedisService();
        redis.execute('SET', 'key1', 'val');
        expect(redis.execute('EXISTS', 'key1').value).toBe('1');
        expect(redis.execute('EXISTS', 'key2').value).toBe('0');
    });

    it('KEYS * returns all keys', () => {
        const redis = createRedisService();
        redis.execute('SET', 'user:1', 'alice');
        redis.execute('SET', 'user:2', 'bob');
        redis.execute('SET', 'session:abc', 'data');
        const result = redis.execute('KEYS', '*');
        expect(result.value!.split('\n')).toHaveLength(3);
    });

    it('KEYS with pattern filters', () => {
        const redis = createRedisService();
        redis.execute('SET', 'user:1', 'a');
        redis.execute('SET', 'user:2', 'b');
        redis.execute('SET', 'session:x', 'c');
        const result = redis.execute('KEYS', 'user:*');
        expect(result.value!.split('\n')).toHaveLength(2);
    });

    it('SET with EX sets TTL', () => {
        const redis = createRedisService();
        redis.execute('SET', 'temp', 'val', 'EX', '300');
        expect(redis.execute('TTL', 'temp').value).toBe('300');
    });

    it('TTL returns -1 for no expiry', () => {
        const redis = createRedisService();
        redis.execute('SET', 'perm', 'val');
        expect(redis.execute('TTL', 'perm').value).toBe('-1');
    });

    it('TTL returns -2 for missing key', () => {
        const redis = createRedisService();
        expect(redis.execute('TTL', 'missing').value).toBe('-2');
    });

    it('EXPIRE sets TTL on existing key', () => {
        const redis = createRedisService();
        redis.execute('SET', 'key', 'val');
        expect(redis.execute('EXPIRE', 'key', '60').value).toBe('1');
        expect(redis.execute('TTL', 'key').value).toBe('60');
    });

    it('DBSIZE returns key count', () => {
        const redis = createRedisService();
        redis.execute('SET', 'a', '1');
        redis.execute('SET', 'b', '2');
        expect(redis.execute('DBSIZE').value).toBe('2');
    });

    it('PING returns PONG', () => {
        const redis = createRedisService();
        expect(redis.execute('PING').value).toBe('PONG');
    });

    it('PING with message echoes it', () => {
        const redis = createRedisService();
        expect(redis.execute('PING', 'hello').value).toBe('hello');
    });

    it('INFO returns server info', () => {
        const redis = createRedisService();
        const result = redis.execute('INFO');
        expect(result.ok).toBe(true);
        expect(result.value).toContain('redis_version');
    });

    it('FLUSHALL clears all keys', () => {
        const redis = createRedisService();
        redis.execute('SET', 'a', '1');
        redis.execute('SET', 'b', '2');
        redis.execute('FLUSHALL');
        expect(redis.execute('DBSIZE').value).toBe('0');
    });

    it('EVAL simulates Lua execution', () => {
        const redis = createRedisService();
        const result = redis.execute('EVAL', 'return 1', '0');
        expect(result.ok).toBe(true);
    });

    it('CONFIG GET returns config value', () => {
        const redis = createRedisService({ port: 6380 });
        expect(redis.execute('CONFIG', 'GET', 'port').value).toBe('6380');
    });

    it('CONFIG SET updates config', () => {
        const redis = createRedisService();
        redis.execute('CONFIG', 'SET', 'maxmemory', '256mb');
        expect(redis.execute('CONFIG', 'GET', 'maxmemory').value).toBe('256mb');
    });

    // ── Authentication ───────────────────────────────────────

    it('no-auth redis is authenticated by default', () => {
        const redis = createRedisService();
        expect(redis.isAuthenticated()).toBe(true);
    });

    it('password-protected redis blocks commands before auth', () => {
        const redis = createRedisService({ requirepass: 'supersecret' });
        expect(redis.isAuthenticated()).toBe(false);
        const result = redis.execute('GET', 'key');
        expect(result.ok).toBe(false);
        expect(result.error).toContain('NOAUTH');
    });

    it('AUTH with correct password authenticates', () => {
        const redis = createRedisService({ requirepass: 'supersecret' });
        expect(redis.auth('supersecret')).toBe(true);
        expect(redis.isAuthenticated()).toBe(true);
        expect(redis.execute('SET', 'key', 'val').ok).toBe(true);
    });

    it('AUTH with wrong password fails', () => {
        const redis = createRedisService({ requirepass: 'supersecret' });
        expect(redis.auth('wrong')).toBe(false);
        expect(redis.isAuthenticated()).toBe(false);
    });

    it('PING works without auth', () => {
        const redis = createRedisService({ requirepass: 'secret' });
        expect(redis.execute('PING').ok).toBe(true);
    });

    // ── Security Scan ────────────────────────────────────────

    it('detects no-auth vulnerability', () => {
        const redis = createRedisService();
        const issues = redis.securityScan();
        const noAuth = issues.find(i => i.type === 'no_auth');
        expect(noAuth).toBeDefined();
        expect(noAuth!.severity).toBe('critical');
    });

    it('detects weak password', () => {
        const redis = createRedisService({ requirepass: 'short' });
        const issues = redis.securityScan();
        const weak = issues.find(i => i.type === 'weak_password');
        expect(weak).toBeDefined();
    });

    it('detects exposed bind address', () => {
        const redis = createRedisService({ bind: '0.0.0.0' });
        const issues = redis.securityScan();
        const exposed = issues.find(i => i.type === 'exposed_bind');
        expect(exposed).toBeDefined();
    });

    it('detects disabled protected mode', () => {
        const redis = createRedisService({ protectedMode: false });
        const issues = redis.securityScan();
        const pm = issues.find(i => i.type === 'protected_mode_off');
        expect(pm).toBeDefined();
    });

    it('detects unrenamed dangerous commands', () => {
        const redis = createRedisService();
        const issues = redis.securityScan();
        const dangerous = issues.find(i => i.type === 'dangerous_command');
        expect(dangerous).toBeDefined();
    });

    it('no dangerous command warning when renamed', () => {
        const redis = createRedisService({
            requirepass: 'a-very-long-secure-password-that-is-long',
            renamedCommands: {
                FLUSHALL: '', FLUSHDB: '', DEBUG: '', SHUTDOWN: '',
                SLAVEOF: '', REPLICAOF: '', CONFIG: 'cfg_secret',
                MODULE: '', BGSAVE: '', BGREWRITEAOF: '',
            },
        });
        const issues = redis.securityScan();
        expect(issues.find(i => i.type === 'dangerous_command')).toBeUndefined();
    });

    // ── Stats ────────────────────────────────────────────────

    it('getStats returns accurate counts', () => {
        const redis = createRedisService();
        redis.execute('SET', 'a', '1');
        redis.execute('SET', 'b', '2');
        redis.execute('GET', 'a');

        const stats = redis.getStats();
        expect(stats.totalKeys).toBe(2);
        expect(stats.totalCommands).toBe(3);
        expect(stats.authenticated).toBe(true);
    });
});
