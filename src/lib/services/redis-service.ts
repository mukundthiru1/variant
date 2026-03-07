/**
 * VARIANT — Redis Service Simulation
 *
 * Simulates a Redis-compatible key-value store:
 * - GET/SET/DEL/KEYS/TTL operations
 * - AUTH (password-based)
 * - CONFIG GET/SET
 * - Lua scripting simulation
 * - Security: unauthenticated access, dangerous commands
 *
 * All operations are synchronous and pure-data.
 */

// ── Types ────────────────────────────────────────────────

export interface RedisEntry {
    readonly key: string;
    readonly value: string;
    readonly type: 'string' | 'list' | 'set' | 'hash';
    readonly ttl: number | null;
    readonly createdAt: number;
}

export interface RedisConfig {
    readonly requirepass?: string;
    readonly bind?: string;
    readonly port?: number;
    readonly protectedMode?: boolean;
    readonly maxmemory?: string;
    readonly renamedCommands?: Readonly<Record<string, string>>;
}

export interface RedisCommandResult {
    readonly ok: boolean;
    readonly value: string | null;
    readonly error?: string;
}

export interface RedisSecurityIssue {
    readonly type: RedisSecurityType;
    readonly severity: 'low' | 'medium' | 'high' | 'critical';
    readonly description: string;
    readonly recommendation: string;
    readonly mitre?: string;
}

export type RedisSecurityType =
    | 'no_auth' | 'weak_password' | 'exposed_bind'
    | 'dangerous_command' | 'protected_mode_off'
    | 'rce_via_eval' | 'config_write'
    | (string & {});

export interface RedisService {
    /** Execute a Redis command. */
    execute(command: string, ...args: string[]): RedisCommandResult;
    /** Authenticate. */
    auth(password: string): boolean;
    /** Check if authenticated. */
    isAuthenticated(): boolean;
    /** Security scan. */
    securityScan(): readonly RedisSecurityIssue[];
    /** Get stats. */
    getStats(): RedisStats;
}

export interface RedisStats {
    readonly totalKeys: number;
    readonly totalCommands: number;
    readonly authenticated: boolean;
    readonly memoryUsedBytes: number;
    readonly connectedClients: number;
    readonly config: Readonly<Record<string, string>>;
}

// ── Factory ──────────────────────────────────────────────

export function createRedisService(config: RedisConfig = {}): RedisService {
    const store = new Map<string, { value: string; type: string; ttl: number | null; createdAt: number }>();
    const configMap = new Map<string, string>();
    let authenticated = !config.requirepass;
    let totalCommands = 0;

    // Initialize config
    configMap.set('requirepass', config.requirepass ?? '');
    configMap.set('bind', config.bind ?? '127.0.0.1');
    configMap.set('port', String(config.port ?? 6379));
    configMap.set('protected-mode', config.protectedMode !== false ? 'yes' : 'no');
    configMap.set('maxmemory', config.maxmemory ?? '0');

    const DANGEROUS_COMMANDS = new Set([
        'FLUSHALL', 'FLUSHDB', 'DEBUG', 'SHUTDOWN', 'SLAVEOF', 'REPLICAOF',
        'CONFIG', 'MODULE', 'BGSAVE', 'BGREWRITEAOF',
    ]);

    const renamedCommands = config.renamedCommands ?? {};

    function resolveCommand(cmd: string): string {
        const upper = cmd.toUpperCase();
        // Check if renamed
        for (const [original, renamed] of Object.entries(renamedCommands)) {
            if (renamed.toUpperCase() === upper) return original.toUpperCase();
        }
        return upper;
    }

    function requireAuth(): RedisCommandResult | null {
        if (!authenticated) {
            return { ok: false, value: null, error: 'NOAUTH Authentication required' };
        }
        return null;
    }

    const service: RedisService = {
        execute(command: string, ...args: string[]): RedisCommandResult {
            totalCommands++;
            const cmd = resolveCommand(command);

            // AUTH doesn't require prior auth
            if (cmd === 'AUTH') {
                if (!config.requirepass) {
                    return { ok: false, value: null, error: 'ERR Client sent AUTH, but no password is set' };
                }
                if (args[0] === config.requirepass) {
                    authenticated = true;
                    return { ok: true, value: 'OK' };
                }
                return { ok: false, value: null, error: 'ERR invalid password' };
            }

            // PING doesn't require auth
            if (cmd === 'PING') {
                return { ok: true, value: args[0] ?? 'PONG' };
            }

            const authErr = requireAuth();
            if (authErr) return authErr;

            switch (cmd) {
                case 'SET': {
                    if (args.length < 2) return { ok: false, value: null, error: 'ERR wrong number of arguments' };
                    const key = args[0]!;
                    const value = args[1]!;
                    let ttl: number | null = null;
                    if (args.length >= 4 && args[2]!.toUpperCase() === 'EX') {
                        ttl = parseInt(args[3]!, 10);
                    }
                    store.set(key, { value, type: 'string', ttl, createdAt: Date.now() });
                    return { ok: true, value: 'OK' };
                }

                case 'GET': {
                    if (args.length < 1) return { ok: false, value: null, error: 'ERR wrong number of arguments' };
                    const entry = store.get(args[0]!);
                    if (!entry) return { ok: true, value: null };
                    return { ok: true, value: entry.value };
                }

                case 'DEL': {
                    if (args.length < 1) return { ok: false, value: null, error: 'ERR wrong number of arguments' };
                    let deleted = 0;
                    for (const key of args) {
                        if (store.delete(key)) deleted++;
                    }
                    return { ok: true, value: String(deleted) };
                }

                case 'EXISTS': {
                    if (args.length < 1) return { ok: false, value: null, error: 'ERR wrong number of arguments' };
                    return { ok: true, value: store.has(args[0]!) ? '1' : '0' };
                }

                case 'KEYS': {
                    const pattern = args[0] ?? '*';
                    let keys: string[];
                    if (pattern === '*') {
                        keys = Array.from(store.keys());
                    } else {
                        const regex = new RegExp('^' + pattern.replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
                        keys = Array.from(store.keys()).filter(k => regex.test(k));
                    }
                    return { ok: true, value: keys.join('\n') };
                }

                case 'TTL': {
                    if (args.length < 1) return { ok: false, value: null, error: 'ERR wrong number of arguments' };
                    const entry = store.get(args[0]!);
                    if (!entry) return { ok: true, value: '-2' };
                    if (entry.ttl === null) return { ok: true, value: '-1' };
                    return { ok: true, value: String(entry.ttl) };
                }

                case 'EXPIRE': {
                    if (args.length < 2) return { ok: false, value: null, error: 'ERR wrong number of arguments' };
                    const entry = store.get(args[0]!);
                    if (!entry) return { ok: true, value: '0' };
                    store.set(args[0]!, { ...entry, ttl: parseInt(args[1]!, 10) });
                    return { ok: true, value: '1' };
                }

                case 'DBSIZE': {
                    return { ok: true, value: String(store.size) };
                }

                case 'INFO': {
                    return { ok: true, value: `redis_version:7.2.0\nused_memory:${store.size * 100}\nconnected_clients:1\ntotal_commands_processed:${totalCommands}` };
                }

                case 'CONFIG': {
                    if (args.length < 2) return { ok: false, value: null, error: 'ERR wrong number of arguments' };
                    const subCmd = args[0]!.toUpperCase();
                    if (subCmd === 'GET') {
                        const val = configMap.get(args[1]!);
                        return { ok: true, value: val ?? null };
                    }
                    if (subCmd === 'SET') {
                        if (args.length < 3) return { ok: false, value: null, error: 'ERR wrong number of arguments' };
                        configMap.set(args[1]!, args[2]!);
                        return { ok: true, value: 'OK' };
                    }
                    return { ok: false, value: null, error: `ERR Unknown subcommand ${subCmd}` };
                }

                case 'EVAL': {
                    // Lua script simulation — just return OK to simulate the vector
                    return { ok: true, value: 'OK (simulated Lua execution)' };
                }

                case 'FLUSHALL':
                case 'FLUSHDB': {
                    store.clear();
                    return { ok: true, value: 'OK' };
                }

                case 'SELECT': {
                    return { ok: true, value: 'OK' };
                }

                default:
                    return { ok: false, value: null, error: `ERR unknown command '${command}'` };
            }
        },

        auth(password: string) {
            const result = service.execute('AUTH', password);
            return result.ok;
        },

        isAuthenticated() {
            return authenticated;
        },

        securityScan() {
            const issues: RedisSecurityIssue[] = [];

            if (!config.requirepass) {
                issues.push({
                    type: 'no_auth', severity: 'critical',
                    description: 'Redis has no password set — anyone can connect',
                    recommendation: 'Set requirepass in redis.conf',
                    mitre: 'T1078',
                });
            } else if (config.requirepass.length < 12) {
                issues.push({
                    type: 'weak_password', severity: 'high',
                    description: 'Redis password is short and potentially brutable',
                    recommendation: 'Use a password of at least 32 characters',
                });
            }

            const bind = configMap.get('bind') ?? '';
            if (bind === '0.0.0.0' || bind === '') {
                issues.push({
                    type: 'exposed_bind', severity: 'high',
                    description: 'Redis is bound to all interfaces — exposed to network',
                    recommendation: 'Bind to 127.0.0.1 or specific internal interface',
                    mitre: 'T1190',
                });
            }

            if (configMap.get('protected-mode') === 'no') {
                issues.push({
                    type: 'protected_mode_off', severity: 'medium',
                    description: 'Protected mode is disabled',
                    recommendation: 'Enable protected mode when binding to public interfaces',
                });
            }

            // Check for unrenamed dangerous commands
            for (const cmd of DANGEROUS_COMMANDS) {
                if (!(cmd in renamedCommands)) {
                    issues.push({
                        type: 'dangerous_command', severity: 'medium',
                        description: `Dangerous command ${cmd} is not renamed/disabled`,
                        recommendation: `Rename or disable ${cmd} in redis.conf`,
                    });
                    break; // One finding is enough
                }
            }

            return Object.freeze(issues);
        },

        getStats() {
            return Object.freeze({
                totalKeys: store.size,
                totalCommands,
                authenticated,
                memoryUsedBytes: store.size * 100,
                connectedClients: 1,
                config: Object.freeze(Object.fromEntries(configMap)),
            });
        },
    };

    return service;
}
