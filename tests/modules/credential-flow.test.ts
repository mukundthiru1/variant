/**
 * VARIANT — Credential Flow Module Tests
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createEventBus, stubFabric, stubServices } from '../helpers';
import type { EventBus, EngineEvent } from '../../src/core/events';
import type { SimulationContext, ServiceLocator } from '../../src/core/modules';
import type { CredentialEntry, WorldSpec } from '../../src/core/world/types';
import {
    createCredentialFlowModule,
    scanForCredentials,
    deriveToken,
    crackHash,
    type DiscoveredCredential,
    type CredentialSource,
    type CredentialStore,
} from '../../src/modules/credential-flow';

const WORLD: WorldSpec = {
    version: '2.0',
    trust: 'community',
    meta: {
        title: 'Credential Flow Test',
        scenario: 'credential-flow',
        briefing: [],
        difficulty: 'beginner',
        mode: 'attack',
        vulnClasses: [],
        tags: [],
        estimatedMinutes: 10,
        author: { name: 'unit-test', id: 'unit', type: 'santh' },
    },
    machines: {},
    startMachine: 'web',
    network: { segments: [], edges: [] },
    credentials: [],
    objectives: [],
    modules: [],
    scoring: {
        maxScore: 1000,
        timeBonus: false,
        stealthBonus: false,
        hintPenalty: 25,
        tiers: [],
    },
    hints: [],
};

function makeContext(eventBus: EventBus, services: ServiceLocator = stubServices()): SimulationContext {
    return {
        vms: new Map(),
        fabric: stubFabric(),
        events: eventBus,
        world: WORLD,
        tick: 0,
        services,
    };
}

function makeSource(overrides: Partial<CredentialSource> = {}): CredentialSource {
    return {
        module: 'test-suite',
        machine: 'web',
        path: '/tmp/secret',
        method: 'manual',
        tick: 1,
        ...overrides,
    };
}

function makeCredential(overrides: Partial<DiscoveredCredential> = {}): DiscoveredCredential {
    return {
        id: 'manual',
        type: 'password',
        value: 'DefaultPass123',
        source: makeSource(),
        targets: [],
        status: 'raw',
        ...overrides,
    };
}

function hashValue(value: string): string {
    let hash = 5381;
    for (let i = 0; i < value.length; i++) {
        hash = ((hash << 5) + hash + value.charCodeAt(i)) & 0xffffffff;
    }
    return (hash >>> 0).toString(16).padStart(8, '0');
}

function makeWorldCredentials(): readonly CredentialEntry[] {
    return [
        {
            id: 'seed-admin-password',
            type: 'password',
            value: 'seed-pass-1',
            foundAt: {
                machine: 'db',
                path: '/srv/seed',
                method: 'seed',
            },
            validAt: {
                machine: 'db',
                service: 'ssh',
                user: 'admin',
            },
        },
        {
            id: 'seed-api-token',
            type: 'api-token',
            value: 'seed-token-1',
            foundAt: {
                machine: 'api',
                path: '/srv/token',
                method: 'seed',
            },
            validAt: {
                machine: 'api',
                service: 'http',
                user: 'svc',
            },
        },
    ];
}

describe('Credential Flow Module', () => {
    let eventBus: EventBus;
    let module: ReturnType<typeof createCredentialFlowModule>;

    beforeEach(() => {
        eventBus = createEventBus();
        module = createCredentialFlowModule(makeWorldCredentials(), eventBus);
    });

    afterEach(() => {
        module.destroy();
    });

    it('registers and retrieves credentials by deterministic ID', () => {
        const id = module.register(makeCredential({
            value: 'alpha',
            source: makeSource({ machine: 'web', path: '/etc/passwd', tick: 10 }),
        }));

        const retrieved = module.get(id);
        expect(retrieved?.id).toBe(id);
        expect(retrieved?.value).toBe('alpha');
        expect(retrieved?.source.machine).toBe('web');
        expect(retrieved?.source.path).toBe('/etc/passwd');
    });

    it('queries by type', () => {
        module.register(makeCredential({ id: 'p1', type: 'password', value: 'p1' }));
        module.register(makeCredential({ id: 't1', type: 'token', value: 't1', source: makeSource({ tick: 2 }) }));
        module.register(makeCredential({ id: 'p2', type: 'password', value: 'p2', source: makeSource({ tick: 3 }) }));

        expect(module.query({ type: 'password' })).toHaveLength(2);
        expect(module.query({ type: 'token' })).toHaveLength(1);
    });

    it('queries by source machine', () => {
        module.register(makeCredential({ id: 'a', value: 'a', source: makeSource({ machine: 'app' }) }));
        module.register(makeCredential({ id: 'b', value: 'b', source: makeSource({ machine: 'db', tick: 2 }) }));

        expect(module.query({ sourceMachine: 'app' })).toHaveLength(1);
        expect(module.query({ sourceMachine: 'db' })).toHaveLength(1);
    });

    it('queries by username', () => {
        module.register(makeCredential({ id: 'a', value: 'a', username: 'alice' }));
        module.register(makeCredential({ id: 'b', value: 'b', username: 'bob', source: makeSource({ tick: 2 }) }));

        expect(module.query({ username: 'alice' })).toHaveLength(1);
        expect(module.query({ username: 'bob' })).toHaveLength(1);
    });

    it('queries by target constraints', () => {
        module.register(makeCredential({
            id: 'targeted',
            value: 'target',
            targets: [{ machine: 'db', service: 'postgres', user: 'svc', port: 5432 }],
        }));

        expect(module.query({ targetMachine: 'db' })).toHaveLength(1);
        expect(module.query({ targetService: 'postgres' })).toHaveLength(1);
        expect(module.query({ targetUser: 'svc' })).toHaveLength(1);
        expect(module.query({ targetPort: 5432 })).toHaveLength(1);
    });

    it('validates against a matching target', () => {
        const credentialId = module.register(makeCredential({
            id: 'valid',
            targets: [{ machine: 'db', service: 'postgres', user: 'svc', port: 5432 }],
        }));

        const result = module.validate(credentialId, {
            machine: 'db',
            service: 'postgres',
            user: 'svc',
            port: 5432,
        });

        expect(result.success).toBe(true);
        expect(result.reason).toBe('ok');
        expect(result.credential?.status).toBe('validated');
    });

    it('fails validation when target does not match', () => {
        const credentialId = module.register(makeCredential({
            id: 'invalid-target',
            targets: [{ machine: 'db', service: 'postgres', user: 'svc' }],
        }));

        const result = module.validate(credentialId, {
            machine: 'web',
            service: 'postgres',
            user: 'svc',
        });

        expect(result.success).toBe(false);
        expect(result.reason).toBe('invalid-target');
    });

    it('fails validation for unknown credential', () => {
        const result = module.validate('missing-id', {
            machine: 'db',
            service: 'postgres',
            user: 'svc',
        });

        expect(result.success).toBe(false);
        expect(result.reason).toBe('not-found');
    });

    it('fails validation for expired credentials', () => {
        const id = module.register(makeCredential({
            id: 'expired',
            status: 'expired',
            targets: [{ machine: 'db', service: 'postgres', user: 'svc' }],
        }));

        const result = module.validate(id, {
            machine: 'db',
            service: 'postgres',
            user: 'svc',
        });

        expect(result.success).toBe(false);
        expect(result.reason).toBe('expired');
    });

    it('builds chain links for derived credentials', () => {
        const parentId = module.register(makeCredential({ id: 'parent', value: 'root-pass' }));
        const jwt = deriveToken({ ...makeCredential({ id: parentId, value: 'root-pass' }) }, 'jwt');
        const jwtId = module.register(jwt);
        const kerberos = deriveToken({ ...jwt, id: jwtId }, 'kerberos-ticket');
        const kerberosId = module.register(kerberos);

        const chain = module.getChain(kerberosId);

        expect(chain).toHaveLength(2);
        expect(chain[0]?.parentId).toBe(parentId);
        expect(chain[0]?.childId).toBe(jwtId);
        expect(chain[1]?.parentId).toBe(jwtId);
        expect(chain[1]?.childId).toBe(kerberosId);
    });

    it('emits chain-extended on derivation', () => {
        const parentId = module.register(makeCredential({ id: 'parent2', value: 'root' }));
        let chainEvents: EngineEvent[] = [];
        eventBus.on('credential:chain-extended', (event) => {
            chainEvents = [event];
        });

        const derived = deriveToken({ ...makeCredential({ id: parentId, value: 'root' }) }, 'jwt');
        const derivedId = module.register(derived);

        expect(chainEvents).toHaveLength(1);
        const first = chainEvents[0] as Extract<EngineEvent, { type: 'credential:chain-extended' }>;
        expect(first.parentId).toBe(parentId);
        expect(first.childId).toBe(derivedId);
    });

    it('emits validated event on successful validation', () => {
        const credentialId = module.register(makeCredential({
            id: 'valid-event',
            targets: [{ machine: 'app', service: 'ssh', user: 'admin' }],
        }));

        let seenCredentialId = '';
        eventBus.on('credential:validated', (event) => {
            seenCredentialId = event.credentialId;
        });

        const result = module.validate(credentialId, { machine: 'app', service: 'ssh', user: 'admin' });

        expect(result.success).toBe(true);
        expect(seenCredentialId).toBe(credentialId);
    });

    it('prevents duplicate registration', () => {
        const source = makeSource({ machine: 'web', tick: 2 });
        let registeredCount = 0;
        eventBus.on('credential:registered', () => {
            registeredCount += 1;
        });

        const first = module.register(makeCredential({ id: 'dup', value: 'same', source }));
        const second = module.register(makeCredential({ id: 'dup', value: 'same', source }));

        expect(first).toBe(second);
        expect(registeredCount).toBe(1);
        expect(module.query({ sourceMachine: 'web' })).toHaveLength(1);
    });

    it('auto-registers discovered credentials from auth:credential-found events', () => {
        const context = makeContext(eventBus, stubServices());
        module.init(context);

        const registered: EngineEvent[] = [];
        eventBus.on('credential:registered', (event) => {
            registered.push(event);
        });

        eventBus.emit({
            type: 'auth:credential-found',
            credentialId: 'seed-admin-password',
            machine: 'web',
            location: '/runtime/discovery/creds.txt',
            timestamp: 100,
        });

        expect(registered).toHaveLength(1);
        const matches = module.query({
            type: 'password',
            sourceMachine: 'web',
            sourcePath: '/runtime/discovery/creds.txt',
        });
        expect(matches).toHaveLength(1);
    });

    it('auto-registers credentials from fs:read content scanning', () => {
        const context = makeContext(eventBus, stubServices());
        module.init(context);

        let registeredCount = 0;
        eventBus.on('credential:registered', () => {
            registeredCount += 1;
        });

        const event = {
            type: 'fs:read',
            machine: 'web',
            path: '/etc/app/config',
            user: 'app',
            timestamp: 101,
            content: 'API_KEY=AKIA1234567890ABCDEFGH\nDB_PASSWORD=paSSw0rd\nPASSWORD=password1\n',
        } as EngineEvent & { content: string };
        eventBus.emit(event);

        expect(registeredCount).toBeGreaterThanOrEqual(2);
        expect(module.query({ sourceMachine: 'web' })).toHaveLength(5);
    });

    it('scanForCredentials detects AWS and SSH patterns', () => {
        const content = [
            'AKIAZZZZZZZZZZZZZZZZZZ',
            '-----BEGIN RSA PRIVATE KEY-----',
            'fake-key',
            '-----END RSA PRIVATE KEY-----',
        ].join('\n');

        const found = scanForCredentials(content, makeSource({ tick: 200, path: '/tmp/keys' }));
        expect(found.some((entry) => entry.type === 'api-key')).toBe(true);
        expect(found.some((entry) => entry.type === 'ssh-key')).toBe(true);
    });

    it('scanForCredentials detects JWT tokens', () => {
        const token = 'eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
        const found = scanForCredentials(token, makeSource({ tick: 201, path: '/tmp/jwt' }));

        expect(found).toHaveLength(1);
        expect(found[0]?.type).toBe('token');
        expect(found[0]?.value.startsWith('eyJ')).toBe(true);
    });

    it('scanForCredentials detects env and database credentials', () => {
        const found = scanForCredentials([
            'DB_USER=app',
            'DB_PASSWORD=p@ss',
            'API_TOKEN=token-abc',
            'COOKIE_SESSION=abc123',
            'mysql://app:dbpass@db.host/report',
        ].join('\n'), makeSource({ tick: 202, path: '/app/.env' }));

        expect(found.some((entry) => entry.type === 'password')).toBe(true);
        expect(found.some((entry) => entry.type === 'api-key')).toBe(true);
        expect(found.some((entry) => entry.type === 'cookie')).toBe(true);
    });

    it('cracks hash with matching weak candidate', () => {
        const cleartext = 'CrackThis!';
        const hashed = hashValue(cleartext);
        const hashedCredential = makeCredential({
            id: 'hash-1',
            type: 'hash',
            value: hashed,
            status: 'raw',
        });

        const cracked = crackHash(hashedCredential, ['bad', cleartext, 'other']);
        expect(cracked).not.toBeNull();
        expect(cracked?.type).toBe('password');
        expect(cracked?.status).toBe('cracked');
        expect(cracked?.value).toBe(cleartext);
        expect(cracked?.derivedFrom).toBe('hash-1');
    });

    it('returns null when hash cannot be cracked', () => {
        const hashedCredential = makeCredential({
            id: 'hash-2',
            type: 'hash',
            value: hashValue('topsecret'),
            status: 'raw',
        });

        const cracked = crackHash(hashedCredential, ['bad', 'worse']);
        expect(cracked).toBeNull();
    });

    it('registers credential store in ServiceLocator and allows query', () => {
        const services = stubServices();
        const context = makeContext(eventBus, services);
        module.init(context);

        const store = context.services.get<CredentialStore>('credential-store');
        expect(store).toBeDefined();
        if (store === undefined) return;

        const id = store.register(makeCredential({ id: 'svc', value: 'service-pass', source: makeSource({ tick: 50, machine: 'svc-host' }) }));
        expect(store.get(id)?.source.machine).toBe('svc-host');
        expect(module.get(id)?.id).toBe(id);
    });

    it('supports id and derivedFrom filtering', () => {
        const parentId = module.register(makeCredential({ id: 'base', value: 'base-pass' }));
        const derived = deriveToken({ ...makeCredential({ id: parentId, value: 'base-pass' }) }, 'jwt');
        const derivedId = module.register(derived);

        expect(module.query({ id: parentId })).toHaveLength(1);
        expect(module.query({ derivedFrom: parentId })[0]?.id).toBe(derivedId);
    });

    it('supports source method filtering', () => {
        const scanId = module.register(makeCredential({ id: 's1', value: 'a', source: makeSource({ method: 'scan', tick: 1 }) }));
        module.register(makeCredential({ id: 's2', value: 'b', source: makeSource({ method: 'manual', tick: 2 }) }));

        expect(module.query({ sourceMethod: 'scan' })).toHaveLength(1);
        const found = module.query({ sourceMethod: 'scan' });
        expect(found[0]?.id).toBe(scanId);
    });

    it('derives token credential from password input', () => {
        const parent = module.register(makeCredential({ id: 'derive-parent', value: 'parent-pass' }));
        const derived = deriveToken({ ...makeCredential({ id: parent, value: 'parent-pass' }) }, 'kerberos-ticket');

        expect(derived.type).toBe('kerberos-ticket');
        expect(derived.derivedFrom).toBe(parent);
        expect(derived.source.method).toBe('derive:kerberos-ticket');
    });
});
