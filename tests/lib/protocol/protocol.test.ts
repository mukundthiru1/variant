/**
 * VARIANT — Protocol Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createProtocolEngine } from '../../../src/lib/protocol/protocol-engine';
import type { ProtocolDefinition } from '../../../src/lib/protocol/types';

function makeSimpleProtocol(): ProtocolDefinition {
    return {
        id: 'simple',
        name: 'Simple Protocol',
        defaultPort: 9000,
        transport: 'tcp',
        pattern: 'request-response',
        messageTypes: [
            {
                id: 'HELLO',
                direction: 'client-to-server',
                fields: [{ name: 'name', type: 'string', required: true }],
            },
            {
                id: 'WELCOME',
                direction: 'server-to-client',
                fields: [{ name: 'greeting', type: 'string', required: true }],
            },
            {
                id: 'QUERY',
                direction: 'client-to-server',
                fields: [{ name: 'data', type: 'string', required: true }],
            },
            {
                id: 'RESPONSE',
                direction: 'server-to-client',
                fields: [{ name: 'result', type: 'string', required: true }],
            },
            {
                id: 'BYE',
                direction: 'client-to-server',
                fields: [],
            },
        ],
        states: [
            {
                id: 'init',
                name: 'Initial',
                terminal: false,
                transitions: [
                    {
                        to: 'authenticated',
                        onMessage: 'HELLO',
                        response: 'WELCOME',
                        responseFields: { greeting: 'Welcome!' },
                    },
                ],
            },
            {
                id: 'authenticated',
                name: 'Authenticated',
                terminal: false,
                transitions: [
                    {
                        to: 'authenticated',
                        onMessage: 'QUERY',
                        response: 'RESPONSE',
                        responseFields: { result: 'OK' },
                    },
                    {
                        to: 'closed',
                        onMessage: 'BYE',
                    },
                ],
            },
            {
                id: 'closed',
                name: 'Closed',
                terminal: true,
                transitions: [],
            },
        ],
        initialState: 'init',
        parser: {
            delimiter: ' ',
            typeIdentifier: { kind: 'first-word' },
            encoding: 'utf-8',
        },
    };
}

function makeConditionalProtocol(): ProtocolDefinition {
    return {
        id: 'conditional',
        name: 'Conditional Protocol',
        defaultPort: 9001,
        transport: 'tcp',
        pattern: 'request-response',
        messageTypes: [
            {
                id: 'AUTH',
                direction: 'client-to-server',
                fields: [
                    { name: 'user', type: 'string', required: true },
                    { name: 'pass', type: 'string', required: true },
                ],
            },
            {
                id: 'OK',
                direction: 'server-to-client',
                fields: [{ name: 'message', type: 'string', required: true }],
            },
            {
                id: 'FAIL',
                direction: 'server-to-client',
                fields: [{ name: 'message', type: 'string', required: true }],
            },
        ],
        states: [
            {
                id: 'init',
                name: 'Initial',
                terminal: false,
                transitions: [
                    {
                        to: 'authed',
                        onMessage: 'AUTH',
                        condition: { kind: 'field-equals', field: 'pass', value: 'secret' },
                        response: 'OK',
                        responseFields: { message: 'Authenticated' },
                    },
                    {
                        to: 'denied',
                        onMessage: 'AUTH',
                        condition: { kind: 'always' },
                        response: 'FAIL',
                        responseFields: { message: 'Bad password' },
                    },
                ],
            },
            { id: 'authed', name: 'Authenticated', terminal: false, transitions: [] },
            { id: 'denied', name: 'Denied', terminal: true, transitions: [] },
        ],
        initialState: 'init',
        parser: {
            delimiter: ' ',
            typeIdentifier: { kind: 'first-word' },
            encoding: 'utf-8',
        },
    };
}

describe('ProtocolEngine', () => {
    const src = { machine: 'client', port: 12345 };
    const dst = { machine: 'server', port: 9000 };

    it('registers and retrieves protocols', () => {
        const engine = createProtocolEngine();
        engine.registerProtocol(makeSimpleProtocol());

        expect(engine.getProtocol('simple')).not.toBeNull();
        expect(engine.getProtocol('nonexistent')).toBeNull();
        expect(engine.listProtocols().length).toBe(1);
    });

    it('creates sessions', () => {
        const engine = createProtocolEngine();
        engine.registerProtocol(makeSimpleProtocol());

        const id = engine.createSession('simple', src, dst);
        expect(id).not.toBeNull();

        const session = engine.getSession(id!);
        expect(session).not.toBeNull();
        expect(session!.active).toBe(true);
        expect(session!.currentState).toBe('init');
    });

    it('returns null for unknown protocol', () => {
        const engine = createProtocolEngine();
        expect(engine.createSession('nonexistent', src, dst)).toBeNull();
    });

    it('sends message and receives response', () => {
        const engine = createProtocolEngine();
        engine.registerProtocol(makeSimpleProtocol());

        const id = engine.createSession('simple', src, dst)!;
        const response = engine.sendMessage(id, 'HELLO', { name: 'test' }, 1);

        expect(response).not.toBeNull();
        expect(response!.messageType).toBe('WELCOME');
        expect(response!.fields['greeting']).toBe('Welcome!');
        expect(response!.direction).toBe('server-to-client');
    });

    it('transitions state on message', () => {
        const engine = createProtocolEngine();
        engine.registerProtocol(makeSimpleProtocol());

        const id = engine.createSession('simple', src, dst)!;
        engine.sendMessage(id, 'HELLO', { name: 'test' }, 1);

        const session = engine.getSession(id);
        expect(session!.currentState).toBe('authenticated');
    });

    it('captures all messages', () => {
        const engine = createProtocolEngine();
        engine.registerProtocol(makeSimpleProtocol());

        const id = engine.createSession('simple', src, dst)!;
        engine.sendMessage(id, 'HELLO', { name: 'test' }, 1);
        engine.sendMessage(id, 'QUERY', { data: 'foo' }, 2);

        const capture = engine.getCapture(id);
        expect(capture.length).toBe(4); // 2 requests + 2 responses
        expect(capture[0]!.direction).toBe('client-to-server');
        expect(capture[1]!.direction).toBe('server-to-client');
    });

    it('closes session on terminal state', () => {
        const engine = createProtocolEngine();
        engine.registerProtocol(makeSimpleProtocol());

        const id = engine.createSession('simple', src, dst)!;
        engine.sendMessage(id, 'HELLO', { name: 'test' }, 1);
        engine.sendMessage(id, 'BYE', {}, 2);

        const session = engine.getSession(id);
        expect(session!.active).toBe(false);
        expect(session!.currentState).toBe('closed');
    });

    it('rejects messages on inactive session', () => {
        const engine = createProtocolEngine();
        engine.registerProtocol(makeSimpleProtocol());

        const id = engine.createSession('simple', src, dst)!;
        engine.closeSession(id);

        const result = engine.sendMessage(id, 'HELLO', { name: 'test' }, 1);
        expect(result).toBeNull();
    });

    it('returns null for unknown message type', () => {
        const engine = createProtocolEngine();
        engine.registerProtocol(makeSimpleProtocol());

        const id = engine.createSession('simple', src, dst)!;
        const result = engine.sendMessage(id, 'NONEXISTENT', {}, 1);
        expect(result).toBeNull();
    });

    it('returns null for no matching transition', () => {
        const engine = createProtocolEngine();
        engine.registerProtocol(makeSimpleProtocol());

        const id = engine.createSession('simple', src, dst)!;
        // QUERY in init state has no transition
        const result = engine.sendMessage(id, 'QUERY', { data: 'foo' }, 1);
        expect(result).toBeNull();
    });

    it('conditional transition: field-equals', () => {
        const engine = createProtocolEngine();
        engine.registerProtocol(makeConditionalProtocol());

        const id = engine.createSession('conditional', src, dst)!;
        const response = engine.sendMessage(id, 'AUTH', { user: 'admin', pass: 'secret' }, 1);

        expect(response!.messageType).toBe('OK');
        expect(engine.getSession(id)!.currentState).toBe('authed');
    });

    it('conditional transition: fallback to always', () => {
        const engine = createProtocolEngine();
        engine.registerProtocol(makeConditionalProtocol());

        const id = engine.createSession('conditional', src, dst)!;
        const response = engine.sendMessage(id, 'AUTH', { user: 'admin', pass: 'wrong' }, 1);

        expect(response!.messageType).toBe('FAIL');
        expect(engine.getSession(id)!.active).toBe(false); // denied is terminal
    });

    it('parseMessage with first-word identifier', () => {
        const engine = createProtocolEngine();
        engine.registerProtocol(makeSimpleProtocol());

        const parsed = engine.parseMessage('simple', 'HELLO world');
        expect(parsed).not.toBeNull();
        expect(parsed!.type).toBe('HELLO');
        expect(parsed!.fields['name']).toBe('world');
    });

    it('parseMessage returns null for unknown protocol', () => {
        const engine = createProtocolEngine();
        expect(engine.parseMessage('nonexistent', 'HELLO')).toBeNull();
    });

    it('listActiveSessions', () => {
        const engine = createProtocolEngine();
        engine.registerProtocol(makeSimpleProtocol());

        engine.createSession('simple', src, dst);
        engine.createSession('simple', src, dst);

        expect(engine.listActiveSessions().length).toBe(2);
    });

    it('closeSession', () => {
        const engine = createProtocolEngine();
        engine.registerProtocol(makeSimpleProtocol());

        const id = engine.createSession('simple', src, dst)!;
        expect(engine.closeSession(id)).toBe(true);
        expect(engine.getSession(id)!.active).toBe(false);
        expect(engine.closeSession('nonexistent')).toBe(false);
    });

    it('onMessage handler receives messages', () => {
        const engine = createProtocolEngine();
        engine.registerProtocol(makeSimpleProtocol());

        const received: string[] = [];
        engine.onMessage((_sid, msg) => {
            received.push(msg.messageType);
        });

        const id = engine.createSession('simple', src, dst)!;
        engine.sendMessage(id, 'HELLO', { name: 'test' }, 1);

        expect(received).toContain('HELLO');
        expect(received).toContain('WELCOME');
    });

    it('onMessage unsubscribe', () => {
        const engine = createProtocolEngine();
        engine.registerProtocol(makeSimpleProtocol());

        const received: string[] = [];
        const unsub = engine.onMessage((_sid, msg) => {
            received.push(msg.messageType);
        });

        const id = engine.createSession('simple', src, dst)!;
        engine.sendMessage(id, 'HELLO', { name: 'test' }, 1);
        unsub();
        engine.sendMessage(id, 'QUERY', { data: 'foo' }, 2);

        expect(received.length).toBe(2); // HELLO + WELCOME only
    });

    it('message seq numbers increment', () => {
        const engine = createProtocolEngine();
        engine.registerProtocol(makeSimpleProtocol());

        const id = engine.createSession('simple', src, dst)!;
        engine.sendMessage(id, 'HELLO', { name: 'test' }, 1);

        const capture = engine.getCapture(id);
        expect(capture[0]!.seq).toBe(0);
        expect(capture[1]!.seq).toBe(1);
    });

    it('clear removes everything', () => {
        const engine = createProtocolEngine();
        engine.registerProtocol(makeSimpleProtocol());
        engine.createSession('simple', src, dst);

        engine.clear();

        expect(engine.listProtocols().length).toBe(0);
        expect(engine.listActiveSessions().length).toBe(0);
    });

    it('field-contains condition', () => {
        const engine = createProtocolEngine();
        const protocol: ProtocolDefinition = {
            id: 'contains-test',
            name: 'Contains Test',
            defaultPort: 9002,
            transport: 'tcp',
            pattern: 'request-response',
            messageTypes: [
                { id: 'CMD', direction: 'client-to-server', fields: [{ name: 'input', type: 'string', required: true }] },
                { id: 'ALERT', direction: 'server-to-client', fields: [] },
            ],
            states: [{
                id: 'ready',
                name: 'Ready',
                terminal: false,
                transitions: [{
                    to: 'ready',
                    onMessage: 'CMD',
                    condition: { kind: 'field-contains', field: 'input', substring: 'DROP TABLE' },
                    response: 'ALERT',
                    responseFields: {},
                }],
            }],
            initialState: 'ready',
            parser: { delimiter: ' ', typeIdentifier: { kind: 'first-word' }, encoding: 'utf-8' },
        };
        engine.registerProtocol(protocol);

        const id = engine.createSession('contains-test', src, dst)!;

        // Normal input — no transition match
        const r1 = engine.sendMessage(id, 'CMD', { input: 'SELECT * FROM users' }, 1);
        expect(r1).toBeNull();

        // SQL injection — matches
        const r2 = engine.sendMessage(id, 'CMD', { input: "'; DROP TABLE users; --" }, 2);
        expect(r2).not.toBeNull();
        expect(r2!.messageType).toBe('ALERT');
    });

    it('field-matches condition', () => {
        const engine = createProtocolEngine();
        const protocol: ProtocolDefinition = {
            id: 'regex-test',
            name: 'Regex Test',
            defaultPort: 9003,
            transport: 'tcp',
            pattern: 'request-response',
            messageTypes: [
                { id: 'REQ', direction: 'client-to-server', fields: [{ name: 'path', type: 'string', required: true }] },
                { id: 'BLOCKED', direction: 'server-to-client', fields: [] },
            ],
            states: [{
                id: 'ready',
                name: 'Ready',
                terminal: false,
                transitions: [{
                    to: 'ready',
                    onMessage: 'REQ',
                    condition: { kind: 'field-matches', field: 'path', pattern: '\\.\\./.*' },
                    response: 'BLOCKED',
                    responseFields: {},
                }],
            }],
            initialState: 'ready',
            parser: { delimiter: ' ', typeIdentifier: { kind: 'first-word' }, encoding: 'utf-8' },
        };
        engine.registerProtocol(protocol);

        const id = engine.createSession('regex-test', src, dst)!;

        const r1 = engine.sendMessage(id, 'REQ', { path: '/normal/path' }, 1);
        expect(r1).toBeNull();

        const r2 = engine.sendMessage(id, 'REQ', { path: '../../etc/passwd' }, 2);
        expect(r2).not.toBeNull();
        expect(r2!.messageType).toBe('BLOCKED');
    });
});
