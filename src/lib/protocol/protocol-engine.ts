/**
 * VARIANT — Network Protocol Engine Implementation
 *
 * Simulates network protocols with state machines, message
 * parsing, session management, and traffic capture.
 *
 * SWAPPABILITY: Implements ProtocolEngine. Replace this file.
 */

import type {
    ProtocolEngine,
    ProtocolDefinition,
    ProtocolSession,
    ProtocolState,
    ProtocolTransition,
    TransitionCondition,
    CapturedMessage,
    Endpoint,
} from './types';

interface MutableSession {
    id: string;
    protocolId: string;
    currentState: string;
    source: Endpoint;
    destination: Endpoint;
    messages: CapturedMessage[];
    active: boolean;
    startedAt: string;
    seq: number;
}

let nextSessionId = 1;

export function createProtocolEngine(): ProtocolEngine {
    const protocols = new Map<string, ProtocolDefinition>();
    const sessions = new Map<string, MutableSession>();
    const messageHandlers: Array<(sessionId: string, message: CapturedMessage) => void> = [];

    function getState(protocol: ProtocolDefinition, stateId: string): ProtocolState | undefined {
        return protocol.states.find(s => s.id === stateId);
    }

    function checkCondition(
        condition: TransitionCondition,
        fields: Readonly<Record<string, unknown>>,
    ): boolean {
        switch (condition.kind) {
            case 'always':
                return true;
            case 'field-equals':
                return fields[condition.field] === condition.value;
            case 'field-contains': {
                const val = fields[condition.field];
                return typeof val === 'string' && val.includes(condition.substring);
            }
            case 'field-matches': {
                const val = fields[condition.field];
                if (typeof val !== 'string') return false;
                return new RegExp(condition.pattern).test(val);
            }
        }
    }

    function findTransition(
        protocol: ProtocolDefinition,
        stateId: string,
        messageType: string,
        fields: Readonly<Record<string, unknown>>,
    ): ProtocolTransition | null {
        const state = getState(protocol, stateId);
        if (state === undefined) return null;

        for (const transition of state.transitions) {
            if (transition.onMessage !== messageType) continue;
            if (transition.condition !== undefined && !checkCondition(transition.condition, fields)) {
                continue;
            }
            return transition;
        }
        return null;
    }

    function toSession(s: MutableSession): ProtocolSession {
        return {
            id: s.id,
            protocolId: s.protocolId,
            currentState: s.currentState,
            source: s.source,
            destination: s.destination,
            messages: [...s.messages],
            active: s.active,
            startedAt: s.startedAt,
        };
    }

    return {
        registerProtocol(protocol: ProtocolDefinition): void {
            protocols.set(protocol.id, protocol);
        },

        getProtocol(id: string): ProtocolDefinition | null {
            return protocols.get(id) ?? null;
        },

        listProtocols(): readonly ProtocolDefinition[] {
            return [...protocols.values()];
        },

        createSession(protocolId: string, source: Endpoint, dest: Endpoint): string | null {
            const protocol = protocols.get(protocolId);
            if (protocol === undefined) return null;

            const id = `session-${nextSessionId++}`;
            const session: MutableSession = {
                id,
                protocolId,
                currentState: protocol.initialState,
                source,
                destination: dest,
                messages: [],
                active: true,
                startedAt: new Date().toISOString(),
                seq: 0,
            };

            sessions.set(id, session);
            return id;
        },

        getSession(id: string): ProtocolSession | null {
            const session = sessions.get(id);
            if (session === undefined) return null;
            return toSession(session);
        },

        sendMessage(
            sessionId: string,
            messageType: string,
            fields: Readonly<Record<string, unknown>>,
            tick: number,
        ): CapturedMessage | null {
            const session = sessions.get(sessionId);
            if (session === undefined || !session.active) return null;

            const protocol = protocols.get(session.protocolId);
            if (protocol === undefined) return null;

            // Verify message type exists
            const msgType = protocol.messageTypes.find(m => m.id === messageType);
            if (msgType === undefined) return null;

            // Build raw representation
            const raw = buildRaw(messageType, fields, protocol);

            // Record the client message
            const clientMsg: CapturedMessage = {
                seq: session.seq++,
                direction: 'client-to-server',
                messageType,
                fields: { ...fields },
                raw,
                tick,
            };
            session.messages.push(clientMsg);

            for (const handler of messageHandlers) {
                handler(sessionId, clientMsg);
            }

            // Find matching transition
            const transition = findTransition(protocol, session.currentState, messageType, fields);
            if (transition === null) return null;

            // Apply state transition
            session.currentState = transition.to;

            // Check if terminal
            const newState = getState(protocol, transition.to);
            if (newState !== undefined && newState.terminal) {
                session.active = false;
            }

            // Generate response if configured
            if (transition.response !== undefined) {
                const responseFields: Record<string, unknown> = { ...(transition.responseFields ?? {}) };
                const responseRaw = buildRaw(transition.response, responseFields, protocol);

                const responseMsg: CapturedMessage = {
                    seq: session.seq++,
                    direction: 'server-to-client',
                    messageType: transition.response,
                    fields: responseFields,
                    raw: responseRaw,
                    tick,
                };
                session.messages.push(responseMsg);

                for (const handler of messageHandlers) {
                    handler(sessionId, responseMsg);
                }

                return responseMsg;
            }

            return null;
        },

        parseMessage(protocolId: string, raw: string): { type: string; fields: Record<string, unknown> } | null {
            const protocol = protocols.get(protocolId);
            if (protocol === undefined) return null;

            const parser = protocol.parser;
            let typeName: string | null = null;

            switch (parser.typeIdentifier.kind) {
                case 'first-word': {
                    const firstSpace = raw.indexOf(' ');
                    typeName = firstSpace > 0 ? raw.slice(0, firstSpace) : raw.trim();
                    break;
                }
                case 'header': {
                    const lines = raw.split(parser.delimiter);
                    for (const line of lines) {
                        const colonIdx = line.indexOf(':');
                        if (colonIdx > 0) {
                            const key = line.slice(0, colonIdx).trim();
                            if (key.toLowerCase() === parser.typeIdentifier.headerName.toLowerCase()) {
                                typeName = line.slice(colonIdx + 1).trim();
                                break;
                            }
                        }
                    }
                    break;
                }
                case 'regex': {
                    const match = new RegExp(parser.typeIdentifier.pattern).exec(raw);
                    if (match !== null && match[parser.typeIdentifier.group] !== undefined) {
                        typeName = match[parser.typeIdentifier.group]!;
                    }
                    break;
                }
                case 'fixed':
                    typeName = parser.typeIdentifier.messageType;
                    break;
            }

            if (typeName === null) return null;

            // Find the matching message type
            const msgType = protocol.messageTypes.find(
                m => m.id.toLowerCase() === typeName!.toLowerCase()
            );
            if (msgType === undefined) return { type: typeName, fields: { raw } };

            // Parse fields from raw data
            const fields: Record<string, unknown> = {};
            const parts = raw.split(parser.delimiter);

            for (let i = 0; i < msgType.fields.length && i < parts.length; i++) {
                const field = msgType.fields[i]!;
                const value = parts[i + 1]?.trim(); // +1 to skip the type identifier
                if (value !== undefined) {
                    fields[field.name] = field.type === 'number' ? Number(value) : value;
                }
            }

            return { type: typeName, fields };
        },

        getCapture(sessionId: string): readonly CapturedMessage[] {
            const session = sessions.get(sessionId);
            if (session === undefined) return [];
            return [...session.messages];
        },

        closeSession(sessionId: string): boolean {
            const session = sessions.get(sessionId);
            if (session === undefined) return false;
            session.active = false;
            return true;
        },

        listActiveSessions(): readonly ProtocolSession[] {
            const active: ProtocolSession[] = [];
            for (const session of sessions.values()) {
                if (session.active) {
                    active.push(toSession(session));
                }
            }
            return active;
        },

        onMessage(handler: (sessionId: string, message: CapturedMessage) => void): () => void {
            messageHandlers.push(handler);
            return () => {
                const idx = messageHandlers.indexOf(handler);
                if (idx >= 0) messageHandlers.splice(idx, 1);
            };
        },

        clear(): void {
            protocols.clear();
            sessions.clear();
            messageHandlers.length = 0;
            nextSessionId = 1;
        },
    };
}

function buildRaw(
    messageType: string,
    fields: Readonly<Record<string, unknown>>,
    protocol: ProtocolDefinition,
): string {
    const msgDef = protocol.messageTypes.find(m => m.id === messageType);
    if (msgDef?.template !== undefined) {
        let raw = msgDef.template;
        for (const [key, value] of Object.entries(fields)) {
            raw = raw.replace(`{{${key}}}`, String(value));
        }
        return raw;
    }

    // Default: space-separated
    const parts = [messageType];
    for (const value of Object.values(fields)) {
        parts.push(String(value));
    }
    return parts.join(' ');
}
