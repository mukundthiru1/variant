/**
 * VARIANT — Network Protocol Engine
 *
 * Simulates network protocols at the application layer.
 * Level designers define protocol grammars — request/response
 * patterns, state machines, and exploit conditions.
 *
 * FEATURES:
 * - Protocol definitions with typed messages
 * - State machine for protocol sessions
 * - Vulnerability injection points in protocol handling
 * - Traffic capture and replay
 * - Custom protocol grammars (not just HTTP/DNS/SMTP)
 *
 * SWAPPABILITY: Implements ProtocolEngine. Replace this file.
 */

// ── Protocol Definition ─────────────────────────────────────────

/** A complete protocol definition. */
export interface ProtocolDefinition {
    /** Unique protocol ID. */
    readonly id: string;
    /** Protocol name (e.g., 'HTTP', 'custom-c2'). */
    readonly name: string;
    /** Default port. */
    readonly defaultPort: number;
    /** Transport layer. */
    readonly transport: 'tcp' | 'udp';
    /** Whether the protocol is request-response or streaming. */
    readonly pattern: 'request-response' | 'streaming' | 'pub-sub';
    /** Message types this protocol supports. */
    readonly messageTypes: readonly MessageType[];
    /** Protocol state machine. */
    readonly states: readonly ProtocolState[];
    /** Initial state ID. */
    readonly initialState: string;
    /** Parser for raw bytes to messages. */
    readonly parser: ParserConfig;
}

/** A type of message in the protocol. */
export interface MessageType {
    /** Message type ID. */
    readonly id: string;
    /** Direction. */
    readonly direction: 'client-to-server' | 'server-to-client' | 'both';
    /** Fields in this message. */
    readonly fields: readonly MessageField[];
    /** Format template for serialization. */
    readonly template?: string;
}

/** A field in a protocol message. */
export interface MessageField {
    readonly name: string;
    readonly type: 'string' | 'number' | 'bytes' | 'enum' | 'list';
    readonly required: boolean;
    /** Valid values for enum type. */
    readonly enumValues?: readonly string[];
    /** Default value. */
    readonly defaultValue?: unknown;
}

// ── Protocol State Machine ──────────────────────────────────────

/** A state in the protocol state machine. */
export interface ProtocolState {
    /** State ID. */
    readonly id: string;
    /** Human-readable name. */
    readonly name: string;
    /** Whether this is a terminal state. */
    readonly terminal: boolean;
    /** Transitions from this state. */
    readonly transitions: readonly ProtocolTransition[];
}

/** A transition between protocol states. */
export interface ProtocolTransition {
    /** Target state ID. */
    readonly to: string;
    /** Message type that triggers this transition. */
    readonly onMessage: string;
    /** Optional condition on message fields. */
    readonly condition?: TransitionCondition;
    /** Response to generate (message type ID). */
    readonly response?: string;
    /** Response field values. */
    readonly responseFields?: Readonly<Record<string, unknown>>;
}

/** Condition for a protocol transition. */
export type TransitionCondition =
    | { readonly kind: 'field-equals'; readonly field: string; readonly value: unknown }
    | { readonly kind: 'field-contains'; readonly field: string; readonly substring: string }
    | { readonly kind: 'field-matches'; readonly field: string; readonly pattern: string }
    | { readonly kind: 'always' };

// ── Parser Configuration ────────────────────────────────────────

/** How to parse raw data into protocol messages. */
export interface ParserConfig {
    /** Delimiter between messages. */
    readonly delimiter: string;
    /** How to identify message type from raw data. */
    readonly typeIdentifier: TypeIdentifier;
    /** Encoding. */
    readonly encoding: 'utf-8' | 'ascii' | 'binary';
}

export type TypeIdentifier =
    | { readonly kind: 'first-word' }
    | { readonly kind: 'header'; readonly headerName: string }
    | { readonly kind: 'regex'; readonly pattern: string; readonly group: number }
    | { readonly kind: 'fixed'; readonly messageType: string };

// ── Protocol Session ────────────────────────────────────────────

/** A live protocol session between two endpoints. */
export interface ProtocolSession {
    /** Session ID. */
    readonly id: string;
    /** Protocol being used. */
    readonly protocolId: string;
    /** Current state. */
    readonly currentState: string;
    /** Source endpoint. */
    readonly source: Endpoint;
    /** Destination endpoint. */
    readonly destination: Endpoint;
    /** Messages exchanged. */
    readonly messages: readonly CapturedMessage[];
    /** Whether the session is still active. */
    readonly active: boolean;
    /** When the session started. */
    readonly startedAt: string;
}

export interface Endpoint {
    readonly machine: string;
    readonly port: number;
}

/** A captured protocol message. */
export interface CapturedMessage {
    /** Message sequence number. */
    readonly seq: number;
    /** Direction. */
    readonly direction: 'client-to-server' | 'server-to-client';
    /** Message type ID. */
    readonly messageType: string;
    /** Parsed fields. */
    readonly fields: Readonly<Record<string, unknown>>;
    /** Raw data. */
    readonly raw: string;
    /** Simulation tick. */
    readonly tick: number;
}

// ── Protocol Engine Interface ───────────────────────────────────

export interface ProtocolEngine {
    /** Register a protocol definition. */
    registerProtocol(protocol: ProtocolDefinition): void;

    /** Get a protocol by ID. */
    getProtocol(id: string): ProtocolDefinition | null;

    /** List all registered protocols. */
    listProtocols(): readonly ProtocolDefinition[];

    /** Create a new session. */
    createSession(protocolId: string, source: Endpoint, dest: Endpoint): string | null;

    /** Get a session by ID. */
    getSession(id: string): ProtocolSession | null;

    /** Send a message in a session. Returns the response message or null. */
    sendMessage(
        sessionId: string,
        messageType: string,
        fields: Readonly<Record<string, unknown>>,
        tick: number,
    ): CapturedMessage | null;

    /** Parse raw data into a message. */
    parseMessage(protocolId: string, raw: string): { type: string; fields: Record<string, unknown> } | null;

    /** Get all messages from a session. */
    getCapture(sessionId: string): readonly CapturedMessage[];

    /** Close a session. */
    closeSession(sessionId: string): boolean;

    /** List active sessions. */
    listActiveSessions(): readonly ProtocolSession[];

    /** Subscribe to session events. */
    onMessage(handler: (sessionId: string, message: CapturedMessage) => void): () => void;

    /** Clear all protocols and sessions. */
    clear(): void;
}
