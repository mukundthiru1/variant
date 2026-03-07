/**
 * VARIANT — WAF (Web Application Firewall) Types
 *
 * Simulates OWASP ModSecurity CRS-style rule evaluation.
 * Players learn to write WAF rules and bypass them.
 *
 * EXTENSIBILITY: Custom rule sets via registry.
 * SWAPPABILITY: Implements WAFEngine interface.
 */

// ── WAF Rule ───────────────────────────────────────────────

export interface WAFRule {
    readonly id: number;
    readonly phase: WAFPhase;
    readonly action: WAFAction;
    readonly severity: WAFSeverity;
    readonly targets: readonly WAFTarget[];
    readonly operators: readonly WAFOperator[];
    readonly transforms: readonly WAFTransform[];
    readonly msg: string;
    readonly tag?: readonly string[];
    readonly chain?: boolean;
    readonly skipAfter?: string;
    readonly enabled: boolean;
}

export type WAFPhase = 1 | 2 | 3 | 4 | 5;
export type WAFAction = 'deny' | 'drop' | 'pass' | 'log' | 'block' | 'allow' | 'redirect';
export type WAFSeverity = 'EMERGENCY' | 'ALERT' | 'CRITICAL' | 'ERROR' | 'WARNING' | 'NOTICE' | 'INFO' | 'DEBUG';

export type WAFTarget =
    | 'ARGS' | 'ARGS_NAMES' | 'ARGS_GET' | 'ARGS_POST'
    | 'REQUEST_URI' | 'REQUEST_URI_RAW'
    | 'REQUEST_HEADERS' | 'REQUEST_HEADERS_NAMES'
    | 'REQUEST_BODY' | 'REQUEST_METHOD'
    | 'REQUEST_COOKIES' | 'REQUEST_COOKIES_NAMES'
    | 'RESPONSE_BODY' | 'RESPONSE_HEADERS'
    | 'TX' | 'IP' | 'SESSION'
    | 'REMOTE_ADDR' | 'REQUEST_LINE'
    | (string & {});

export type WAFTransform =
    | 'lowercase' | 'urlDecode' | 'urlDecodeUni'
    | 'htmlEntityDecode' | 'compressWhitespace'
    | 'removeWhitespace' | 'replaceNulls'
    | 'removeNulls' | 'base64Decode'
    | 'hexDecode' | 'normalizePath'
    | 'length' | 'sha1' | 'md5'
    | 'none'
    | (string & {});

export interface WAFOperator {
    readonly type: WAFOperatorType;
    readonly value: string;
    readonly negated?: boolean;
}

export type WAFOperatorType =
    | 'rx' | 'eq' | 'ge' | 'gt' | 'le' | 'lt'
    | 'contains' | 'containsWord' | 'beginsWith' | 'endsWith'
    | 'streq' | 'within' | 'pm' | 'pmFromFile'
    | 'detectSQLi' | 'detectXSS'
    | 'ipMatch' | 'geoLookup'
    | (string & {});

// ── WAF Request ────────────────────────────────────────────

export interface WAFRequest {
    readonly method: string;
    readonly uri: string;
    readonly uriRaw: string;
    readonly headers: Readonly<Record<string, string>>;
    readonly cookies: Readonly<Record<string, string>>;
    readonly args: Readonly<Record<string, string>>;
    readonly argsGet: Readonly<Record<string, string>>;
    readonly argsPost: Readonly<Record<string, string>>;
    readonly body: string;
    readonly remoteAddr: string;
    readonly protocol: string;
}

// ── WAF Evaluation Result ──────────────────────────────────

export interface WAFEvalResult {
    readonly blocked: boolean;
    readonly action: WAFAction;
    readonly matchedRules: readonly WAFRuleMatch[];
    readonly anomalyScore: number;
    readonly inboundScore: number;
    readonly response?: {
        readonly statusCode: number;
        readonly body: string;
        readonly headers: Readonly<Record<string, string>>;
    };
}

export interface WAFRuleMatch {
    readonly ruleId: number;
    readonly msg: string;
    readonly severity: WAFSeverity;
    readonly matchedTarget: string;
    readonly matchedValue: string;
    readonly operator: string;
}

// ── WAF Engine Interface ───────────────────────────────────

export interface WAFEngine {
    /** Evaluate a request. */
    evaluate(request: WAFRequest): WAFEvalResult;
    /** Add a rule. */
    addRule(rule: WAFRule): void;
    /** Remove a rule by ID. */
    removeRule(id: number): boolean;
    /** Enable/disable a rule. */
    setRuleEnabled(id: number, enabled: boolean): boolean;
    /** Get all rules. */
    getRules(): readonly WAFRule[];
    /** Get matched rule statistics. */
    getStats(): WAFStats;
    /** Reset stats. */
    resetStats(): void;
    /** Set anomaly scoring threshold. */
    setAnomalyThreshold(threshold: number): void;
    /** Get the anomaly threshold. */
    getAnomalyThreshold(): number;
    /** Set paranoia level (1-4). */
    setParanoiaLevel(level: 1 | 2 | 3 | 4): void;
}

export interface WAFStats {
    readonly requestsEvaluated: number;
    readonly requestsBlocked: number;
    readonly requestsAllowed: number;
    readonly ruleHits: Readonly<Record<number, number>>;
    readonly topBlockedRules: readonly { ruleId: number; count: number; msg: string }[];
}
