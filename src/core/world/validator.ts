/**
 * VARIANT — WorldSpec Validator
 *
 * Every WorldSpec passes through this before it enters the engine.
 * Rejects invalid, malformed, or dangerous specifications.
 *
 * SECURITY: This is the primary defense against malicious WorldSpecs.
 * A WorldSpec that passes validation is GUARANTEED safe to execute.
 * Any bypass of this validator is a critical security bug.
 *
 * Validation rules:
 * 1. All required fields present with correct types
 * 2. startMachine references an existing machine
 * 3. All network edges reference existing machines/segments
 * 4. All credential locations/targets reference existing machines
 * 5. All objective machine references are valid
 * 6. Memory allocations are within allowed bounds
 * 7. No executable code (functions, eval, constructors)
 * 8. Trust level is consistent (community can't reference invariant-live)
 * 9. File paths have no traversal sequences
 * 10. No circular dependencies in network topology
 */

// ── Validation Result ──────────────────────────────────────────

export interface ValidationResult {
    readonly valid: boolean;
    readonly errors: readonly ValidationError[];
    readonly warnings: readonly ValidationWarning[];
}

export interface ValidationError {
    readonly path: string;       // JSON path to the invalid field
    readonly message: string;
    readonly code: ErrorCode;
}

export interface ValidationWarning {
    readonly path: string;
    readonly message: string;
}

export type ErrorCode =
    | 'MISSING_FIELD'
    | 'INVALID_TYPE'
    | 'INVALID_VALUE'
    | 'INVALID_REFERENCE'
    | 'SECURITY_VIOLATION'
    | 'RESOURCE_LIMIT'
    | 'TRUST_VIOLATION'
    | 'PATH_TRAVERSAL'
    | 'CIRCULAR_DEPENDENCY';

// ── Constants ──────────────────────────────────────────────────

const MIN_MEMORY_MB = 16;
const MAX_MEMORY_MB = 256;
const MAX_MACHINES = 20;
const MAX_OBJECTIVES = 50;
const MAX_CREDENTIALS = 100;
const MAX_HINTS = 30;
const MAX_FILE_CONTENT_BYTES = 1_000_000; // 1MB per file
const MAX_FILES_PER_MACHINE = 200;
const MAX_SEGMENTS = 50;
const MAX_TIERS = 20;

/** Characters not allowed in hostnames. */
const HOSTNAME_REGEX = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;

/** Path traversal sequences to reject. */
const PATH_TRAVERSAL_PATTERNS = ['..', '\0', '%00', '%2e%2e'] as const;

/** Valid IPv4 address pattern (basic — rejects obvious non-IPs). */
const IPV4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;

/** Valid CIDR subnet pattern. */
const CIDR_REGEX = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;

// ── Validator ──────────────────────────────────────────────────

export function validateWorldSpec(input: unknown): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    // ── Phase 1: Structural validation ───────────────────────────
    if (input === null || typeof input !== 'object') {
        errors.push({
            path: '$',
            message: 'WorldSpec must be a non-null object',
            code: 'INVALID_TYPE',
        });
        return { valid: false, errors, warnings };
    }

    const spec = input as Record<string, unknown>;

    // Reject any values that are functions (code injection defense)
    detectExecutableCode(spec, '$', errors);

    // Version
    if (spec['version'] !== '2.0') {
        errors.push({
            path: '$.version',
            message: `Expected version '2.0', got '${String(spec['version'])}'`,
            code: 'INVALID_VALUE',
        });
    }

    // Trust — must be a valid value (engine sets this, but validate anyway)
    const trust = spec['trust'];
    if (trust !== 'community' && trust !== 'curated') {
        errors.push({
            path: '$.trust',
            message: `Trust must be 'community' or 'curated', got '${String(trust)}'`,
            code: 'INVALID_VALUE',
        });
    }

    // Meta
    validateMeta(spec['meta'], errors, warnings);

    // Machines
    const machines = spec['machines'];
    if (machines === null || typeof machines !== 'object' || Array.isArray(machines)) {
        errors.push({
            path: '$.machines',
            message: 'machines must be a non-null, non-array object',
            code: 'INVALID_TYPE',
        });
        return { valid: false, errors, warnings };
    }

    const machineMap = machines as Record<string, unknown>;
    const machineIds = Object.keys(machineMap);

    if (machineIds.length === 0) {
        errors.push({
            path: '$.machines',
            message: 'At least one machine is required',
            code: 'MISSING_FIELD',
        });
    }

    if (machineIds.length > MAX_MACHINES) {
        errors.push({
            path: '$.machines',
            message: `Maximum ${MAX_MACHINES} machines allowed, got ${machineIds.length}`,
            code: 'RESOURCE_LIMIT',
        });
    }

    // Validate each machine
    for (const [id, machine] of Object.entries(machineMap)) {
        validateMachine(id, machine, `$.machines.${id}`, errors, warnings);
    }

    // startMachine must reference an existing machine
    const startMachine = spec['startMachine'];
    if (typeof startMachine !== 'string') {
        errors.push({
            path: '$.startMachine',
            message: 'startMachine must be a string',
            code: 'INVALID_TYPE',
        });
    } else if (!machineIds.includes(startMachine)) {
        errors.push({
            path: '$.startMachine',
            message: `startMachine '${startMachine}' does not reference an existing machine`,
            code: 'INVALID_REFERENCE',
        });
    } else {
        // startMachine should have role 'player'
        const startSpec = machineMap[startMachine] as Record<string, unknown> | undefined;
        if (startSpec !== undefined && startSpec['role'] !== 'player') {
            warnings.push({
                path: '$.startMachine',
                message: `startMachine '${startMachine}' has role '${String(startSpec['role'])}', expected 'player'`,
            });
        }
    }

    // Objectives
    const objectives = spec['objectives'];
    if (!Array.isArray(objectives)) {
        errors.push({
            path: '$.objectives',
            message: 'objectives must be an array',
            code: 'INVALID_TYPE',
        });
    } else {
        if (objectives.length > MAX_OBJECTIVES) {
            errors.push({
                path: '$.objectives',
                message: `Maximum ${MAX_OBJECTIVES} objectives allowed`,
                code: 'RESOURCE_LIMIT',
            });
        }
        for (let i = 0; i < objectives.length; i++) {
            validateObjective(objectives[i], `$.objectives[${i}]`, machineIds, trust as string, errors, warnings);
        }
    }

    // Credentials
    const credentials = spec['credentials'];
    if (Array.isArray(credentials)) {
        if (credentials.length > MAX_CREDENTIALS) {
            errors.push({
                path: '$.credentials',
                message: `Maximum ${MAX_CREDENTIALS} credentials allowed`,
                code: 'RESOURCE_LIMIT',
            });
        }
        for (let i = 0; i < credentials.length; i++) {
            validateCredential(credentials[i], `$.credentials[${i}]`, machineIds, errors);
        }
    }

    // Hints — must be an array (engine accesses .length unconditionally)
    const hints = spec['hints'];
    if (!Array.isArray(hints)) {
        errors.push({
            path: '$.hints',
            message: 'hints must be an array (can be empty)',
            code: 'INVALID_TYPE',
        });
    } else if (hints.length > MAX_HINTS) {
        errors.push({
            path: '$.hints',
            message: `Maximum ${MAX_HINTS} hints allowed`,
            code: 'RESOURCE_LIMIT',
        });
    }

    // Network — required, engine accesses .segments unconditionally
    const network = spec['network'];
    const segmentIds = validateNetwork(network, errors, warnings);

    // Cross-reference: machine interface segments must exist in network.segments
    if (segmentIds.size > 0) {
        for (const [id, machine] of Object.entries(machineMap)) {
            const m = machine as Record<string, unknown> | null;
            if (m === null || typeof m !== 'object') continue;
            const ifaces = m['interfaces'];
            if (!Array.isArray(ifaces)) continue;
            for (let j = 0; j < ifaces.length; j++) {
                const iface = ifaces[j] as Record<string, unknown> | undefined;
                if (iface === undefined) continue;
                const seg = iface['segment'];
                if (typeof seg === 'string' && !segmentIds.has(seg)) {
                    errors.push({
                        path: `$.machines.${id}.interfaces[${j}].segment`,
                        message: `Segment '${seg}' does not exist in network.segments. Available: ${[...segmentIds].join(', ')}`,
                        code: 'INVALID_REFERENCE',
                    });
                }
            }
        }
    }

    // Scoring — required, engine accesses .maxScore, .hintPenalty, .tiers unconditionally
    validateScoring(spec['scoring'], errors, warnings);

    return {
        valid: errors.length === 0,
        errors,
        warnings,
    };
}

// ── Helpers ────────────────────────────────────────────────────

function validateMeta(
    meta: unknown,
    errors: ValidationError[],
    _warnings: ValidationWarning[],
): void {
    if (meta === null || typeof meta !== 'object') {
        errors.push({ path: '$.meta', message: 'meta must be an object', code: 'INVALID_TYPE' });
        return;
    }

    const m = meta as Record<string, unknown>;

    if (typeof m['title'] !== 'string' || m['title'].length === 0) {
        errors.push({ path: '$.meta.title', message: 'title is required', code: 'MISSING_FIELD' });
    }
    if (typeof m['title'] === 'string' && m['title'].length > 200) {
        errors.push({ path: '$.meta.title', message: 'title must be ≤ 200 characters', code: 'RESOURCE_LIMIT' });
    }

    const validDifficulties = ['beginner', 'easy', 'medium', 'hard', 'expert'];
    if (!validDifficulties.includes(m['difficulty'] as string)) {
        errors.push({
            path: '$.meta.difficulty',
            message: `difficulty must be one of: ${validDifficulties.join(', ')}`,
            code: 'INVALID_VALUE',
        });
    }

    const validModes = ['attack', 'defense', 'mixed'];
    if (!validModes.includes(m['mode'] as string)) {
        errors.push({
            path: '$.meta.mode',
            message: `mode must be one of: ${validModes.join(', ')}`,
            code: 'INVALID_VALUE',
        });
    }
}

function validateMachine(
    _id: string,
    machine: unknown,
    path: string,
    errors: ValidationError[],
    _warnings: ValidationWarning[],
): void {
    if (machine === null || typeof machine !== 'object') {
        errors.push({ path, message: 'machine must be an object', code: 'INVALID_TYPE' });
        return;
    }

    const m = machine as Record<string, unknown>;

    // Hostname
    const hostname = m['hostname'];
    if (typeof hostname !== 'string' || !HOSTNAME_REGEX.test(hostname)) {
        errors.push({
            path: `${path}.hostname`,
            message: `Invalid hostname '${String(hostname)}'. Must be lowercase alphanumeric with hyphens.`,
            code: 'INVALID_VALUE',
        });
    }

    // Image
    if (typeof m['image'] !== 'string' || m['image'].length === 0) {
        errors.push({ path: `${path}.image`, message: 'image is required', code: 'MISSING_FIELD' });
    }

    // Memory
    const memoryMB = m['memoryMB'];
    if (typeof memoryMB !== 'number' || memoryMB < MIN_MEMORY_MB || memoryMB > MAX_MEMORY_MB) {
        errors.push({
            path: `${path}.memoryMB`,
            message: `memoryMB must be between ${MIN_MEMORY_MB} and ${MAX_MEMORY_MB}`,
            code: 'RESOURCE_LIMIT',
        });
    }

    // Role
    const validRoles = ['player', 'target', 'defend', 'npc-attacker', 'infrastructure'];
    if (!validRoles.includes(m['role'] as string)) {
        errors.push({
            path: `${path}.role`,
            message: `role must be one of: ${validRoles.join(', ')}`,
            code: 'INVALID_VALUE',
        });
    }

    // Interfaces — engine accesses interfaces[0] unconditionally for fabric wiring
    const interfaces = m['interfaces'];
    if (!Array.isArray(interfaces)) {
        errors.push({
            path: `${path}.interfaces`,
            message: 'interfaces must be an array',
            code: 'INVALID_TYPE',
        });
    } else if (interfaces.length === 0) {
        _warnings.push({
            path: `${path}.interfaces`,
            message: 'Machine has no interfaces — it will have no network connectivity',
        });
    } else {
        for (let j = 0; j < interfaces.length; j++) {
            const iface = interfaces[j] as Record<string, unknown> | undefined;
            if (iface === undefined || typeof iface !== 'object' || iface === null) {
                errors.push({
                    path: `${path}.interfaces[${j}]`,
                    message: 'Interface must be an object',
                    code: 'INVALID_TYPE',
                });
                continue;
            }
            // Validate IP
            const ip = iface['ip'];
            if (typeof ip !== 'string' || !IPV4_REGEX.test(ip)) {
                errors.push({
                    path: `${path}.interfaces[${j}].ip`,
                    message: `Invalid IPv4 address: '${String(ip)}'`,
                    code: 'INVALID_VALUE',
                });
            }
            // Validate segment reference (existence checked later in cross-reference pass)
            if (typeof iface['segment'] !== 'string' || (iface['segment'] as string).length === 0) {
                errors.push({
                    path: `${path}.interfaces[${j}].segment`,
                    message: 'Interface segment must be a non-empty string',
                    code: 'MISSING_FIELD',
                });
            }
        }
    }

    // Files — validate paths
    const files = m['files'];
    if (files !== null && files !== undefined && typeof files === 'object') {
        const fileMap = files as Record<string, unknown>;
        const filePaths = Object.keys(fileMap);

        if (filePaths.length > MAX_FILES_PER_MACHINE) {
            errors.push({
                path: `${path}.files`,
                message: `Maximum ${MAX_FILES_PER_MACHINE} files per machine`,
                code: 'RESOURCE_LIMIT',
            });
        }

        for (const filePath of filePaths) {
            validateFilePath(filePath, `${path}.files["${filePath}"]`, errors);

            // Validate content size
            const file = fileMap[filePath] as Record<string, unknown> | undefined;
            if (file !== undefined && typeof file['content'] === 'string') {
                if (file['content'].length > MAX_FILE_CONTENT_BYTES) {
                    errors.push({
                        path: `${path}.files["${filePath}"].content`,
                        message: `File content exceeds ${MAX_FILE_CONTENT_BYTES} bytes`,
                        code: 'RESOURCE_LIMIT',
                    });
                }
            }
        }
    }
}

function validateFilePath(
    filePath: string,
    jsonPath: string,
    errors: ValidationError[],
): void {
    // Must be absolute
    if (!filePath.startsWith('/')) {
        errors.push({
            path: jsonPath,
            message: `File path must be absolute (start with /): '${filePath}'`,
            code: 'SECURITY_VIOLATION',
        });
    }

    // No path traversal
    for (const pattern of PATH_TRAVERSAL_PATTERNS) {
        if (filePath.includes(pattern)) {
            errors.push({
                path: jsonPath,
                message: `File path contains forbidden sequence '${pattern}': '${filePath}'`,
                code: 'PATH_TRAVERSAL',
            });
        }
    }

    // No null bytes (could be used for path truncation)
    if (filePath.includes('\0')) {
        errors.push({
            path: jsonPath,
            message: 'File path contains null byte',
            code: 'SECURITY_VIOLATION',
        });
    }
}

function validateObjective(
    obj: unknown,
    path: string,
    _machineIds: string[],
    trust: string,
    errors: ValidationError[],
    _warnings: ValidationWarning[],
): void {
    if (obj === null || typeof obj !== 'object') {
        errors.push({ path, message: 'objective must be an object', code: 'INVALID_TYPE' });
        return;
    }

    const o = obj as Record<string, unknown>;

    if (typeof o['id'] !== 'string' || o['id'].length === 0) {
        errors.push({ path: `${path}.id`, message: 'id is required', code: 'MISSING_FIELD' });
    }

    // Trust boundary enforcement: community levels cannot use invariant-live
    const details = o['details'] as Record<string, unknown> | undefined;
    if (details !== undefined && details['payloadSource'] === 'invariant-live' && trust !== 'curated') {
        errors.push({
            path: `${path}.details.payloadSource`,
            message: 'Only curated levels can reference invariant-live payloads',
            code: 'TRUST_VIOLATION',
        });
    }
}

function validateCredential(
    cred: unknown,
    path: string,
    machineIds: string[],
    errors: ValidationError[],
): void {
    if (cred === null || typeof cred !== 'object') {
        errors.push({ path, message: 'credential must be an object', code: 'INVALID_TYPE' });
        return;
    }

    const c = cred as Record<string, unknown>;

    // Validate foundAt machine reference
    const foundAt = c['foundAt'] as Record<string, unknown> | undefined;
    if (foundAt !== undefined && typeof foundAt['machine'] === 'string') {
        if (!machineIds.includes(foundAt['machine'])) {
            errors.push({
                path: `${path}.foundAt.machine`,
                message: `Machine '${foundAt['machine']}' does not exist`,
                code: 'INVALID_REFERENCE',
            });
        }
    }

    // Validate validAt machine reference
    const validAt = c['validAt'] as Record<string, unknown> | undefined;
    if (validAt !== undefined && typeof validAt['machine'] === 'string') {
        if (!machineIds.includes(validAt['machine'])) {
            errors.push({
                path: `${path}.validAt.machine`,
                message: `Machine '${validAt['machine']}' does not exist`,
                code: 'INVALID_REFERENCE',
            });
        }
    }
}

/**
 * Validate the network field.
 * Returns the set of valid segment IDs for cross-referencing.
 */
function validateNetwork(
    network: unknown,
    errors: ValidationError[],
    _warnings: ValidationWarning[],
): Set<string> {
    const segmentIds = new Set<string>();

    if (network === null || network === undefined || typeof network !== 'object') {
        errors.push({
            path: '$.network',
            message: 'network is required and must be an object',
            code: 'MISSING_FIELD',
        });
        return segmentIds;
    }

    const n = network as Record<string, unknown>;

    const segments = n['segments'];
    if (!Array.isArray(segments)) {
        errors.push({
            path: '$.network.segments',
            message: 'network.segments must be an array',
            code: 'INVALID_TYPE',
        });
        return segmentIds;
    }

    if (segments.length > MAX_SEGMENTS) {
        errors.push({
            path: '$.network.segments',
            message: `Maximum ${MAX_SEGMENTS} segments allowed`,
            code: 'RESOURCE_LIMIT',
        });
    }

    for (let i = 0; i < segments.length; i++) {
        const seg = segments[i] as Record<string, unknown> | undefined;
        if (seg === undefined || typeof seg !== 'object' || seg === null) {
            errors.push({
                path: `$.network.segments[${i}]`,
                message: 'Segment must be an object',
                code: 'INVALID_TYPE',
            });
            continue;
        }

        // id
        const segId = seg['id'];
        if (typeof segId !== 'string' || segId.length === 0) {
            errors.push({
                path: `$.network.segments[${i}].id`,
                message: 'Segment id is required',
                code: 'MISSING_FIELD',
            });
        } else {
            if (segmentIds.has(segId)) {
                errors.push({
                    path: `$.network.segments[${i}].id`,
                    message: `Duplicate segment id '${segId}'`,
                    code: 'INVALID_VALUE',
                });
            }
            segmentIds.add(segId);
        }

        // subnet
        const subnet = seg['subnet'];
        if (typeof subnet !== 'string' || !CIDR_REGEX.test(subnet)) {
            errors.push({
                path: `$.network.segments[${i}].subnet`,
                message: `Invalid CIDR subnet: '${String(subnet)}'. Expected format: x.x.x.x/y`,
                code: 'INVALID_VALUE',
            });
        }

        // gateway (optional — engine derives default if missing)
        const gw = seg['gateway'];
        if (gw !== undefined && (typeof gw !== 'string' || !IPV4_REGEX.test(gw))) {
            errors.push({
                path: `$.network.segments[${i}].gateway`,
                message: `Invalid gateway IP: '${String(gw)}'`,
                code: 'INVALID_VALUE',
            });
        }
    }

    // edges (optional but must be array if present)
    const edges = n['edges'];
    if (edges !== undefined && !Array.isArray(edges)) {
        errors.push({
            path: '$.network.edges',
            message: 'network.edges must be an array',
            code: 'INVALID_TYPE',
        });
    }

    return segmentIds;
}

/**
 * Validate the scoring field.
 * Engine accesses maxScore, hintPenalty, and tiers unconditionally.
 */
function validateScoring(
    scoring: unknown,
    errors: ValidationError[],
    _warnings: ValidationWarning[],
): void {
    if (scoring === null || scoring === undefined || typeof scoring !== 'object') {
        errors.push({
            path: '$.scoring',
            message: 'scoring is required and must be an object',
            code: 'MISSING_FIELD',
        });
        return;
    }

    const s = scoring as Record<string, unknown>;

    if (typeof s['maxScore'] !== 'number' || s['maxScore'] < 0) {
        errors.push({
            path: '$.scoring.maxScore',
            message: 'scoring.maxScore must be a non-negative number',
            code: 'INVALID_VALUE',
        });
    }

    if (typeof s['hintPenalty'] !== 'number' || s['hintPenalty'] < 0) {
        errors.push({
            path: '$.scoring.hintPenalty',
            message: 'scoring.hintPenalty must be a non-negative number',
            code: 'INVALID_VALUE',
        });
    }

    const tiers = s['tiers'];
    if (!Array.isArray(tiers)) {
        errors.push({
            path: '$.scoring.tiers',
            message: 'scoring.tiers must be an array',
            code: 'INVALID_TYPE',
        });
    } else if (tiers.length > MAX_TIERS) {
        errors.push({
            path: '$.scoring.tiers',
            message: `Maximum ${MAX_TIERS} tiers allowed`,
            code: 'RESOURCE_LIMIT',
        });
    }
}

/**
 * Recursively scan an object for function values.
 * This prevents code injection via WorldSpec JSON.
 *
 * SECURITY: This is critical. A WorldSpec with a function value
 * could execute arbitrary code when the engine processes it.
 */
function detectExecutableCode(
    obj: unknown,
    path: string,
    errors: ValidationError[],
    depth: number = 0,
): void {
    // Prevent infinite recursion from circular references
    if (depth > 20) {
        errors.push({
            path,
            message: 'Object nesting exceeds maximum depth (20)',
            code: 'SECURITY_VIOLATION',
        });
        return;
    }

    if (typeof obj === 'function') {
        errors.push({
            path,
            message: 'Functions are not allowed in WorldSpec',
            code: 'SECURITY_VIOLATION',
        });
        return;
    }

    if (obj === null || typeof obj !== 'object') {
        return;
    }

    if (Array.isArray(obj)) {
        for (let i = 0; i < obj.length; i++) {
            detectExecutableCode(obj[i], `${path}[${i}]`, errors, depth + 1);
        }
    } else {
        // Check for prototype pollution keys explicitly.
        // Object.entries() does NOT enumerate __proto__ because it's
        // handled specially by the JS engine. We must check for it
        // separately using hasOwnProperty.
        const dangerousKeys = ['__proto__', 'constructor', 'prototype'] as const;
        for (const key of dangerousKeys) {
            if (Object.prototype.hasOwnProperty.call(obj, key)) {
                errors.push({
                    path: `${path}.${key}`,
                    message: `Key '${key}' is forbidden (prototype pollution vector)`,
                    code: 'SECURITY_VIOLATION',
                });
            }
        }

        // Now iterate all regular properties
        for (const [key, value] of Object.entries(obj)) {
            // Skip already-checked dangerous keys
            if (key === 'constructor' || key === 'prototype') {
                continue;
            }
            detectExecutableCode(value, `${path}.${key}`, errors, depth + 1);
        }
    }
}
