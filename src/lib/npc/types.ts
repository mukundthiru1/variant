/**
 * VARIANT — NPC (Non-Player Character) System
 *
 * Simulates other users on the system — admins, employees,
 * attackers. Their activity appears in logs, process lists,
 * and file modifications, making the world feel alive.
 *
 * Level designers configure:
 *   - NPC profiles (name, role, behavior patterns)
 *   - Schedules (when they're active)
 *   - Actions (what commands they run, what files they touch)
 *   - For attackers: attack scripts with timelines
 *
 * DESIGN: Pure module. Runs against the dynamics engine.
 * Produces events and VFS modifications on schedule.
 * Everything is configurable. No hardcoded behaviors.
 */

// ── Types ──────────────────────────────────────────────────────

// Open union — third-party packages can use any string for NPC roles
export type NPCRole = 'admin' | 'employee' | 'attacker' | 'service-account' | 'custom' | (string & {});

export interface NPCDefinition {
    /** Unique NPC ID. */
    readonly id: string;
    /** Display name. */
    readonly name: string;
    /** Username on the system. */
    readonly username: string;
    /** Role. Any string accepted. */
    readonly role: NPCRole;
    /** Machine this NPC operates on. */
    readonly machine: string;
    /** Source IP (for login events). */
    readonly sourceIP?: string;
    /**
     * Scheduled actions. Each fires at a specific tick
     * relative to simulation start.
     */
    readonly schedule: readonly NPCAction[];
    /**
     * Recurring actions. Fire every N ticks.
     */
    readonly recurring?: readonly RecurringAction[];
    /**
     * Reactive actions. Fire in response to player actions.
     */
    readonly reactions?: readonly NPCReaction[];
    /**
     * Whether NPC appears in process lists.
     */
    readonly showInProcessList?: boolean;
    /**
     * Process entries when NPC is "active".
     */
    readonly processes?: readonly NPCProcess[];
    /**
     * Open extension point.
     * Third-party packages attach custom NPC data here.
     */
    readonly extensions?: Readonly<Record<string, unknown>>;
}

export interface NPCAction {
    /** Tick when this action fires. */
    readonly tick: number;
    /** Action type. */
    readonly type: NPCActionType;
}

export type NPCActionType =
    | NPCLoginAction
    | NPCLogoutAction
    | NPCCommandAction
    | NPCFileModifyAction
    | NPCLogAction
    | NPCAlertAction
    | NPCAttackAction
    | NPCSendEmailAction
    | NPCNetworkAction
    | NPCCustomAction;

export interface NPCLoginAction {
    readonly kind: 'login';
    /** Login method. Any string — third-party auth methods accepted. */
    readonly method: 'ssh' | 'console' | 'su' | (string & {});
    /** Success or failure. */
    readonly success: boolean;
    /**
     * If failed, how many attempts before giving up.
     * Generates multiple auth.log entries.
     */
    readonly attempts?: number;
}

export interface NPCLogoutAction {
    readonly kind: 'logout';
}

export interface NPCCommandAction {
    readonly kind: 'command';
    /** Shell command the NPC "runs". */
    readonly command: string;
    /**
     * If true, the command is actually executed against the
     * VFS (e.g., writing a file). If false, it just generates
     * a log entry.
     */
    readonly execute?: boolean;
}

export interface NPCFileModifyAction {
    readonly kind: 'file-modify';
    /** File path. */
    readonly path: string;
    /** New content. */
    readonly content: string;
    /**
     * Modification type.
     * 'replace' = overwrite entire file
     * 'append' = add to end
     * 'create' = create new file
     * 'delete' = remove file
     */
    readonly modification: 'replace' | 'append' | 'create' | 'delete' | (string & {});
}

export interface NPCLogAction {
    readonly kind: 'log';
    /** Log file to write to. */
    readonly logFile: string;
    /** Log entry content. */
    readonly message: string;
}

export interface NPCAlertAction {
    readonly kind: 'alert';
    /** Alert message shown to player. */
    readonly message: string;
    readonly severity: 'info' | 'warning' | 'critical' | (string & {});
}

export interface NPCAttackAction {
    readonly kind: 'attack';
    /** Attack type identifier. */
    readonly attackType: string;
    /** Target (machine ID, service, or path). */
    readonly target: string;
    /**
     * Log entries this attack generates.
     * These appear in the target machine's logs.
     */
    readonly logEntries: readonly string[];
    /**
     * If the attack "succeeds" (e.g., attacker gains access),
     * what event to emit.
     */
    readonly successEvent?: string;
}

export interface NPCSendEmailAction {
    readonly kind: 'send-email';
    /** Email address to send to. */
    readonly to: string;
    /** Email address to send from. */
    readonly from: string;
    /** Subject line. */
    readonly subject: string;
    /** Email body. */
    readonly body: string;
    /** Is this a phishing email? */
    readonly malicious?: boolean;
    /** What happens if opened/clicked. */
    readonly maliciousAction?: string;
}

export interface NPCNetworkAction {
    readonly kind: 'network';
    /** Target machine ID or IP. */
    readonly target: string;
    /** Port to connect to/scan. */
    readonly port: number;
    /** Protocol. */
    readonly protocol: 'tcp' | 'udp';
    /** What kind of network activity. */
    readonly activity: 'scan' | 'connect' | 'transfer' | 'exfiltrate' | (string & {});
    /** Bytes to transfer (for transfer/exfiltrate). */
    readonly bytes?: number;
}

export interface NPCCustomAction {
    readonly kind: 'custom';
    /** Custom action identifier. Any string — third-party packages define these. */
    readonly action: string;
    /** Arbitrary parameters. */
    readonly params: Readonly<Record<string, unknown>>;
}

export interface RecurringAction {
    /** Fire every N ticks. */
    readonly intervalTicks: number;
    /** Action to perform. */
    readonly action: NPCActionType;
    /** Start tick. Default: 0. */
    readonly startTick?: number;
    /** Stop tick. Default: never. */
    readonly stopTick?: number;
}

export interface NPCReaction {
    /** Event type to react to. */
    readonly trigger: string;
    /** Delay in ticks before reacting. */
    readonly delay?: number;
    /** Action to take. */
    readonly action: NPCActionType;
    /** Only react once, or every occurrence. Default: 'every'. */
    readonly frequency?: 'once' | 'every';
}

export interface NPCProcess {
    readonly pid: number;
    readonly command: string;
    readonly args?: string;
}

// ── NPC Event generators ───────────────────────────────────────

/**
 * Convert NPC actions into dynamic events that the
 * dynamics engine can process.
 *
 * Returns a DynamicsSpec-compatible structure.
 */
export interface NPCTimedEvent {
    readonly tick: number;
    readonly npcId: string;
    readonly action: NPCActionType;
}

export function expandNPCSchedule(
    npc: NPCDefinition,
    maxTicks: number,
): readonly NPCTimedEvent[] {
    const events: NPCTimedEvent[] = [];

    // Scheduled actions
    for (const scheduled of npc.schedule) {
        events.push({
            tick: scheduled.tick,
            npcId: npc.id,
            action: scheduled.type,
        });
    }

    // Recurring actions
    if (npc.recurring !== undefined) {
        for (const recurring of npc.recurring) {
            const start = recurring.startTick ?? 0;
            const stop = recurring.stopTick ?? maxTicks;
            for (let tick = start; tick <= stop; tick += recurring.intervalTicks) {
                events.push({
                    tick,
                    npcId: npc.id,
                    action: recurring.action,
                });
            }
        }
    }

    // Sort by tick
    events.sort((a, b) => a.tick - b.tick);

    return events;
}

// ── Pre-built NPC templates ────────────────────────────────────

/**
 * Pre-built NPC behavior templates.
 * Level designers can use these directly or customize.
 */
export const NPC_TEMPLATES = {

    /**
     * System administrator who periodically checks logs,
     * runs updates, and rotates credentials.
     */
    sysadmin(username: string, machine: string): NPCDefinition {
        return {
            id: `npc-sysadmin-${username}`,
            name: `Admin ${username}`,
            username,
            role: 'admin',
            machine,
            sourceIP: '10.0.0.1',
            schedule: [
                { tick: 10, type: { kind: 'login', method: 'ssh', success: true } },
                { tick: 12, type: { kind: 'command', command: 'tail -f /var/log/auth.log' } },
                { tick: 20, type: { kind: 'command', command: 'apt update && apt upgrade -y' } },
                { tick: 30, type: { kind: 'command', command: 'systemctl status nginx' } },
                { tick: 50, type: { kind: 'logout' } },
            ],
            recurring: [
                {
                    intervalTicks: 100,
                    action: { kind: 'log', logFile: '/var/log/auth.log', message: `pam_unix(sshd:session): session opened for user ${username} by (uid=0)` },
                },
            ],
            showInProcessList: true,
            processes: [
                { pid: 2345, command: '/usr/sbin/sshd', args: `-D -o AuthorizedKeysCommand=${username}` },
            ],
        };
    },

    /**
     * Employee who does normal work — reads files,
     * accesses the web app, sends emails.
     */
    employee(username: string, machine: string): NPCDefinition {
        return {
            id: `npc-employee-${username}`,
            name: `Employee ${username}`,
            username,
            role: 'employee',
            machine,
            sourceIP: '10.0.0.50',
            schedule: [
                { tick: 5, type: { kind: 'login', method: 'ssh', success: true } },
                { tick: 8, type: { kind: 'command', command: 'cd /var/www && ls -la' } },
                { tick: 15, type: { kind: 'command', command: 'cat /etc/app.conf' } },
                { tick: 30, type: { kind: 'command', command: 'curl http://localhost/api/status' } },
                { tick: 60, type: { kind: 'logout' } },
            ],
            showInProcessList: true,
            processes: [
                { pid: 3456, command: 'bash' },
            ],
        };
    },

    /**
     * Brute-force attacker who hammers SSH with failed logins.
     * Creates noise in auth.log.
     */
    bruteForceAttacker(machine: string, sourceIP: string): NPCDefinition {
        return {
            id: `npc-attacker-brute-${sourceIP}`,
            name: `Attacker from ${sourceIP}`,
            username: 'root',
            role: 'attacker',
            machine,
            sourceIP,
            schedule: [],
            recurring: [
                {
                    intervalTicks: 5,
                    action: { kind: 'login', method: 'ssh', success: false, attempts: 3 },
                    startTick: 50,
                    stopTick: 200,
                },
            ],
        };
    },

    /**
     * Cron job that runs periodically (log rotation, backups, etc.).
     */
    cronService(machine: string, command: string, interval: number): NPCDefinition {
        return {
            id: `npc-cron-${command.replace(/\s+/g, '-').slice(0, 20)}`,
            name: `Cron: ${command}`,
            username: 'root',
            role: 'service-account',
            machine,
            sourceIP: '127.0.0.1',
            schedule: [],
            recurring: [
                {
                    intervalTicks: interval,
                    action: { kind: 'command', command, execute: false },
                },
                {
                    intervalTicks: interval,
                    action: {
                        kind: 'log',
                        logFile: '/var/log/syslog',
                        message: `CRON[${1000 + Math.floor(Math.random() * 9000)}]: (root) CMD (${command})`,
                    },
                },
            ],
        };
    },
} as const;

// ── NPC Template Registry ──────────────────────────────────────

/**
 * A template factory — takes parameters and returns an NPCDefinition.
 * Third-party packages register their own templates here.
 */
export type NPCTemplateFactory = (params: Readonly<Record<string, unknown>>) => NPCDefinition;

/**
 * Metadata for a registered NPC template.
 */
export interface NPCTemplateMeta {
    readonly id: string;
    readonly displayName: string;
    readonly description: string;
    readonly role: NPCRole;
    /** Parameter names this template accepts. */
    readonly parameterNames: readonly string[];
}

/**
 * Registry for NPC templates. Append-only.
 * Level designers reference templates by ID in their WorldSpecs.
 */
export interface NPCTemplateRegistry {
    register(meta: NPCTemplateMeta, factory: NPCTemplateFactory): void;
    create(id: string, params: Readonly<Record<string, unknown>>): NPCDefinition | null;
    has(id: string): boolean;
    getMeta(id: string): NPCTemplateMeta | null;
    list(): readonly string[];
    getAll(): readonly NPCTemplateMeta[];
}

/**
 * Create an NPC template registry.
 */
export function createNPCTemplateRegistry(): NPCTemplateRegistry {
    const factories = new Map<string, NPCTemplateFactory>();
    const metadata = new Map<string, NPCTemplateMeta>();

    return {
        register(meta: NPCTemplateMeta, factory: NPCTemplateFactory): void {
            if (factories.has(meta.id)) {
                throw new Error(
                    `NPCTemplateRegistry: template '${meta.id}' is already registered. ` +
                    `Registrations are append-only.`,
                );
            }
            if (meta.id.length === 0) {
                throw new Error('NPCTemplateRegistry: template ID must be non-empty.');
            }
            factories.set(meta.id, factory);
            metadata.set(meta.id, Object.freeze(meta));
        },

        create(id: string, params: Readonly<Record<string, unknown>>): NPCDefinition | null {
            const factory = factories.get(id);
            if (factory === undefined) return null;
            return factory(params);
        },

        has(id: string): boolean {
            return factories.has(id);
        },

        getMeta(id: string): NPCTemplateMeta | null {
            return metadata.get(id) ?? null;
        },

        list(): readonly string[] {
            return Object.freeze(Array.from(factories.keys()));
        },

        getAll(): readonly NPCTemplateMeta[] {
            return Object.freeze(Array.from(metadata.values()));
        },
    };
}
