/**
 * VARIANT — WorldSpec Composition
 *
 * Enables level designers to build scenarios by extending
 * base levels. Instead of writing a 500-line WorldSpec from
 * scratch, they write a 50-line overlay that changes only
 * what's different.
 *
 * DESIGN: Pure function. No side effects. No dependencies on core/.
 *   Input:  base WorldSpec + overlay WorldSpecPatch
 *   Output: merged WorldSpec
 *
 * MERGE STRATEGY:
 *   - Scalars: overlay wins (e.g., title, difficulty)
 *   - Objects: deep merge (e.g., machines.webserver gets new files)
 *   - Arrays: concatenate by default, replace if flagged
 *   - Absent fields in overlay: base value preserved
 *
 * SECURITY: The composed result must still pass the validator.
 * Composition does not bypass validation — it happens before it.
 *
 * Usage:
 *   const base = loadLevel('demo-01');
 *   const patch: WorldSpecPatch = {
 *       meta: { title: 'Demo 01 — Hard Mode', difficulty: 'hard' },
 *       machines: {
 *           'web-server': {
 *               files: { '/etc/shadow': { content: 'root:$6$...:...' } },
 *           },
 *       },
 *       objectives: [{ id: 'extra', ... }],  // appended
 *   };
 *   const merged = composeWorldSpec(base, patch);
 */

import type {
    WorldSpec,
    MachineSpec,
    ObjectiveSpec,
    CredentialEntry,
    GameOverSpec,
    ScoringConfig,
    WorldMeta,
    NetworkSpec,
    DynamicsSpec,
    MailSystemSpec,
    VariantInternetSpec,
    FileSpec,
    ServiceConfig,
    MachineFirewallRule,
    CronEntry,
    ProcessSpec,
} from './types';

// ── Patch Types ──────────────────────────────────────────────

/**
 * A partial overlay that can be applied to a base WorldSpec.
 * Every field is optional. Only specified fields are merged.
 */
export interface WorldSpecPatch {
    /** Override metadata fields. Deep-merged with base. */
    readonly meta?: Partial<WorldMeta>;

    /** Machine patches. Key = machine ID. Deep-merged with base machines. */
    readonly machines?: Readonly<Record<string, MachineSpecPatch>>;

    /** Add new machines. Key = machine ID. Must not collide with base. */
    readonly addMachines?: Readonly<Record<string, MachineSpec>>;

    /** Remove machines by ID. */
    readonly removeMachines?: readonly string[];

    /** Override start machine. */
    readonly startMachine?: string;

    /** Network patches. */
    readonly network?: Partial<NetworkSpec>;

    /** Credentials to add (appended to base). */
    readonly addCredentials?: readonly CredentialEntry[];

    /** Credential IDs to remove from base. */
    readonly removeCredentials?: readonly string[];

    /** Objectives to add (appended to base). */
    readonly addObjectives?: readonly ObjectiveSpec[];

    /** Objective IDs to remove from base. */
    readonly removeObjectives?: readonly string[];

    /**
     * Replace objectives entirely (instead of append/remove).
     * If set, addObjectives and removeObjectives are ignored.
     */
    readonly objectives?: readonly ObjectiveSpec[];

    /** Override game-over spec. */
    readonly gameOver?: GameOverSpec;

    /** Override dynamics spec. Merged with base. */
    readonly dynamics?: Partial<DynamicsSpec>;

    /** Override mail spec. */
    readonly mail?: MailSystemSpec;

    /** Override variant internet spec. */
    readonly variantInternet?: VariantInternetSpec;

    /** Additional modules to load (appended to base). */
    readonly addModules?: readonly string[];

    /** Modules to remove from base. */
    readonly removeModules?: readonly string[];

    /** Override scoring config. Deep-merged with base. */
    readonly scoring?: Partial<ScoringConfig>;

    /** Additional hints (appended to base). */
    readonly addHints?: readonly string[];

    /** Override tick interval. */
    readonly tickIntervalMs?: number;

    /** Additional extensions (merged with base). */
    readonly extensions?: Readonly<Record<string, unknown>>;
}

/**
 * Partial machine spec for patching an existing machine.
 * Only specified fields are merged into the base machine.
 */
export interface MachineSpecPatch {
    readonly hostname?: string;
    readonly backend?: string;
    readonly image?: string;
    readonly memoryMB?: number;
    readonly role?: MachineSpec['role'];

    /** Files to add or override (merged with base files). */
    readonly files?: Readonly<Record<string, FileSpec>>;

    /** File paths to remove from base. */
    readonly removeFiles?: readonly string[];

    readonly env?: Readonly<Record<string, string>>;
    readonly services?: readonly ServiceConfig[];
    readonly processes?: readonly ProcessSpec[];
    readonly firewall?: readonly MachineFirewallRule[];
    readonly crontab?: readonly CronEntry[];
    readonly packages?: readonly string[];
    readonly extensions?: Readonly<Record<string, unknown>>;
}

// ── Composition ──────────────────────────────────────────────

/**
 * Compose a base WorldSpec with a patch overlay.
 * Returns a new WorldSpec — neither input is mutated.
 *
 * The result should still be passed through validateWorldSpec()
 * before entering the engine.
 */
export function composeWorldSpec(
    base: WorldSpec,
    patch: WorldSpecPatch,
): WorldSpec {
    // Meta: deep merge
    const meta: WorldMeta = patch.meta !== undefined
        ? { ...base.meta, ...patch.meta } as WorldMeta
        : base.meta;

    // Machines: merge patches, add new, remove deleted
    let machines = { ...base.machines };

    // Apply machine patches
    if (patch.machines !== undefined) {
        for (const [id, machinePatch] of Object.entries(patch.machines)) {
            const baseMachine = machines[id];
            if (baseMachine !== undefined) {
                machines[id] = patchMachine(baseMachine, machinePatch);
            }
        }
    }

    // Add new machines
    if (patch.addMachines !== undefined) {
        for (const [id, machine] of Object.entries(patch.addMachines)) {
            machines[id] = machine;
        }
    }

    // Remove machines
    if (patch.removeMachines !== undefined) {
        for (const id of patch.removeMachines) {
            delete machines[id];
        }
    }

    // Network
    const network: NetworkSpec = patch.network !== undefined
        ? {
            segments: patch.network.segments ?? base.network.segments,
            edges: patch.network.edges ?? base.network.edges,
        }
        : base.network;

    // Credentials
    let credentials = [...base.credentials];
    if (patch.removeCredentials !== undefined) {
        const removeSet = new Set(patch.removeCredentials);
        credentials = credentials.filter(c => !removeSet.has(c.id));
    }
    if (patch.addCredentials !== undefined) {
        credentials = credentials.concat(patch.addCredentials);
    }

    // Objectives
    let objectives: readonly ObjectiveSpec[];
    if (patch.objectives !== undefined) {
        objectives = patch.objectives;
    } else {
        let objs = [...base.objectives];
        if (patch.removeObjectives !== undefined) {
            const removeSet = new Set(patch.removeObjectives);
            objs = objs.filter(o => !removeSet.has(o.id));
        }
        if (patch.addObjectives !== undefined) {
            objs = objs.concat(patch.addObjectives);
        }
        objectives = objs;
    }

    // Modules
    let modules = [...base.modules];
    if (patch.removeModules !== undefined) {
        const removeSet = new Set(patch.removeModules);
        modules = modules.filter(m => !removeSet.has(m));
    }
    if (patch.addModules !== undefined) {
        modules = modules.concat(patch.addModules);
    }

    // Hints
    let hints = [...base.hints];
    if (patch.addHints !== undefined) {
        hints = hints.concat(patch.addHints);
    }

    // Dynamics: merge timed + reactive events
    let dynamics = base.dynamics;
    if (patch.dynamics !== undefined && dynamics !== undefined) {
        const timedEvents = [
            ...(dynamics.timedEvents ?? []),
            ...(patch.dynamics.timedEvents ?? []),
        ];
        const reactiveEvents = [
            ...(dynamics.reactiveEvents ?? []),
            ...(patch.dynamics.reactiveEvents ?? []),
        ];
        dynamics = { timedEvents, reactiveEvents };
    } else if (patch.dynamics !== undefined) {
        dynamics = patch.dynamics as DynamicsSpec;
    }

    // Scoring: deep merge
    const scoring: ScoringConfig = patch.scoring !== undefined
        ? { ...base.scoring, ...patch.scoring } as ScoringConfig
        : base.scoring;

    // Extensions: merge
    const extensions = (base.extensions !== undefined || patch.extensions !== undefined)
        ? { ...(base.extensions ?? {}), ...(patch.extensions ?? {}) }
        : undefined;

    // Build the composed spec
    const composed: Record<string, unknown> = {
        version: base.version,
        trust: base.trust,
        meta,
        machines,
        startMachine: patch.startMachine ?? base.startMachine,
        network,
        credentials,
        objectives,
        modules,
        scoring,
        hints,
    };

    // Only include optional fields if they have values
    const gameOver = patch.gameOver ?? base.gameOver;
    if (gameOver !== undefined) composed['gameOver'] = gameOver;
    if (dynamics !== undefined) composed['dynamics'] = dynamics;

    const mail = patch.mail ?? base.mail;
    if (mail !== undefined) composed['mail'] = mail;

    const variantInternet = patch.variantInternet ?? base.variantInternet;
    if (variantInternet !== undefined) composed['variantInternet'] = variantInternet;

    const startConfig = base.startConfig;
    if (startConfig !== undefined) composed['startConfig'] = startConfig;

    const tickIntervalMs = patch.tickIntervalMs ?? base.tickIntervalMs;
    if (tickIntervalMs !== undefined) composed['tickIntervalMs'] = tickIntervalMs;

    const resources = base.resources;
    if (resources !== undefined) composed['resources'] = resources;

    if (extensions !== undefined) composed['extensions'] = extensions;

    return composed as unknown as WorldSpec;
}

// ── Machine Patching ─────────────────────────────────────────

function patchMachine(
    base: MachineSpec,
    patch: MachineSpecPatch,
): MachineSpec {
    // Merge files
    let files = base.files;
    if (patch.files !== undefined || patch.removeFiles !== undefined) {
        const merged = { ...(base.files ?? {}) };

        if (patch.removeFiles !== undefined) {
            for (const path of patch.removeFiles) {
                delete merged[path];
            }
        }

        if (patch.files !== undefined) {
            for (const [path, fileSpec] of Object.entries(patch.files)) {
                merged[path] = fileSpec;
            }
        }

        files = merged;
    }

    // Merge env
    const env = (base.env !== undefined || patch.env !== undefined)
        ? { ...(base.env ?? {}), ...(patch.env ?? {}) }
        : undefined;

    // Build merged machine
    const merged: Record<string, unknown> = {
        hostname: patch.hostname ?? base.hostname,
        image: patch.image ?? base.image,
        memoryMB: patch.memoryMB ?? base.memoryMB,
        role: patch.role ?? base.role,
        interfaces: base.interfaces,
    };

    // Conditional fields
    const backend = patch.backend ?? base.backend;
    if (backend !== undefined) merged['backend'] = backend;
    if (base.user !== undefined) merged['user'] = base.user;
    if (base.users !== undefined) merged['users'] = base.users;
    if (base.codebase !== undefined) merged['codebase'] = base.codebase;
    if (base.attackScript !== undefined) merged['attackScript'] = base.attackScript;
    if (files !== undefined) merged['files'] = files;
    if (env !== undefined) merged['env'] = env;

    const services = patch.services ?? base.services;
    if (services !== undefined) merged['services'] = services;

    const processes = patch.processes ?? base.processes;
    if (processes !== undefined) merged['processes'] = processes;

    const firewall = patch.firewall ?? base.firewall;
    if (firewall !== undefined) merged['firewall'] = firewall;

    const crontab = patch.crontab ?? base.crontab;
    if (crontab !== undefined) merged['crontab'] = crontab;

    const packages = patch.packages !== undefined
        ? [...(base.packages ?? []), ...patch.packages]
        : base.packages;
    if (packages !== undefined) merged['packages'] = packages;

    const extensions = (base.extensions !== undefined || patch.extensions !== undefined)
        ? { ...(base.extensions ?? {}), ...(patch.extensions ?? {}) }
        : undefined;
    if (extensions !== undefined) merged['extensions'] = extensions;

    return merged as unknown as MachineSpec;
}
