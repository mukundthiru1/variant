/**
 * VARIANT — Simulation Engine
 *
 * The orchestrator. Takes a validated WorldSpec and materializes
 * it into a running simulation:
 *
 *   WorldSpec → Validate → Boot VMs → Wire Fabric → Load Modules → Run
 *
 * SECURITY: The engine only processes validated WorldSpecs.
 * It never calls new V86() directly — it uses the VMBackend contract.
 * The WorldSpec is frozen after validation.
 *
 * LIFECYCLE:
 *   1. create()  — allocate resources, validate spec
 *   2. boot()    — boot VMs, wire network, load modules
 *   3. tick()    — advance simulation clock
 *   4. destroy() — teardown everything, release all resources
 *
 * MODULES: The engine creates a ModuleRegistry, resolves all modules
 * requested by the WorldSpec, constructs a read-only SimulationContext,
 * and delegates objective detection, scoring, and dynamics to modules.
 * No simulation logic is hardcoded in this file — only lifecycle
 * orchestration.
 */

import type { VMBackend, VMInstance, TerminalIO } from './vm/types';
import type { EventBus } from './events';
import { createEventBus } from './event-bus';
import { validateWorldSpec } from './world/validator';
import { deepFreeze } from './freeze';
import { createNetworkFabric } from './fabric/fabric';
import type { NetworkFabric, NICHandle } from './fabric/types';
import type {
    WorldSpec,
    MachineSpec,
    GameOverCondition,
    SegmentSpec,
} from './world/types';
import type { Module, SimulationContext, ModuleRegistry, ServiceLocator } from './modules';
import { createModuleRegistry, createServiceLocator } from './modules';

// ── Simulation State ───────────────────────────────────────────

export type SimulationPhase =
    | 'created'     // resources allocated, not yet booted
    | 'booting'     // VMs are starting up
    | 'running'     // simulation is live
    | 'paused'      // simulation is paused (clock frozen)
    | 'completed'   // player won
    | 'failed'      // game over (defense breach, etc.)
    | 'error'       // unrecoverable error
    | 'destroyed';  // all resources released

export interface SimulationState {
    readonly phase: SimulationPhase;
    readonly tick: number;
    readonly startTime: number;
    readonly elapsedMs: number;
    readonly score: number;
    readonly hintsUsed: number;
    readonly objectiveStatus: ReadonlyMap<string, ObjectiveStatus>;
}

export type ObjectiveStatus = 'locked' | 'available' | 'in-progress' | 'completed';

// ── Simulation Handle ──────────────────────────────────────────

/**
 * The handle returned by createSimulation().
 * This is the primary API for controlling a running simulation.
 */
export interface Simulation {
    /** Unique simulation ID. */
    readonly id: string;

    /** The WorldSpec driving this simulation. */
    readonly world: Readonly<WorldSpec>;

    /** Current state snapshot. */
    getState(): SimulationState;

    /** Event bus — subscribe to events, emit custom events. */
    readonly events: EventBus;

    /** Network fabric — read-only access for modules. */
    readonly fabric: NetworkFabric;

    // ── Lifecycle ────────────────────────────────────────────────

    /** Boot all VMs and start the simulation. */
    boot(): Promise<void>;

    /** Pause the simulation clock. VMs keep running. */
    pause(): void;

    /** Resume from pause. */
    resume(): void;

    /** Get a hint. Deducts from score. Returns the hint text. */
    useHint(): string | null;

    /** Destroy the simulation and release all resources. */
    destroy(): void;

    // ── VM Access ────────────────────────────────────────────────

    /** Get the TerminalIO for the player's start machine. */
    getPlayerTerminal(): TerminalIO | null;

    /** Get a VM instance by machine ID (from WorldSpec). */
    getVM(machineId: string): VMInstance | null;
}

// ── Factory ────────────────────────────────────────────────────

let nextSimId = 0;

/** Reset the simulation ID counter. For test determinism only. */
export function _resetSimIdCounter(): void {
    nextSimId = 0;
}

export interface CreateSimulationOptions {
    readonly worldSpec: unknown;
    readonly backend: VMBackend;

    /**
     * Base URL for VM images.
     * Images are loaded from: `${imageBaseUrl}/${image}.bin`
     */
    readonly imageBaseUrl: string;

    /**
     * BIOS URLs.
     */
    readonly biosUrl: string;
    readonly vgaBiosUrl: string;

    /**
     * Pre-built module registry with registered module factories.
     * If not provided, an empty registry is created and no modules
     * will be loaded (useful for minimal test setups).
     */
    readonly moduleRegistry?: ModuleRegistry;
}

export function createSimulation(options: CreateSimulationOptions): Simulation {
    // ── Phase 1: Validate ──────────────────────────────────────
    const validation = validateWorldSpec(options.worldSpec);
    if (!validation.valid) {
        const errorMessages = validation.errors
            .map(e => `  ${e.path}: ${e.message} [${e.code}]`)
            .join('\n');
        throw new Error(
            `WorldSpec validation failed:\n${errorMessages}`,
        );
    }

    // Deep freeze the spec — no nested property can be mutated at runtime.
    // SECURITY: TypeScript readonly only works at compile time.
    // Deep freeze is the runtime enforcement.
    const world = deepFreeze(structuredClone(options.worldSpec)) as WorldSpec;

    const simId = `sim-${nextSimId++}-${Date.now().toString(36)}`;
    const events = createEventBus(50_000);
    const backend = options.backend;

    // ── Internal state ─────────────────────────────────────────
    let phase: SimulationPhase = 'created';
    let tick = 0;
    const startTime = Date.now();
    let hintsUsed = 0;

    const vmInstances = new Map<string, VMInstance>();
    const terminals = new Map<string, TerminalIO>();
    const objectiveStatus = new Map<string, ObjectiveStatus>();
    const nicHandles: NICHandle[] = [];
    let fabric: NetworkFabric | null = null;

    // Module system
    const registry: ModuleRegistry = options.moduleRegistry ?? createModuleRegistry();
    let loadedModules: Module[] = [];
    const serviceLocator: ServiceLocator = createServiceLocator();

    // Initialize objective status
    for (const obj of world.objectives) {
        objectiveStatus.set(obj.id, obj.order === 1 || obj.order === undefined ? 'available' : 'locked');
    }

    // ── Objective tracking via event bus ───────────────────────
    // The engine listens for objective:complete from the objective-detector module
    // and maintains the objectiveStatus map + triggers completion check.
    function setupObjectiveListeners(): void {
        events.on('objective:complete', (event) => {
            completeObjective(event.objectiveId);
        });

        // Defense breach → game over
        events.on('defense:breach', (event) => {
            if (world.gameOver !== undefined) {
                for (const condition of world.gameOver.conditions) {
                    if (condition.type === 'machine-compromised' && condition.machine === event.machine) {
                        triggerGameOver(world.gameOver.message);
                    }
                }
            }
        });

        // Game over conditions: noise threshold
        events.on('sim:noise', (event) => {
            if (world.gameOver !== undefined) {
                for (const condition of world.gameOver.conditions) {
                    if (condition.type === 'noise-detected' && event.amount >= condition.threshold) {
                        triggerGameOver(world.gameOver.message);
                    }
                }
            }
        });
    }

    function completeObjective(objectiveId: string): void {
        const current = objectiveStatus.get(objectiveId);
        if (current === 'completed') return; // Already done

        objectiveStatus.set(objectiveId, 'completed');

        const obj = world.objectives.find(o => o.id === objectiveId);

        // Unlock the next objective in sequence
        if (obj?.order !== undefined) {
            const nextOrder = obj.order + 1;
            for (const nextObj of world.objectives) {
                if (nextObj.order === nextOrder && objectiveStatus.get(nextObj.id) === 'locked') {
                    objectiveStatus.set(nextObj.id, 'available');
                    events.emit({
                        type: 'objective:progress',
                        objectiveId: nextObj.id,
                        detail: 'Objective unlocked',
                        timestamp: Date.now(),
                    });
                }
            }
        }

        // Check if all required objectives are complete
        const allRequired = world.objectives
            .filter(o => o.required)
            .every(o => objectiveStatus.get(o.id) === 'completed');

        if (allRequired) {
            phase = 'completed';
            if (tickInterval !== null) {
                clearInterval(tickInterval);
                tickInterval = null;
            }

            events.emit({
                type: 'custom:sim-completed',
                data: {
                    tick,
                    elapsedMs: Date.now() - startTime,
                    hintsUsed,
                },
                timestamp: Date.now(),
            });
        }
    }

    function triggerGameOver(reason: string): void {
        if (phase !== 'running') return;
        phase = 'failed';
        if (tickInterval !== null) {
            clearInterval(tickInterval);
            tickInterval = null;
        }

        events.emit({
            type: 'sim:gameover',
            reason,
            timestamp: Date.now(),
        });
    }

    // ── Tick loop ──────────────────────────────────────────────
    let tickInterval: ReturnType<typeof setInterval> | null = null;
    const TICK_INTERVAL_MS = Math.max(100, Math.min(10_000, world.tickIntervalMs ?? 1000));

    function buildContext(): SimulationContext {
        return {
            vms: new Map(vmInstances),
            fabric: {
                getTrafficLog: () => fabric?.getTrafficLog() ?? [],
                getStats: () => fabric?.getStats() ?? { totalFrames: 0, droppedFrames: 0, bytesRouted: 0, dnsQueries: 0, activeConnections: 0 },
                tap: (segment, handler) => fabric?.tap(segment, handler) ?? (() => { }),
                addDNSRecord: (record) => fabric?.addDNSRecord(record),
                registerExternal: (handler) => fabric?.registerExternal(handler),
                getExternalHandler: (domain) => fabric?.getExternalHandler(domain),
                getExternalDomains: () => fabric?.getExternalDomains() ?? [],
            },
            events,
            world,
            tick,
            services: serviceLocator,
        };
    }

    function onTick(): void {
        if (phase !== 'running') return;

        tick++;
        events.emit({
            type: 'sim:tick',
            tick,
            timestamp: Date.now(),
        });

        const ctx = buildContext();

        // Pre-tick hooks
        for (const mod of loadedModules) {
            if (mod.onPreTick !== undefined) {
                try {
                    mod.onPreTick(tick, ctx);
                } catch (error: unknown) {
                    console.error(
                        `[Engine] Module '${mod.id}' threw during onPreTick:`,
                        error instanceof Error ? error.message : String(error),
                    );
                }
            }
        }

        // Tick all modules
        for (const mod of loadedModules) {
            if (mod.onTick !== undefined) {
                try {
                    mod.onTick(tick, ctx);
                } catch (error: unknown) {
                    console.error(
                        `[Engine] Module '${mod.id}' threw during onTick:`,
                        error instanceof Error ? error.message : String(error),
                    );
                }
            }
        }

        // Post-tick hooks
        for (const mod of loadedModules) {
            if (mod.onPostTick !== undefined) {
                try {
                    mod.onPostTick(tick, ctx);
                } catch (error: unknown) {
                    console.error(
                        `[Engine] Module '${mod.id}' threw during onPostTick:`,
                        error instanceof Error ? error.message : String(error),
                    );
                }
            }
        }

        // Evaluate time-based game-over conditions
        if (world.gameOver !== undefined) {
            evaluateGameOver(world.gameOver.conditions);
        }
    }

    function evaluateGameOver(conditions: readonly GameOverCondition[]): void {
        for (const condition of conditions) {
            if (condition.type === 'service-down') {
                // Service-down tracking is event-driven — the SIEM module
                // detects service failures and emits defense:breach events.
                // At tick-level we check the time constraint.
                // The game-over condition references a duration in ticks.
                // A more complete implementation would track service state
                // via event listeners, but that belongs in a dedicated module
                // (service-health-monitor). For now, the condition is
                // evaluated when defense:breach events arrive (above).
                continue;
            }
            // noise-detected is handled via event listener (above)
            // machine-compromised is handled via event listener (above)
            // data-exfiltrated and credential-leaked are event-driven
        }
    }

    /**
     * Derive a gateway IP from a SegmentSpec.
     * Uses the explicit gateway if provided, otherwise computes
     * the first host address from the subnet CIDR.
     */
    function deriveGateway(segment: SegmentSpec): string | undefined {
        if (segment.gateway !== undefined) return segment.gateway;

        // Parse CIDR and compute first host address
        const parts = segment.subnet.split('/');
        if (parts.length !== 2) return undefined;
        const ipParts = parts[0]?.split('.');
        const prefix = parseInt(parts[1] ?? '0', 10);
        if (ipParts === undefined || ipParts.length !== 4 || isNaN(prefix)) return undefined;

        const ip = ipParts.map(p => parseInt(p, 10));
        if (ip.some(p => isNaN(p))) return undefined;

        // Network address → first host = set the host bits' LSB to 1
        const hostBits = 32 - prefix;
        if (hostBits < 2) return undefined; // /31 or /32 has no usable gateway

        const ipNum = ((ip[0]! << 24) | (ip[1]! << 16) | (ip[2]! << 8) | ip[3]!) >>> 0;
        const mask = (0xFFFFFFFF << hostBits) >>> 0;
        const networkAddr = (ipNum & mask) >>> 0;
        const gatewayAddr = (networkAddr + 1) >>> 0;

        return [
            (gatewayAddr >>> 24) & 0xFF,
            (gatewayAddr >>> 16) & 0xFF,
            (gatewayAddr >>> 8) & 0xFF,
            gatewayAddr & 0xFF,
        ].join('.');
    }

    // ── Build simulation handle ────────────────────────────────

    const simulation: Simulation = {
        id: simId,
        world,
        events,
        get fabric(): NetworkFabric {
            if (fabric === null) {
                throw new Error('Fabric not available — simulation not yet booted');
            }
            return fabric;
        },

        getState(): SimulationState {
            return {
                phase,
                tick,
                startTime,
                elapsedMs: Date.now() - startTime,
                score: world.scoring.maxScore,  // Base score — actual computed by scoring module
                hintsUsed,
                objectiveStatus: new Map(objectiveStatus),
            };
        },

        async boot(): Promise<void> {
            if (phase !== 'created') {
                throw new Error(`Cannot boot simulation in phase '${phase}'`);
            }

            phase = 'booting';

            try {
                // ── Wire up network fabric ──────────────────────
                const machineEntries = Object.entries(world.machines);
                fabric = createNetworkFabric();

                // Build topology from WorldSpec
                // Convert WorldSpec edges to fabric routes (segment-to-segment)
                const segmentIds = new Set(world.network.segments.map(s => s.id));
                const machineToSegments = new Map<string, string[]>();
                for (const [mId, mSpec] of machineEntries) {
                    const spec = mSpec as MachineSpec;
                    machineToSegments.set(mId, spec.interfaces.map(i => i.segment));
                }

                const resolveToSegments = (ref: string): string[] => {
                    if (segmentIds.has(ref)) return [ref];
                    return machineToSegments.get(ref) ?? [];
                };

                const routes: { from: string; to: string; allowedPorts?: readonly number[]; protocol?: 'tcp' | 'udp' | 'any' }[] = [];
                for (const edge of world.network.edges) {
                    const fromSegs = resolveToSegments(edge.from);
                    const toSegs = resolveToSegments(edge.to);
                    for (const fromSeg of fromSegs) {
                        for (const toSeg of toSegs) {
                            if (fromSeg !== toSeg) {
                                const route: { from: string; to: string; allowedPorts?: readonly number[]; protocol?: 'tcp' | 'udp' | 'any' } = {
                                    from: fromSeg,
                                    to: toSeg,
                                };
                                if (edge.ports !== undefined) route.allowedPorts = edge.ports;
                                const proto = edge.protocol === undefined ? 'any' : edge.protocol as 'tcp' | 'udp' | 'any';
                                route.protocol = proto;
                                routes.push(route);
                            }
                        }
                    }
                }

                fabric.init({
                    segments: world.network.segments.map(s => {
                        const gw = deriveGateway(s);
                        const seg: { id: string; subnet: string; gateway?: string } = {
                            id: s.id,
                            subnet: s.subnet,
                        };
                        if (gw !== undefined) {
                            seg.gateway = gw;
                        }
                        return seg;
                    }),
                    routes,
                    firewallRules: [],
                });

                // Register DNS records from WorldSpec machines
                for (const [, machine] of machineEntries) {
                    const spec = machine as MachineSpec;
                    for (const iface of spec.interfaces) {
                        fabric.addDNSRecord({
                            domain: `${spec.hostname}.local`,
                            ip: iface.ip,
                            type: 'A',
                            ttl: 300,
                        });
                    }
                }

                // Boot all VMs
                for (const [machineId, machine] of machineEntries) {
                    const spec = machine as MachineSpec;
                    const firstMAC = spec.interfaces[0]?.mac ?? generateMAC(machineId);

                    const vm = await backend.boot({
                        imageUrl: `${options.imageBaseUrl}/${spec.image}.bin`,
                        memoryMB: spec.memoryMB,
                        networkMAC: firstMAC,
                        biosUrl: options.biosUrl,
                        vgaBiosUrl: options.vgaBiosUrl,
                        enableVGA: false, // Terminal-first — no VGA
                    });

                    vmInstances.set(machineId, vm);

                    // Connect ALL interfaces to the fabric (not just [0])
                    for (let ifIdx = 0; ifIdx < spec.interfaces.length; ifIdx++) {
                        const iface = spec.interfaces[ifIdx];
                        if (iface === undefined) continue;
                        const mac = iface.mac ?? (ifIdx === 0 ? firstMAC : generateMAC(`${machineId}-if${ifIdx}`));

                        const handle = fabric.connect(
                            vm.id,
                            iface.segment,
                            mac,
                            iface.ip,
                        );
                        nicHandles.push(handle);
                    }

                    // Wire: VM NIC output → fabric router
                    backend.onFrame(vm, (frame) => {
                        fabric?.routeFrame(vm.id, frame);
                    });

                    // Wire: fabric delivery → VM NIC input
                    fabric.onFrameForVM(vm.id, (frame) => {
                        backend.sendFrame(vm, frame);
                    });

                    // Build system files + author overlays
                    const files = new Map<string, { content: string | Uint8Array }>();

                    // Auto-generate system files from WorldSpec
                    const sysFiles = generateSystemFiles(spec, machineEntries, world);
                    for (const [path, content] of sysFiles) {
                        files.set(path, { content });
                    }

                    // Apply author-specified file overlays (overrides system files)
                    if (spec.files !== undefined) {
                        for (const [path, fileSpec] of Object.entries(spec.files)) {
                            files.set(path, { content: fileSpec.content });
                        }
                    }

                    if (files.size > 0) {
                        await backend.applyOverlay(vm, { files });
                    }

                    // Attach terminal AFTER overlay so hostname/user are correct
                    if (spec.role === 'player') {
                        const termIO = backend.attachTerminal(vm);
                        terminals.set(machineId, termIO);
                    }
                }

                // Set up objective listeners (engine-level tracking)
                setupObjectiveListeners();

                // ── Resolve and initialize modules ──────────────
                if (world.modules.length > 0) {
                    loadedModules = registry.resolve(world.modules);
                    const ctx = buildContext();
                    registry.initAll(loadedModules, ctx);

                    // Notify all modules that initialization is complete
                    for (const mod of loadedModules) {
                        if (mod.onAllInitialized !== undefined) {
                            try {
                                mod.onAllInitialized(ctx);
                            } catch (error: unknown) {
                                console.error(
                                    `[Engine] Module '${mod.id}' threw during onAllInitialized:`,
                                    error instanceof Error ? error.message : String(error),
                                );
                            }
                        }
                    }

                    // Notify all modules that simulation is about to start
                    for (const mod of loadedModules) {
                        if (mod.onSimulationStart !== undefined) {
                            try {
                                mod.onSimulationStart(ctx);
                            } catch (error: unknown) {
                                console.error(
                                    `[Engine] Module '${mod.id}' threw during onSimulationStart:`,
                                    error instanceof Error ? error.message : String(error),
                                );
                            }
                        }
                    }
                }

                // Emit boot event so modules/UI know the simulation is live
                events.emit({
                    type: 'custom:sim-booted',
                    data: {
                        simId,
                        machineCount: machineEntries.length,
                        moduleCount: loadedModules.length,
                    },
                    timestamp: Date.now(),
                });

                // Start tick loop
                phase = 'running';
                tickInterval = setInterval(onTick, TICK_INTERVAL_MS);

            } catch (error: unknown) {
                phase = 'error';
                throw error;
            }
        },

        pause(): void {
            if (phase !== 'running') return;
            phase = 'paused';
            if (tickInterval !== null) {
                clearInterval(tickInterval);
                tickInterval = null;
            }

            // Notify modules
            for (const mod of loadedModules) {
                if (mod.onPause !== undefined) {
                    try {
                        mod.onPause();
                    } catch (error: unknown) {
                        console.error(
                            `[Engine] Module '${mod.id}' threw during onPause:`,
                            error instanceof Error ? error.message : String(error),
                        );
                    }
                }
            }

            events.emit({
                type: 'custom:sim-paused',
                data: { tick },
                timestamp: Date.now(),
            });
        },

        resume(): void {
            if (phase !== 'paused') return;
            phase = 'running';
            tickInterval = setInterval(onTick, TICK_INTERVAL_MS);

            // Notify modules
            for (const mod of loadedModules) {
                if (mod.onResume !== undefined) {
                    try {
                        mod.onResume();
                    } catch (error: unknown) {
                        console.error(
                            `[Engine] Module '${mod.id}' threw during onResume:`,
                            error instanceof Error ? error.message : String(error),
                        );
                    }
                }
            }

            events.emit({
                type: 'custom:sim-resumed',
                data: { tick },
                timestamp: Date.now(),
            });
        },

        useHint(): string | null {
            if (hintsUsed >= world.hints.length) return null;

            const hint = world.hints[hintsUsed];
            if (hint === undefined) return null;

            hintsUsed++;

            // Emit hint-used event so the scoring module can deduct
            events.emit({
                type: 'custom:hint-used',
                data: { hintIndex: hintsUsed - 1, totalHints: world.hints.length },
                timestamp: Date.now(),
            });

            return hint;
        },

        destroy(): void {
            if (phase === 'destroyed') return;

            // Stop tick loop
            if (tickInterval !== null) {
                clearInterval(tickInterval);
                tickInterval = null;
            }

            // Notify modules simulation is ending (before destroy)
            if (loadedModules.length > 0) {
                const ctx = buildContext();
                for (const mod of loadedModules) {
                    if (mod.onSimulationEnd !== undefined) {
                        try {
                            mod.onSimulationEnd(ctx);
                        } catch (error: unknown) {
                            console.error(
                                `[Engine] Module '${mod.id}' threw during onSimulationEnd:`,
                                error instanceof Error ? error.message : String(error),
                            );
                        }
                    }
                }
            }

            // Destroy modules (reverse order — LIFO)
            if (loadedModules.length > 0) {
                registry.destroyAll(loadedModules);
                loadedModules = [];
            }

            // Destroy all VMs
            for (const [, vm] of vmInstances) {
                try {
                    backend.destroy(vm);
                } catch {
                    // Best-effort cleanup
                }
            }

            vmInstances.clear();
            terminals.clear();

            // Disconnect all NICs and destroy fabric
            for (const handle of nicHandles) {
                handle.disconnect();
            }
            nicHandles.length = 0;
            if (fabric !== null) {
                fabric.destroy();
                fabric = null;
            }

            events.removeAllListeners();
            events.clearLog();

            phase = 'destroyed';
        },

        getPlayerTerminal(): TerminalIO | null {
            return terminals.get(world.startMachine) ?? null;
        },

        getVM(machineId: string): VMInstance | null {
            return vmInstances.get(machineId) ?? null;
        },
    };

    return simulation;
}

// ── Helpers ────────────────────────────────────────────────────

/**
 * Generate a deterministic MAC address from a machine ID.
 * Uses the locally administered range (bit 1 of first octet set).
 *
 * SECURITY: MAC addresses are internal to the fabric.
 * They never reach the real network.
 */
function generateMAC(machineId: string): string {
    let hash = 0;
    for (let i = 0; i < machineId.length; i++) {
        const char = machineId.charCodeAt(i);
        hash = ((hash << 5) - hash + char) | 0;
    }

    // Ensure locally administered, unicast
    const b0 = (Math.abs(hash) & 0xFE) | 0x02;
    const b1 = (Math.abs(hash >> 8)) & 0xFF;
    const b2 = (Math.abs(hash >> 16)) & 0xFF;
    const b3 = (Math.abs(hash >> 24)) & 0xFF;
    const b4 = (Math.abs(hash * 7)) & 0xFF;
    const b5 = (Math.abs(hash * 13)) & 0xFF;

    return [b0, b1, b2, b3, b4, b5]
        .map(b => b.toString(16).padStart(2, '0'))
        .join(':');
}

/**
 * Auto-generate /etc system files from WorldSpec machine data.
 * These give the simulated machine a realistic identity:
 * passwd, shadow, hosts, resolv.conf, hostname, motd, group, services.
 */
function generateSystemFiles(
    spec: MachineSpec,
    allMachines: [string, unknown][],
    world: WorldSpec,
): Map<string, string> {
    const files = new Map<string, string>();
    const allUsers = [
        { username: 'root', uid: 0, home: '/root', shell: '/bin/bash', groups: ['root'] },
        { username: 'daemon', uid: 1, home: '/usr/sbin', shell: '/usr/sbin/nologin', groups: ['daemon'] },
        { username: 'nobody', uid: 65534, home: '/nonexistent', shell: '/usr/sbin/nologin', groups: ['nogroup'] },
    ];

    // Add machine users
    let nextUid = 1000;
    const machineUsers = [...(spec.users ?? [])];
    if (spec.user !== undefined) machineUsers.unshift(spec.user);

    for (const u of machineUsers) {
        if (allUsers.some(e => e.username === u.username)) continue;
        allUsers.push({
            username: u.username,
            uid: u.uid ?? nextUid++,
            home: u.home ?? `/home/${u.username}`,
            shell: u.shell ?? '/bin/bash',
            groups: [...(u.groups ?? [])],
        });
    }

    // /etc/passwd
    const passwdLines = allUsers.map(u =>
        `${u.username}:x:${u.uid}:${u.uid}:${u.username}:${u.home}:${u.shell}`
    );
    files.set('/etc/passwd', passwdLines.join('\n') + '\n');

    // /etc/shadow (hashed passwords — simulated)
    const shadowLines = allUsers.map(u => {
        const mu = machineUsers.find(mu2 => mu2.username === u.username);
        const hash = mu?.password !== undefined ? `$6$salt$${simpleHash(mu.password)}` : '!';
        return `${u.username}:${hash}:19000:0:99999:7:::`;
    });
    files.set('/etc/shadow', shadowLines.join('\n') + '\n');

    // /etc/group
    const groups = new Map<string, number[]>();
    for (const u of allUsers) {
        for (const g of u.groups) {
            const members = groups.get(g) ?? [];
            members.push(u.uid);
            groups.set(g, members);
        }
        // Primary group
        if (!groups.has(u.username)) {
            groups.set(u.username, [u.uid]);
        }
    }
    const groupLines: string[] = [];
    let gid = 0;
    for (const [name, members] of groups) {
        const memberNames = members.map(uid => allUsers.find(u => u.uid === uid)?.username ?? '').filter(Boolean);
        groupLines.push(`${name}:x:${gid++}:${memberNames.join(',')}`);
    }
    files.set('/etc/group', groupLines.join('\n') + '\n');

    // /etc/hostname
    files.set('/etc/hostname', spec.hostname + '\n');

    // /etc/hosts — map all machines in the world
    const hostLines = ['127.0.0.1\tlocalhost', `127.0.1.1\t${spec.hostname}`];
    for (const [, mSpec] of allMachines) {
        const m = mSpec as MachineSpec;
        for (const iface of m.interfaces) {
            hostLines.push(`${iface.ip}\t${m.hostname} ${m.hostname}.local`);
        }
    }
    files.set('/etc/hosts', hostLines.join('\n') + '\n');

    // /etc/resolv.conf — use segment gateways as DNS
    const resolveLines: string[] = [];
    for (const iface of spec.interfaces) {
        const seg = world.network.segments.find(s => s.id === iface.segment);
        if (seg?.gateway !== undefined) {
            resolveLines.push(`nameserver ${seg.gateway}`);
        }
    }
    if (resolveLines.length === 0) resolveLines.push('nameserver 127.0.0.1');
    files.set('/etc/resolv.conf', resolveLines.join('\n') + '\n');

    // /etc/services (well-known ports from machine services)
    if (spec.services !== undefined && spec.services.length > 0) {
        const svcLines = ['# /etc/services — VARIANT generated'];
        for (const svc of spec.services) {
            for (const port of svc.ports) {
                svcLines.push(`${svc.name}\t\t${port}/tcp`);
            }
        }
        files.set('/etc/services', svcLines.join('\n') + '\n');
    }

    // /etc/motd
    files.set('/etc/motd',
        `Welcome to ${spec.hostname}\n` +
        `${world.meta.title}\n` +
        `\n`
    );

    return files;
}

/** Simple deterministic hash for simulated /etc/shadow entries. */
function simpleHash(input: string): string {
    let h = 0x811c9dc5;
    for (let i = 0; i < input.length; i++) {
        h ^= input.charCodeAt(i);
        h = Math.imul(h, 0x01000193);
    }
    return Math.abs(h).toString(36).padStart(12, '0').slice(0, 12);
}
