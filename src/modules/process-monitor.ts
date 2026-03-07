/**
 * VARIANT — Process Monitor Module
 *
 * Wires the process tree system into the simulation module lifecycle.
 * Bootstraps realistic process trees for each machine, monitors for
 * suspicious process lineage, and emits defense:alert events when
 * anomalies are detected.
 *
 * EXTENSIBILITY:
 *   - Custom process trees per machine via config
 *   - Anomaly detection runs every N ticks (configurable)
 *   - Custom anomaly rules can be added via the process tree
 *
 * SWAPPABILITY: Implements Module interface. Replace this file.
 */

import type { Module, SimulationContext, Capability } from '../core/modules';
import type { Unsubscribe } from '../core/events';
import { bootstrapLinuxProcessTree } from '../lib/process/process-tree';
import type { ProcessTree } from '../lib/process/process-tree';

// ── Module ID ──────────────────────────────────────────────

const MODULE_ID = 'process-monitor';
const MODULE_VERSION = '1.0.0';

// ── Config ────────────────────────────────────────────────

export interface ProcessMonitorConfig {
    /** How often to check for anomalies (in ticks). Default: 10. */
    readonly anomalyCheckInterval?: number;
    /** Whether to auto-bootstrap process trees from WorldSpec services. Default: true. */
    readonly autoBootstrap?: boolean;
}

// ── Factory ────────────────────────────────────────────────

export function createProcessMonitor(monitorConfig?: ProcessMonitorConfig): Module {
    const cfg = monitorConfig ?? {};
    const anomalyInterval = cfg.anomalyCheckInterval ?? 10;
    const unsubscribers: Unsubscribe[] = [];
    const trees = new Map<string, ProcessTree>();

    const module: Module = {
        id: MODULE_ID,
        type: 'defense',
        version: MODULE_VERSION,
        description: 'Process monitor — bootstraps process trees, detects suspicious process lineage and anomalies',

        provides: [
            { name: 'process-monitoring' },
            { name: 'process-tree' },
        ] as readonly Capability[],
        requires: [] as readonly Capability[],

        init(context: SimulationContext): void {
            trees.clear();

            if (cfg.autoBootstrap !== false) {
                // Bootstrap process trees for each machine based on WorldSpec
                for (const [machineId, machine] of Object.entries(context.world.machines)) {
                    const services = machine.services?.map(s => s.name) ?? [];
                    const tree = bootstrapLinuxProcessTree(machineId, services);
                    trees.set(machineId, tree);
                }
            }

            // Listen for process spawn requests
            const spawnUnsub = context.events.onPrefix('custom:', (event) => {
                if (event.type === 'custom:dynamics-spawn') {
                    const data = event.data as { machine: string; process: { name: string; command: string; args?: string; user?: string } } | null;
                    if (data === null || typeof data !== 'object') return;

                    const tree = trees.get(data.machine);
                    if (tree === undefined) return;

                    const spawnCfg: import('../lib/process/process-tree').SpawnConfig = {
                        name: data.process.name,
                        command: data.process.command,
                        ...(data.process.args !== undefined ? { args: data.process.args } : {}),
                        ...(data.process.user !== undefined ? { user: data.process.user } : {}),
                    };
                    tree.spawn(spawnCfg);
                }

                // Process tree query
                if (event.type === 'custom:process-query') {
                    const data = event.data as { machine: string } | null;
                    if (data === null || typeof data !== 'object') return;

                    const tree = trees.get(data.machine);
                    if (tree === undefined) return;

                    context.events.emit({
                        type: 'custom:process-query-result',
                        data: {
                            machine: data.machine,
                            processes: tree.all(),
                            count: tree.count(),
                            psAux: tree.formatPsAux(),
                        },
                        timestamp: Date.now(),
                    });
                }
            });
            unsubscribers.push(spawnUnsub);
        },

        onTick(tick: number, context: SimulationContext): void {
            // Update all process trees
            for (const tree of trees.values()) {
                tree.tick(tick);
            }

            // Periodic anomaly check
            if (tick % anomalyInterval === 0) {
                for (const [machineId, tree] of trees) {
                    const anomalies = tree.detectAnomalies();
                    for (const anomaly of anomalies) {
                        context.events.emit({
                            type: 'defense:alert',
                            machine: machineId,
                            ruleId: `process/${anomaly.type}`,
                            severity: anomaly.severity === 'critical' ? 'critical' : anomaly.severity === 'warning' ? 'high' : 'medium',
                            detail: anomaly.description,
                            timestamp: Date.now(),
                        });
                    }
                }
            }
        },

        destroy(): void {
            for (const unsub of unsubscribers) {
                unsub();
            }
            unsubscribers.length = 0;
            trees.clear();
        },
    };

    return module;
}
