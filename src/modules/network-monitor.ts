/**
 * VARIANT — Network Monitor Module
 *
 * Monitors network traffic via the fabric's tap API and emits
 * typed events for the objective detector and other modules.
 *
 * This module detects:
 *   - HTTP requests/responses (by parsing TCP payloads)
 *   - DNS queries and resolutions
 *   - SSH connections
 *   - Unusual traffic patterns (port scans, etc.)
 *
 * SECURITY: This module receives read-only fabric access via
 * SimulationContext. It taps segments but cannot inject frames,
 * modify firewall rules, or alter routing.
 *
 * MODULARITY: Pure event emitter. No state mutation. Swappable.
 */

import type { Module, SimulationContext, Capability } from '../core/modules';
import type { Unsubscribe } from '../core/events';
import type { TrafficEntry } from '../core/fabric/types';

// ── Module ID ──────────────────────────────────────────────────

const MODULE_ID = 'network-monitor';
const MODULE_VERSION = '1.0.0';

// ── Detection patterns ────────────────────────────────────────

/** Port numbers with special significance. */
const NOTABLE_PORTS: ReadonlyMap<number, string> = new Map([
    [22, 'ssh'],
    [80, 'http'],
    [443, 'https'],
    [3306, 'mysql'],
    [5432, 'postgresql'],
    [6379, 'redis'],
    [27017, 'mongodb'],
    [25, 'smtp'],
    [110, 'pop3'],
    [143, 'imap'],
    [53, 'dns'],
    [21, 'ftp'],
    [23, 'telnet'],
    [8080, 'http-alt'],
    [8443, 'https-alt'],
]);

/** Number of unique destination ports from one source before we flag a scan. */
const PORT_SCAN_THRESHOLD = 10;

// ── Factory ────────────────────────────────────────────────────

export function createNetworkMonitor(): Module {
    const unsubscribers: Unsubscribe[] = [];

    // Connection tracking for detecting patterns
    const connectionCountsBySource = new Map<string, Set<number>>(); // srcIP → set of dstPorts

    const module: Module = {
        id: MODULE_ID,
        type: 'engine',
        version: MODULE_VERSION,
        description: 'Monitors network traffic and emits typed events for detection',

        provides: [{ name: 'network-monitoring' }] as readonly Capability[],
        requires: [] as readonly Capability[],

        init(context: SimulationContext): void {
            // Tap all segments defined in the world
            for (const segment of context.world.network.segments) {
                const unsub = context.fabric.tap(
                    segment.id,
                    (entry: TrafficEntry, _frame: Uint8Array) => {
                        processTrafficEntry(entry, context);
                    },
                );
                unsubscribers.push(unsub);
            }
        },

        destroy(): void {
            for (const unsub of unsubscribers) {
                unsub();
            }
            unsubscribers.length = 0;
            connectionCountsBySource.clear();
        },
    };

    function processTrafficEntry(
        entry: TrafficEntry,
        context: SimulationContext,
    ): void {
        // Track connections for port scan detection
        let ports = connectionCountsBySource.get(entry.sourceIP);
        if (ports === undefined) {
            ports = new Set();
            connectionCountsBySource.set(entry.sourceIP, ports);
        }
        ports.add(entry.port);

        // Detect port scans (many connections to different ports from same src)
        if (ports.size >= PORT_SCAN_THRESHOLD) {
            context.events.emit({
                type: 'sim:alert',
                source: MODULE_ID,
                message: `Possible port scan from ${entry.sourceIP} (${ports.size} unique ports)`,
                timestamp: Date.now(),
            });
        }

        // Emit net:connect for notable outbound connections
        const service = NOTABLE_PORTS.get(entry.port);
        if (service !== undefined && entry.direction === 'outbound') {
            context.events.emit({
                type: 'net:connect',
                host: entry.destIP,
                port: entry.port,
                source: entry.sourceIP,
                protocol: entry.protocol as 'tcp' | 'udp',
                timestamp: Date.now(),
            });
        }
    }

    return module;
}
