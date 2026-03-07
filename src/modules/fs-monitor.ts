/**
 * VARIANT — Filesystem Monitor Module
 *
 * Monitors filesystem activity inside VMs by parsing serial
 * output for filesystem event markers. The VM's init scripts
 * set up inotifywait-based watchers that emit structured
 * markers on the serial port.
 *
 * Marker format (emitted by in-VM watcher script):
 *   %%FS:READ:/path/to/file:USER%%
 *   %%FS:WRITE:/path/to/file:USER%%
 *   %%FS:EXEC:/path/to/file:USER%%
 *
 * This module listens for custom events forwarded by the terminal
 * module when it detects FS markers in the serial stream, then
 * emits typed fs:* events on the event bus.
 *
 * SECURITY: This module only reads events from the event bus.
 * It has no access to the VM's internals, filesystem, or
 * memory. It only emits events — no mutations.
 *
 * MODULARITY: This is a Module. It speaks only through the
 * event bus. The objective detector (a separate module) listens
 * for the fs:* events this module emits.
 */

import type { Module, SimulationContext, Capability } from '../core/modules';
import type { Unsubscribe } from '../core/events';

// ── Module ID ──────────────────────────────────────────────────

const MODULE_ID = 'filesystem-monitor';
const MODULE_VERSION = '1.0.0';

// ── Marker parsing ─────────────────────────────────────────────

/** Regex to match filesystem event markers in serial output. */
const FS_MARKER_REGEX = /%%FS:(READ|WRITE|EXEC):([^:]+):([^%]+)%%/;

interface FSEvent {
    readonly operation: 'READ' | 'WRITE' | 'EXEC';
    readonly path: string;
    readonly user: string;
}

export function parseMarker(line: string): FSEvent | null {
    const match = FS_MARKER_REGEX.exec(line);
    if (match === null) return null;

    const op = match[1] as 'READ' | 'WRITE' | 'EXEC' | undefined;
    const path = match[2];
    const user = match[3];

    if (op === undefined || path === undefined || user === undefined) return null;

    return { operation: op, path, user };
}

// ── Factory ────────────────────────────────────────────────────

export function createFilesystemMonitor(): Module {
    const unsubscribers: Unsubscribe[] = [];

    const module: Module = {
        id: MODULE_ID,
        type: 'engine',
        version: MODULE_VERSION,
        description: 'Monitors filesystem activity in VMs via serial output markers',

        provides: [{ name: 'filesystem-monitoring' }] as readonly Capability[],
        requires: [] as readonly Capability[],

        init(context: SimulationContext): void {
            // Listen for custom:fs-marker events that the terminal module
            // forwards when it detects %%FS:...%% markers in the byte stream.
            //
            // Event data format:
            //   { machine: string; marker: string } — preferred (includes machine ID)
            //   string — legacy (raw marker, machine defaults to 'unknown')
            const unsub = context.events.onPrefix('custom:', (event) => {
                if (event.type !== 'custom:fs-marker') return;
                const rawData = (event as { data: unknown }).data;

                let markerStr: string;
                let machine: string;

                if (typeof rawData === 'string') {
                    // Legacy: raw marker string, no machine info
                    markerStr = rawData;
                    machine = 'unknown';
                } else if (
                    rawData !== null &&
                    typeof rawData === 'object' &&
                    'marker' in rawData &&
                    typeof (rawData as { marker: unknown }).marker === 'string'
                ) {
                    const data = rawData as { machine?: string; marker: string };
                    markerStr = data.marker;
                    machine = typeof data.machine === 'string' ? data.machine : 'unknown';
                } else {
                    return;
                }

                const fsEvent = parseMarker(markerStr);
                if (fsEvent === null) return;

                // Emit typed FS events
                switch (fsEvent.operation) {
                    case 'READ':
                        context.events.emit({
                            type: 'fs:read',
                            path: fsEvent.path,
                            machine,
                            user: fsEvent.user,
                            timestamp: Date.now(),
                        });
                        break;
                    case 'WRITE':
                        context.events.emit({
                            type: 'fs:write',
                            path: fsEvent.path,
                            machine,
                            user: fsEvent.user,
                            timestamp: Date.now(),
                        });
                        break;
                    case 'EXEC':
                        context.events.emit({
                            type: 'fs:exec',
                            path: fsEvent.path,
                            machine,
                            user: fsEvent.user,
                            args: [],
                            timestamp: Date.now(),
                        });
                        break;
                }
            });
            unsubscribers.push(unsub);
        },

        destroy(): void {
            for (const unsub of unsubscribers) {
                unsub();
            }
            unsubscribers.length = 0;
        },
    };

    return module;
}

/**
 * Helper: Generate the in-VM watcher script that emits FS markers.
 * This script is injected into VMs via filesystem overlay.
 *
 * The script uses inotifywait to monitor specified directories
 * and outputs structured markers to the serial port (stdout).
 */
export function generateFSWatcherScript(
    watchPaths: readonly string[],
): string {
    const paths = watchPaths.map(p => `"${p}"`).join(' ');

    return `#!/bin/sh
# VARIANT FS Monitor — auto-generated, do not edit
# Watches paths and emits structured markers for the host module

WATCH_PATHS="${paths}"

if ! command -v inotifywait >/dev/null 2>&1; then
    # Alpine: install inotify-tools
    apk add --quiet inotify-tools 2>/dev/null || true
fi

inotifywait -m -r -e access,modify,create,delete $WATCH_PATHS 2>/dev/null | while read dir action file; do
    case "$action" in
        ACCESS*)
            echo "%%FS:READ:$dir$file:$(whoami)%%"
            ;;
        MODIFY*|CREATE*)
            echo "%%FS:WRITE:$dir$file:$(whoami)%%"
            ;;
        DELETE*)
            echo "%%FS:WRITE:$dir$file:$(whoami)%%"
            ;;
    esac
done &
`;
}
