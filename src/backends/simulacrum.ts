/**
 * VARIANT — Simulacrum Backend
 *
 * A lightweight VMBackend implementation that uses a VFS +
 * ScriptedShell instead of real x86 emulation. Consumes ~1-5MB
 * per instance instead of 64-256MB.
 *
 * Simulacra handle:
 *   - Terminal I/O via ScriptedShell (command → output)
 *   - Network frames via protocol handlers (registered externally)
 *   - Filesystem via VFS
 *
 * What they DON'T do:
 *   - Run real kernel/userspace code
 *   - Execute arbitrary binaries
 *   - Support real process isolation
 *
 * For 90% of levels, players interact with target machines
 * through predictable commands. The Simulacrum handles those.
 * For the rare case where a real shell is needed, the engine
 * can swap in v86 via the BackendRouter.
 *
 * REPLACEABILITY: Implements VMBackend. Swap this file.
 * Nothing else changes.
 */

import type {
    VMBackend,
    VMBootConfig,
    VMInstance,
    VMSnapshot,
    VMState,
    TerminalIO,
    FilesystemOverlay,
    OverlayFile,
} from '../core/vm/types';
import type { Unsubscribe } from '../core/events';
import type { VFSSnapshot } from '../lib/vfs/types';
import { createVFS } from '../lib/vfs/vfs';
import { createShell } from '../lib/shell/shell';
import type { ScriptedShell, CommandHandler, UserSpec } from '../lib/shell/types';
import type { ServiceConfig } from '../core/world/types';

// ── Types ──────────────────────────────────────────────────────

export interface SimulacrumConfig {
    /** Initial VFS snapshot to boot from. If omitted, creates minimal FS. */
    readonly initialFS?: VFSSnapshot;
    /** Hostname. Default: derived from image URL. */
    readonly hostname?: string;
    /** Default user for SSH sessions. Default: 'root'. */
    readonly defaultUser?: string;
    /** Custom commands to add to the shell. */
    readonly customCommands?: ReadonlyMap<string, CommandHandler>;
    /** Process list for `ps` output. */
    readonly processes?: readonly ProcessEntry[];
    /** Network interface config for `ifconfig`/`ip` output. */
    readonly networkConfig?: NetworkConfig;
    /** Services running on this machine (for ss, netstat, nmap responses). */
    readonly services?: readonly ServiceConfig[];
    /** System users (for auth commands: sudo, su, ssh). */
    readonly users?: readonly UserSpec[];
    /** Event emitter for auth/network events. */
    readonly emit?: (event: { type: string; [key: string]: unknown }) => void;
}

export interface ProcessEntry {
    readonly pid: number;
    readonly user: string;
    readonly command: string;
    readonly args?: string;
}

export interface NetworkConfig {
    readonly interfaces: readonly NetworkInterfaceConfig[];
    readonly routes?: readonly RouteEntry[];
    readonly listenPorts?: readonly ListenPort[];
}

export interface NetworkInterfaceConfig {
    readonly name: string;
    readonly ip: string;
    readonly mac: string;
    readonly netmask: string;
}

export interface RouteEntry {
    readonly destination: string;
    readonly gateway: string;
    readonly iface: string;
}

export interface ListenPort {
    readonly proto: 'tcp' | 'udp';
    readonly port: number;
    readonly process: string;
}

// ── Internal VM state ──────────────────────────────────────────

interface SimulacrumInstance {
    readonly id: string;
    readonly config: VMBootConfig;
    readonly simConfig: SimulacrumConfig;
    state: VMState;
    readonly shell: ScriptedShell;
    readonly vfsSnapshot: VFSSnapshot;
    readonly outputHandlers: Set<(byte: number) => void>;
    readonly frameHandlers: Set<(frame: Uint8Array) => void>;
    inputBuffer: string;
}

// ── Factory ────────────────────────────────────────────────────

let nextSimId = 0;

export function createSimulacrumBackend(configs?: ReadonlyMap<string, SimulacrumConfig>): VMBackend {
    const instances = new Map<string, SimulacrumInstance>();
    const imageConfigs = configs ?? new Map<string, SimulacrumConfig>();

    function getConfigForImage(imageUrl: string): SimulacrumConfig {
        // Try exact match first
        const exact = imageConfigs.get(imageUrl);
        if (exact !== undefined) return exact;

        // Try matching by image name (last path segment without extension)
        const imageName = imageUrl.split('/').pop()?.replace(/\.\w+$/, '') ?? '';
        const byName = imageConfigs.get(imageName);
        if (byName !== undefined) return byName;

        // Default config
        return {};
    }

    function getInstance(vm: VMInstance): SimulacrumInstance {
        const instance = instances.get(vm.id);
        if (instance === undefined) {
            throw new Error(`SimulacrumBackend: VM '${vm.id}' not found`);
        }
        return instance;
    }

    function emitOutput(instance: SimulacrumInstance, text: string): void {
        const encoder = new TextEncoder();
        const bytes = encoder.encode(text);
        for (const byte of bytes) {
            for (const handler of instance.outputHandlers) {
                handler(byte);
            }
        }
    }

    function processInput(instance: SimulacrumInstance): void {
        const lineEnd = instance.inputBuffer.indexOf('\r');
        if (lineEnd === -1) return;

        const command = instance.inputBuffer.slice(0, lineEnd);
        instance.inputBuffer = instance.inputBuffer.slice(lineEnd + 1);
        // Skip newlines after carriage return
        if (instance.inputBuffer.startsWith('\n')) {
            instance.inputBuffer = instance.inputBuffer.slice(1);
        }

        // Echo newline
        emitOutput(instance, '\r\n');

        if (command.length > 0) {
            const result = instance.shell.execute(command);
            if (result.output.length > 0) {
                // Convert \n to \r\n for terminal
                const termOutput = result.output.replace(/\n/g, '\r\n');
                emitOutput(instance, termOutput);
            }
        }

        // Show prompt
        emitOutput(instance, instance.shell.getPrompt());
    }

    const backend: VMBackend = {
        setEmitter(vmId: string, emitFn: (event: { type: string; [key: string]: unknown }) => void): void {
            const instance = instances.get(vmId);
            if (instance !== undefined) {
                instance.shell.setEmit(emitFn);
            }
        },
        async boot(config: VMBootConfig): Promise<VMInstance> {
            const id = `simulacrum-${nextSimId++}`;
            const simConfig = getConfigForImage(config.imageUrl);

            // Create VFS
            const vfs = simConfig.initialFS !== undefined
                ? createVFS(simConfig.initialFS)
                : createVFS();

            // Ensure basic filesystem structure
            if (!vfs.exists('/etc')) vfs.mkdir('/etc', { recursive: true });
            if (!vfs.exists('/tmp')) vfs.mkdir('/tmp', { recursive: true });
            if (!vfs.exists('/var/log')) vfs.mkdir('/var/log', { recursive: true });
            if (!vfs.exists('/root')) vfs.mkdir('/root', { recursive: true });
            if (!vfs.exists('/home')) vfs.mkdir('/home', { recursive: true });

            const hostname = simConfig.hostname ?? config.imageUrl.split('/').pop()?.replace(/\.\w+$/, '') ?? 'localhost';
            vfs.writeFile('/etc/hostname', hostname);

            // Create shell with optional custom commands, services, and users
            const shell = createShell(buildShellConfig(vfs, hostname, simConfig));

            const instance: SimulacrumInstance = {
                id,
                config,
                simConfig,
                state: 'running',
                shell,
                vfsSnapshot: vfs.serialize(),
                outputHandlers: new Set(),
                frameHandlers: new Set(),
                inputBuffer: '',
            };

            instances.set(id, instance);

            return {
                id,
                config,
                state: 'running',
            };
        },

        attachTerminal(vm: VMInstance): TerminalIO {
            const instance = getInstance(vm);

            // Send initial prompt (overlay has already been applied by the engine)
            setTimeout(() => {
                emitOutput(instance, `\r\n${instance.shell.getHostname()} login: ${instance.shell.getUser()}\r\n`);
                emitOutput(instance, instance.shell.getPrompt());
            }, 0);

            return {
                sendToVM(data: string | Uint8Array): void {
                    const text = typeof data === 'string' ? data : new TextDecoder().decode(data);

                    // Echo printable characters
                    for (const ch of text) {
                        if (ch === '\r' || ch === '\n') {
                            // Will be processed in processInput
                        } else if (ch === '\x7f' || ch === '\b') {
                            // Backspace
                            if (instance.inputBuffer.length > 0) {
                                instance.inputBuffer = instance.inputBuffer.slice(0, -1);
                                emitOutput(instance, '\b \b');
                            }
                            continue;
                        } else if (ch === '\x03') {
                            // Ctrl+C
                            instance.inputBuffer = '';
                            emitOutput(instance, '^C\r\n');
                            emitOutput(instance, instance.shell.getPrompt());
                            continue;
                        } else {
                            emitOutput(instance, ch);
                        }
                    }

                    instance.inputBuffer += text;
                    processInput(instance);
                },

                onOutput(handler: (byte: number) => void): Unsubscribe {
                    instance.outputHandlers.add(handler);
                    return () => { instance.outputHandlers.delete(handler); };
                },
            };
        },

        sendFrame(vm: VMInstance, frame: Uint8Array): void {
            // Frames from the fabric are dispatched to all
            // registered handlers (protocol modules, services, etc.).
            const instance = getInstance(vm);
            for (const handler of instance.frameHandlers) {
                handler(frame);
            }
        },

        onFrame(vm: VMInstance, handler: (frame: Uint8Array) => void): Unsubscribe {
            const instance = getInstance(vm);
            instance.frameHandlers.add(handler);
            return () => { instance.frameHandlers.delete(handler); };
        },

        async applyOverlay(vm: VMInstance, overlay: FilesystemOverlay): Promise<void> {
            const instance = getInstance(vm);
            const vfs = instance.shell.getVFS();
            for (const [path, entry] of overlay.files) {
                const overlayEntry = entry as OverlayFile;
                const content = typeof overlayEntry.content === 'string'
                    ? overlayEntry.content
                    : new TextDecoder().decode(overlayEntry.content);
                vfs.writeFile(path, content);
            }

            // Sync shell state from overlaid system files
            if (overlay.files.has('/etc/hostname')) {
                const hostnameContent = vfs.readFile('/etc/hostname');
                if (hostnameContent !== null) {
                    instance.shell.setHostname(hostnameContent.trim());
                }
            }

            // Detect user from /etc/passwd — find the first non-system user (uid >= 1000)
            if (overlay.files.has('/etc/passwd')) {
                const passwdContent = vfs.readFile('/etc/passwd');
                if (passwdContent !== null) {
                    const lines = passwdContent.split('\n');
                    for (const line of lines) {
                        const parts = line.split(':');
                        const uid = parseInt(parts[2] ?? '0', 10);
                        const username = parts[0];
                        if (uid >= 1000 && username !== undefined && username !== 'nobody') {
                            instance.shell.setUser(username);
                            break;
                        }
                    }
                }
            }
        },

        async snapshot(vm: VMInstance): Promise<VMSnapshot> {
            const instance = getInstance(vm);
            const vfs = instance.shell.getVFS();
            const snap = vfs.serialize();
            const json = JSON.stringify(snap);
            const encoder = new TextEncoder();
            const data = encoder.encode(json);
            return {
                vmId: vm.id,
                timestamp: Date.now(),
                data: data.buffer as ArrayBuffer,
            };
        },

        async restore(vm: VMInstance, snap: VMSnapshot): Promise<void> {
            // Simulacra snapshots restore the VFS state.
            // The shell state (cwd, env) is not preserved — acceptable tradeoff.
            const instance = getInstance(vm);
            const decoder = new TextDecoder();
            const json = decoder.decode(snap.data);
            const vfsSnap = JSON.parse(json) as VFSSnapshot;

            // Recreate VFS and shell from snapshot
            const vfs = createVFS(vfsSnap);
            const newShell = createShell(buildShellConfig(vfs, instance.shell.getHostname(), instance.simConfig));

            // Replace shell reference (need to cast away readonly)
            (instance as { shell: ScriptedShell }).shell = newShell;
        },

        async reset(vm: VMInstance): Promise<void> {
            const instance = getInstance(vm);
            // Restore from initial snapshot
            const vfs = createVFS(instance.vfsSnapshot);
            const newShell = createShell(buildShellConfig(vfs, instance.shell.getHostname(), instance.simConfig));
            (instance as { shell: ScriptedShell }).shell = newShell;
        },

        destroy(vm: VMInstance): void {
            const instance = instances.get(vm.id);
            if (instance !== undefined) {
                instance.outputHandlers.clear();
                instance.frameHandlers.clear();
                instance.state = 'stopped';
                instances.delete(vm.id);
            }
        },
    };

    return backend;
}

// ── Custom command builders ────────────────────────────────────

function buildCommands(config: SimulacrumConfig): ReadonlyMap<string, CommandHandler> {
    const commands = new Map<string, CommandHandler>();

    // Override ps with configured processes
    if (config.processes !== undefined && config.processes.length > 0) {
        const procs = config.processes;
        commands.set('ps', () => {
            const lines = ['PID   USER     TIME  COMMAND'];
            for (const p of procs) {
                const pidStr = String(p.pid).padStart(5);
                const cmd = p.args !== undefined ? `${p.command} ${p.args}` : p.command;
                lines.push(`${pidStr} ${p.user.padEnd(8)} 0:00 ${cmd}`);
            }
            return { output: lines.join('\n') + '\n', exitCode: 0 };
        });
    }

    // Override ifconfig with configured network
    if (config.networkConfig !== undefined) {
        const netCfg = config.networkConfig;
        commands.set('ifconfig', () => {
            const lines: string[] = [];
            for (const iface of netCfg.interfaces) {
                lines.push(`${iface.name}      Link encap:Ethernet  HWaddr ${iface.mac}`);
                lines.push(`          inet addr:${iface.ip}  Bcast:${iface.ip.replace(/\.\d+$/, '.255')}  Mask:${iface.netmask}`);
                lines.push('          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1');
                lines.push('');
            }
            return { output: lines.join('\n'), exitCode: 0 };
        });

        commands.set('ip', (args) => {
            if (args[0] === 'addr' || args[0] === 'a') {
                const lines: string[] = [];
                let idx = 1;
                for (const iface of netCfg.interfaces) {
                    lines.push(`${idx}: ${iface.name}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500`);
                    lines.push(`    inet ${iface.ip}/24 scope global ${iface.name}`);
                    idx++;
                }
                return { output: lines.join('\n') + '\n', exitCode: 0 };
            }
            if (args[0] === 'route' || args[0] === 'r') {
                const lines: string[] = [];
                for (const route of netCfg.routes ?? []) {
                    lines.push(`${route.destination} via ${route.gateway} dev ${route.iface}`);
                }
                return { output: lines.join('\n') + '\n', exitCode: 0 };
            }
            return { output: 'Usage: ip [addr|route]\n', exitCode: 0 };
        });

        // Override netstat with listen ports
        if (netCfg.listenPorts !== undefined && netCfg.listenPorts.length > 0) {
            const ports = netCfg.listenPorts;
            commands.set('netstat', (args) => {
                if (args.some(a => a.includes('l'))) {
                    const lines = [
                        'Active Internet connections (only servers)',
                        'Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name',
                    ];
                    for (const p of ports) {
                        lines.push(`${p.proto}    0      0 0.0.0.0:${p.port}             0.0.0.0:*               LISTEN      -/${p.process}`);
                    }
                    return { output: lines.join('\n') + '\n', exitCode: 0 };
                }
                return { output: 'Active Internet connections (w/o servers)\n', exitCode: 0 };
            });

            commands.set('ss', (args) => {
                if (args.some(a => a.includes('l'))) {
                    const lines = ['State    Recv-Q   Send-Q     Local Address:Port      Peer Address:Port   Process'];
                    for (const p of ports) {
                        lines.push(`LISTEN   0        128              0.0.0.0:${p.port}           0.0.0.0:*       ${p.process}`);
                    }
                    return { output: lines.join('\n') + '\n', exitCode: 0 };
                }
                return { output: 'State    Recv-Q   Send-Q     Local Address:Port      Peer Address:Port\n', exitCode: 0 };
            });
        }
    }

    // Add custom commands from config
    if (config.customCommands !== undefined) {
        for (const [name, handler] of config.customCommands) {
            commands.set(name, handler);
        }
    }

    return commands;
}

import type { ShellConfig } from '../lib/shell/types';
import type { VirtualFilesystem } from '../lib/vfs/types';

/** Build ShellConfig, excluding undefined optional fields (exactOptionalPropertyTypes). */
function buildShellConfig(vfs: VirtualFilesystem, hostname: string, simConfig: SimulacrumConfig): ShellConfig {
    const base = {
        vfs,
        hostname,
        user: simConfig.defaultUser ?? 'root',
        customCommands: buildCommands(simConfig),
    };
    return Object.assign(base,
        simConfig.services !== undefined ? { services: simConfig.services } : {},
        simConfig.users !== undefined ? { users: simConfig.users } : {},
        simConfig.emit !== undefined ? { emit: simConfig.emit } : {},
    ) as ShellConfig;
}
