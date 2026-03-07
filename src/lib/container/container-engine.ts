/**
 * VARIANT — Container Runtime Engine
 *
 * Simulates Docker-style container lifecycle with:
 * - Container create/start/stop/remove/exec
 * - Image management with vulnerability tracking
 * - Security scanning (privileged, mounts, caps, secrets)
 * - Network management
 * - Container log simulation
 *
 * All operations are synchronous and pure-data.
 */

import type {
    ContainerEngine,
    Container,
    ContainerCreateConfig,
    ContainerExecResult,
    ContainerImage,
    ImageLayer,
    ContainerNetwork,
    ContainerSecurityScan,
    SecurityFinding,
    ContainerStats,
} from './types';

// ── Helpers ───────────────────────────────────────────────

let containerCounter = 0;
let imageCounter = 0;
let networkCounter = 0;

function generateContainerId(): string {
    return `${++containerCounter}${Date.now().toString(16)}${Math.random().toString(36).slice(2, 8)}`.slice(0, 12);
}

function generateImageId(): string {
    return `sha256:${++imageCounter}${Date.now().toString(16)}${Math.random().toString(36).slice(2, 14)}`.padEnd(71, '0');
}

function generateDigest(): string {
    const chars = '0123456789abcdef';
    let hash = 'sha256:';
    for (let i = 0; i < 64; i++) hash += chars[Math.floor(Math.random() * 16)];
    return hash;
}

const SENSITIVE_MOUNTS = new Set([
    '/var/run/docker.sock', '/proc', '/sys', '/dev', '/etc/shadow',
    '/etc/passwd', '/root', '/host', '/',
]);

const SECRET_ENV_PATTERNS = [
    /password/i, /secret/i, /api.?key/i, /access.?key/i, /token/i,
    /private.?key/i, /credential/i, /auth/i,
];

// ── Factory ──────────────────────────────────────────────

export function createContainerEngine(): ContainerEngine {
    const containers = new Map<string, Container & { logs: string[] }>();
    const images = new Map<string, ContainerImage>();
    const networks = new Map<string, ContainerNetwork & { containers: string[] }>();
    let pidCounter = 1000;

    // Default bridge network
    networks.set('bridge', {
        id: 'bridge0',
        name: 'bridge',
        driver: 'bridge',
        subnet: '172.17.0.0/16',
        gateway: '172.17.0.1',
        containers: [],
    });

    function findContainer(idOrName: string): (Container & { logs: string[] }) | undefined {
        const direct = containers.get(idOrName);
        if (direct) return direct;
        for (const c of containers.values()) {
            if (c.name === idOrName) return c;
            if (c.id.startsWith(idOrName)) return c;
        }
        return undefined;
    }

    function getOrCreateImage(repository: string, tag: string): ContainerImage {
        const key = `${repository}:${tag}`;
        let img = images.get(key);
        if (!img) {
            img = Object.freeze({
                id: generateImageId(),
                repository,
                tag,
                digest: generateDigest(),
                size: 50_000_000 + Math.floor(Math.random() * 200_000_000),
                created: Date.now(),
                layers: Object.freeze([
                    { digest: generateDigest(), size: 30_000_000, command: 'ADD rootfs / #' },
                    { digest: generateDigest(), size: 5_000_000, command: `RUN apt-get update && apt-get install -y ${repository.split('/').pop()}` },
                    { digest: generateDigest(), size: 1_000, command: 'CMD ["start"]' },
                ] as ImageLayer[]),
                env: {},
                entrypoint: [],
                cmd: ['start'],
                exposedPorts: [],
                user: 'root',
                vulnerabilities: [],
            });
            images.set(key, img);
        }
        return img;
    }

    const engine: ContainerEngine = {
        create(config: ContainerCreateConfig): Container {
            const [repo, tag] = config.image.includes(':')
                ? config.image.split(':') as [string, string]
                : [config.image, 'latest'];

            const image = getOrCreateImage(repo!, tag!);
            const id = generateContainerId();

            const container: Container & { logs: string[] } = {
                id,
                name: config.name,
                image: config.image,
                imageId: image.id,
                status: 'created',
                created: Date.now(),
                ports: config.ports ?? [],
                volumes: config.volumes ?? [],
                env: config.env ?? {},
                labels: config.labels ?? {},
                networkMode: config.networkMode ?? 'bridge',
                privileged: config.privileged ?? false,
                capabilities: config.capabilities ?? [],
                securityOpt: config.securityOpt ?? [],
                user: config.user ?? 'root',
                entrypoint: config.entrypoint ?? image.entrypoint,
                command: config.command ?? image.cmd,
                readOnly: config.readOnly ?? false,
                restartPolicy: config.restartPolicy ?? 'no',
                logs: [],
            };

            containers.set(id, container);
            return container;
        },

        start(id: string): boolean {
            const c = findContainer(id);
            if (!c || c.status === 'running') return false;
            const updated = {
                ...c,
                status: 'running' as const,
                started: Date.now(),
                pid: ++pidCounter,
                logs: c.logs,
            };
            updated.logs.push(`[${new Date().toISOString()}] Container ${c.name} started`);
            containers.set(c.id, updated);

            // Add to network
            const net = networks.get(c.networkMode);
            if (net) net.containers.push(c.id);

            return true;
        },

        stop(id: string): boolean {
            const c = findContainer(id);
            if (!c || c.status !== 'running') return false;
            const { pid: _pid, ...rest } = c;
            const updated: Container & { logs: string[] } = {
                ...rest,
                status: 'exited' as const,
                logs: c.logs,
            };
            updated.logs.push(`[${new Date().toISOString()}] Container ${c.name} stopped`);
            containers.set(c.id, updated);

            // Remove from network
            const net = networks.get(c.networkMode);
            if (net) {
                const idx = net.containers.indexOf(c.id);
                if (idx >= 0) net.containers.splice(idx, 1);
            }

            return true;
        },

        remove(id: string): boolean {
            const c = findContainer(id);
            if (!c) return false;
            if (c.status === 'running') return false; // Must stop first
            return containers.delete(c.id);
        },

        get(idOrName: string): Container | null {
            return findContainer(idOrName) ?? null;
        },

        list(all?: boolean): readonly Container[] {
            const result = Array.from(containers.values());
            if (all) return Object.freeze(result);
            return Object.freeze(result.filter(c => c.status === 'running'));
        },

        exec(id: string, command: readonly string[]): ContainerExecResult {
            const c = findContainer(id);
            if (!c || c.status !== 'running') {
                return { exitCode: 1, stdout: '', stderr: `Container ${id} is not running` };
            }

            const cmdStr = command.join(' ');
            c.logs.push(`[${new Date().toISOString()}] exec: ${cmdStr}`);

            // Simulate common commands
            if (cmdStr === 'id') {
                return { exitCode: 0, stdout: `uid=0(${c.user}) gid=0(root) groups=0(root)`, stderr: '' };
            }
            if (cmdStr === 'whoami') {
                return { exitCode: 0, stdout: c.user, stderr: '' };
            }
            if (cmdStr === 'hostname') {
                return { exitCode: 0, stdout: c.id.slice(0, 12), stderr: '' };
            }
            if (cmdStr === 'env') {
                return {
                    exitCode: 0,
                    stdout: Object.entries(c.env).map(([k, v]) => `${k}=${v}`).join('\n'),
                    stderr: '',
                };
            }
            if (cmdStr.startsWith('cat /proc/1/cgroup')) {
                if (c.privileged) {
                    return { exitCode: 0, stdout: '0::/\n', stderr: '' };
                }
                return { exitCode: 0, stdout: `0::/docker/${c.id}\n`, stderr: '' };
            }
            if (cmdStr === 'mount') {
                const mounts = c.volumes.map(v => `${v.source} on ${v.destination} type ${v.type} (${v.mode})`).join('\n');
                return { exitCode: 0, stdout: mounts || 'overlay on / type overlay (rw)', stderr: '' };
            }

            return { exitCode: 0, stdout: `Executed: ${cmdStr}`, stderr: '' };
        },

        pullImage(repository: string, tag?: string): ContainerImage {
            return getOrCreateImage(repository, tag ?? 'latest');
        },

        listImages(): readonly ContainerImage[] {
            return Object.freeze(Array.from(images.values()));
        },

        securityScan(id: string): ContainerSecurityScan {
            const c = findContainer(id);
            if (!c) {
                return { containerId: id, findings: [], riskLevel: 'safe' };
            }

            const findings: SecurityFinding[] = [];

            // Privileged mode
            if (c.privileged) {
                findings.push({
                    type: 'privileged_container',
                    severity: 'critical',
                    description: 'Container is running in privileged mode with full host access',
                    recommendation: 'Remove --privileged flag; use specific capabilities instead',
                    mitre: 'T1611',
                });
            }

            // Docker socket mount
            for (const vol of c.volumes) {
                if (vol.source === '/var/run/docker.sock') {
                    findings.push({
                        type: 'docker_socket_mount',
                        severity: 'critical',
                        description: 'Docker socket is mounted — enables container escape via docker API',
                        recommendation: 'Remove docker.sock mount; use Docker API proxy with ACLs',
                        mitre: 'T1611',
                    });
                }
                if (SENSITIVE_MOUNTS.has(vol.source) && vol.source !== '/var/run/docker.sock') {
                    findings.push({
                        type: 'sensitive_mount',
                        severity: 'high',
                        description: `Sensitive host path mounted: ${vol.source} → ${vol.destination}`,
                        recommendation: `Remove mount of ${vol.source} or use read-only mode`,
                        mitre: 'T1006',
                    });
                }
            }

            // Dangerous capabilities
            if (c.capabilities.includes('SYS_ADMIN')) {
                findings.push({
                    type: 'cap_sys_admin',
                    severity: 'critical',
                    description: 'CAP_SYS_ADMIN grants near-root access to the host',
                    recommendation: 'Remove SYS_ADMIN capability; use specific capabilities',
                    mitre: 'T1611',
                });
            }
            if (c.capabilities.includes('NET_RAW')) {
                findings.push({
                    type: 'cap_net_raw',
                    severity: 'medium',
                    description: 'CAP_NET_RAW enables packet sniffing and spoofing',
                    recommendation: 'Remove NET_RAW capability unless explicitly needed',
                });
            }

            // Running as root
            if (c.user === 'root') {
                findings.push({
                    type: 'root_user',
                    severity: 'medium',
                    description: 'Container running as root user',
                    recommendation: 'Set a non-root USER in Dockerfile',
                });
            }

            // Writable root filesystem
            if (!c.readOnly) {
                findings.push({
                    type: 'writable_rootfs',
                    severity: 'low',
                    description: 'Container has writable root filesystem',
                    recommendation: 'Set --read-only flag and use tmpfs for writable paths',
                });
            }

            // No seccomp/apparmor
            if (c.securityOpt.length === 0) {
                findings.push({
                    type: 'no_seccomp',
                    severity: 'low',
                    description: 'No security profile (seccomp/apparmor) applied',
                    recommendation: 'Apply default seccomp profile or custom apparmor profile',
                });
            }

            // Secret in env vars
            for (const key of Object.keys(c.env)) {
                if (SECRET_ENV_PATTERNS.some(p => p.test(key))) {
                    findings.push({
                        type: 'env_secret',
                        severity: 'high',
                        description: `Potential secret in environment variable: ${key}`,
                        recommendation: 'Use Docker secrets or a secrets manager instead of env vars',
                    });
                    break;
                }
            }

            // Host network
            if (c.networkMode === 'host') {
                findings.push({
                    type: 'host_network',
                    severity: 'high',
                    description: 'Container using host network mode — shares host network namespace',
                    recommendation: 'Use bridge networking with explicit port mappings',
                });
            }

            // Determine overall risk
            let riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical' = 'safe';
            for (const f of findings) {
                if (f.severity === 'critical') { riskLevel = 'critical'; break; }
                if (f.severity === 'high') riskLevel = 'high';
                else if (f.severity === 'medium' && riskLevel !== 'high') riskLevel = 'medium';
                else if (f.severity === 'low' && riskLevel === 'safe') riskLevel = 'low';
            }

            return Object.freeze({ containerId: c.id, findings: Object.freeze(findings), riskLevel });
        },

        createNetwork(name: string, driver?: string, subnet?: string): ContainerNetwork {
            const id = `net-${++networkCounter}`;
            const net: ContainerNetwork & { containers: string[] } = {
                id,
                name,
                driver: (driver ?? 'bridge') as any,
                subnet: subnet ?? `172.${18 + networkCounter}.0.0/16`,
                gateway: subnet ? subnet.replace(/\.0\/\d+$/, '.1') : `172.${18 + networkCounter}.0.1`,
                containers: [],
            };
            networks.set(name, net);
            return net;
        },

        listNetworks(): readonly ContainerNetwork[] {
            return Object.freeze(Array.from(networks.values()).map(n => ({
                id: n.id,
                name: n.name,
                driver: n.driver,
                subnet: n.subnet,
                gateway: n.gateway,
                containers: [...n.containers],
            })));
        },

        logs(id: string, tail?: number): readonly string[] {
            const c = findContainer(id);
            if (!c) return [];
            if (tail !== undefined) return Object.freeze(c.logs.slice(-tail));
            return Object.freeze([...c.logs]);
        },

        getStats(): ContainerStats {
            let running = 0;
            let stopped = 0;
            let privileged = 0;
            for (const c of containers.values()) {
                if (c.status === 'running') running++;
                else stopped++;
                if (c.privileged) privileged++;
            }
            return Object.freeze({
                totalContainers: containers.size,
                runningContainers: running,
                stoppedContainers: stopped,
                totalImages: images.size,
                totalNetworks: networks.size,
                privilegedContainers: privileged,
            });
        },
    };

    return engine;
}
