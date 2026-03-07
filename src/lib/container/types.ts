/**
 * VARIANT — Container Runtime Types
 *
 * Simulates Docker/containerd-style container lifecycle
 * for container escape, image poisoning, registry attacks,
 * and container security training.
 *
 * EXTENSIBILITY: Custom runtime via open union.
 * SWAPPABILITY: Implements ContainerEngine interface.
 */

// ── Container ─────────────────────────────────────────────

export interface Container {
    readonly id: string;
    readonly name: string;
    readonly image: string;
    readonly imageId: string;
    readonly status: ContainerStatus;
    readonly created: number;
    readonly started?: number;
    readonly pid?: number;
    readonly ports: readonly PortMapping[];
    readonly volumes: readonly VolumeMount[];
    readonly env: Readonly<Record<string, string>>;
    readonly labels: Readonly<Record<string, string>>;
    readonly networkMode: string;
    readonly privileged: boolean;
    readonly capabilities: readonly string[];
    readonly securityOpt: readonly string[];
    readonly user: string;
    readonly entrypoint: readonly string[];
    readonly command: readonly string[];
    readonly readOnly: boolean;
    readonly restartPolicy: RestartPolicy;
}

export type ContainerStatus =
    | 'created' | 'running' | 'paused' | 'restarting' | 'exited' | 'dead'
    | (string & {});

export type RestartPolicy = 'no' | 'always' | 'on-failure' | 'unless-stopped';

export interface PortMapping {
    readonly containerPort: number;
    readonly hostPort: number;
    readonly protocol: 'tcp' | 'udp';
    readonly hostIP?: string;
}

export interface VolumeMount {
    readonly source: string;
    readonly destination: string;
    readonly mode: 'rw' | 'ro';
    readonly type: 'bind' | 'volume' | 'tmpfs';
}

// ── Container Image ───────────────────────────────────────

export interface ContainerImage {
    readonly id: string;
    readonly repository: string;
    readonly tag: string;
    readonly digest: string;
    readonly size: number;
    readonly created: number;
    readonly layers: readonly ImageLayer[];
    readonly env: Readonly<Record<string, string>>;
    readonly entrypoint: readonly string[];
    readonly cmd: readonly string[];
    readonly exposedPorts: readonly number[];
    readonly user: string;
    readonly vulnerabilities: readonly ImageVulnerability[];
}

export interface ImageLayer {
    readonly digest: string;
    readonly size: number;
    readonly command: string;
}

export interface ImageVulnerability {
    readonly cveId: string;
    readonly severity: 'low' | 'medium' | 'high' | 'critical';
    readonly package: string;
    readonly installedVersion: string;
    readonly fixedVersion?: string;
    readonly description: string;
}

// ── Container Network ─────────────────────────────────────

export interface ContainerNetwork {
    readonly id: string;
    readonly name: string;
    readonly driver: 'bridge' | 'host' | 'none' | 'overlay' | (string & {});
    readonly subnet: string;
    readonly gateway: string;
    readonly containers: readonly string[];
}

// ── Security Scan Result ──────────────────────────────────

export interface ContainerSecurityScan {
    readonly containerId: string;
    readonly findings: readonly SecurityFinding[];
    readonly riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
}

export interface SecurityFinding {
    readonly type: SecurityFindingType;
    readonly severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
    readonly description: string;
    readonly recommendation: string;
    readonly mitre?: string;
}

export type SecurityFindingType =
    | 'privileged_container' | 'host_pid' | 'host_network'
    | 'docker_socket_mount' | 'sensitive_mount' | 'cap_sys_admin'
    | 'cap_net_raw' | 'no_seccomp' | 'no_apparmor'
    | 'root_user' | 'writable_rootfs' | 'exposed_port'
    | 'env_secret' | 'image_vulnerability'
    | (string & {});

// ── Container Engine Interface ────────────────────────────

export interface ContainerEngine {
    /** Create a container. */
    create(config: ContainerCreateConfig): Container;
    /** Start a container. */
    start(id: string): boolean;
    /** Stop a container. */
    stop(id: string): boolean;
    /** Remove a container. */
    remove(id: string): boolean;
    /** Get a container by ID or name. */
    get(idOrName: string): Container | null;
    /** List all containers. */
    list(all?: boolean): readonly Container[];
    /** Execute a command in a container. */
    exec(id: string, command: readonly string[]): ContainerExecResult;
    /** Pull an image. */
    pullImage(repository: string, tag?: string): ContainerImage;
    /** List images. */
    listImages(): readonly ContainerImage[];
    /** Scan a container for security issues. */
    securityScan(id: string): ContainerSecurityScan;
    /** Create a network. */
    createNetwork(name: string, driver?: string, subnet?: string): ContainerNetwork;
    /** List networks. */
    listNetworks(): readonly ContainerNetwork[];
    /** Get container logs. */
    logs(id: string, tail?: number): readonly string[];
    /** Get stats. */
    getStats(): ContainerStats;
}

export interface ContainerCreateConfig {
    readonly name: string;
    readonly image: string;
    readonly ports?: readonly PortMapping[];
    readonly volumes?: readonly VolumeMount[];
    readonly env?: Readonly<Record<string, string>>;
    readonly labels?: Readonly<Record<string, string>>;
    readonly privileged?: boolean;
    readonly capabilities?: readonly string[];
    readonly securityOpt?: readonly string[];
    readonly user?: string;
    readonly entrypoint?: readonly string[];
    readonly command?: readonly string[];
    readonly readOnly?: boolean;
    readonly networkMode?: string;
    readonly restartPolicy?: RestartPolicy;
}

export interface ContainerExecResult {
    readonly exitCode: number;
    readonly stdout: string;
    readonly stderr: string;
}

export interface ContainerStats {
    readonly totalContainers: number;
    readonly runningContainers: number;
    readonly stoppedContainers: number;
    readonly totalImages: number;
    readonly totalNetworks: number;
    readonly privilegedContainers: number;
}
