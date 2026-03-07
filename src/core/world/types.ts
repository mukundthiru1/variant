/**
 * VARIANT — WorldSpec Type Definitions
 *
 * The universal level format. Pure data. No code.
 * Community authors write these. AI generates these.
 * The engine validates and interprets them.
 *
 * SECURITY INVARIANT: WorldSpecs cannot contain functions, callbacks,
 * or executable code. Every field is a primitive, string, number, boolean,
 * array, or nested object of the same. The validator rejects anything else.
 *
 * SECURITY INVARIANT: The 'trust' field is set by the engine, never by
 * the author. Community levels cannot reference INVARIANT payloads.
 *
 * EXTENSIBILITY: New fields can be added to MachineSpec, ObjectiveSpec,
 * etc. without breaking existing levels — unknown fields are ignored
 * by older engine versions (forward compatibility).
 *
 * EXTENSIBILITY: The 'extensions' record on every major type allows
 * third-party packages to attach arbitrary data without schema changes.
 * Convention: namespace keys as 'vendor/feature'.
 */

// ── Top-level WorldSpec ────────────────────────────────────────

export interface WorldSpec {
    readonly version: '2.0';

    /**
     * Trust level. Set by the engine, not the author.
     * 'community' = can only reference open primitives
     * 'curated'   = can reference INVARIANT sensor payloads
     */
    readonly trust: 'community' | 'curated';

    readonly meta: WorldMeta;

    /** All machines in the simulation. Key = machine ID. */
    readonly machines: Readonly<Record<string, MachineSpec>>;

    /** Which machine the player starts on. Must be a key in machines. */
    readonly startMachine: string;

    /**
     * How the UI starts — which lenses are open and how they're arranged.
     * String = preset name ('terminal', 'desktop', 'soc-workstation').
     * Object = custom lens configuration.
     * Default: 'terminal' (single terminal lens).
     */
    readonly startConfig?: StartConfigSpec;

    /** Network topology connecting the machines. */
    readonly network: NetworkSpec;

    /** Credential graph — where creds are found, where they're valid. */
    readonly credentials: readonly CredentialEntry[];

    /** Win conditions (attack) and/or lose conditions (defense). */
    readonly objectives: readonly ObjectiveSpec[];

    /** Defense mode: what ends the game. */
    readonly gameOver?: GameOverSpec;

    /** Dynamic events that change the world during gameplay. */
    readonly dynamics?: DynamicsSpec;

    /**
     * Mail system — pre-populated inboxes, phishing campaigns,
     * social engineering traps. Configurable per level.
     */
    readonly mail?: MailSystemSpec;

    /** Simulated external services (VARIANT Internet). */
    readonly variantInternet?: VariantInternetSpec;

    /** Module IDs this level requires. */
    readonly modules: readonly string[];

    /** Scoring configuration. */
    readonly scoring: ScoringConfig;

    /** Progressive hints. Each hint penalizes score. */
    readonly hints: readonly string[];

    /**
     * Tick interval in milliseconds. Default: 1000 (1 tick/sec).
     * Lower values = faster simulation (good for time-pressure scenarios).
     * Higher values = slower simulation (good for complex analysis).
     * Clamped to [100, 10000] by the validator.
     */
    readonly tickIntervalMs?: number;

    /**
     * Resource estimation. The engine uses this to warn players
     * on low-memory devices before loading.
     */
    readonly resources?: ResourceEstimation;

    /**
     * Simulated cloud infrastructure. Players discover and exploit
     * S3 buckets, IAM policies, Lambda functions, etc. through
     * the VARIANT Internet API services.
     */
    readonly cloud?: CloudInfraSpec;

    /**
     * Active Directory domain simulation with users, groups,
     * GPOs, and Kerberos attack surface.
     */
    readonly activeDirectory?: ActiveDirectorySpec;

    /** Kubernetes cluster topology and resources. */
    readonly kubernetes?: KubernetesSpec;

    /** CI/CD pipeline topology. */
    readonly pipeline?: PipelineSpec;

    /**
     * Open extension point. Third-party packages can attach
     * arbitrary data here. Convention: 'vendor/feature' keys.
     * The engine passes this through untouched.
     */
    readonly extensions?: Readonly<Record<string, unknown>>;
}

// ── Meta ───────────────────────────────────────────────────────

export interface WorldMeta {
    readonly title: string;
    readonly scenario: string;
    readonly briefing: readonly string[];
    readonly difficulty: Difficulty;
    readonly mode: GameMode;
    readonly vulnClasses: readonly string[];
    readonly tags: readonly string[];
    readonly estimatedMinutes: number;
    readonly author: AuthorInfo;
}

export type Difficulty = 'beginner' | 'easy' | 'medium' | 'hard' | 'expert' | (string & {});
export type GameMode = 'attack' | 'defense' | 'mixed' | (string & {});

export interface AuthorInfo {
    readonly name: string;
    readonly id: string;
    /** 'santh' for curated levels, player ID for community. */
    readonly type: 'santh' | 'community' | 'ai-generated' | (string & {});
}

// ── Machines ───────────────────────────────────────────────────

export interface MachineSpec {
    readonly hostname: string;

    /**
     * Backend to use for this machine. Level designer chooses.
     * 'simulacrum'  — VFS + ScriptedShell, ~1-5MB (default for targets)
     * 'simulacrum+' — Simulacrum + lwIP TCP/IP, ~5-10MB
     * 'v86'         — Full x86 emulation, ~32-128MB (default for player)
     * 'container2wasm' — Docker containers in WASM, ~30-50MB
     * Any string    — custom backends registered via BackendRouter
     * Default: 'v86' for role=player, 'simulacrum' for everything else.
     */
    readonly backend?: string;

    /** Disk image reference from the image factory. */
    readonly image: string;

    /** RAM in MB. Clamped to [16, 256] by the validator. */
    readonly memoryMB: number;

    /** Role in the simulation. */
    readonly role: MachineRole;

    /** Player's identity on this machine (if role=player). */
    readonly user?: UserSpec;

    /** Other system users. */
    readonly users?: readonly UserSpec[];

    /** Network interfaces. */
    readonly interfaces: readonly InterfaceSpec[];

    /** Codebase from the library (optional). */
    readonly codebase?: CodebaseConfig;

    /** NPC attacker script (if role=npc-attacker). */
    readonly attackScript?: AttackScriptConfig;

    // ── Overlay (applied on top of base image at boot) ──────────

    /** Files to inject. Key = absolute path. */
    readonly files?: Readonly<Record<string, FileSpec>>;

    /** Environment variables to set. */
    readonly env?: Readonly<Record<string, string>>;

    /** Services to start at boot. */
    readonly services?: readonly ServiceConfig[];

    /** Processes visible in ps/top (simulated background activity). */
    readonly processes?: readonly ProcessSpec[];

    /** iptables-style firewall rules for this machine. */
    readonly firewall?: readonly MachineFirewallRule[];

    /** Cron entries. */
    readonly crontab?: readonly CronEntry[];

    /** Additional packages to install from the mirror. */
    readonly packages?: readonly string[];

    /**
     * Open extension point for this machine.
     * Third-party packages can attach arbitrary data.
     */
    readonly extensions?: Readonly<Record<string, unknown>>;
}

export type MachineRole =
    | 'player'          // player starts here
    | 'target'          // attack target
    | 'defend'          // player must defend this
    | 'npc-attacker'    // automated adversary
    | 'infrastructure'  // supporting service (DB, DNS, etc.)
    | (string & {});    // open — third-party roles accepted

export interface UserSpec {
    readonly username: string;
    readonly password?: string;
    readonly shell?: string;
    readonly home?: string;
    readonly groups?: readonly string[];
    readonly uid?: number;
    readonly sudo?: boolean;
}

export interface InterfaceSpec {
    readonly ip: string;
    readonly segment: string;
    readonly mac?: string;         // auto-generated if not specified
}

// ── Codebase ───────────────────────────────────────────────────

export interface CodebaseConfig {
    /** Codebase ID from the library (e.g., 'ecommerce-node'). */
    readonly id: string;

    /** Version (e.g., '2.1'). */
    readonly version: string;

    /**
     * Vulnerability toggles.
     * true  = enabled (exploitable)
     * false = disabled (not present)
     * 'patched' = was vulnerable, now fixed (red herring)
     */
    readonly vulns: Readonly<Record<string, boolean | 'patched'>>;
}

// ── NPC Attacker ───────────────────────────────────────────────

export interface AttackScriptConfig {
    /** Attack profile (e.g., 'sqli-scanner', 'brute-force'). */
    readonly profile: string;

    /** Timeline: tick → command to execute. */
    readonly timeline: Readonly<Record<number, string>>;

    /** If true, the attacker adapts to the player's defenses. */
    readonly adaptToDefense?: boolean;
}

// ── Files ──────────────────────────────────────────────────────

export interface FileSpec {
    /** File content. */
    readonly content: string;

    /** Unix permissions (octal). Defaults to 0o644. */
    readonly mode?: number;

    /** File type. */
    readonly type?: 'file' | 'directory' | 'symlink' | (string & {});

    /** Symlink target (if type=symlink). */
    readonly target?: string;

    /** Owner. Defaults to 'root'. */
    readonly owner?: string;
}

// ── Services ───────────────────────────────────────────────────

export interface ServiceConfig {
    /**
     * Service type. Any string — resolved via ServiceHandlerFactory.
     * Well-known types: 'http', 'ssh', 'mysql', 'dns', 'smtp', 'ftp'.
     * Third-party: 'vendor/custom-service'.
     */
    readonly name: string;

    /** Command to start the service (for v86 backends). */
    readonly command: string;

    /** Ports this service listens on. */
    readonly ports: readonly number[];

    /** Whether the service auto-starts at boot. */
    readonly autostart: boolean;

    /**
     * Service-specific configuration. Open record.
     * HTTP: { webroot: '/var/www', defaultPage: 'index.html' }
     * SSH: { banner: 'OpenSSH_8.9', maxAttempts: 3 }
     * MySQL: { database: 'appdb', tables: [...] }
     * Custom: anything
     */
    readonly config?: Readonly<Record<string, unknown>>;
}

export interface ProcessSpec {
    /** Process name as shown in ps/top. */
    readonly name: string;
    readonly pid: number;
    readonly user: string;
    readonly cpu?: number;
    readonly mem?: number;
}

export interface MachineFirewallRule {
    readonly chain: 'INPUT' | 'OUTPUT' | 'FORWARD' | (string & {});
    readonly action: 'ACCEPT' | 'DROP' | 'REJECT' | (string & {});
    readonly protocol?: 'tcp' | 'udp' | 'icmp' | (string & {});
    readonly port?: number;
    readonly source?: string;
    readonly destination?: string;
}

export interface CronEntry {
    readonly schedule: string;    // cron expression
    readonly command: string;
    readonly user?: string;       // defaults to 'root'
}

// ── Network ────────────────────────────────────────────────────

export interface NetworkSpec {
    readonly segments: readonly SegmentSpec[];
    readonly edges: readonly EdgeSpec[];
}

export interface SegmentSpec {
    readonly id: string;
    readonly subnet: string;
    readonly gateway?: string;
    readonly vlan?: number;
}

export interface EdgeSpec {
    readonly from: string;         // machine ID
    readonly to: string;           // machine ID or segment ID
    readonly ports?: readonly number[];
    readonly protocol?: 'tcp' | 'udp' | 'any' | (string & {});
    readonly bidirectional?: boolean;
}

// ── Credentials ────────────────────────────────────────────────

export interface CredentialEntry {
    readonly id: string;
    readonly type: CredentialType;
    readonly value: string;

    /** Where the credential can be found (file path, environment, etc.). */
    readonly foundAt: CredentialLocation;

    /** Where the credential is valid. */
    readonly validAt: CredentialTarget;
}

export type CredentialType =
    | 'password'
    | 'ssh-key'
    | 'api-token'
    | 'jwt-secret'
    | 'database-password'
    | 'cookie'
    | 'certificate'
    | (string & {});    // open — third-party credential types accepted

export interface CredentialLocation {
    readonly machine: string;
    readonly path?: string;          // file path
    readonly env?: string;           // environment variable
    readonly service?: string;       // service name (e.g., 'mysql')
    readonly method?: string;        // how to find it (for hints)
}

export interface CredentialTarget {
    readonly machine: string;
    readonly service: string;
    readonly user: string;
    readonly port?: number;
}

// ── Objectives ─────────────────────────────────────────────────

export interface ObjectiveSpec {
    readonly id: string;
    readonly title: string;
    readonly description: string;
    readonly type: ObjectiveType;
    readonly required: boolean;      // must complete to win
    readonly order?: number;         // suggested completion order
    readonly reward?: number;        // bonus points
    readonly details: ObjectiveDetails;
}

export type ObjectiveType =
    | 'find-file'
    | 'read-data'
    | 'exfiltrate'
    | 'escalate'
    | 'lateral-move'
    | 'credential-find'
    | 'write-rule'
    | 'survive'
    | 'patch-vuln'
    | 'custom'
    | (string & {});    // open — third-party objective types accepted

/**
 * Objective-specific details. Discriminated by parent ObjectiveType.
 * The engine uses these to evaluate completion.
 */
export type ObjectiveDetails =
    | FindFileDetails
    | ReadDataDetails
    | ExfiltrateDetails
    | EscalateDetails
    | LateralMoveDetails
    | CredentialFindDetails
    | WriteRuleDetails
    | SurviveDetails
    | PatchVulnDetails
    | CustomDetails;

export interface FindFileDetails {
    readonly kind: 'find-file';
    readonly machine: string;
    readonly path: string;
    readonly contentMatch?: string;  // regex to match file content
}

export interface ReadDataDetails {
    readonly kind: 'read-data';
    readonly machine: string;
    readonly dataId: string;
    readonly description: string;
}

export interface ExfiltrateDetails {
    readonly kind: 'exfiltrate';
    readonly data: string;
    readonly fromMachine: string;
}

export interface EscalateDetails {
    readonly kind: 'escalate';
    readonly machine: string;
    readonly fromUser: string;
    readonly toUser: string;
}

export interface LateralMoveDetails {
    readonly kind: 'lateral-move';
    readonly fromMachine: string;
    readonly toMachine: string;
}

export interface CredentialFindDetails {
    readonly kind: 'credential-find';
    readonly credentialId: string;
}

export interface WriteRuleDetails {
    readonly kind: 'write-rule';
    readonly vulnClass: string;
    readonly minDetection: number;   // 0-1 (e.g., 0.80 = 80%)
    readonly maxFalsePositive: number;
    readonly payloadSource: 'known-patterns' | 'invariant-live';
}

export interface SurviveDetails {
    readonly kind: 'survive';
    readonly ticks: number;
}

export interface PatchVulnDetails {
    readonly kind: 'patch-vuln';
    readonly machine: string;
    readonly vulnId: string;
}

export interface CustomDetails {
    readonly kind: 'custom';
    readonly evaluator: string;      // module ID that evaluates this objective
    readonly params: Readonly<Record<string, string | number | boolean>>;
}

/**
 * Generic objective details for third-party objective types.
 *
 * NOT part of the ObjectiveDetails discriminated union (that would
 * break TypeScript narrowing). Instead, third-party code uses
 * `CustomDetails` with `kind: 'custom'` for fully typed scenarios,
 * or casts to this type when building objectives with arbitrary kinds.
 *
 * The objective-detector's `default` switch case handles any
 * `kind` value not in the built-in set — it delegates to the
 * custom event system (listening on `custom:<kind>:` prefix).
 *
 * Usage by third-party level designers:
 *   const objective: ObjectiveSpec = {
 *       id: 'obj-1', title: '...', description: '...',
 *       type: 'detect-ransomware',  // any string
 *       required: true,
 *       details: { kind: 'custom', evaluator: 'ransomware-detector', params: { ... } },
 *   };
 */
export interface GenericDetails {
    readonly kind: string;
    readonly machine?: string;
    readonly params?: Readonly<Record<string, unknown>>;
}

// ── Game Over (defense mode) ───────────────────────────────────

export interface GameOverSpec {
    readonly conditions: readonly GameOverCondition[];
    readonly message: string;
}

export type GameOverCondition =
    | MachineCompromisedCondition
    | DataExfiltratedCondition
    | ServiceDownCondition
    | CredentialLeakedCondition
    | NoiseDetectedCondition
    | CustomGameOverCondition;

export interface MachineCompromisedCondition {
    readonly type: 'machine-compromised';
    readonly machine: string;
}

export interface DataExfiltratedCondition {
    readonly type: 'data-exfiltrated';
    readonly data: string;
}

export interface ServiceDownCondition {
    readonly type: 'service-down';
    readonly machine: string;
    readonly service: string;
    readonly durationTicks: number;
}

export interface CredentialLeakedCondition {
    readonly type: 'credential-leaked';
    readonly credentialId: string;
}

export interface NoiseDetectedCondition {
    readonly type: 'noise-detected';
    readonly threshold: number;
}

/**
 * Custom game-over condition. Delegates to a registered handler
 * in the GameOverConditionHandlerRegistry. Third-party packages
 * register handlers by name. Zero core changes needed.
 */
export interface CustomGameOverCondition {
    readonly type: 'custom';
    /** Handler ID in the GameOverConditionHandlerRegistry. */
    readonly handler: string;
    /** Arbitrary parameters for the handler. */
    readonly params: Readonly<Record<string, unknown>>;
}

// ── Dynamics ───────────────────────────────────────────────────

export interface DynamicsSpec {
    /** Events that trigger at specific ticks. */
    readonly timedEvents?: readonly TimedEvent[];

    /** Events triggered by player actions. */
    readonly reactiveEvents?: readonly ReactiveEvent[];
}

export interface TimedEvent {
    readonly tick: number;
    readonly action: DynamicAction;
    /** Repeat interval (ticks). If set, this event fires repeatedly. */
    readonly repeatInterval?: number;
}

export interface ReactiveEvent {
    readonly trigger: string;        // event type to watch for
    readonly condition?: string;     // JSON path condition
    readonly action: DynamicAction;
    /** If true, this event only fires once. Default: false. */
    readonly once?: boolean;
}

export type DynamicAction =
    | { readonly type: 'spawn-process'; readonly machine: string; readonly process: ProcessSpec }
    | { readonly type: 'modify-file'; readonly machine: string; readonly path: string; readonly content: string }
    | { readonly type: 'alert'; readonly message: string; readonly severity: 'info' | 'warning' | 'critical' | (string & {}) }
    | { readonly type: 'rotate-credential'; readonly credentialId: string; readonly newValue: string }
    | { readonly type: 'send-email'; readonly to: string; readonly template: string; readonly delay?: number }
    | { readonly type: 'npc-action'; readonly npc: string; readonly action: string; readonly params?: Readonly<Record<string, unknown>> }
    | { readonly type: 'start-service'; readonly machine: string; readonly service: string }
    | { readonly type: 'stop-service'; readonly machine: string; readonly service: string }
    | { readonly type: 'inject-traffic'; readonly fromMachine: string; readonly toMachine: string; readonly pattern: string }
    | { readonly type: 'open-lens'; readonly lensType: string; readonly targetMachine?: string; readonly config?: Readonly<Record<string, unknown>> }
    | { readonly type: 'custom'; readonly action: string; readonly params: Readonly<Record<string, unknown>> };

// ── VARIANT Internet ───────────────────────────────────────────

export interface VariantInternetSpec {
    readonly services: readonly VariantInternetService[];
    readonly dnsRecords: readonly VariantDNSRecord[];

    /** Git repositories available for cloning within the simulation. */
    readonly gitRepos?: readonly GitRepoSpec[];

    /** Social media profiles discoverable via OSINT. */
    readonly socialProfiles?: readonly SocialProfileSpec[];

    /** Forum/paste site content for recon scenarios. */
    readonly pasteSites?: readonly PasteSiteSpec[];

    /** WHOIS records for domain recon. */
    readonly whoisRecords?: readonly WhoisRecordSpec[];

    /** Certificate transparency logs. */
    readonly certRecords?: readonly CertTransparencyRecord[];
}

export interface VariantInternetService {
    readonly domain: string;
    readonly type:
        | 'search'
        | 'cloud-metadata'
        | 'package-repo'
        | 'c2'
        | 'website'
        | 'api'
        | 'git'
        | 'social-media'
        | 'paste-site'
        | 'forum'
        | 'whois'
        | 'cert-transparency'
        | 'dns-lookup'
        | (string & {});
    readonly image?: string;         // VM image to boot for this service
    readonly staticContent?: Readonly<Record<string, string>>; // path → response

    /** Search engine configuration (type='search' only). */
    readonly searchConfig?: SearchEngineConfig;

    /** API configuration (type='api' only). */
    readonly apiConfig?: ApiServiceConfig;
}

/**
 * Search engine configuration. Level designers define what results
 * appear for specific queries — enabling OSINT/recon scenarios.
 */
export interface SearchEngineConfig {
    /** Query → results mapping. Query keys are case-insensitive. */
    readonly results: Readonly<Record<string, readonly SearchResultSpec[]>>;
    /** Default results shown when query has no explicit mapping. */
    readonly defaultResults?: readonly SearchResultSpec[];
    /** Search engine branding. */
    readonly engineName?: string;
}

export interface SearchResultSpec {
    readonly title: string;
    readonly url: string;
    readonly snippet: string;
    /** If set, clicking this result leads to the specified domain's handler. */
    readonly domain?: string;
}

/**
 * API service configuration. Defines endpoints with method + path → response.
 */
export interface ApiServiceConfig {
    /** Route definitions. Key = "METHOD /path" (e.g., "GET /api/users"). */
    readonly routes: Readonly<Record<string, ApiRouteSpec>>;
    /** Whether the API requires authentication headers. */
    readonly requiresAuth?: boolean;
    /** Expected auth header value (if requiresAuth). */
    readonly authToken?: string;
}

export interface ApiRouteSpec {
    readonly status: number;
    readonly contentType: string;
    readonly body: string;
    /** Response headers. */
    readonly headers?: Readonly<Record<string, string>>;
}

/**
 * Git repository spec. Players can `git clone` these repos
 * within the simulation to explore source code, find secrets, etc.
 */
export interface GitRepoSpec {
    /** Repository domain (e.g., 'git.internal.corp'). */
    readonly domain: string;
    /** Repository path (e.g., '/org/repo.git'). */
    readonly path: string;
    /** Repository name for display. */
    readonly name: string;
    /** Repository description. */
    readonly description?: string;
    /** File tree. Key = file path relative to repo root. */
    readonly files: Readonly<Record<string, GitFileSpec>>;
    /** Commit log (most recent first). */
    readonly commits?: readonly GitCommitSpec[];
    /** Branches (first = default). */
    readonly branches?: readonly string[];
    /** Whether the repo is public (no auth needed). */
    readonly public?: boolean;
}

export interface GitFileSpec {
    readonly content: string;
    /** When this file was last modified (commit index, 0 = latest). */
    readonly lastModified?: number;
}

export interface GitCommitSpec {
    readonly hash: string;
    readonly author: string;
    readonly email: string;
    readonly message: string;
    readonly timestamp: number;
    /** Files changed in this commit. */
    readonly changedFiles?: readonly string[];
}

/**
 * Social media profile for OSINT recon scenarios.
 * Players discover these through search, DNS, or direct URL.
 */
export interface SocialProfileSpec {
    /** Platform domain (e.g., 'social.variant.net'). */
    readonly domain: string;
    /** Profile path (e.g., '/@admin'). */
    readonly profilePath: string;
    /** Display name. */
    readonly displayName: string;
    /** Username/handle. */
    readonly username: string;
    /** Bio text. */
    readonly bio?: string;
    /** Posts/messages from this profile. */
    readonly posts?: readonly SocialPostSpec[];
    /** Linked accounts (other profiles, emails, etc.). */
    readonly links?: readonly string[];
    /** Profile metadata (join date, location, etc.). */
    readonly metadata?: Readonly<Record<string, string>>;
}

export interface SocialPostSpec {
    readonly id: string;
    readonly content: string;
    readonly timestamp: number;
    /** Mentions of other users. */
    readonly mentions?: readonly string[];
    /** If true, this post contains exploitable information. */
    readonly sensitive?: boolean;
}

/**
 * Paste site content (think pastebin). Players find leaked
 * credentials, code snippets, config files here.
 */
export interface PasteSiteSpec {
    /** Paste site domain. */
    readonly domain: string;
    /** Individual pastes. */
    readonly pastes: readonly PasteSpec[];
}

export interface PasteSpec {
    readonly id: string;
    readonly title?: string;
    readonly author?: string;
    readonly content: string;
    readonly language?: string;
    readonly timestamp: number;
    /** If true, this paste appears in search results. */
    readonly indexed?: boolean;
    /** If set, paste expires after this tick. */
    readonly expiresTick?: number;
}

/**
 * WHOIS record for domain reconnaissance.
 */
export interface WhoisRecordSpec {
    readonly domain: string;
    readonly registrant: string;
    readonly registrantEmail?: string;
    readonly registrar: string;
    readonly createdDate: string;
    readonly updatedDate: string;
    readonly expiresDate: string;
    readonly nameservers: readonly string[];
    readonly status: string;
}

/**
 * Certificate transparency log entry.
 * Players use these for subdomain enumeration.
 */
export interface CertTransparencyRecord {
    readonly domain: string;
    readonly issuer: string;
    readonly validFrom: string;
    readonly validTo: string;
    readonly serialNumber: string;
    /** Subject Alternative Names — subdomain discovery goldmine. */
    readonly subjectAltNames: readonly string[];
}

export interface VariantDNSRecord {
    readonly domain: string;
    readonly ip: string;
    readonly type?: 'A' | 'AAAA' | 'CNAME' | 'MX' | 'TXT' | 'NS' | 'PTR' | (string & {});
    /** For MX records. */
    readonly priority?: number;
    /** For TXT/CNAME records. */
    readonly value?: string;
}

// ── Cloud Infrastructure ───────────────────────────────────────

/**
 * Simulated cloud infrastructure. Enables:
 *   - SSRF → metadata → IAM credential abuse
 *   - S3 bucket discovery/enumeration/exfiltration
 *   - IAM policy analysis and privilege escalation
 *   - Lambda function code review for secrets
 *   - Cloud API enumeration and abuse
 *
 * All data is pure simulation — no real cloud calls.
 * Served through VARIANT Internet API service handlers.
 */
export interface CloudInfraSpec {
    /** Cloud provider for this level. */
    readonly provider: 'aws' | 'gcp' | 'azure' | (string & {});

    /** AWS account ID or GCP project ID. */
    readonly accountId: string;

    /** Simulated S3/GCS/Azure Blob buckets. */
    readonly buckets?: readonly CloudBucketSpec[];

    /** IAM users and their policies. */
    readonly iamUsers?: readonly IAMUserSpec[];

    /** IAM roles that can be assumed. */
    readonly iamRoles?: readonly IAMRoleSpec[];

    /** IAM policies (referenceable by users/roles). */
    readonly iamPolicies?: readonly IAMPolicySpec[];

    /** Lambda/Cloud Functions. */
    readonly functions?: readonly CloudFunctionSpec[];

    /** Secrets Manager / Parameter Store secrets. */
    readonly secrets?: readonly CloudSecretSpec[];

    /** Cloud API endpoints the player can interact with. */
    readonly apiEndpoints?: readonly CloudApiEndpoint[];

    /** VPC/network configuration (for cloud network enumeration). */
    readonly vpcs?: readonly CloudVPCSpec[];

    /** EC2/VM instances visible via cloud API. */
    readonly instances?: readonly CloudInstanceSpec[];
}

export interface CloudBucketSpec {
    readonly name: string;
    /** Public access level. */
    readonly access: 'private' | 'public-read' | 'public-read-write' | 'authenticated-read' | (string & {});
    /** Objects in the bucket. Key = object key. */
    readonly objects: Readonly<Record<string, CloudObjectSpec>>;
    /** Bucket policy (JSON string). */
    readonly policy?: string;
    /** CORS configuration. */
    readonly corsEnabled?: boolean;
    /** Server-side encryption. */
    readonly encryption?: 'none' | 'AES256' | 'aws:kms';
    /** Versioning enabled. */
    readonly versioning?: boolean;
    /** Logging enabled (and where). */
    readonly loggingBucket?: string;
}

export interface CloudObjectSpec {
    readonly content: string;
    readonly contentType: string;
    readonly size?: number;
    readonly lastModified?: string;
    /** Object-level ACL override. */
    readonly acl?: 'private' | 'public-read' | (string & {});
    /** Metadata tags. */
    readonly metadata?: Readonly<Record<string, string>>;
}

export interface IAMUserSpec {
    readonly username: string;
    /** Access key ID (for API access). */
    readonly accessKeyId?: string;
    /** Secret access key. */
    readonly secretAccessKey?: string;
    /** Inline policy document (JSON). */
    readonly inlinePolicy?: string;
    /** Referenced managed policy IDs. */
    readonly attachedPolicies?: readonly string[];
    /** Groups this user belongs to. */
    readonly groups?: readonly string[];
    /** Console password (if console access enabled). */
    readonly consolePassword?: string;
    /** MFA enabled. */
    readonly mfaEnabled?: boolean;
    /** Last activity timestamp. */
    readonly lastActivity?: string;
}

export interface IAMRoleSpec {
    readonly roleName: string;
    /** Trust policy (who can assume this role). */
    readonly trustPolicy: string;
    /** Inline policy document. */
    readonly inlinePolicy?: string;
    /** Managed policy ARNs. */
    readonly attachedPolicies?: readonly string[];
    /** Instance profile (if attached to EC2). */
    readonly instanceProfile?: string;
}

export interface IAMPolicySpec {
    readonly policyId: string;
    readonly policyName: string;
    /** Policy document (JSON). */
    readonly document: string;
    /** Description. */
    readonly description?: string;
}

export interface CloudFunctionSpec {
    readonly name: string;
    readonly runtime: string;
    /** Function source code (the interesting part — may contain secrets). */
    readonly code: string;
    /** Environment variables (may contain secrets). */
    readonly env?: Readonly<Record<string, string>>;
    /** IAM role for execution. */
    readonly executionRole?: string;
    /** Triggers. */
    readonly triggers?: readonly string[];
    /** Timeout in seconds. */
    readonly timeout?: number;
    /** Memory in MB. */
    readonly memoryMB?: number;
}

export interface CloudSecretSpec {
    readonly name: string;
    readonly value: string;
    /** Description. */
    readonly description?: string;
    /** Key used for encryption. */
    readonly kmsKeyId?: string;
    /** Rotation enabled. */
    readonly rotation?: boolean;
    /** Last rotated timestamp. */
    readonly lastRotated?: string;
    /** Tags. */
    readonly tags?: Readonly<Record<string, string>>;
}

export interface CloudApiEndpoint {
    /** API path (e.g., 'sts', 'iam', 's3', 'lambda'). */
    readonly service: string;
    /** Region. */
    readonly region: string;
    /** Whether this endpoint requires valid IAM credentials. */
    readonly requiresAuth: boolean;
}

export interface CloudVPCSpec {
    readonly vpcId: string;
    readonly cidr: string;
    readonly subnets: readonly CloudSubnetSpec[];
    readonly securityGroups: readonly CloudSecurityGroupSpec[];
}

export interface CloudSubnetSpec {
    readonly subnetId: string;
    readonly cidr: string;
    readonly availabilityZone: string;
    readonly public: boolean;
}

export interface CloudSecurityGroupSpec {
    readonly groupId: string;
    readonly name: string;
    readonly ingressRules: readonly CloudSGRule[];
    readonly egressRules: readonly CloudSGRule[];
}

export interface CloudSGRule {
    readonly protocol: 'tcp' | 'udp' | 'icmp' | '-1' | (string & {});
    readonly fromPort: number;
    readonly toPort: number;
    readonly source: string;
    readonly description?: string;
}

export interface CloudInstanceSpec {
    readonly instanceId: string;
    readonly instanceType: string;
    readonly state: 'running' | 'stopped' | 'terminated' | (string & {});
    readonly privateIp: string;
    readonly publicIp?: string;
    readonly subnetId: string;
    readonly securityGroups: readonly string[];
    readonly iamRole?: string;
    readonly tags?: Readonly<Record<string, string>>;
}

// ── Active Directory / Kerberos ───────────────────────────────

export interface ActiveDirectorySpec {
    /** AD domain name (e.g., 'corp.local'). */
    readonly domain: string;
    /** Machine IDs for domain controllers. */
    readonly domainControllers: readonly string[];
    /** External/forest trust domain names. */
    readonly forestTrusts?: readonly string[];
    readonly organizationalUnits: readonly OUSpec[];
    readonly users: readonly ADUserSpec[];
    readonly groups: readonly ADGroupSpec[];
    readonly groupPolicies: readonly GPOSpec[];
    readonly kerberos: KerberosSpec;
    readonly serviceAccounts: readonly ServiceAccountSpec[];
}

export interface ADUserSpec {
    readonly samAccountName: string;
    readonly displayName: string;
    readonly email: string;
    readonly department: string;
    readonly title: string;
    /** Group distinguished names. */
    readonly memberOf: readonly string[];
    readonly passwordLastSet: string;
    readonly lastLogon: string;
    readonly enabled: boolean;
    /** SPN on user objects enables Kerberoasting paths. */
    readonly spn?: string;
    /** Mirrors adminCount=1 for protected/high-value principals. */
    readonly adminCount?: boolean;
}

export interface ADGroupSpec {
    readonly name: string;
    readonly dn: string;
    readonly members: readonly string[];
    /** Domain Admins / Enterprise Admins / other high-value groups. */
    readonly isPrivileged: boolean;
}

export interface KerberosSpec {
    /** KRBTGT hash material for Golden Ticket simulation. */
    readonly krbtgtHash: string;
    readonly tickets: readonly KerberosTicketSpec[];
    readonly servicePrincipalNames: readonly SPNSpec[];
    readonly delegationRules: readonly DelegationRuleSpec[];
}

export interface KerberosTicketSpec {
    readonly type: 'TGT' | 'TGS' | (string & {});
    readonly principal: string;
    readonly realm: string;
    readonly encType: string;
    readonly hash: string;
    readonly validFrom: string;
    readonly validTo: string;
}

export interface GPOSpec {
    readonly name: string;
    readonly guid: string;
    readonly linkedOUs: readonly string[];
    readonly settings: Readonly<Record<string, unknown>>;
    /** Known risky misconfig IDs (e.g., 'cpassword-in-sysvol'). */
    readonly vulnerabilities?: readonly string[];
}

export interface OUSpec {
    readonly name: string;
    readonly dn: string;
    /** Child object distinguished names. */
    readonly children: readonly string[];
}

export interface SPNSpec {
    readonly spn: string;
    readonly accountDn: string;
    readonly serviceClass: string;
    readonly host: string;
}

export interface DelegationRuleSpec {
    readonly type: 'unconstrained' | 'constrained' | 'resource-based' | (string & {});
    readonly sourceDn: string;
    readonly targetSpns: readonly string[];
    readonly protocolTransition?: boolean;
}

export interface ServiceAccountSpec {
    readonly samAccountName: string;
    readonly dn: string;
    readonly spns: readonly string[];
    readonly delegationTrusted?: boolean;
    readonly passwordLastSet?: string;
    readonly managedPassword?: boolean;
}

export interface KubernetesSpec {
    readonly clusterName: string;
    readonly apiServerMachine: string;
    readonly namespaces: readonly K8sNamespaceSpec[];
    readonly rbac: readonly K8sRBACRuleSpec[];
    readonly serviceAccounts: readonly K8sServiceAccountSpec[];
    readonly secrets: readonly K8sSecretSpec[];
    readonly networkPolicies?: readonly K8sNetworkPolicySpec[];
}

export interface K8sNamespaceSpec {
    readonly name: string;
    readonly pods: readonly K8sPodSpec[];
    readonly services: readonly K8sServiceSpec[];
    readonly configMaps?: readonly K8sConfigMapSpec[];
}

export interface K8sPodSpec {
    readonly name: string;
    readonly namespace: string;
    readonly image: string;
    readonly machineId?: string;
    readonly serviceAccount?: string;
    readonly securityContext?: {
        readonly privileged?: boolean;
        readonly runAsRoot?: boolean;
        readonly hostNetwork?: boolean;
        readonly hostPID?: boolean;
    };
    readonly volumes?: readonly K8sVolumeSpec[];
    readonly env?: Readonly<Record<string, string>>;
}

export interface K8sRBACRuleSpec {
    readonly subject: string;
    readonly role: string;
    readonly namespace?: string;
    readonly resources: readonly string[];
    readonly verbs: readonly ('get' | 'list' | 'create' | 'delete' | 'exec' | '*' | (string & {}))[];
}

export interface K8sServiceAccountSpec {
    readonly name: string;
    readonly namespace: string;
    readonly token?: string;
}

export interface K8sSecretSpec {
    readonly name: string;
    readonly namespace: string;
    readonly type: 'Opaque' | 'kubernetes.io/dockerconfigjson' | 'kubernetes.io/tls' | (string & {});
    readonly data: Readonly<Record<string, string>>;
}

export interface K8sNetworkPolicySpec {
    readonly name: string;
    readonly namespace: string;
    readonly labels?: Readonly<Record<string, string>>;
}

export interface K8sServiceSpec {
    readonly name: string;
    readonly namespace: string;
    readonly type?: string;
    readonly selector?: Readonly<Record<string, string>>;
    readonly ports?: readonly number[];
}

export interface K8sConfigMapSpec {
    readonly name: string;
    readonly namespace: string;
    readonly data: Readonly<Record<string, string>>;
}

export interface K8sVolumeSpec {
    readonly name: string;
    readonly mountPath: string;
    readonly type?: string;
}

export interface PipelineSpec {
    readonly tool: 'jenkins' | 'gitlab-ci' | 'github-actions' | (string & {});
    readonly serverMachine: string;
    readonly pipelines: readonly PipelineDefinitionSpec[];
    readonly secrets: Readonly<Record<string, string>>;
    readonly runners: readonly PipelineRunnerSpec[];
}

export interface PipelineDefinitionSpec {
    readonly name: string;
    readonly trigger: 'push' | 'pr' | 'schedule' | (string & {});
    readonly stages: readonly PipelineStageSpec[];
    readonly vulnerabilities?: readonly string[];
}

export interface PipelineStageSpec {
    readonly name: string;
    readonly commands: readonly string[];
    readonly env?: Readonly<Record<string, string>>;
    readonly artifacts?: readonly string[];
}

export interface PipelineRunnerSpec {
    readonly name: string;
    readonly machineId: string;
}

// ── Scoring ────────────────────────────────────────────────────

export interface ScoringConfig {
    readonly maxScore: number;
    readonly timeBonus: boolean;
    readonly stealthBonus: boolean;
    readonly hintPenalty: number;    // points deducted per hint used
    readonly tiers: readonly ScoringTier[];

    /**
     * Custom scoring rules. Third-party packages can define
     * their own scoring mechanics via module ID.
     */
    readonly customRules?: readonly CustomScoringRule[];
}

export interface ScoringTier {
    readonly name: string;           // e.g., 'MASTERY', 'PROFICIENT'
    readonly minScore: number;
    readonly color: string;
}

export interface CustomScoringRule {
    /** Module ID that implements evaluation. */
    readonly evaluator: string;
    /** Points awarded when the rule triggers. */
    readonly points: number;
    /** Parameters passed to the evaluator. */
    readonly params: Readonly<Record<string, unknown>>;
}

// ── Start Config (UI) ──────────────────────────────────────────

/**
 * How the UI starts. String = preset name. Object = custom.
 * Resolved by the lens compositor at boot time.
 */
export type StartConfigSpec =
    | string
    | {
        readonly lenses: readonly StartLensSpec[];
        readonly layout?: unknown;  // LayoutNode from ui/lens/types
    };

export interface StartLensSpec {
    readonly type: string;
    readonly targetMachine?: string;
    readonly config?: Readonly<Record<string, unknown>>;
    readonly title?: string;
}

// ── Mail System ────────────────────────────────────────────────

/**
 * Mail system configuration. Enables social engineering scenarios,
 * phishing detection training, and email-based attack/defense.
 */
export interface MailSystemSpec {
    /** Mail accounts. Key = email address. */
    readonly accounts: Readonly<Record<string, MailAccountSpec>>;

    /** Pre-loaded emails (inbox contents at level start). */
    readonly inbox?: readonly MailMessageSpec[];

    /** Email templates that dynamics can reference. */
    readonly templates?: Readonly<Record<string, MailTemplateSpec>>;
}

export interface MailAccountSpec {
    /** Display name. */
    readonly displayName: string;
    /** Machine this account is on. */
    readonly machine: string;
    /** Role for AI-generated NPC replies. */
    readonly role?: string;
}

export interface MailMessageSpec {
    /** Unique message ID. */
    readonly id: string;
    readonly from: string;
    readonly to: string;
    readonly subject: string;
    /** Message body (plain text or HTML). */
    readonly body: string;
    /** Whether the body is HTML. Default: false. */
    readonly html?: boolean;
    /** Delivery tick (0 = already in inbox at start). */
    readonly deliverAtTick?: number;
    /** Attachments. */
    readonly attachments?: readonly MailAttachmentSpec[];
    /** Is this email part of a phishing/social engineering attack? */
    readonly malicious?: boolean;
    /** If malicious, what happens if the player interacts (for scoring). */
    readonly maliciousAction?: string;
    /** Headers for forensics training. */
    readonly headers?: Readonly<Record<string, string>>;
}

export interface MailAttachmentSpec {
    readonly filename: string;
    readonly content: string;
    /** MIME type. */
    readonly mimeType: string;
    /** Is this attachment malicious? */
    readonly malicious?: boolean;
}

export interface MailTemplateSpec {
    readonly from: string;
    readonly subject: string;
    readonly body: string;
    readonly html?: boolean;
    readonly attachments?: readonly MailAttachmentSpec[];
    readonly malicious?: boolean;
    readonly maliciousAction?: string;
    readonly headers?: Readonly<Record<string, string>>;
}

// ── Resource Estimation ────────────────────────────────────────

/**
 * Resource estimation for the Chromebook constraint.
 * The engine calculates this from the WorldSpec at boot time.
 * If the player's device can't handle it, they get a warning.
 */
export interface ResourceEstimation {
    /** Estimated total RAM usage in MB. */
    readonly estimatedRAMMB: number;
    /** Estimated boot time in seconds. */
    readonly estimatedBootSeconds: number;
    /** Minimum tier: 'chromebook' | 'laptop' | 'workstation'. */
    readonly minimumTier: 'chromebook' | 'laptop' | 'workstation';
}
