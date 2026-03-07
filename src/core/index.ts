/**
 * VARIANT — Core barrel export
 *
 * Public API for the core engine.
 * Import from '@core' — never from individual files.
 */

// Events
export type {
    EngineEvent,
    EventType,
    EventBus,
    EventHandler,
    EventByType,
    Unsubscribe,
    FsReadEvent,
    FsWriteEvent,
    FsExecEvent,
    NetRequestEvent,
    NetResponseEvent,
    NetDnsEvent,
    NetConnectEvent,
    AuthLoginEvent,
    AuthEscalateEvent,
    AuthCredentialFoundEvent,
    ObjectiveProgressEvent,
    ObjectiveCompleteEvent,
    DefenseBreachEvent,
    DefenseAlertEvent,
    SimTickEvent,
    SimAlertEvent,
    SimNoiseEvent,
    SimGameOverEvent,
    LensOpenEvent,
    LensCloseEvent,
    CustomEvent,
} from './events';

export { createEventBus } from './event-bus';

// VM
export type {
    VMBackend,
    VMBootConfig,
    VMInstance,
    VMState,
    TerminalIO,
    FilesystemOverlay,
    OverlayFile,
    VMSnapshot,
} from './vm/types';

export { VMBootError, VMOverlayError, VMSnapshotError } from './vm/types';
export { createV86Backend } from './vm/v86-backend';

// Fabric
export type {
    NetworkFabric,
    NetworkTopology,
    NetworkSegment,
    NetworkRoute,
    FirewallRule,
    DNSRecord,
    DNSResponse,
    NICHandle,
    TrafficEntry,
    FabricStats,
    ExternalServiceHandler,
    ExternalRequest,
    ExternalResponse,
    PackageMirrorConfig,
    PackageEcosystem,
} from './fabric/types';

export { FabricRoutingError, FabricDNSError } from './fabric/types';
export { createNetworkFabric } from './fabric/fabric';
export {
    parseFrame,
    parseEthernetHeader,
    parseIPv4Header,
    parseTCPHeader,
    parseUDPHeader,
    parseARP,
    parseDNSQuery,
    buildUDPFrame,
    buildARPReply,
    buildDNSResponse,
    buildDNSNXDomain,
    isInSubnet,
    ipToUint32,
    uint32ToIP,
} from './fabric/frames';

// World
export type {
    WorldSpec,
    WorldMeta,
    MachineSpec,
    MachineRole,
    UserSpec,
    InterfaceSpec,
    CodebaseConfig,
    AttackScriptConfig,
    FileSpec,
    ServiceConfig,
    ProcessSpec,
    MachineFirewallRule,
    CronEntry,
    NetworkSpec,
    SegmentSpec,
    EdgeSpec,
    CredentialEntry,
    CredentialType,
    CredentialLocation,
    CredentialTarget,
    ObjectiveSpec,
    ObjectiveType,
    GameOverSpec,
    GameOverCondition,
    CustomGameOverCondition,
    ScoringConfig,
    ScoringTier,
    CustomScoringRule,
    Difficulty,
    GameMode,
    AuthorInfo,
    ObjectiveDetails,
    GenericDetails,
    CustomDetails,
    DynamicAction,
    DynamicsSpec,
    TimedEvent,
    ReactiveEvent,
    StartConfigSpec,
    ResourceEstimation,
    VariantInternetSpec,
    VariantInternetService,
    VariantDNSRecord,
    SearchEngineConfig,
    SearchResultSpec,
    ApiServiceConfig,
    ApiRouteSpec,
    GitRepoSpec,
    GitFileSpec,
    GitCommitSpec,
    SocialProfileSpec,
    SocialPostSpec,
    PasteSiteSpec,
    PasteSpec,
    WhoisRecordSpec,
    CertTransparencyRecord,
    MailSystemSpec,
    MailAccountSpec,
    MailMessageSpec,
    MailAttachmentSpec,
    MailTemplateSpec,
    CloudInfraSpec,
    CloudBucketSpec,
    CloudObjectSpec,
    IAMUserSpec,
    IAMRoleSpec,
    IAMPolicySpec,
    CloudFunctionSpec,
    CloudSecretSpec,
    CloudApiEndpoint,
    CloudVPCSpec,
    CloudSubnetSpec,
    CloudSecurityGroupSpec,
    CloudSGRule,
    CloudInstanceSpec,
    ActiveDirectorySpec,
    ADUserSpec,
    ADGroupSpec,
    KerberosSpec,
    KerberosTicketSpec,
    GPOSpec,
    OUSpec,
    SPNSpec,
    DelegationRuleSpec,
    ServiceAccountSpec,
    KubernetesSpec,
    K8sConfigMapSpec,
    K8sNamespaceSpec,
    K8sNetworkPolicySpec,
    K8sPodSpec,
    K8sRBACRuleSpec,
    K8sSecretSpec,
    K8sServiceAccountSpec,
    K8sServiceSpec,
    K8sVolumeSpec,
    PipelineDefinitionSpec,
    PipelineRunnerSpec,
    PipelineSpec,
    PipelineStageSpec,
} from './world/types';

export { validateWorldSpec } from './world/validator';
export type { ValidationResult, ValidationError, ValidationWarning, ErrorCode } from './world/validator';

// World composition
export type { WorldSpecPatch, MachineSpecPatch } from './world/compose';
export { composeWorldSpec } from './world/compose';

// World migration
export type { MigrationStep, MigrationRegistry } from './world/migrate';
export { createMigrationRegistry } from './world/migrate';

// Modules
export type {
    Module,
    ModuleType,
    Capability,
    SimulationContext,
    ModuleRegistry,
    ModuleMetadata,
    ServiceLocator,
} from './modules';

export { createModuleRegistry, createServiceLocator, ModuleLoadError } from './modules';

// Engine
export type {
    Simulation,
    SimulationState,
    SimulationPhase,
    ObjectiveStatus,
    CreateSimulationOptions,
} from './engine';

export { createSimulation, _resetSimIdCounter } from './engine';

// Middleware
export type {
    EventMiddleware,
    NamedMiddleware,
    MiddlewareStack,
} from './middleware';

export { createMiddlewareStack, createMiddlewareEventBus, createRateLimitMiddleware } from './middleware';

// Pipeline
export type {
    Pipeline,
    PipelineStage,
    PipelineResult,
    PipelineBuilder,
} from './pipeline';

export { createPipeline } from './pipeline';

// Plugin
export type {
    Plugin,
    PluginContext,
    PluginRegistry,
} from './plugin';

export { createPluginRegistry, PluginLoadError } from './plugin';

// Event query
export type { EventQuery } from './event-query';
export { createEventQuery } from './event-query';

// Snapshot
export type {
    SimulationSnapshot,
    ObjectiveSnapshotEntry,
    SerializedEvent,
    SnapshotSource,
    SnapshotDiff,
    ObjectiveChange,
} from './snapshot';

export { createSnapshot, isValidSnapshot, diffSnapshots } from './snapshot';

// Utilities
export { deepFreeze } from './freeze';
