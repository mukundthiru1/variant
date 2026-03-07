/**
 * VARIANT — Modules barrel export
 *
 * All modules are exported from here.
 * The engine registers these at build time.
 */

export { createObjectiveDetector } from './objective-detector';
export { createSessionModule } from './session-module';
export { createFilesystemMonitor, parseMarker, generateFSWatcherScript } from './fs-monitor';
export { createNetworkMonitor } from './network-monitor';
export { createGameOverDetector } from './gameover-detector';
export { createScoringEngine } from './scoring-engine';
export { createVariantInternet } from './variant-internet';
export { createCloudApiModule } from './cloud-api';
export { createCredentialFlowModule } from './credential-flow';
export { createADModule } from './ad-module';
export { createPipelineModule } from './pipeline-module';
export { createK8sApiModule } from './k8s-api-module';
export { createMailModule } from './mail-module';

export {
    createDynamicsEngine,
    createDynamicActionHandlerRegistry,
} from './dynamics-engine';
export type {
    DynamicActionHandler,
    DynamicActionHandlerRegistry,
} from './dynamics-engine';

export {
    createObjectiveEvaluatorRegistry,
    registerBuiltinEvaluators,
} from './objective-evaluators';
export type {
    ObjectiveEvaluator,
    ObjectiveEvaluatorContext,
    ObjectiveEvaluatorRegistry,
    ObjectiveEvaluationResult,
} from './objective-evaluators';

export { createSIEMModule } from './siem-module';
export type { SIEMModuleConfig } from './siem-module';

export { createCorrelationModule } from './correlation-module';
export type { CorrelationModuleConfig } from './correlation-module';

export { createStateMachineModule } from './state-machine-module';
export type { StateMachineModuleConfig, TransitionTrigger } from './state-machine-module';

export { createNPCEngine } from './npc-engine';
export type { NPCEngineConfig } from './npc-engine';

export { createTrafficGenerator } from './traffic-generator';
export { createPersistenceModule } from './persistence-module';
export {
    createFirewallEngine,
    evaluateRule,
    evaluateChain,
    parseIptablesOutput,
    parseIptablesCommand,
} from './firewall-engine';

export { createProcessMonitor } from './process-monitor';
export type { ProcessMonitorConfig } from './process-monitor';
export { createForensicsModule } from './forensics-module';
export { createLateralMovementModule } from './lateral-movement';

export type {
    TrafficGeneratorConfig,
    TrafficPattern,
    TrafficPatternType,
} from './traffic-generator';
export { createPrivescModule } from './privesc-module';
export { createThreatIntelModule } from './threat-intel-module';
export type {
    MitreTechnique,
    KillChainPhase,
    KillChainPhaseName,
    CVEEntry,
    TechniqueDetection,
    ThreatIntelService,
} from './threat-intel-module';

export { createExfilModule } from './exfil-module';
export type { ExfilModule, ExfilStats, ExfilIndicator, DNSQuery, HTTPRequest } from './exfil-module';

export type {
    SessionProtocol,
    SessionStatus,
    SessionFilter,
    MachineAuthState,
    SessionStore,
    SessionModuleConfig,
} from './session-module';

export type {
    ScoreBreakdown,
    ScoringEngineConfig,
} from './scoring-engine';

export type {
    CredentialType,
    CredentialSource,
    AuthTarget,
    DiscoveredCredential,
    CredentialChainLink,
    CredentialFilter,
    AuthResult,
    CredentialStore,
} from './credential-flow';

export type {
    PacketInfo,
    FirewallDecision,
    RuleHitCounter,
} from './firewall-engine';

export type {
    GameOverConditionHandler,
    GameOverConditionHandlerRegistry,
} from './gameover-detector';

export type {
    TimelineEntry,
    TimelineFilter,
    EvidenceFile,
    EvidenceBundle,
    IncidentType,
    IncidentReport,
} from './forensics-module';

export type {
    MachineAccess,
    MovementResult,
    PivotChainEntry,
    LateralMovementTechnique,
} from './lateral-movement';

export type {
    PersistenceTechnique,
    PersistenceIndicator,
} from './persistence-module';

export type {
    SuidBinary,
    SudoersEntry,
    EscalationPath,
} from './privesc-module';

export type { LensCommand } from './terminal';

// Terminal lens is not a standard module — it's a UI component.
// It's imported directly by the App shell.
