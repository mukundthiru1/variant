/**
 * VARIANT — Vuln barrel export.
 */
export type {
    VulnCategory,
    VulnDifficulty,
    VulnDefinition,
    VulnPatch,
    VulnClue,
    VulnDetection,
    DetectionTrigger,
    FileReadTrigger,
    FileWriteTrigger,
    CommandTrigger,
    HTTPTrigger,
    CustomTrigger,
    BaseCodebase,
    InjectionResult,
    InjectionError,
} from './types';
export { injectVulnerabilities } from './types';
