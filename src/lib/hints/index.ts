/**
 * VARIANT — Hint System barrel export
 */
export type {
    HintDefinition,
    HintTier,
    HintContent,
    HintTrigger,
    TickTrigger,
    AttemptsTrigger,
    EventTrigger,
    ObjectiveTrigger,
    CompoundTrigger,
    CustomTrigger,
    HintState,
    HintEngine,
} from './types';

export { createHintEngine } from './hint-engine';
