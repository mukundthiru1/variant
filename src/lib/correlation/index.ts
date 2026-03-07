export type {
    CorrelationRule,
    CorrelationStrategy,
    SequenceStrategy,
    ThresholdStrategy,
    UniqueStrategy,
    SequenceStep,
    StepCondition,
    CorrelationAction,
    CorrelationEvent,
    CorrelationMatch,
    CorrelationEngine,
} from './types';

export { createCorrelationEngine } from './correlation-engine';
