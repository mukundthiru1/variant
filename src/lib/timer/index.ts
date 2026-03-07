/**
 * VARIANT — Timer System barrel export
 */
export type {
    TimerType,
    TimerState,
    TimerDefinition,
    TimerExpiry,
    GameOverExpiry,
    EventExpiry,
    ObjectiveExpiry,
    CustomExpiry,
    TimerInstance,
    TimerClock,
    TimerEvent,
    TimerEventKind,
} from './types';

export { createTimerClock } from './timer-clock';
