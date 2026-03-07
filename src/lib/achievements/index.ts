/**
 * VARIANT — Achievement System barrel export
 */
export type {
    AchievementDefinition,
    AchievementCategory,
    AchievementTier,
    AchievementCondition,
    CompleteLevelCondition,
    ScoreCondition,
    StealthCondition,
    SpeedCondition,
    TechniqueCondition,
    CountCondition,
    StreakCondition,
    CompoundCondition,
    CustomCondition,
    AchievementProgress,
    SessionResult,
    AchievementEngine,
} from './types';

export { createAchievementEngine } from './achievement-engine';
