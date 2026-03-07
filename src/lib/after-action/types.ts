/**
 * VARIANT — After-Action Report Types
 *
 * Post-game breakdown: timeline, score analysis, missed
 * opportunities, optimal path comparison, improvement tips.
 *
 * The AAR is what transforms a game session into a learning
 * experience. It's the difference between "I failed" and
 * "I understand why I failed and what to do next time."
 *
 * DESIGN:
 *   - Generated from TelemetryReport + ReplayRecording
 *   - Structured sections for UI rendering
 *   - Each section is independently renderable
 *   - Includes both quantitative (scores, times) and
 *     qualitative (tips, comparisons) content
 *
 * EXTENSIBILITY:
 *   - Custom report sections
 *   - Custom analyzers
 *   - Community-contributed tips
 *   - AI-generated feedback (future)
 *
 * SWAPPABILITY: Pure types. No implementation here.
 */

// ── After-Action Report ─────────────────────────────────────

export interface AfterActionReport {
    /** Session metadata. */
    readonly session: SessionSummary;

    /** Score breakdown. */
    readonly scoring: ScoreBreakdown;

    /** Timeline of key events. */
    readonly timeline: readonly TimelineEntry[];

    /** What went well. */
    readonly strengths: readonly Observation[];

    /** What could be improved. */
    readonly improvements: readonly Observation[];

    /** Specific tips for improvement. */
    readonly tips: readonly Tip[];

    /** Missed opportunities the player didn't find. */
    readonly missed: readonly MissedOpportunity[];

    /** Skill assessments based on this session. */
    readonly skills: readonly SkillAssessment[];

    /** Overall grade. */
    readonly grade: Grade;
}

// ── Session Summary ─────────────────────────────────────────

export interface SessionSummary {
    readonly levelId: string;
    readonly levelTitle: string;
    readonly difficulty: string;
    readonly durationSeconds: number;
    readonly totalTicks: number;
    readonly phase: string;
    readonly completed: boolean;
}

// ── Score Breakdown ─────────────────────────────────────────

export interface ScoreBreakdown {
    readonly maxScore: number;
    readonly baseScore: number;
    readonly timeBonus: number;
    readonly stealthBonus: number;
    readonly hintPenalty: number;
    readonly objectiveBonus: number;
    readonly finalScore: number;
    readonly percentile: number; // 0-100, compared to all players
}

// ── Timeline ────────────────────────────────────────────────

export interface TimelineEntry {
    readonly tick: number;
    readonly wallTimeSeconds: number;
    readonly type: TimelineEntryType;
    readonly title: string;
    readonly description: string;
    readonly significance: 'minor' | 'moderate' | 'major' | 'critical';
}

export type TimelineEntryType =
    | 'objective-complete'
    | 'credential-found'
    | 'machine-accessed'
    | 'technique-used'
    | 'hint-used'
    | 'alert-triggered'
    | 'stuck-period'
    | 'custom';

// ── Observations ────────────────────────────────────────────

export interface Observation {
    readonly category: string;
    readonly title: string;
    readonly description: string;
    readonly evidence: string;
}

// ── Tips ─────────────────────────────────────────────────────

export interface Tip {
    readonly id: string;
    readonly category: string;
    readonly title: string;
    readonly description: string;
    readonly priority: 'low' | 'medium' | 'high';
    /** Related skill area. */
    readonly skill: string;
    /** Suggested next level to practice this skill. */
    readonly suggestedLevel: string | null;
}

// ── Missed Opportunities ────────────────────────────────────

export interface MissedOpportunity {
    readonly id: string;
    readonly title: string;
    readonly description: string;
    readonly where: string;
    readonly technique: string;
    readonly difficulty: string;
}

// ── Skill Assessment ────────────────────────────────────────

export interface SkillAssessment {
    readonly skill: string;
    readonly displayName: string;
    readonly level: SkillLevel;
    readonly score: number;    // 0-100
    readonly change: number;   // Delta from previous assessment
    readonly evidence: string;
}

export type SkillLevel = 'novice' | 'beginner' | 'intermediate' | 'advanced' | 'expert';

// ── Grade ───────────────────────────────────────────────────

export interface Grade {
    readonly letter: 'S' | 'A' | 'B' | 'C' | 'D' | 'F';
    readonly label: string;
    readonly description: string;
}

// ── Report Generator ────────────────────────────────────────

export interface AfterActionGenerator {
    /**
     * Generate an after-action report from telemetry data.
     */
    generate(config: AfterActionConfig): AfterActionReport;
}

export interface AfterActionConfig {
    readonly levelId: string;
    readonly levelTitle: string;
    readonly difficulty: string;
    readonly maxScore: number;
    readonly finalScore: number;
    readonly finalPhase: string;
    readonly totalTicks: number;
    readonly durationSeconds: number;
    readonly hintsUsed: number;
    readonly noiseLevel: number;
    readonly objectivesCompleted: readonly string[];
    readonly totalObjectives: number;
    readonly techniquesUsed: readonly string[];
    readonly commandCount: number;
    readonly machinesAccessed: readonly string[];
    readonly stuckPeriods: readonly { fromTick: number; toTick: number; durationTicks: number; context: string }[];
}
