/**
 * VARIANT — Telemetry/Analytics Engine Types
 *
 * Tracks player behavior during a simulation session.
 * What commands were tried, where did they get stuck,
 * what techniques were used, where was time spent.
 *
 * This data drives everything: difficulty tuning, hint triggers,
 * after-action reports, achievement evaluation, and content
 * quality scoring.
 *
 * PRIVACY: All telemetry is local-first. Nothing is sent
 * to any server without explicit player consent. The engine
 * produces a TelemetryReport that the player owns.
 *
 * DESIGN:
 *   - Passive collection — no player action required
 *   - Events are categorized and bucketed by tick ranges
 *   - Time-weighted metrics (where was most time spent?)
 *   - Command frequency analysis
 *   - Stuck detection (no progress for N ticks)
 *
 * EXTENSIBILITY:
 *   - Custom metric collectors
 *   - Custom analyzers
 *   - Export formats
 *
 * SWAPPABILITY: Pure types. No implementation here.
 */

// ── Telemetry Metrics ───────────────────────────────────────

export interface TelemetryMetrics {
    /** Total simulation ticks elapsed. */
    readonly totalTicks: number;

    /** Total wall-clock time in milliseconds. */
    readonly totalWallTimeMs: number;

    /** Total commands executed. */
    readonly totalCommands: number;

    /** Total unique commands tried. */
    readonly uniqueCommands: number;

    /** Commands per minute (rate). */
    readonly commandsPerMinute: number;

    /** Machines accessed (logged into). */
    readonly machinesAccessed: readonly string[];

    /** Files read. */
    readonly filesRead: readonly string[];

    /** Files modified. */
    readonly filesModified: readonly string[];

    /** Network connections made. */
    readonly connectionsAttempted: number;

    /** Successful logins. */
    readonly successfulLogins: number;

    /** Failed logins. */
    readonly failedLogins: number;

    /** Techniques/vuln classes detected. */
    readonly techniquesUsed: readonly string[];

    /** Noise level at end of session. */
    readonly finalNoiseLevel: number;

    /** Hints used. */
    readonly hintsUsed: number;

    /** Objectives completed. */
    readonly objectivesCompleted: readonly string[];

    /** Final score. */
    readonly finalScore: number;

    /** Final phase. */
    readonly finalPhase: string;
}

// ── Command Tracking ────────────────────────────────────────

export interface CommandEntry {
    readonly tick: number;
    readonly wallTimeMs: number;
    readonly machine: string;
    readonly user: string;
    readonly command: string;
    readonly cwd: string;
}

// ── Time Buckets ────────────────────────────────────────────

export interface TimeBucket {
    readonly fromTick: number;
    readonly toTick: number;
    readonly commands: number;
    readonly events: number;
    readonly objectivesCompleted: number;
    /** Activity level: 0 = idle, 1 = active, 2 = burst */
    readonly activityLevel: number;
}

// ── Stuck Detection ─────────────────────────────────────────

export interface StuckPeriod {
    readonly fromTick: number;
    readonly toTick: number;
    readonly durationTicks: number;
    readonly lastCommand: string;
    readonly machine: string;
    /** What the player was likely stuck on. */
    readonly context: string;
}

// ── Telemetry Collector ─────────────────────────────────────

export interface TelemetryCollector {
    /** Record a command execution. */
    recordCommand(entry: CommandEntry): void;

    /** Record an event (for event counting). */
    recordEvent(eventType: string, tick: number): void;

    /** Record an objective completion. */
    recordObjectiveComplete(objectiveId: string, tick: number): void;

    /** Record a login attempt. */
    recordLogin(machine: string, user: string, success: boolean, tick: number): void;

    /** Record a file access. */
    recordFileAccess(path: string, mode: 'read' | 'write', tick: number): void;

    /** Record a network connection. */
    recordConnection(target: string, port: number, tick: number): void;

    /** Record technique detection. */
    recordTechnique(technique: string, tick: number): void;

    /** Record hint usage. */
    recordHint(hintId: string, tick: number): void;

    /** Set final simulation state. */
    setFinalState(score: number, phase: string, noiseLevel: number): void;

    /** Generate the telemetry report. */
    generateReport(totalTicks: number, totalWallTimeMs: number): TelemetryReport;

    /** Reset all collected data. */
    reset(): void;
}

// ── Telemetry Report ────────────────────────────────────────

export interface TelemetryReport {
    /** Summary metrics. */
    readonly metrics: TelemetryMetrics;

    /** Full command history. */
    readonly commands: readonly CommandEntry[];

    /** Time-bucketed activity. */
    readonly timeBuckets: readonly TimeBucket[];

    /** Periods where the player appeared stuck. */
    readonly stuckPeriods: readonly StuckPeriod[];

    /** Command frequency (command → count). */
    readonly commandFrequency: Readonly<Record<string, number>>;

    /** Event frequency (eventType → count). */
    readonly eventFrequency: Readonly<Record<string, number>>;

    /** Timeline of objective completions. */
    readonly objectiveTimeline: readonly { readonly objectiveId: string; readonly tick: number }[];
}
