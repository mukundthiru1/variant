/**
 * VARIANT — Notification System Types
 *
 * In-simulation notification engine. Drives narrative through
 * contextual alerts: "New email received", "SSH connection from
 * unknown IP", "File modified: /etc/passwd".
 *
 * Notifications are the heartbeat of the simulation experience.
 * They tell the player what's happening, create urgency, and
 * guide attention without breaking immersion.
 *
 * DESIGN:
 *   - Notifications are triggered by events, timers, or conditions
 *   - They have priority, category, and lifetime
 *   - The UI renders them as toasts, badge counts, or alerts
 *   - History is preserved for review
 *   - Notifications can be interactive (click to open a lens)
 *
 * EXTENSIBILITY:
 *   - Custom notification types
 *   - Custom renderers
 *   - Notification pack plugins
 *   - Sound/visual themes
 *
 * SWAPPABILITY: Pure types. No implementation here.
 */

// ── Notification ────────────────────────────────────────────

export interface Notification {
    /** Unique notification ID. */
    readonly id: string;

    /** When this notification was created (sim tick). */
    readonly tick: number;

    /** Wall clock timestamp. */
    readonly timestamp: number;

    /** Notification category. */
    readonly category: NotificationCategory;

    /** Priority — higher priority notifications interrupt more. */
    readonly priority: NotificationPriority;

    /** Short title (shown in toast header). */
    readonly title: string;

    /** Body text (shown in expanded view). */
    readonly body: string;

    /** Icon identifier. */
    readonly icon: string;

    /** Which machine this notification is about (null = global). */
    readonly machine: string | null;

    /** Source module/service that generated this notification. */
    readonly source: string;

    /**
     * Action to perform when the notification is clicked.
     * null = no action (informational only).
     */
    readonly action: NotificationAction | null;

    /** Auto-dismiss after this many ticks. 0 = manual dismiss only. */
    readonly lifetimeTicks: number;

    /** Has the user acknowledged this notification? */
    readonly acknowledged: boolean;

    /** Grouping key — notifications with the same group collapse. */
    readonly group: string | null;
}

export type NotificationCategory =
    | 'security'        // Security events (login, breach, scan)
    | 'system'          // System events (service start/stop, error)
    | 'network'         // Network events (connection, DNS, traffic)
    | 'email'           // Email received
    | 'file'            // File system changes
    | 'objective'       // Objective progress
    | 'hint'            // Hint available
    | 'achievement'     // Achievement unlocked
    | 'npc'             // NPC activity
    | 'narrative'       // Story/narrative beats
    | (string & {});    // Open for extensions

export type NotificationPriority =
    | 'low'         // Informational, auto-dismiss quickly
    | 'medium'      // Notable, stays longer
    | 'high'        // Important, requires attention
    | 'critical';   // Urgent, interrupts, stays until acknowledged

// ── Notification Actions ────────────────────────────────────

export type NotificationAction =
    | OpenLensAction
    | NavigateAction
    | RunCommandAction
    | CustomAction;

export interface OpenLensAction {
    readonly kind: 'open-lens';
    /** Lens type to open (e.g., 'terminal', 'log-viewer'). */
    readonly lensType: string;
    /** Target machine (if applicable). */
    readonly machine: string | null;
    /** Lens config overrides. */
    readonly config: Readonly<Record<string, unknown>>;
}

export interface NavigateAction {
    readonly kind: 'navigate';
    /** Where to navigate within the current lens. */
    readonly target: string;
}

export interface RunCommandAction {
    readonly kind: 'run-command';
    /** Shell command to execute on click. */
    readonly command: string;
    readonly machine: string;
}

export interface CustomAction {
    readonly kind: 'custom';
    readonly type: string;
    readonly payload: unknown;
}

// ── Notification Rules ──────────────────────────────────────

/**
 * A rule that generates notifications from events.
 * Registered by modules to turn engine events into user-visible notifications.
 */
export interface NotificationRule {
    /** Rule ID. */
    readonly id: string;

    /** Event type(s) that trigger this rule. */
    readonly eventTypes: readonly string[];

    /** Whether to use prefix matching on event types. */
    readonly prefixMatch: boolean;

    /** Generate a notification from an event. Return null to suppress. */
    readonly generate: (event: unknown, tick: number) => NotificationTemplate | null;
}

export interface NotificationTemplate {
    readonly category: NotificationCategory;
    readonly priority: NotificationPriority;
    readonly title: string;
    readonly body: string;
    readonly icon: string;
    readonly machine: string | null;
    readonly action: NotificationAction | null;
    readonly lifetimeTicks: number;
    readonly group: string | null;
}

// ── Notification Engine ─────────────────────────────────────

export interface NotificationEngine {
    /** Register a notification rule. */
    addRule(rule: NotificationRule): void;

    /** Remove a rule by ID. */
    removeRule(ruleId: string): void;

    /** Push a notification directly (bypassing rules). */
    push(template: NotificationTemplate, tick: number): Notification;

    /** Process an event through all rules. Returns generated notifications. */
    processEvent(event: unknown, eventType: string, tick: number): readonly Notification[];

    /** Acknowledge a notification by ID. */
    acknowledge(notificationId: string): boolean;

    /** Acknowledge all notifications. */
    acknowledgeAll(): void;

    /** Dismiss a notification by ID (remove from active list). */
    dismiss(notificationId: string): boolean;

    /** Get all active (non-dismissed) notifications. */
    getActive(): readonly Notification[];

    /** Get active notifications filtered by category. */
    getByCategory(category: string): readonly Notification[];

    /** Get unacknowledged count. */
    getUnacknowledgedCount(): number;

    /** Get all notifications (including dismissed). */
    getHistory(): readonly Notification[];

    /** Tick — auto-dismiss expired notifications. Returns dismissed IDs. */
    tick(currentTick: number): readonly string[];

    /** Subscribe to new notifications. */
    onNotification(handler: (notification: Notification) => void): () => void;

    /** Subscribe to dismissals. */
    onDismiss(handler: (notificationId: string) => void): () => void;

    /** Clear all notifications and history. */
    clear(): void;
}
