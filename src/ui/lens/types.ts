/**
 * VARIANT — Lens Type System
 *
 * A lens is a view into the simulation. The terminal is a lens.
 * A web browser is a lens. An email client is a lens. Each one shows
 * a different facet of the same underlying simulation.
 *
 * Level designers configure which lenses are available and how they're
 * arranged. The player can open, close, resize, and rearrange them.
 *
 * EXTENSIBILITY: Everything is string-keyed and registry-based.
 * Adding a new lens type = registering a LensDefinition at runtime.
 * Zero changes to core. Third-party lens packages import the registry,
 * call register(), and their lens appears in the compositor.
 *
 * SECURITY: Lenses are read/write views into simulation state.
 * They CANNOT:
 *   - Execute code outside the simulation
 *   - Access the host filesystem
 *   - Make network requests to the real internet
 *   - Modify core engine state directly
 *   - Access other lenses' internal state (only via message bus)
 *
 * They CAN:
 *   - Read VM terminal output
 *   - Send input to VM terminals
 *   - Render HTTP responses from simulated services
 *   - Display event bus data (alerts, logs, traffic)
 *   - Read/write VFS contents (for Simulacrum backends)
 *   - Send messages to other lenses via the lens message bus
 */

import type { EventBus } from '../../core/events';

// ── Well-Known Lens Types (constants, not a closed union) ──────
//
// These are the lens types we ship. But the system accepts ANY string.
// Third-party packages define their own type strings.
//
export const LENS_TERMINAL = 'terminal' as const;
export const LENS_BROWSER = 'browser' as const;
export const LENS_EMAIL = 'email' as const;
export const LENS_FILE_MANAGER = 'file-manager' as const;
export const LENS_NETWORK_MAP = 'network-map' as const;
export const LENS_PACKET_CAPTURE = 'packet-capture' as const;
export const LENS_LOG_VIEWER = 'log-viewer' as const;
export const LENS_CODE_EDITOR = 'code-editor' as const;
export const LENS_DEFENSE_DASHBOARD = 'defense-dashboard' as const;
export const LENS_DATABASE_CONSOLE = 'database-console' as const;
export const LENS_PROCESS_VIEWER = 'process-viewer' as const;
export const LENS_CLOUD_CONSOLE = 'cloud-console' as const;

// ── Lens Definition (what a lens type IS) ──────────────────────

/**
 * A lens definition describes a type of lens.
 * This is what gets registered in the LensRegistry.
 *
 * EXTENSIBILITY: Any package can create a LensDefinition and register it.
 * The compositor discovers it via the registry. No imports needed.
 */
export interface LensDefinition {
    /**
     * Unique type identifier. Any string. Convention: kebab-case.
     * Well-known types use the LENS_* constants above.
     * Third-party types should be namespaced: 'vendor/lens-name'.
     */
    readonly type: string;

    /** Human-readable name shown in the lens picker. */
    readonly displayName: string;

    /** Short description for tooltips. */
    readonly description: string;

    /** Icon identifier (emoji, icon class, or SVG path). */
    readonly icon: string;

    /**
     * What this lens needs from the simulation.
     * Used by the compositor to validate whether a lens can be opened
     * in the current simulation context.
     */
    readonly capabilities: LensCapabilities;

    /**
     * Layout constraints for this lens type.
     * The compositor respects these when arranging panels.
     */
    readonly constraints: LensConstraints;

    /**
     * Keyboard shortcut to open this lens. Convention: 'ctrl+shift+X'.
     * null = no shortcut.
     */
    readonly shortcut: string | null;

    /**
     * Can multiple instances of this lens be open simultaneously?
     * Terminal: true (multiple shells). Network map: false (one is enough).
     */
    readonly allowMultiple: boolean;

    /**
     * Lifecycle hooks called by the compositor.
     * These are OPTIONAL — sensible defaults are applied.
     */
    readonly lifecycle?: LensLifecycle;
}

/**
 * What capabilities a lens requires or provides.
 * The compositor uses these to determine validity.
 */
export interface LensCapabilities {
    /**
     * Does this lens need a target machine?
     * 'required' — must specify a machine (terminal, browser)
     * 'optional' — can target a machine or be global (log viewer)
     * 'none'     — never targets a machine (network map, defense dash)
     */
    readonly targetMachine: 'required' | 'optional' | 'none';

    /**
     * What backend types does this lens work with?
     * null = works with all backends.
     * ['simulacrum', 'simulacrum+'] = only these backends.
     */
    readonly compatibleBackends: readonly string[] | null;

    /**
     * Does this lens need write access to the simulation?
     * Read-only lenses (network map, log viewer) get a frozen context.
     * Writable lenses (terminal, code editor) get mutable access.
     */
    readonly writable: boolean;

    /**
     * Custom capability flags. Third-party lenses can declare
     * arbitrary capabilities. The compositor passes these through.
     * Example: { 'needs-webgl': true, 'needs-audio': true }
     */
    readonly custom: Readonly<Record<string, unknown>>;
}

/**
 * Layout constraints for a lens type.
 */
export interface LensConstraints {
    /** Minimum width in pixels. Default: 200. */
    readonly minWidth: number;
    /** Minimum height in pixels. Default: 150. */
    readonly minHeight: number;
    /** Preferred aspect ratio (width/height). null = no preference. */
    readonly preferredAspectRatio: number | null;
    /** Preferred initial size as a fraction of the viewport. Default: 0.5. */
    readonly preferredSize: number;
}

/**
 * Lifecycle hooks for a lens instance.
 * Called by the compositor at specific moments.
 * All hooks are optional.
 */
export interface LensLifecycle {
    /**
     * Called when the lens instance is created.
     * Return a cleanup function that runs on destroy.
     */
    readonly onInit?: (ctx: LensContext) => (() => void) | void;

    /** Called when the lens receives keyboard focus. */
    readonly onFocus?: (ctx: LensContext) => void;

    /** Called when the lens loses keyboard focus. */
    readonly onBlur?: (ctx: LensContext) => void;

    /** Called when the lens is resized. */
    readonly onResize?: (ctx: LensContext, width: number, height: number) => void;

    /**
     * Called when another lens sends a message to this lens.
     * Enables lens-to-lens communication (e.g., terminal opens a browser).
     */
    readonly onMessage?: (ctx: LensContext, message: LensMessage) => void;

    /** Called before destruction. Last chance to clean up. */
    readonly onDestroy?: (ctx: LensContext) => void;
}

// ── Lens Instance (a running lens) ─────────────────────────────

/**
 * A lens instance. Each open panel in the UI is one of these.
 * Multiple instances of the same type can exist (e.g., two terminals).
 */
export interface LensInstance {
    /** Unique ID for this lens instance. Auto-generated. */
    readonly id: string;

    /** The lens type (matches a LensDefinition.type in the registry). */
    readonly type: string;

    /** Human-readable title shown in the tab/title bar. Mutable by the lens. */
    readonly title: string;

    /**
     * Which machine this lens is connected to (if any).
     * A terminal lens targets a specific machine's shell.
     * A browser lens targets a specific machine's HTTP service.
     * Network map / defense dashboard target null.
     */
    readonly targetMachine: string | null;

    /**
     * Lens-specific configuration. Each lens type defines its own shape.
     * This is an open record — any key/value pairs. Frozen on creation.
     *
     * Terminal: { shellId?: string }
     * Browser: { url: string }
     * Email: { account: string }
     * Code Editor: { path: string, language?: string }
     * Custom: anything the lens type needs
     */
    readonly config: Readonly<Record<string, unknown>>;
}

// ── Lens Context (what the compositor gives a running lens) ─────

/**
 * The context object passed to lens lifecycle hooks and components.
 * This is the lens's entire API surface into the simulation.
 *
 * SECURITY: The context is scoped. A lens can only access what's
 * appropriate for its capabilities. Read-only lenses get a frozen
 * simulation reference. Writable lenses get controlled mutation.
 */
export interface LensContext {
    /** This lens instance. */
    readonly instance: LensInstance;

    /** The lens definition from the registry. */
    readonly definition: LensDefinition;

    /** The simulation's event bus (for subscribing to events). */
    readonly events: EventBus;

    /**
     * Send a message to another lens instance.
     * The target lens's onMessage lifecycle hook will be called.
     * Returns false if the target lens doesn't exist or doesn't accept messages.
     */
    readonly sendMessage: (targetLensId: string, message: LensMessage) => boolean;

    /**
     * Broadcast a message to all lenses of a given type.
     * Returns the number of lenses that received the message.
     */
    readonly broadcastMessage: (targetType: string, message: LensMessage) => number;

    /**
     * Request the compositor to open a new lens.
     * This is how a terminal causes a browser to open (e.g., `browse http://...`).
     */
    readonly requestOpenLens: (request: OpenLensRequest) => void;

    /**
     * Update this lens's title (shown in the tab bar).
     * Example: terminal changes title to 'admin@web-01:~$' after SSH.
     */
    readonly setTitle: (title: string) => void;

    /**
     * Request keyboard focus for this lens.
     */
    readonly requestFocus: () => void;
}

/**
 * A message sent between lens instances.
 * Open structure — lens types define their own message schemas.
 */
export interface LensMessage {
    /** Message type. Convention: 'action:verb' or 'data:type'. */
    readonly type: string;

    /** Message payload. Any serializable data. */
    readonly payload: Readonly<Record<string, unknown>>;

    /** The lens ID that sent this message. Set by the compositor. */
    readonly fromLensId: string;
}

/**
 * A request to open a new lens.
 * Sent by a lens to the compositor via LensContext.requestOpenLens().
 */
export interface OpenLensRequest {
    /** The lens type to open. Must be registered in the LensRegistry. */
    readonly type: string;

    /** Target machine (if applicable). */
    readonly targetMachine?: string;

    /** Lens-specific config. */
    readonly config?: Readonly<Record<string, unknown>>;

    /** Where to place the new lens relative to the requesting lens. */
    readonly position?: 'right' | 'bottom' | 'tab' | 'float';
}

// ── Layout ─────────────────────────────────────────────────────

/**
 * A node in the layout tree. Layouts are recursive:
 * a split contains two children, each of which can be a lens or another split.
 *
 * This is a pure data structure — the compositor renders it.
 * Layout changes produce new trees (immutable).
 */
export type LayoutNode =
    | { readonly type: 'lens'; readonly lensId: string }
    | { readonly type: 'split-h'; readonly children: readonly [LayoutNode, LayoutNode]; readonly ratio: number }
    | { readonly type: 'split-v'; readonly children: readonly [LayoutNode, LayoutNode]; readonly ratio: number }
    | { readonly type: 'tabs'; readonly children: readonly LayoutNode[]; readonly activeIndex: number };

// ── Compositor State ───────────────────────────────────────────

/**
 * The complete state of all lenses and their layout.
 * This is what the LensCompositor component renders.
 * Immutable — all updates produce a new state.
 */
export interface CompositorState {
    /** All lens instances, keyed by ID. */
    readonly lenses: ReadonlyMap<string, LensInstance>;

    /** The layout tree that determines how lenses are arranged. */
    readonly layout: LayoutNode;

    /** Which lens currently has keyboard focus. */
    readonly focusedLensId: string | null;

    /** The taskbar items (lens IDs in display order). */
    readonly taskbar: readonly string[];

    /** Whether a lens is maximized (covers the full viewport). */
    readonly maximizedLensId: string | null;
}

// ── Compositor Actions ─────────────────────────────────────────

/**
 * Actions that modify the compositor state.
 * Used via a reducer pattern for predictable state transitions.
 *
 * EXTENSIBILITY: The 'custom' action type allows third-party
 * lens packages to define their own actions without modifying this union.
 */
export type CompositorAction =
    | { readonly type: 'open-lens'; readonly lens: LensInstance; readonly position?: 'right' | 'bottom' | 'tab' }
    | { readonly type: 'close-lens'; readonly lensId: string }
    | { readonly type: 'focus-lens'; readonly lensId: string }
    | { readonly type: 'set-title'; readonly lensId: string; readonly title: string }
    | { readonly type: 'set-layout'; readonly layout: LayoutNode }
    | { readonly type: 'set-split-ratio'; readonly path: readonly number[]; readonly ratio: number }
    | { readonly type: 'toggle-maximize'; readonly lensId: string }
    | { readonly type: 'swap-lenses'; readonly lensIdA: string; readonly lensIdB: string }
    | { readonly type: 'custom'; readonly action: string; readonly payload: Readonly<Record<string, unknown>> };

// ── Start Configuration ────────────────────────────────────────

/**
 * How a level starts — which lenses are open and how they're arranged.
 * This is what level designers configure in the WorldSpec.
 *
 * String presets are convenience aliases for common configurations.
 * The custom object form allows full control.
 *
 * EXTENSIBILITY: String presets are resolved via a preset registry.
 * Third-party packages can register new preset names.
 */
export type StartConfig =
    | string                               // Preset name (resolved via registry)
    | { readonly lenses: readonly StartLensConfig[]; readonly layout?: LayoutNode };

/**
 * A lens to open on level start.
 */
export interface StartLensConfig {
    /** Lens type. Must be registered in the LensRegistry. */
    readonly type: string;

    /** Target machine from the WorldSpec. */
    readonly targetMachine?: string;

    /** Lens-specific config. */
    readonly config?: Readonly<Record<string, unknown>>;

    /** Initial title override. */
    readonly title?: string;
}

// ── Lens Registry ──────────────────────────────────────────────

/**
 * The lens registry. Manages lens type definitions.
 *
 * EXTENSIBILITY: Third-party packages call register() to add
 * their lens types. The compositor discovers available lenses
 * by querying the registry.
 *
 * SECURITY: Registration is append-only. Once registered, a lens
 * type cannot be overwritten (prevents definition poisoning).
 * The engine validates all lens types referenced by WorldSpecs
 * against the registry at boot time.
 */
export interface LensRegistry {
    /**
     * Register a new lens type definition.
     * Throws if a definition with the same type ID already exists.
     */
    register(definition: LensDefinition): void;

    /**
     * Get a lens definition by type ID.
     * Returns undefined if not registered.
     */
    get(type: string): LensDefinition | undefined;

    /**
     * Check if a lens type is registered.
     */
    has(type: string): boolean;

    /**
     * Get all registered lens definitions.
     * Returns a frozen array — mutations have no effect.
     */
    getAll(): readonly LensDefinition[];

    /**
     * Get all registered lens type IDs.
     */
    getTypes(): readonly string[];
}

// ── Start Config Preset Registry ───────────────────────────────

/**
 * Registry for start configuration presets.
 * Level designers type 'terminal' and the registry resolves it
 * to a full StartConfig with lenses and layout.
 *
 * EXTENSIBILITY: Third-party packages can register new presets.
 * A training platform could register 'ctf-standard' as a preset.
 */
export interface StartConfigPresetRegistry {
    /**
     * Register a named preset.
     * Throws if the preset name already exists.
     */
    register(name: string, config: { readonly lenses: readonly StartLensConfig[]; readonly layout?: LayoutNode }): void;

    /**
     * Resolve a preset name to a full start config.
     * Returns undefined if the preset name is not registered.
     */
    resolve(name: string): { readonly lenses: readonly StartLensConfig[]; readonly layout?: LayoutNode } | undefined;

    /**
     * Get all registered preset names.
     */
    getNames(): readonly string[];
}

