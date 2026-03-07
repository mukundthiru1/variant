/**
 * VARIANT — Lens System
 *
 * Public API for the lens compositor.
 *
 * Types: LensDefinition, LensInstance, LensContext, CompositorState, etc.
 * Registry: createLensRegistry(), createStartConfigPresetRegistry()
 * State: compositorReducer(), createInitialState(), generateLensId()
 */

// ── Types ──────────────────────────────────────────────────────
export type {
    LensDefinition,
    LensCapabilities,
    LensConstraints,
    LensLifecycle,
    LensInstance,
    LensContext,
    LensMessage,
    OpenLensRequest,
    LayoutNode,
    CompositorState,
    CompositorAction,
    StartConfig,
    StartLensConfig,
    LensRegistry,
    StartConfigPresetRegistry,
} from './types';

export {
    LENS_TERMINAL,
    LENS_BROWSER,
    LENS_EMAIL,
    LENS_FILE_MANAGER,
    LENS_NETWORK_MAP,
    LENS_PACKET_CAPTURE,
    LENS_LOG_VIEWER,
    LENS_CODE_EDITOR,
    LENS_DEFENSE_DASHBOARD,
    LENS_DATABASE_CONSOLE,
    LENS_PROCESS_VIEWER,
    LENS_CLOUD_CONSOLE,
} from './types';

// ── Registry ───────────────────────────────────────────────────
export {
    createLensRegistry,
    createStartConfigPresetRegistry,
    registerDefaultPresets,
} from './registry';

// ── State ──────────────────────────────────────────────────────
export {
    compositorReducer,
    createInitialState,
    generateLensId,
    collectLensIds,
} from './compositor-state';
