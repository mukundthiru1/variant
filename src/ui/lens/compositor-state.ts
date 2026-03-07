/**
 * VARIANT — Lens Compositor State Management
 *
 * Pure reducer for compositor state. All state transitions are
 * predictable and testable. The React component dispatches actions;
 * this module computes the next state.
 *
 * DESIGN: Immutable state. Every action produces a new state object.
 * React's reconciliation handles the diff. No mutation.
 *
 * EXTENSIBILITY: The 'custom' action type allows third-party
 * packages to extend the reducer without modifying this file.
 * Custom action handlers are registered via a middleware pattern.
 */

import type {
    CompositorState,
    CompositorAction,
    LensInstance,
    LayoutNode,
} from './types';

// ── ID Generation ──────────────────────────────────────────────

let nextLensId = 0;

/**
 * Generate a unique lens instance ID.
 * Deterministic within a session. Not globally unique across tabs.
 */
export function generateLensId(): string {
    return `lens-${(nextLensId++).toString(36)}`;
}

/**
 * Reset the ID counter. Only for testing.
 */
export function _resetLensIdCounter(): void {
    nextLensId = 0;
}

// ── Initial State ──────────────────────────────────────────────

/**
 * Create the initial compositor state.
 * Starts with no lenses and an empty layout.
 */
export function createInitialState(): CompositorState {
    return {
        lenses: new Map(),
        layout: { type: 'lens', lensId: '' },
        focusedLensId: null,
        taskbar: [],
        maximizedLensId: null,
    };
}

// ── Reducer ────────────────────────────────────────────────────

/**
 * Pure reducer for compositor state.
 * Given the current state and an action, returns the next state.
 *
 * DESIGN: This is intentionally a plain function, not a class.
 * It can be tested without React, mocked trivially, and composed.
 */
export function compositorReducer(
    state: CompositorState,
    action: CompositorAction,
): CompositorState {
    switch (action.type) {
        case 'open-lens':
            return openLens(state, action.lens, action.position);
        case 'close-lens':
            return closeLens(state, action.lensId);
        case 'focus-lens':
            return focusLens(state, action.lensId);
        case 'set-title':
            return setTitle(state, action.lensId, action.title);
        case 'set-layout':
            return { ...state, layout: action.layout };
        case 'set-split-ratio':
            return setSplitRatio(state, action.path, action.ratio);
        case 'toggle-maximize':
            return toggleMaximize(state, action.lensId);
        case 'swap-lenses':
            return swapLenses(state, action.lensIdA, action.lensIdB);
        case 'custom':
            // Custom actions are no-ops at the base level.
            // Middleware can intercept these before reaching the reducer.
            return state;
    }
}

// ── Action Implementations ─────────────────────────────────────

function openLens(
    state: CompositorState,
    lens: LensInstance,
    position?: 'right' | 'bottom' | 'tab',
): CompositorState {
    const newLenses = new Map(state.lenses);
    newLenses.set(lens.id, lens);

    const newTaskbar = [...state.taskbar, lens.id];

    // Determine new layout
    let newLayout: LayoutNode;

    if (state.lenses.size === 0) {
        // First lens — it fills the viewport
        newLayout = { type: 'lens', lensId: lens.id };
    } else if (position === 'tab') {
        // Add as a tab alongside the focused lens
        newLayout = addAsTab(state.layout, state.focusedLensId, lens.id);
    } else if (position === 'bottom') {
        // Split the focused lens vertically
        newLayout = splitAt(state.layout, state.focusedLensId, lens.id, 'split-v');
    } else {
        // Default: split the focused lens horizontally (right)
        newLayout = splitAt(state.layout, state.focusedLensId, lens.id, 'split-h');
    }

    return {
        ...state,
        lenses: newLenses,
        layout: newLayout,
        focusedLensId: lens.id,
        taskbar: newTaskbar,
    };
}

function closeLens(state: CompositorState, lensId: string): CompositorState {
    if (!state.lenses.has(lensId)) return state;

    const newLenses = new Map(state.lenses);
    newLenses.delete(lensId);

    const newTaskbar = state.taskbar.filter(id => id !== lensId);
    const newLayout = removeLensFromLayout(state.layout, lensId);

    // If the focused lens was closed, focus the first remaining lens
    let newFocusId: string | null = state.focusedLensId;
    if (newFocusId === lensId) {
        newFocusId = newTaskbar.length > 0 ? (newTaskbar[0] ?? null) : null;
    }

    // If the maximized lens was closed, un-maximize
    const newMaximizedId = state.maximizedLensId === lensId ? null : state.maximizedLensId;

    return {
        ...state,
        lenses: newLenses,
        layout: newLayout,
        focusedLensId: newFocusId,
        taskbar: newTaskbar,
        maximizedLensId: newMaximizedId,
    };
}

function focusLens(state: CompositorState, lensId: string): CompositorState {
    if (!state.lenses.has(lensId)) return state;
    if (state.focusedLensId === lensId) return state;
    return { ...state, focusedLensId: lensId };
}

function setTitle(state: CompositorState, lensId: string, title: string): CompositorState {
    const lens = state.lenses.get(lensId);
    if (lens === undefined) return state;

    const updatedLens: LensInstance = { ...lens, title };
    const newLenses = new Map(state.lenses);
    newLenses.set(lensId, updatedLens);

    return { ...state, lenses: newLenses };
}

function setSplitRatio(state: CompositorState, path: readonly number[], ratio: number): CompositorState {
    const clampedRatio = Math.max(0.1, Math.min(0.9, ratio));
    const newLayout = updateLayoutAtPath(state.layout, path, clampedRatio);
    return { ...state, layout: newLayout };
}

function toggleMaximize(state: CompositorState, lensId: string): CompositorState {
    if (!state.lenses.has(lensId)) return state;

    if (state.maximizedLensId === lensId) {
        return { ...state, maximizedLensId: null };
    }
    return { ...state, maximizedLensId: lensId, focusedLensId: lensId };
}

function swapLenses(state: CompositorState, lensIdA: string, lensIdB: string): CompositorState {
    if (!state.lenses.has(lensIdA) || !state.lenses.has(lensIdB)) return state;

    const newLayout = swapInLayout(state.layout, lensIdA, lensIdB);
    return { ...state, layout: newLayout };
}

// ── Layout Tree Operations ─────────────────────────────────────

/**
 * Split an existing lens node to add a new lens beside it.
 */
function splitAt(
    node: LayoutNode,
    targetLensId: string | null,
    newLensId: string,
    splitType: 'split-h' | 'split-v',
): LayoutNode {
    if (targetLensId === null) {
        // No target — wrap the entire layout
        return {
            type: splitType,
            ratio: 0.5,
            children: [node, { type: 'lens', lensId: newLensId }],
        };
    }

    if (node.type === 'lens') {
        if (node.lensId === targetLensId) {
            return {
                type: splitType,
                ratio: 0.5,
                children: [node, { type: 'lens', lensId: newLensId }],
            };
        }
        return node;
    }

    if (node.type === 'split-h' || node.type === 'split-v') {
        return {
            ...node,
            children: [
                splitAt(node.children[0], targetLensId, newLensId, splitType),
                splitAt(node.children[1], targetLensId, newLensId, splitType),
            ] as readonly [LayoutNode, LayoutNode],
        };
    }

    if (node.type === 'tabs') {
        return {
            ...node,
            children: node.children.map(
                child => splitAt(child, targetLensId, newLensId, splitType),
            ),
        };
    }

    return node;
}

/**
 * Add a new lens as a tab alongside an existing lens.
 */
function addAsTab(
    node: LayoutNode,
    targetLensId: string | null,
    newLensId: string,
): LayoutNode {
    if (targetLensId === null) {
        return {
            type: 'tabs',
            children: [node, { type: 'lens', lensId: newLensId }],
            activeIndex: 1,
        };
    }

    if (node.type === 'lens') {
        if (node.lensId === targetLensId) {
            return {
                type: 'tabs',
                children: [node, { type: 'lens', lensId: newLensId }],
                activeIndex: 1,
            };
        }
        return node;
    }

    if (node.type === 'split-h' || node.type === 'split-v') {
        return {
            ...node,
            children: [
                addAsTab(node.children[0], targetLensId, newLensId),
                addAsTab(node.children[1], targetLensId, newLensId),
            ] as readonly [LayoutNode, LayoutNode],
        };
    }

    if (node.type === 'tabs') {
        // Check if target is in this tab group
        const hasTarget = node.children.some(child =>
            child.type === 'lens' && child.lensId === targetLensId,
        );

        if (hasTarget) {
            return {
                ...node,
                children: [...node.children, { type: 'lens', lensId: newLensId }],
                activeIndex: node.children.length,
            };
        }

        return {
            ...node,
            children: node.children.map(
                child => addAsTab(child, targetLensId, newLensId),
            ),
        };
    }

    return node;
}

/**
 * Remove a lens from the layout tree.
 * When a split has only one child left, collapse it.
 */
function removeLensFromLayout(node: LayoutNode, lensId: string): LayoutNode {
    if (node.type === 'lens') {
        // If this IS the lens to remove, return an empty placeholder
        if (node.lensId === lensId) {
            return { type: 'lens', lensId: '' };
        }
        return node;
    }

    if (node.type === 'split-h' || node.type === 'split-v') {
        const left = removeLensFromLayout(node.children[0], lensId);
        const right = removeLensFromLayout(node.children[1], lensId);

        // Collapse: if one side is empty, return the other
        if (left.type === 'lens' && left.lensId === '') return right;
        if (right.type === 'lens' && right.lensId === '') return left;

        return { ...node, children: [left, right] as readonly [LayoutNode, LayoutNode] };
    }

    if (node.type === 'tabs') {
        const filtered = node.children
            .map(child => removeLensFromLayout(child, lensId))
            .filter(child => !(child.type === 'lens' && child.lensId === ''));

        if (filtered.length === 0) return { type: 'lens', lensId: '' };
        if (filtered.length === 1) return filtered[0]!;

        const newActiveIndex = Math.min(node.activeIndex, filtered.length - 1);
        return { ...node, children: filtered, activeIndex: newActiveIndex };
    }

    return node;
}

/**
 * Update the split ratio at a specific path in the layout tree.
 */
function updateLayoutAtPath(
    node: LayoutNode,
    path: readonly number[],
    ratio: number,
): LayoutNode {
    if (path.length === 0) {
        if (node.type === 'split-h' || node.type === 'split-v') {
            return { ...node, ratio };
        }
        return node;
    }

    const head = path[0];
    const rest = path.slice(1);

    if (head === undefined) return node;

    if (node.type === 'split-h' || node.type === 'split-v') {
        const children = [...node.children] as [LayoutNode, LayoutNode];
        if (head === 0 || head === 1) {
            children[head] = updateLayoutAtPath(children[head], rest, ratio);
        }
        return { ...node, children };
    }

    if (node.type === 'tabs') {
        const children = [...node.children];
        if (head >= 0 && head < children.length) {
            children[head] = updateLayoutAtPath(children[head]!, rest, ratio);
        }
        return { ...node, children };
    }

    return node;
}

/**
 * Swap two lens IDs in the layout tree.
 */
function swapInLayout(node: LayoutNode, idA: string, idB: string): LayoutNode {
    if (node.type === 'lens') {
        if (node.lensId === idA) return { ...node, lensId: idB };
        if (node.lensId === idB) return { ...node, lensId: idA };
        return node;
    }

    if (node.type === 'split-h' || node.type === 'split-v') {
        return {
            ...node,
            children: [
                swapInLayout(node.children[0], idA, idB),
                swapInLayout(node.children[1], idA, idB),
            ] as readonly [LayoutNode, LayoutNode],
        };
    }

    if (node.type === 'tabs') {
        return {
            ...node,
            children: node.children.map(child => swapInLayout(child, idA, idB)),
        };
    }

    return node;
}

// ── Utility: Collect all lens IDs from a layout ────────────────

/**
 * Collect all lens IDs referenced in a layout tree.
 * Useful for validation — every ID in the layout must exist in the lens map.
 */
export function collectLensIds(node: LayoutNode): readonly string[] {
    if (node.type === 'lens') {
        return node.lensId === '' ? [] : [node.lensId];
    }

    if (node.type === 'split-h' || node.type === 'split-v') {
        return [
            ...collectLensIds(node.children[0]),
            ...collectLensIds(node.children[1]),
        ];
    }

    if (node.type === 'tabs') {
        return node.children.flatMap(child => collectLensIds(child));
    }

    return [];
}
