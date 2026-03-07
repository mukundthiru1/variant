/**
 * VARIANT — Lens Compositor
 *
 * Renders the layout tree of open lenses. Manages:
 *   - Split panes (horizontal/vertical) with drag-to-resize
 *   - Tab groups
 *   - Lens focus management
 *   - Taskbar for switching between lenses
 *
 * The compositor is the bridge between the pure state (CompositorState)
 * and the React component tree. It renders LensInstance data into
 * actual lens components (TerminalLens, BrowserLens, etc.) by looking
 * up the lens type in the LensRegistry.
 *
 * ARCHITECTURE: The compositor does NOT know about specific lens types.
 * It renders a generic container for each lens and delegates to a
 * render function provided by the parent. This keeps the compositor
 * reusable and lens-type-agnostic.
 */

import { useCallback, useRef, useState } from 'react';
import type { LayoutNode, LensInstance, CompositorState, CompositorAction } from '../lens/types';

// ── Props ───────────────────────────────────────────────────────

export interface LensCompositorProps {
    readonly state: CompositorState;
    readonly dispatch: (action: CompositorAction) => void;

    /**
     * Render function for a lens. The compositor calls this to get
     * the React element for each lens instance. The parent provides
     * the actual lens components (terminal, browser, etc.).
     */
    readonly renderLens: (lens: LensInstance, focused: boolean) => JSX.Element;
}

// ── Compositor Component ────────────────────────────────────────

export function LensCompositor({ state, dispatch, renderLens }: LensCompositorProps): JSX.Element {
    return (
        <div style={{
            display: 'flex',
            flexDirection: 'column',
            height: '100%',
            width: '100%',
            overflow: 'hidden',
        }}>
            {/* Main layout area */}
            <div style={{ flex: 1, overflow: 'hidden', position: 'relative' }}>
                {state.maximizedLensId !== null ? (
                    // Maximized mode: render only the maximized lens
                    renderMaximized(state, dispatch, renderLens)
                ) : (
                    // Normal mode: render the layout tree
                    <LayoutRenderer
                        node={state.layout}
                        state={state}
                        dispatch={dispatch}
                        renderLens={renderLens}
                        path={[]}
                    />
                )}
            </div>

            {/* Taskbar */}
            {state.taskbar.length > 1 && (
                <Taskbar state={state} dispatch={dispatch} />
            )}
        </div>
    );
}

function renderMaximized(
    state: CompositorState,
    dispatch: (action: CompositorAction) => void,
    renderLens: (lens: LensInstance, focused: boolean) => JSX.Element,
): JSX.Element {
    const lens = state.lenses.get(state.maximizedLensId!);
    if (lens === undefined) return <div />;

    return (
        <div
            style={{ width: '100%', height: '100%', position: 'relative' }}
            onClick={() => { dispatch({ type: 'focus-lens', lensId: lens.id }); }}
        >
            <LensHeader
                lens={lens}
                focused={true}
                dispatch={dispatch}
                maximized={true}
            />
            <div style={{ position: 'absolute', top: 24, left: 0, right: 0, bottom: 0 }}>
                {renderLens(lens, true)}
            </div>
        </div>
    );
}

// ── Layout Tree Renderer ────────────────────────────────────────

interface LayoutRendererProps {
    readonly node: LayoutNode;
    readonly state: CompositorState;
    readonly dispatch: (action: CompositorAction) => void;
    readonly renderLens: (lens: LensInstance, focused: boolean) => JSX.Element;
    readonly path: readonly number[];
}

function LayoutRenderer({ node, state, dispatch, renderLens, path }: LayoutRendererProps): JSX.Element {
    if (node.type === 'lens') {
        const lens = state.lenses.get(node.lensId);
        if (lens === undefined || node.lensId === '') {
            return <div style={{ width: '100%', height: '100%', background: 'var(--bg-primary, #0a0e14)' }} />;
        }

        const focused = state.focusedLensId === lens.id;

        return (
            <div
                style={{
                    width: '100%',
                    height: '100%',
                    display: 'flex',
                    flexDirection: 'column',
                    border: focused ? '1px solid rgba(0, 255, 65, 0.2)' : '1px solid var(--border-default, #21262d)',
                    overflow: 'hidden',
                }}
                onClick={() => { dispatch({ type: 'focus-lens', lensId: lens.id }); }}
            >
                <LensHeader lens={lens} focused={focused} dispatch={dispatch} maximized={false} />
                <div style={{ flex: 1, overflow: 'hidden' }}>
                    {renderLens(lens, focused)}
                </div>
            </div>
        );
    }

    if (node.type === 'split-h' || node.type === 'split-v') {
        return (
            <SplitPane
                direction={node.type === 'split-h' ? 'horizontal' : 'vertical'}
                ratio={node.ratio}
                onRatioChange={(ratio) => { dispatch({ type: 'set-split-ratio', path, ratio }); }}
            >
                <LayoutRenderer
                    node={node.children[0]}
                    state={state}
                    dispatch={dispatch}
                    renderLens={renderLens}
                    path={[...path, 0]}
                />
                <LayoutRenderer
                    node={node.children[1]}
                    state={state}
                    dispatch={dispatch}
                    renderLens={renderLens}
                    path={[...path, 1]}
                />
            </SplitPane>
        );
    }

    if (node.type === 'tabs') {
        return (
            <TabGroup
                node={node}
                state={state}
                dispatch={dispatch}
                renderLens={renderLens}
                path={path}
            />
        );
    }

    return <div />;
}

// ── Split Pane ──────────────────────────────────────────────────

interface SplitPaneProps {
    readonly direction: 'horizontal' | 'vertical';
    readonly ratio: number;
    readonly onRatioChange: (ratio: number) => void;
    readonly children: [JSX.Element, JSX.Element];
}

function SplitPane({ direction, ratio, onRatioChange, children }: SplitPaneProps): JSX.Element {
    const containerRef = useRef<HTMLDivElement | null>(null);
    const [dragging, setDragging] = useState(false);

    const handleMouseDown = useCallback((e: React.MouseEvent) => {
        e.preventDefault();
        setDragging(true);

        const container = containerRef.current;
        if (container === null) return;

        const rect = container.getBoundingClientRect();

        const handleMouseMove = (moveEvent: MouseEvent): void => {
            let newRatio: number;
            if (direction === 'horizontal') {
                newRatio = (moveEvent.clientX - rect.left) / rect.width;
            } else {
                newRatio = (moveEvent.clientY - rect.top) / rect.height;
            }
            onRatioChange(Math.max(0.1, Math.min(0.9, newRatio)));
        };

        const handleMouseUp = (): void => {
            setDragging(false);
            document.removeEventListener('mousemove', handleMouseMove);
            document.removeEventListener('mouseup', handleMouseUp);
        };

        document.addEventListener('mousemove', handleMouseMove);
        document.addEventListener('mouseup', handleMouseUp);
    }, [direction, onRatioChange]);

    const isHorizontal = direction === 'horizontal';

    return (
        <div
            ref={containerRef}
            style={{
                display: 'flex',
                flexDirection: isHorizontal ? 'row' : 'column',
                width: '100%',
                height: '100%',
                overflow: 'hidden',
            }}
        >
            <div style={{
                [isHorizontal ? 'width' : 'height']: `${ratio * 100}%`,
                overflow: 'hidden',
                position: 'relative',
            }}>
                {children[0]}
            </div>

            {/* Drag handle */}
            <div
                onMouseDown={handleMouseDown}
                style={{
                    [isHorizontal ? 'width' : 'height']: '4px',
                    [isHorizontal ? 'cursor' : 'cursor']: isHorizontal ? 'col-resize' : 'row-resize',
                    background: dragging ? 'rgba(0, 255, 65, 0.3)' : 'var(--border-default, #21262d)',
                    flexShrink: 0,
                    transition: 'background 0.1s',
                    zIndex: 2,
                }}
                onMouseEnter={(e) => {
                    if (!dragging) e.currentTarget.style.background = 'rgba(0, 255, 65, 0.15)';
                }}
                onMouseLeave={(e) => {
                    if (!dragging) e.currentTarget.style.background = 'var(--border-default, #21262d)';
                }}
            />

            <div style={{
                flex: 1,
                overflow: 'hidden',
                position: 'relative',
            }}>
                {children[1]}
            </div>
        </div>
    );
}

// ── Tab Group ───────────────────────────────────────────────────

interface TabGroupProps {
    readonly node: Extract<LayoutNode, { type: 'tabs' }>;
    readonly state: CompositorState;
    readonly dispatch: (action: CompositorAction) => void;
    readonly renderLens: (lens: LensInstance, focused: boolean) => JSX.Element;
    readonly path: readonly number[];
}

function TabGroup({ node, state, dispatch, renderLens, path }: TabGroupProps): JSX.Element {
    const activeChild = node.children[node.activeIndex];
    if (activeChild === undefined) return <div />;

    return (
        <div style={{ display: 'flex', flexDirection: 'column', width: '100%', height: '100%', overflow: 'hidden' }}>
            {/* Tab strip */}
            <div style={{
                display: 'flex',
                background: 'var(--bg-secondary, #0d1117)',
                borderBottom: '1px solid var(--border-default, #21262d)',
                overflow: 'hidden',
            }}>
                {node.children.map((child, i) => {
                    if (child.type !== 'lens') return null;
                    const lens = state.lenses.get(child.lensId);
                    if (lens === undefined) return null;

                    const active = i === node.activeIndex;

                    return (
                        <button
                            key={child.lensId}
                            onClick={() => {
                                dispatch({
                                    type: 'set-layout',
                                    layout: updateTabIndex(state.layout, path, i),
                                });
                                dispatch({ type: 'focus-lens', lensId: child.lensId });
                            }}
                            style={{
                                background: active ? 'var(--bg-primary, #0a0e14)' : 'transparent',
                                border: 'none',
                                borderBottom: active ? '2px solid #00ff41' : '2px solid transparent',
                                color: active ? '#e6edf3' : '#666',
                                fontFamily: 'inherit',
                                fontSize: '0.7rem',
                                padding: '4px 12px',
                                cursor: 'pointer',
                            }}
                        >
                            {lens.title}
                        </button>
                    );
                })}
            </div>

            {/* Active tab content */}
            <div style={{ flex: 1, overflow: 'hidden' }}>
                <LayoutRenderer
                    node={activeChild}
                    state={state}
                    dispatch={dispatch}
                    renderLens={renderLens}
                    path={[...path, node.activeIndex]}
                />
            </div>
        </div>
    );
}

// ── Lens Header (title bar for each lens pane) ──────────────────

interface LensHeaderProps {
    readonly lens: LensInstance;
    readonly focused: boolean;
    readonly dispatch: (action: CompositorAction) => void;
    readonly maximized: boolean;
}

function LensHeader({ lens, focused, dispatch, maximized }: LensHeaderProps): JSX.Element {
    return (
        <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            height: '24px',
            padding: '0 8px',
            background: focused ? 'var(--bg-elevated, #1c2128)' : 'var(--bg-secondary, #0d1117)',
            borderBottom: '1px solid var(--border-default, #21262d)',
            fontSize: '0.65rem',
            color: focused ? '#e6edf3' : '#666',
            userSelect: 'none',
            flexShrink: 0,
        }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', overflow: 'hidden' }}>
                <span style={{
                    color: focused ? '#00ff41' : '#444',
                    fontSize: '0.5rem',
                }}>
                    {'\u25CF'}
                </span>
                <span style={{
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                }}>
                    {lens.title}
                </span>
                <span style={{ color: '#444' }}>
                    [{lens.type}]
                </span>
            </div>

            <div style={{ display: 'flex', gap: '4px' }}>
                <button
                    onClick={(e) => {
                        e.stopPropagation();
                        dispatch({ type: 'toggle-maximize', lensId: lens.id });
                    }}
                    style={headerBtnStyle}
                    title={maximized ? 'Restore' : 'Maximize'}
                >
                    {maximized ? '\u25A3' : '\u25A1'}
                </button>
                <button
                    onClick={(e) => {
                        e.stopPropagation();
                        dispatch({ type: 'close-lens', lensId: lens.id });
                    }}
                    style={{ ...headerBtnStyle, color: '#ff5555' }}
                    title="Close"
                >
                    {'\u2715'}
                </button>
            </div>
        </div>
    );
}

// ── Taskbar ─────────────────────────────────────────────────────

interface TaskbarProps {
    readonly state: CompositorState;
    readonly dispatch: (action: CompositorAction) => void;
}

function Taskbar({ state, dispatch }: TaskbarProps): JSX.Element {
    return (
        <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '2px',
            padding: '2px 8px',
            background: 'var(--bg-secondary, #0d1117)',
            borderTop: '1px solid var(--border-default, #21262d)',
            height: '24px',
            overflow: 'hidden',
        }}>
            {state.taskbar.map(lensId => {
                const lens = state.lenses.get(lensId);
                if (lens === undefined) return null;

                const focused = state.focusedLensId === lensId;

                return (
                    <button
                        key={lensId}
                        onClick={() => { dispatch({ type: 'focus-lens', lensId }); }}
                        onDoubleClick={() => { dispatch({ type: 'toggle-maximize', lensId }); }}
                        style={{
                            background: focused ? 'rgba(0, 255, 65, 0.08)' : 'transparent',
                            border: focused ? '1px solid rgba(0, 255, 65, 0.2)' : '1px solid transparent',
                            borderRadius: '2px',
                            color: focused ? '#e6edf3' : '#666',
                            fontFamily: 'inherit',
                            fontSize: '0.6rem',
                            padding: '1px 8px',
                            cursor: 'pointer',
                            maxWidth: '120px',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                        }}
                    >
                        {lens.title}
                    </button>
                );
            })}
        </div>
    );
}

// ── Helpers ──────────────────────────────────────────────────────

function updateTabIndex(layout: LayoutNode, path: readonly number[], newIndex: number): LayoutNode {
    if (path.length === 0) {
        if (layout.type === 'tabs') {
            return { ...layout, activeIndex: newIndex };
        }
        return layout;
    }

    const head = path[0]!;
    const rest = path.slice(1);

    if (layout.type === 'split-h' || layout.type === 'split-v') {
        const children = [...layout.children] as [LayoutNode, LayoutNode];
        if (head === 0 || head === 1) {
            children[head] = updateTabIndex(children[head], rest, newIndex);
        }
        return { ...layout, children };
    }

    if (layout.type === 'tabs') {
        const children = [...layout.children];
        if (head >= 0 && head < children.length) {
            children[head] = updateTabIndex(children[head]!, rest, newIndex);
        }
        return { ...layout, children };
    }

    return layout;
}

const headerBtnStyle: React.CSSProperties = {
    background: 'transparent',
    border: 'none',
    color: '#666',
    fontFamily: 'inherit',
    fontSize: '0.7rem',
    padding: '0 4px',
    cursor: 'pointer',
    lineHeight: 1,
};
