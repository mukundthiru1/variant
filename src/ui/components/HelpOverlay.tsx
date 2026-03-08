/**
 * VARIANT — Keyboard Shortcuts Help Overlay
 *
 * Modal overlay listing all keyboard shortcuts grouped by category.
 * Signal Design System: #D4A03A accent, #0a0a0a background.
 */

export interface HelpOverlayProps {
    readonly open: boolean;
    readonly onClose: () => void;
}

const ACCENT = '#D4A03A';
const BG_OVERLAY = 'rgba(0, 0, 0, 0.75)';
const BG_MODAL = '#0a0a0a';
const BORDER = '1px solid rgba(212, 160, 58, 0.35)';
const ROW_BORDER = '1px solid #1a1a1a';

const shortcutCategories: ReadonlyArray<{
    readonly title: string;
    readonly shortcuts: ReadonlyArray<{ readonly keys: string; readonly description: string }>;
}> = [
    {
        title: 'Navigation',
        shortcuts: [
            { keys: 'Ctrl+Tab', description: 'Next lens tab' },
            { keys: 'Ctrl+Shift+Tab', description: 'Previous lens tab' },
            { keys: 'Ctrl+1 … Ctrl+8', description: 'Switch to lens tab 1–8' },
            { keys: 'Ctrl+`', description: 'Toggle terminal and last focused lens' },
            { keys: 'Ctrl+W', description: 'Close focused lens' },
            { keys: 'F11', description: 'Maximize / restore focused lens' },
            { keys: 'Escape', description: 'Close overlay, unmaximize, or dismiss notifications' },
        ],
    },
    {
        title: 'Lenses',
        shortcuts: [
            { keys: 'Ctrl+Shift+T', description: 'New Terminal' },
            { keys: 'Ctrl+Shift+B', description: 'Browser' },
            { keys: 'Ctrl+Shift+E', description: 'Email' },
            { keys: 'Ctrl+Shift+F', description: 'File Manager' },
            { keys: 'Ctrl+Shift+N', description: 'Network Map' },
            { keys: 'Ctrl+Shift+L', description: 'Log Viewer' },
            { keys: 'Ctrl+Shift+P', description: 'Process Viewer' },
            { keys: 'Ctrl+Shift+K', description: 'Packet Capture' },
        ],
    },
    {
        title: 'Panels & Help',
        shortcuts: [
            { keys: 'Ctrl+H', description: 'Show / hide hint panel' },
            { keys: 'F1 or ?', description: 'Show this keyboard shortcuts help' },
        ],
    },
];

export function HelpOverlay({ open, onClose }: HelpOverlayProps): JSX.Element {
    if (!open) return <></>;

    return (
        <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="help-overlay-title"
            style={{
                position: 'fixed',
                inset: 0,
                zIndex: 10000,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                background: BG_OVERLAY,
                fontFamily: '"JetBrains Mono", "Fira Code", monospace',
            }}
            onClick={(e) => {
                if (e.target === e.currentTarget) onClose();
            }}
        >
            <div
                style={{
                    background: BG_MODAL,
                    border: BORDER,
                    borderRadius: '6px',
                    maxWidth: '560px',
                    width: '90%',
                    maxHeight: '85vh',
                    overflow: 'auto',
                    boxShadow: '0 8px 32px rgba(0,0,0,0.5), 0 0 0 1px rgba(212, 160, 58, 0.1)',
                }}
                onClick={(e) => e.stopPropagation()}
            >
                <div
                    style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '14px 18px',
                        borderBottom: ROW_BORDER,
                    }}
                >
                    <h2
                        id="help-overlay-title"
                        style={{
                            margin: 0,
                            fontSize: '1rem',
                            fontWeight: 700,
                            color: ACCENT,
                            letterSpacing: '0.02em',
                        }}
                    >
                        Keyboard Shortcuts
                    </h2>
                    <button
                        type="button"
                        onClick={onClose}
                        style={{
                            background: 'transparent',
                            border: BORDER,
                            color: '#e0e0e0',
                            padding: '6px 12px',
                            fontFamily: 'inherit',
                            fontSize: '0.75rem',
                            cursor: 'pointer',
                            borderRadius: '4px',
                        }}
                        onMouseEnter={(e) => {
                            e.currentTarget.style.borderColor = ACCENT;
                            e.currentTarget.style.color = ACCENT;
                        }}
                        onMouseLeave={(e) => {
                            e.currentTarget.style.borderColor = 'rgba(212, 160, 58, 0.35)';
                            e.currentTarget.style.color = '#e0e0e0';
                        }}
                    >
                        Close
                    </button>
                </div>

                <div style={{ padding: '12px 18px 18px' }}>
                    {shortcutCategories.map((cat) => (
                        <div key={cat.title} style={{ marginBottom: '18px' }}>
                            <h3
                                style={{
                                    margin: '0 0 8px 0',
                                    fontSize: '0.7rem',
                                    fontWeight: 600,
                                    color: ACCENT,
                                    textTransform: 'uppercase',
                                    letterSpacing: '0.08em',
                                }}
                            >
                                {cat.title}
                            </h3>
                            <table
                                style={{
                                    width: '100%',
                                    borderCollapse: 'collapse',
                                    fontSize: '0.8rem',
                                    color: '#e0e0e0',
                                }}
                            >
                                <tbody>
                                    {cat.shortcuts.map((row) => (
                                        <tr key={row.keys}>
                                            <td
                                                style={{
                                                    padding: '6px 12px 6px 0',
                                                    borderBottom: ROW_BORDER,
                                                    verticalAlign: 'top',
                                                    color: '#b0b0b0',
                                                }}
                                            >
                                                <kbd
                                                    style={{
                                                        display: 'inline-block',
                                                        padding: '2px 8px',
                                                        background: '#1a1a1a',
                                                        border: '1px solid #2a2a2a',
                                                        borderRadius: '4px',
                                                        color: ACCENT,
                                                        fontFamily: 'inherit',
                                                        fontSize: '0.75rem',
                                                        whiteSpace: 'nowrap',
                                                    }}
                                                >
                                                    {row.keys}
                                                </kbd>
                                            </td>
                                            <td
                                                style={{
                                                    padding: '6px 0',
                                                    borderBottom: ROW_BORDER,
                                                    color: '#999',
                                                }}
                                            >
                                                {row.description}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}
