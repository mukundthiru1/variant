/**
 * VARIANT — Settings / About
 *
 * Theme, keyboard shortcuts reference, and About section.
 * Accessible from any screen.
 */

import type { CSSProperties } from 'react';

const VERSION = '0.1.0';
const FONT = '"JetBrains Mono", "Fira Code", monospace';
const COLORS = {
    bg: '#0a0a0a',
    surface: '#0d0d0d',
    text: '#e0e0e0',
    muted: '#666',
    accent: '#D4A03A',
    border: '#1a1a2e',
} as const;

const SHORTCUTS = [
    { keys: 'Ctrl+Shift+T', action: 'New terminal' },
    { keys: 'Ctrl+Shift+B', action: 'Open browser' },
    { keys: 'Ctrl+Shift+E', action: 'Open email' },
    { keys: 'Ctrl+Shift+F', action: 'Open file manager' },
    { keys: 'Ctrl+Shift+L', action: 'Open log viewer' },
    { keys: 'Ctrl+Shift+N', action: 'Open network map' },
    { keys: 'Ctrl+Shift+P', action: 'Open process viewer' },
    { keys: 'Ctrl+Shift+K', action: 'Open packet capture' },
    { keys: 'Ctrl+Tab', action: 'Next lens' },
    { keys: 'Ctrl+Shift+Tab', action: 'Previous lens' },
    { keys: 'Ctrl+W', action: 'Close focused lens' },
    { keys: 'F11', action: 'Toggle maximize lens' },
    { keys: 'Escape', action: 'Restore maximized lens' },
    { keys: 'Ctrl+H', action: 'Toggle hint panel' },
    { keys: 'Ctrl+?', action: 'Toggle help overlay' },
] as const;

export interface SettingsPageProps {
    readonly onBack: () => void;
}

export function SettingsPage({ onBack }: SettingsPageProps): JSX.Element {
    const pageStyle: CSSProperties = {
        minHeight: '100vh',
        background: COLORS.bg,
        color: COLORS.text,
        fontFamily: FONT,
        padding: '2rem 1.5rem',
        boxSizing: 'border-box',
    };

    const sectionStyle: CSSProperties = {
        maxWidth: '640px',
        margin: '0 auto 2rem',
        padding: '1.5rem',
        background: COLORS.surface,
        border: `1px solid ${COLORS.border}`,
        borderRadius: '2px',
    };

    const h2Style: CSSProperties = {
        fontSize: '1rem',
        fontWeight: 700,
        color: COLORS.accent,
        margin: '0 0 1rem 0',
        letterSpacing: '0.02em',
    };

    return (
        <div style={pageStyle}>
            <div style={{ maxWidth: '640px', margin: '0 auto' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
                    <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: COLORS.accent, margin: 0 }}>
                        Settings
                    </h1>
                    <button
                        type="button"
                        onClick={onBack}
                        style={{
                            background: 'transparent',
                            border: `1px solid ${COLORS.border}`,
                            color: COLORS.text,
                            padding: '6px 16px',
                            fontFamily: FONT,
                            fontSize: '0.8rem',
                            cursor: 'pointer',
                            borderRadius: '2px',
                        }}
                    >
                        Back
                    </button>
                </div>

                <section style={sectionStyle}>
                    <h2 style={h2Style}>Theme</h2>
                    <p style={{ fontSize: '0.85rem', color: COLORS.muted, margin: 0 }}>
                        Dark theme only (light theme coming later).
                    </p>
                </section>

                <section style={sectionStyle}>
                    <h2 style={h2Style}>Keyboard shortcuts</h2>
                    <table style={{ width: '100%', fontSize: '0.8rem', borderCollapse: 'collapse' }}>
                        <tbody>
                            {SHORTCUTS.map(({ keys, action }) => (
                                <tr key={keys}>
                                    <td style={{ padding: '6px 12px 6px 0', color: COLORS.accent, fontFamily: 'inherit' }}>
                                        <kbd style={{
                                            background: COLORS.bg,
                                            padding: '2px 6px',
                                            borderRadius: '2px',
                                            border: `1px solid ${COLORS.border}`,
                                        }}>
                                            {keys}
                                        </kbd>
                                    </td>
                                    <td style={{ padding: '6px 0', color: COLORS.text }}>{action}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </section>

                <section style={sectionStyle}>
                    <h2 style={h2Style}>About</h2>
                    <p style={{ fontSize: '0.85rem', color: COLORS.text, margin: '0 0 0.75rem 0' }}>
                        <strong>VARIANT</strong> v{VERSION} — Security Simulation Engine
                    </p>
                    <p style={{ fontSize: '0.8rem', color: COLORS.muted, margin: '0 0 0.5rem 0' }}>
                        Tech: React, TypeScript, v86 (x86 emulator), client-side only.
                    </p>
                    <p style={{ fontSize: '0.8rem', color: COLORS.muted, margin: 0 }}>
                        By Santh. Levels and scenarios run entirely in your browser.
                    </p>
                </section>
            </div>
        </div>
    );
}
