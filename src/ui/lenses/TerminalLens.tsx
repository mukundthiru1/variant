/**
 * VARIANT — Terminal Lens
 *
 * The primary interface. Wraps xterm.js as a lens component.
 * The terminal connects to a VM's serial port via TerminalIO
 * and intercepts OSC escape sequences for lens commands
 * (e.g., `browse http://...` opens a browser lens).
 *
 * SECURITY: The terminal only renders VM output. It cannot
 * execute code on the host. xterm.js is a display emulator.
 */

import { useCallback, useEffect, useRef, useState, type CSSProperties, type MouseEvent } from 'react';
import { Terminal, type ITerminalOptions } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import type { TerminalIO } from '../../core/vm/types';
import type { LensContext } from '../lens/types';

// ── OSC Escape Sequence Detection ──────────────────────────────

const OSC_PREFIX = '\x1b]777;';
const OSC_TERMINATE = '\x07';
const TERMINAL_FONT_SIZE_STORAGE_KEY = 'variant.terminal.font-size';
const DEFAULT_TERMINAL_FONT_SIZE = 14;
const MIN_TERMINAL_FONT_SIZE = 10;
const MAX_TERMINAL_FONT_SIZE = 24;
const COPY_TERMINAL_LINE_COUNT = 50;

export interface TerminalLensProps {
    readonly terminalIO: TerminalIO | null;
    readonly lensContext: LensContext | null;
    readonly focused: boolean;
}

const TERMINAL_OPTIONS = {
    fontFamily: 'var(--font-mono)',
    fontSize: 14,
    lineHeight: 1.2,
    cursorBlink: true,
    cursorStyle: 'block' as const,
    scrollback: 5000,
    allowProposedApi: true,
} as const;

const getThemeValue = (name: string, fallback: string): string => {
    if (typeof window === 'undefined') {
        return fallback;
    }

    const value = getComputedStyle(document.documentElement)
        .getPropertyValue(name)
        .trim();

    return value || fallback;
};

const getSignalTheme = (): Exclude<ITerminalOptions['theme'], undefined> => ({
    background: getThemeValue('--bg-primary', '#0A0A0A'),
    foreground: getThemeValue('--gray-200', '#E0E0E0'),
    cursor: getThemeValue('--signal', '#D4A03A'),
    cursorAccent: getThemeValue('--bg-primary', '#0A0A0A'),
    selectionBackground: getThemeValue(
        '--signal-glow',
        'rgba(212, 160, 58, 0.25)',
    ),
    selectionForeground: getThemeValue('--text-primary', '#E6EDF3'),
    black: getThemeValue('--bg-primary', '#0A0A0A'),
    red: getThemeValue('--signal-boundary', '#C75450'),
    green: getThemeValue('--signal-success', '#3DA67A'),
    yellow: getThemeValue('--signal', '#D4A03A'),
    blue: getThemeValue('--signal-defense', '#4A9EFF'),
    magenta: getThemeValue('--purple', '#8B5CF6'),
    cyan: getThemeValue('--cyan', '#4ECDC4'),
    white: getThemeValue('--gray-200', '#E0E0E0'),
    brightBlack: getThemeValue('--gray-700', '#505050'),
    brightRed: getThemeValue('--signal', '#D4A03A'),
    brightGreen: getThemeValue('--signal-success', '#3DA67A'),
    brightYellow: getThemeValue('--signal', '#D4A03A'),
    brightBlue: getThemeValue('--signal-defense', '#4A9EFF'),
    brightMagenta: getThemeValue('--purple', '#8B5CF6'),
    brightCyan: getThemeValue('--cyan', '#4ECDC4'),
    brightWhite: getThemeValue('--text-primary', '#E6EDF3'),
});

const collectVisibleBufferText = (term: Terminal): string => {
    const buffer = term.buffer.active;
    const lines: string[] = [];

    for (let lineIndex = 0; lineIndex < buffer.length; lineIndex += 1) {
        const line = buffer.getLine(lineIndex);
        if (line === undefined) {
            continue;
        }

        lines.push(line.translateToString(true));
    }

    return lines.join('\n').trimEnd();
};

const clampTerminalFontSize = (value: number): number =>
    Math.max(MIN_TERMINAL_FONT_SIZE, Math.min(MAX_TERMINAL_FONT_SIZE, Math.round(value)));

const getStoredTerminalFontSize = (): number => {
    if (typeof window === 'undefined') {
        return DEFAULT_TERMINAL_FONT_SIZE;
    }

    const stored = window.localStorage.getItem(TERMINAL_FONT_SIZE_STORAGE_KEY);
    if (stored === null) {
        return DEFAULT_TERMINAL_FONT_SIZE;
    }

    const parsed = Number.parseInt(stored, 10);
    if (!Number.isFinite(parsed)) {
        return DEFAULT_TERMINAL_FONT_SIZE;
    }

    return clampTerminalFontSize(parsed);
};

const collectLastBufferLines = (term: Terminal, maxLines: number): string => {
    const buffer = term.buffer.active;
    const totalLines = buffer.length;
    const startLine = Math.max(0, totalLines - Math.max(1, maxLines));
    const lines: string[] = [];

    for (let lineIndex = startLine; lineIndex < totalLines; lineIndex += 1) {
        const line = buffer.getLine(lineIndex);
        if (line === undefined) {
            continue;
        }

        lines.push(line.translateToString(true));
    }

    return lines.join('\n').trimEnd();
};

const headerButtonStyle: CSSProperties = {
    minHeight: '24px',
    padding: '0 var(--space-2)',
    borderRadius: 'var(--radius-sm)',
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontFamily: 'var(--font-mono)',
    fontSize: 'var(--size-xs)',
    color: 'var(--signal)',
    background: 'var(--bg-surface)',
    border: '1px solid var(--border-default)',
};

export function TerminalLens({ terminalIO, lensContext, focused }: TerminalLensProps): JSX.Element {
    const rootRef = useRef<HTMLDivElement | null>(null);
    const terminalHostRef = useRef<HTMLDivElement | null>(null);
    const terminalInstanceRef = useRef<Terminal | null>(null);
    const fitAddonRef = useRef<FitAddon | null>(null);
    const oscBufferRef = useRef<string>('');
    const fitTickRef = useRef<number>(0);
    const copyFlashTimeoutRef = useRef<number>(0);
    const [isTerminalFullscreen, setIsTerminalFullscreen] = useState(false);
    const [fontSize, setFontSize] = useState<number>(() => getStoredTerminalFontSize());
    const [copyFlashActive, setCopyFlashActive] = useState(false);

    const requestTerminalFit = useCallback(() => {
        if (fitTickRef.current !== 0) {
            return;
        }

        fitTickRef.current = requestAnimationFrame(() => {
            fitTickRef.current = 0;
            const fitAddon = fitAddonRef.current;
            if (fitAddon === null) {
                return;
            }

            try {
                fitAddon.fit();
            } catch {
                /* teardown race */
            }
        });
    }, []);

    const requestCopyFallback = useCallback((content: string) => {
        const textarea = document.createElement('textarea');
        textarea.value = content;
        textarea.setAttribute('readonly', '');
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        textarea.style.left = '-9999px';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
    }, []);

    const triggerCopyFlash = useCallback(() => {
        if (copyFlashTimeoutRef.current !== 0) {
            window.clearTimeout(copyFlashTimeoutRef.current);
        }

        setCopyFlashActive(true);
        copyFlashTimeoutRef.current = window.setTimeout(() => {
            setCopyFlashActive(false);
            copyFlashTimeoutRef.current = 0;
        }, 500);
    }, []);

    const handleCopyToClipboard = useCallback(() => {
        const term = terminalInstanceRef.current;
        if (term === null) {
            return;
        }

        const content =
            collectLastBufferLines(term, COPY_TERMINAL_LINE_COUNT) ||
            collectVisibleBufferText(term);
        if (content.length === 0) {
            return;
        }

        if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
            navigator.clipboard
                .writeText(content)
                .then(() => {
                    triggerCopyFlash();
                })
                .catch(() => {
                    requestCopyFallback(content);
                    triggerCopyFlash();
                });
        } else {
            requestCopyFallback(content);
            triggerCopyFlash();
        }
    }, [requestCopyFallback, triggerCopyFlash]);

    const handleClearTerminal = useCallback(() => {
        const term = terminalInstanceRef.current;
        if (term === null) {
            return;
        }

        term.clear();
    }, []);

    const handleIncreaseFontSize = useCallback(() => {
        setFontSize((current) => clampTerminalFontSize(current + 1));
    }, []);

    const handleDecreaseFontSize = useCallback(() => {
        setFontSize((current) => clampTerminalFontSize(current - 1));
    }, []);

    // ── Handle VM output with OSC interception ──────────────────
    const handleVMOutput = useCallback((byte: number) => {
        const term = terminalInstanceRef.current;
        if (term === null) return;

        const char = String.fromCharCode(byte);
        oscBufferRef.current += char;

        if (oscBufferRef.current.includes(OSC_TERMINATE)) {
            const start = oscBufferRef.current.indexOf(OSC_PREFIX);
            if (start !== -1) {
                const payloadStart = start + OSC_PREFIX.length;
                const end = oscBufferRef.current.indexOf(OSC_TERMINATE, payloadStart);
                if (end !== -1) {
                    const payload = oscBufferRef.current.substring(payloadStart, end);
                    const semicolonIdx = payload.indexOf(';');
                    const type = semicolonIdx === -1 ? payload : payload.substring(0, semicolonIdx);
                    const args = semicolonIdx === -1 ? '' : payload.substring(semicolonIdx + 1);

                    if (lensContext !== null) {
                        lensContext.requestOpenLens({
                            type,
                            config: { url: args, initialUrl: args },
                        });
                    }
                    oscBufferRef.current = '';
                    return;
                }
            }
            oscBufferRef.current = '';
        }

        if (oscBufferRef.current.length > 256) {
            oscBufferRef.current = oscBufferRef.current.slice(-64);
        }

        term.write(new Uint8Array([byte]));
    }, [lensContext]);

    // ── Mount terminal ──────────────────────────────────────────
    useEffect(() => {
        const container = terminalHostRef.current;
        if (container === null) {
            return;
        }

        const term = new Terminal({ ...TERMINAL_OPTIONS, theme: getSignalTheme() });
        const fitAddon = new FitAddon();
        term.loadAddon(fitAddon);

        terminalInstanceRef.current = term;
        fitAddonRef.current = fitAddon;

        term.open(container);
        requestTerminalFit();

        container.style.scrollBehavior = 'smooth';

        const viewport = term.element?.querySelector('.xterm-viewport');
        if (viewport instanceof HTMLElement) {
            viewport.style.scrollBehavior = 'smooth';
        }

        term.writeln('\x1b[32m VARIANT Terminal \x1b[0m');
        term.writeln('\x1b[90mConnecting to virtual machine...\x1b[0m');
        term.writeln('');

        const handleTerminalOutput = () => {
            requestTerminalFit();
        };

        const resizeObserver = new ResizeObserver(() => {
            handleTerminalOutput();
        });
        resizeObserver.observe(container);
        window.addEventListener('resize', handleTerminalOutput);

        return () => {
            resizeObserver.disconnect();
                window.removeEventListener('resize', handleTerminalOutput);
                if (fitTickRef.current !== 0) {
                    cancelAnimationFrame(fitTickRef.current);
                    fitTickRef.current = 0;
                }
                term.dispose();
                terminalInstanceRef.current = null;
                fitAddonRef.current = null;
        };
    }, [requestTerminalFit]);

    useEffect(() => {
        if (typeof window === 'undefined') {
            return;
        }

        window.localStorage.setItem(TERMINAL_FONT_SIZE_STORAGE_KEY, String(fontSize));
    }, [fontSize]);

    useEffect(() => {
        return () => {
            if (copyFlashTimeoutRef.current !== 0) {
                window.clearTimeout(copyFlashTimeoutRef.current);
                copyFlashTimeoutRef.current = 0;
            }
        };
    }, []);

    useEffect(() => {
        const term = terminalInstanceRef.current;
        if (term === null) {
            return;
        }

        term.options.fontSize = fontSize;
        requestTerminalFit();
    }, [fontSize, requestTerminalFit]);

    useEffect(() => {
        const root = rootRef.current;
        if (root === null || typeof document === 'undefined') {
            return;
        }

        const handleFullscreenChange = () => {
            const isFs =
                typeof document.fullscreenElement !== 'undefined' &&
                document.fullscreenElement === root;
            setIsTerminalFullscreen(isFs);
            requestTerminalFit();
            return isFs;
        };

        handleFullscreenChange();
        document.addEventListener('fullscreenchange', handleFullscreenChange);
        return () => {
            document.removeEventListener('fullscreenchange', handleFullscreenChange);
        };
    }, [requestTerminalFit]);

    const handleToggleFullscreen = useCallback(() => {
        const root = rootRef.current;
        if (root === null || typeof document === 'undefined') {
            return;
        }

        if (document.fullscreenElement === null) {
            if (root.requestFullscreen) {
                root.requestFullscreen().catch(() => undefined);
            }
            return;
        }

        if (document.exitFullscreen) {
            document.exitFullscreen().catch(() => undefined);
        }
    }, []);

    const handleFontControlMouseEnter = useCallback(
        (event: MouseEvent<HTMLButtonElement>) => {
            if (event.currentTarget.disabled) {
                return;
            }

            event.currentTarget.style.filter = 'brightness(1.22)';
        },
        [],
    );

    const handleFontControlMouseLeave = useCallback((event: MouseEvent<HTMLButtonElement>) => {
        event.currentTarget.style.filter = 'brightness(1)';
    }, []);

    // ── Connect to VM I/O ───────────────────────────────────────
    useEffect(() => {
        const term = terminalInstanceRef.current;
        if (term === null || terminalIO === null) return;

        const unsubOutput = terminalIO.onOutput(handleVMOutput);
        const disposable = term.onData((data: string) => {
            terminalIO.sendToVM(data);
        });

        return () => {
            unsubOutput();
            disposable.dispose();
        };
    }, [terminalIO, handleVMOutput]);

    // ── Focus management ────────────────────────────────────────
    useEffect(() => {
        if (focused && terminalInstanceRef.current !== null) {
            terminalInstanceRef.current.focus();
        }
    }, [focused]);

    // ── Re-fit on any resize ────────────────────────────────────
    useEffect(() => {
        if (fitAddonRef.current !== null) {
            requestTerminalFit();
        }
    }, [requestTerminalFit]);

    const machineHostname = lensContext?.instance.targetMachine ?? 'unknown-host';
    const isConnected = terminalIO !== null;
    const canDecreaseFontSize = fontSize > MIN_TERMINAL_FONT_SIZE;
    const canIncreaseFontSize = fontSize < MAX_TERMINAL_FONT_SIZE;

    return (
        <div
            ref={rootRef}
            className="terminal-container"
            style={{
                width: '100%',
                height: '100%',
                minHeight: 0,
                display: 'flex',
                flexDirection: 'column',
                color: 'var(--text-primary)',
                background: 'var(--bg-primary)',
                overflow: 'hidden',
                position: 'relative',
                border: focused ? '1px solid rgba(212, 160, 58, 0.2)' : '1px solid rgba(212, 160, 58, 0.08)',
                borderTop: focused ? '1px solid rgba(212, 160, 58, 0.3)' : '1px solid rgba(212, 160, 58, 0.08)',
                boxShadow: focused ? '0 0 0 1px rgba(212, 160, 58, 0.15), 0 0 22px rgba(212, 160, 58, 0.15)' : 'none',
            }}
        >
            <style>
                {`
                    @keyframes terminal-connected-pulse {
                        0%, 100% { transform: scale(1); opacity: 0.94; }
                        50% { transform: scale(1.08); opacity: 1; }
                    }
                `}
            </style>
            <div
                style={{
                    height: '36px',
                    padding: '0 var(--space-2)',
                    flexShrink: 0,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: 'var(--space-2)',
                    borderBottom: '1px solid var(--border-default)',
                    background: 'var(--bg-secondary)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: 'var(--size-sm)',
                }}
            >
                <div
                    style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 'var(--space-2)',
                    }}
                >
                    <div
                        style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '6px',
                            padding: '2px 0',
                            color: '#e0e0e0',
                            fontSize: '11px',
                            letterSpacing: '0.01em',
                            fontFamily: 'var(--font-mono)',
                        }}
                        title={isConnected ? `Connected to ${machineHostname}` : `Disconnected from ${machineHostname}`}
                    >
                        <span
                            style={{
                                width: '8px',
                                height: '8px',
                                borderRadius: '50%',
                                background: isConnected ? '#3DA67A' : '#C75450',
                                boxShadow: isConnected ? '0 0 8px rgba(61, 166, 122, 0.35)' : '0 0 8px rgba(199, 84, 80, 0.35)',
                                animation: isConnected ? 'terminal-connected-pulse 1.8s ease-in-out infinite' : 'none',
                                flexShrink: 0,
                            }}
                        />
                        <span style={{ textAlign: 'left' }}>{machineHostname}</span>
                    </div>
                </div>
                <div
                    style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 'var(--space-2)',
                    }}
                >
                    <div
                        style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px',
                            padding: '2px',
                            borderRadius: 'var(--radius-sm)',
                            border: '1px solid rgba(212, 160, 58, 0.2)',
                            background: '#0a0a0a',
                        }}
                    >
                        <button
                            type="button"
                            className="hint-button"
                            onClick={handleDecreaseFontSize}
                            style={headerButtonStyle}
                            title="Decrease terminal font size"
                            disabled={!canDecreaseFontSize}
                            onMouseEnter={handleFontControlMouseEnter}
                            onMouseLeave={handleFontControlMouseLeave}
                        >
                            A-
                        </button>
                        <span
                            style={{
                                minWidth: '28px',
                                textAlign: 'center',
                                color: '#e0e0e0',
                                fontSize: '11px',
                            }}
                            title={`Current font size: ${fontSize}px`}
                        >
                            {fontSize}
                        </span>
                        <button
                            type="button"
                            className="hint-button"
                            onClick={handleIncreaseFontSize}
                            style={headerButtonStyle}
                            title="Increase terminal font size"
                            disabled={!canIncreaseFontSize}
                            onMouseEnter={handleFontControlMouseEnter}
                            onMouseLeave={handleFontControlMouseLeave}
                        >
                            A+
                        </button>
                    </div>
                    <button
                        type="button"
                        className="hint-button"
                        onClick={handleCopyToClipboard}
                        style={{
                            ...headerButtonStyle,
                            color: copyFlashActive ? '#0a0a0a' : headerButtonStyle.color,
                            background: copyFlashActive ? 'rgba(61, 166, 122, 0.92)' : headerButtonStyle.background,
                            border: copyFlashActive ? '1px solid rgba(61, 166, 122, 1)' : headerButtonStyle.border,
                            transition: 'background 180ms ease, color 180ms ease, border-color 180ms ease',
                        }}
                        title={`Copy last ${COPY_TERMINAL_LINE_COUNT} lines`}
                    >
                        Copy
                    </button>
                    <button
                        type="button"
                        className="hint-button"
                        onClick={handleClearTerminal}
                        style={headerButtonStyle}
                        title="Clear terminal"
                    >
                        Clear
                    </button>
                    <button
                        type="button"
                        className="hint-button"
                        onClick={handleToggleFullscreen}
                        style={headerButtonStyle}
                        title="Toggle fullscreen"
                    >
                        {isTerminalFullscreen ? 'Exit full screen' : 'Full screen'}
                    </button>
                </div>
            </div>
            <div
                style={{
                    flex: '1 1 auto',
                    minHeight: 0,
                    width: '100%',
                    overflow: 'hidden',
                    scrollBehavior: 'smooth',
                    background: '#0a0a0a',
                    backgroundColor: '#0a0a0a',
                    position: 'relative',
                }}
            >
                <div
                    ref={terminalHostRef}
                    style={{
                        height: '100%',
                        width: '100%',
                        overflow: 'hidden',
                        scrollBehavior: 'smooth',
                        background: '#0a0a0a',
                        backgroundColor: '#0a0a0a',
                    }}
                />
            </div>
        </div>
    );
}
