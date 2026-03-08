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

import { useEffect, useRef, useCallback } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import type { TerminalIO } from '../../core/vm/types';
import type { LensContext } from '../lens/types';

// ── OSC Escape Sequence Detection ──────────────────────────────

const OSC_PREFIX = '\x1b]777;';
const OSC_TERMINATE = '\x07';

export interface TerminalLensProps {
    readonly terminalIO: TerminalIO | null;
    readonly lensContext: LensContext | null;
    readonly focused: boolean;
}

const TERMINAL_OPTIONS = {
    fontFamily: '"JetBrains Mono", "Fira Code", "Cascadia Code", "SF Mono", monospace',
    fontSize: 14,
    lineHeight: 1.2,
    cursorBlink: true,
    cursorStyle: 'block' as const,
    scrollback: 5000,
    allowProposedApi: true,
    theme: {
        background: '#0a0e14',
        foreground: '#e0e0e0',
        cursor: '#D4A03A',
        cursorAccent: '#0a0e14',
        selectionBackground: 'rgba(212, 160, 58, 0.19)',
        selectionForeground: '#ffffff',
        black: '#0a0a0a',
        red: '#ff5555',
        green: '#3DA67A',
        yellow: '#f1fa8c',
        blue: '#6272a4',
        magenta: '#ff79c6',
        cyan: '#8be9fd',
        white: '#e0e0e0',
        brightBlack: '#44475a',
        brightRed: '#ff6e6e',
        brightGreen: '#69ff94',
        brightYellow: '#ffffa5',
        brightBlue: '#d6acff',
        brightMagenta: '#ff92df',
        brightCyan: '#a4ffff',
        brightWhite: '#ffffff',
    },
} as const;

export function TerminalLens({ terminalIO, lensContext, focused }: TerminalLensProps): JSX.Element {
    const containerRef = useRef<HTMLDivElement | null>(null);
    const terminalRef = useRef<Terminal | null>(null);
    const fitAddonRef = useRef<FitAddon | null>(null);
    const oscBufferRef = useRef<string>('');

    // ── Handle VM output with OSC interception ──────────────────
    const handleVMOutput = useCallback((byte: number) => {
        const term = terminalRef.current;
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
        const container = containerRef.current;
        if (container === null) return;

        const term = new Terminal(TERMINAL_OPTIONS);
        const fitAddon = new FitAddon();
        term.loadAddon(fitAddon);

        terminalRef.current = term;
        fitAddonRef.current = fitAddon;

        term.open(container);
        fitAddon.fit();

        term.writeln('\x1b[32m VARIANT Terminal \x1b[0m');
        term.writeln('\x1b[90mConnecting to virtual machine...\x1b[0m');
        term.writeln('');

        const resizeObserver = new ResizeObserver(() => {
            try { fitAddon.fit(); } catch { /* teardown race */ }
        });
        resizeObserver.observe(container);

        return () => {
            resizeObserver.disconnect();
            term.dispose();
            terminalRef.current = null;
            fitAddonRef.current = null;
        };
    }, []);

    // ── Connect to VM I/O ───────────────────────────────────────
    useEffect(() => {
        const term = terminalRef.current;
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
        if (focused && terminalRef.current !== null) {
            terminalRef.current.focus();
        }
    }, [focused]);

    // ── Re-fit on any resize ────────────────────────────────────
    useEffect(() => {
        if (fitAddonRef.current !== null) {
            try { fitAddonRef.current.fit(); } catch { /* race */ }
        }
    });

    return (
        <div
            ref={containerRef}
            style={{
                width: '100%',
                height: '100%',
                background: '#0a0e14',
                overflow: 'hidden',
            }}
        />
    );
}
