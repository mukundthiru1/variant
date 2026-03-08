/**
 * VARIANT — Terminal Lens
 *
 * The primary interface. Everything starts here.
 * Players boot into a terminal and can open other lenses
 * via escape sequences (browse, email, etc).
 *
 * This component:
 * 1. Creates an xterm.js Terminal instance
 * 2. Connects it to the VM's serial port via TerminalIO
 * 3. Intercepts OSC escape sequences for lens commands
 * 4. Manages terminal lifecycle (mount, resize, destroy)
 *
 * SECURITY: The terminal only renders output from the VM.
 * It cannot execute arbitrary JavaScript. xterm.js is a
 * terminal emulator, not a shell — it processes escape
 * sequences for display purposes only.
 */

import { useEffect, useRef, useCallback } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import type { TerminalIO } from '../core/vm/types';
import type { Unsubscribe } from '../core/events';

// ── OSC Escape Sequence Detection ──────────────────────────────

/**
 * Lens commands are sent as OSC (Operating System Command) sequences.
 * Format: ESC ] 7 7 7 ; command ; args BEL
 *
 * Examples from within the VM:
 *   echo -e '\e]777;browse;http://target.local\a'
 *   echo -e '\e]777;email;inbox\a'
 *   echo -e '\e]777;view;/var/log/auth.log\a'
 *
 * The 777 is our custom OSC code. We intercept these before
 * xterm.js processes them.
 */
const OSC_PREFIX = '\x1b]777;';
const OSC_TERMINATE = '\x07';

export interface LensCommand {
    readonly type: string;   // 'browse', 'email', 'view', 'map', etc.
    readonly args: string;
}

function parseOSCCommand(data: string): LensCommand | null {
    const start = data.indexOf(OSC_PREFIX);
    if (start === -1) return null;

    const payloadStart = start + OSC_PREFIX.length;
    const end = data.indexOf(OSC_TERMINATE, payloadStart);
    if (end === -1) return null;

    const payload = data.substring(payloadStart, end);
    const semicolonIdx = payload.indexOf(';');

    if (semicolonIdx === -1) {
        return { type: payload, args: '' };
    }

    return {
        type: payload.substring(0, semicolonIdx),
        args: payload.substring(semicolonIdx + 1),
    };
}

// ── Terminal Configuration ─────────────────────────────────────

const TERMINAL_OPTIONS = {
    fontFamily: '"JetBrains Mono", "Fira Code", "Cascadia Code", "SF Mono", monospace',
    fontSize: 14,
    lineHeight: 1.2,
    cursorBlink: true,
    cursorStyle: 'block' as const,
    scrollback: 5000,
    allowProposedApi: true,

    // Theme: dark with green accents (terminal aesthetic)
    theme: {
        background: '#0a0a0a',
        foreground: '#e0e0e0',
        cursor: '#D4A03A',
        cursorAccent: '#0a0a0a',
        selectionBackground: 'rgba(212, 160, 58, 0.19)',
        selectionForeground: '#ffffff',

        // ANSI colors
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

// ── Hook ───────────────────────────────────────────────────────

interface UseTerminalOptions {
    /** The TerminalIO handle from the VM backend. */
    readonly terminalIO: TerminalIO | null;

    /** Callback for lens commands intercepted from serial output. */
    readonly onLensCommand?: (command: LensCommand) => void;
}

interface UseTerminalResult {
    /** Ref to attach to the container div. */
    readonly containerRef: React.RefObject<HTMLDivElement | null>;

    /** The xterm Terminal instance (null until mounted). */
    readonly terminal: Terminal | null;
}

/**
 * React hook that manages a terminal instance.
 *
 * Usage:
 *   const { containerRef } = useTerminal({ terminalIO, onLensCommand });
 *   return <div ref={containerRef} style={{ width: '100%', height: '100%' }} />;
 */
export function useTerminal({
    terminalIO,
    onLensCommand,
}: UseTerminalOptions): UseTerminalResult {
    const containerRef = useRef<HTMLDivElement | null>(null);
    const terminalRef = useRef<Terminal | null>(null);
    const fitAddonRef = useRef<FitAddon | null>(null);
    const cleanupRef = useRef<Unsubscribe | null>(null);

    // ── Buffer for OSC sequence detection ──────────────────────
    const oscBufferRef = useRef<string>('');

    const handleVMOutput = useCallback((byte: number) => {
        const term = terminalRef.current;
        if (term === null) return;

        const char = String.fromCharCode(byte);

        // Buffer for OSC detection
        oscBufferRef.current += char;

        // Check for complete OSC command
        if (oscBufferRef.current.includes(OSC_TERMINATE)) {
            const command = parseOSCCommand(oscBufferRef.current);
            if (command !== null && onLensCommand !== undefined) {
                onLensCommand(command);
                // Clear the OSC sequence from output so it doesn't pollute the terminal
                oscBufferRef.current = '';
                return;
            }
            oscBufferRef.current = '';
        }

        // Limit buffer size to prevent memory growth
        if (oscBufferRef.current.length > 256) {
            oscBufferRef.current = oscBufferRef.current.slice(-64);
        }

        // Write byte to terminal display
        term.write(new Uint8Array([byte]));
    }, [onLensCommand]);

    // ── Mount / Unmount ────────────────────────────────────────
    useEffect(() => {
        const container = containerRef.current;
        if (container === null) return;

        // Create terminal
        const term = new Terminal(TERMINAL_OPTIONS);
        const fitAddon = new FitAddon();
        term.loadAddon(fitAddon);

        terminalRef.current = term;
        fitAddonRef.current = fitAddon;

        // Mount
        term.open(container);
        fitAddon.fit();

        // Welcome message (shown before VM connects)
        term.writeln('\x1b[32m╔══════════════════════════════════════════╗\x1b[0m');
        term.writeln('\x1b[32m║\x1b[0m          \x1b[1;32mVARIANT\x1b[0m Terminal             \x1b[32m║\x1b[0m');
        term.writeln('\x1b[32m╚══════════════════════════════════════════╝\x1b[0m');
        term.writeln('');
        term.writeln('\x1b[90mBooting virtual machine...\x1b[0m');
        term.writeln('');

        // Handle resize
        const resizeObserver = new ResizeObserver(() => {
            try {
                fitAddon.fit();
            } catch {
                // FitAddon can throw if the terminal is being torn down
            }
        });
        resizeObserver.observe(container);

        // Cleanup
        return () => {
            resizeObserver.disconnect();
            term.dispose();
            terminalRef.current = null;
            fitAddonRef.current = null;
        };
    }, []); // Mount once

    // ── Connect to VM I/O when terminalIO becomes available ────
    useEffect(() => {
        const term = terminalRef.current;
        if (term === null || terminalIO === null) return;

        // VM output → terminal display
        const unsubOutput = terminalIO.onOutput(handleVMOutput);
        cleanupRef.current = unsubOutput;

        // Terminal input → VM serial
        const disposable = term.onData((data: string) => {
            terminalIO.sendToVM(data);
        });

        return () => {
            unsubOutput();
            disposable.dispose();
            cleanupRef.current = null;
        };
    }, [terminalIO, handleVMOutput]);

    return {
        containerRef,
        terminal: terminalRef.current,
    };
}

// ── CSS for xterm.js ───────────────────────────────────────────

/**
 * Inject xterm.js CSS. We do this programmatically rather than
 * importing the CSS file to avoid Vite CSS processing issues
 * with the xterm.js package path.
 */
let cssInjected = false;
export function injectXtermCSS(): void {
    if (cssInjected) return;
    cssInjected = true;

    // Inject xterm CSS inline — avoids 404 in production builds
    // where node_modules is not served.
    const style = document.createElement('style');
    style.textContent = `
      .xterm {
        position: relative;
        user-select: none;
        cursor: text;
      }
      .xterm.focus, .xterm:focus {
        outline: none;
      }
      .xterm .xterm-viewport {
        overflow-y: scroll;
        cursor: default;
        position: absolute;
        right: 0;
        left: 0;
        top: 0;
        bottom: 0;
      }
      .xterm .xterm-screen {
        position: relative;
      }
      .xterm .xterm-screen canvas {
        position: absolute;
        left: 0;
        top: 0;
      }
      .xterm .xterm-cursor-layer {
        z-index: 4;
      }
    `;
    document.head.appendChild(style);
}
