/**
 * VARIANT — Scripted Shell Contract
 *
 * Interface for a POSIX-like shell that operates against
 * a VirtualFilesystem. Used by Simulacra to handle SSH
 * sessions and terminal interaction.
 *
 * DESIGN: Zero dependencies on core/. Depends only on
 * VFS types. The shell is a pure function:
 *   (command, state) → (output, newState)
 *
 * Replace the implementation in 20 years.
 * This interface stays.
 */

import type { VirtualFilesystem } from '../vfs/types';
import type { ServiceConfig } from '../../core/world/types';

// ── Shell interface ────────────────────────────────────────────

/**
 * A scripted shell that processes commands against a VFS.
 *
 * Implementations must:
 *   1. Support a core set of POSIX commands (ls, cat, cd, pwd, etc.)
 *   2. Be deterministic (no randomness except explicit seeds)
 *   3. Track state (cwd, user, env vars)
 *   4. Support custom command registration
 *   5. Never execute host code
 */
export interface ScriptedShell {
    /** Process a command line. Returns output text + exit code. */
    execute(command: string): ShellResult;

    /** Get the current working directory. */
    getCwd(): string;

    /** Get the current user. */
    getUser(): string;

    /** Get the hostname. */
    getHostname(): string;

    /** Update the hostname (e.g., after overlay applies /etc/hostname). */
    setHostname(name: string): void;

    /** Update the current user (e.g., after overlay applies user config). */
    setUser(name: string): void;

    /** Get the shell prompt string. */
    getPrompt(): string;

    /** Get an environment variable. */
    getEnv(key: string): string | undefined;

    /** Set an environment variable. */
    setEnv(key: string, value: string): void;

    /** Register a custom command handler. */
    registerCommand(name: string, handler: CommandHandler): void;

    /** Check if a command exists. */
    hasCommand(name: string): boolean;

    /** Get the underlying VFS (read-only access for inspection). */
    getVFS(): VirtualFilesystem;

    /** Set the event emitter (for late-binding after engine creates EventBus). */
    setEmit(emit: (event: { type: string; [key: string]: unknown }) => void): void;
}

// ── Result type ────────────────────────────────────────────────

export interface ShellResult {
    /** Output text (stdout + stderr combined). */
    readonly output: string;
    /** Exit code. 0 = success. */
    readonly exitCode: number;
}

// ── Command handler ────────────────────────────────────────────

/**
 * A command handler receives parsed arguments and the shell context.
 * Returns output text and exit code.
 *
 * stdin is provided when the command is on the receiving end of a pipe.
 * Commands that support piped input should read from stdin when no
 * file argument is given.
 */
export type CommandHandler = (
    args: readonly string[],
    ctx: CommandContext,
    stdin?: string,
) => ShellResult;

/**
 * Context passed to command handlers.
 * Provides access to VFS and shell state without exposing internals.
 */
export interface CommandContext {
    readonly vfs: VirtualFilesystem;
    readonly cwd: string;
    readonly user: string;
    readonly hostname: string;
    readonly env: ReadonlyMap<string, string>;
    /** Resolve a path relative to cwd. */
    resolvePath(path: string): string;
    /** Service configuration for network commands (ss, nmap, etc.) */
    readonly services?: readonly ServiceConfig[];
    /** Emit events for auth and network actions */
    emit?(event: { type: string; [key: string]: unknown }): void;
    /** User specifications for auth commands (sudo, su, ssh) */
    readonly users?: readonly UserSpec[];
    /**
     * Resolve a target host (IP or hostname) to its services.
     * Used by nmap, curl, ssh to query remote machine state.
     * Returns undefined if the host is unreachable or unknown.
     */
    resolveRemoteServices?(host: string): readonly ServiceConfig[] | undefined;
    /**
     * Resolve a target host to its hostname.
     * Used by ssh to show the correct prompt after connecting.
     */
    resolveRemoteHostname?(host: string): string | undefined;
}

/** User specification for auth commands */
export interface UserSpec {
    readonly username: string;
    readonly password?: string;
    readonly groups?: readonly string[];
    readonly sudo?: boolean;
}

// ── Shell configuration ────────────────────────────────────────

export interface ShellConfig {
    /** VFS to operate against. */
    readonly vfs: VirtualFilesystem;
    /** Initial working directory. Default: '/root' or '/home/<user>'. */
    readonly cwd?: string;
    /** User running the shell. Default: 'root'. */
    readonly user?: string;
    /** Hostname for prompt. Default: 'localhost'. */
    readonly hostname?: string;
    /** Initial environment variables. */
    readonly env?: ReadonlyMap<string, string>;
    /** Custom commands to register at init. */
    readonly customCommands?: ReadonlyMap<string, CommandHandler>;
    /** Service configuration for network commands. */
    readonly services?: readonly ServiceConfig[];
    /** Emit events for auth and network actions. */
    emit?(event: { type: string; [key: string]: unknown }): void;
    /** User specifications for auth commands. */
    readonly users?: readonly UserSpec[];
    /** Resolve remote host to its services (for nmap, curl, ssh). */
    resolveRemoteServices?(host: string): readonly ServiceConfig[] | undefined;
    /** Resolve remote host to its hostname (for ssh prompt). */
    resolveRemoteHostname?(host: string): string | undefined;
}
