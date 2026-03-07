/**
 * VARIANT — Package Mirror Simulacrum
 *
 * Simulates a package manager mirror (apk, apt, pip, npm).
 * Level designers control:
 *   - Which packages are available
 *   - Which packages have backdoors
 *   - What happens when a package is installed
 *
 * When the player runs `apk add <pkg>` or `pip install <pkg>`,
 * the shell command is intercepted and the mirror provides
 * VFS overlays that simulate the installation.
 *
 * DESIGN: Pure functions. No side effects outside VFS.
 * Implements CommandHandler interface for shell integration.
 */

import type { CommandHandler, ShellResult, CommandContext } from '../shell/types';

// ── Types ──────────────────────────────────────────────────────

export type PackageManagerType = 'apk' | 'apt' | 'pip' | 'npm' | 'gem' | 'cargo' | 'custom';

export interface PackageDefinition {
    /** Package name. */
    readonly name: string;
    /** Version string. */
    readonly version: string;
    /** Description shown in search. */
    readonly description: string;
    /** Files this package "installs" (path → content). */
    readonly files: ReadonlyMap<string, PackageFile>;
    /**
     * If true, this package contains a backdoor.
     * The backdoor behavior is defined in the files.
     */
    readonly backdoored: boolean;
    /** Backdoor description (shown post-detection or in hints). */
    readonly backdoorDescription?: string;
    /** Dependencies that must be installed first. */
    readonly dependencies?: readonly string[];
    /** Size in human-readable form (e.g., '2.3 MB'). */
    readonly size?: string;
}

export interface PackageFile {
    readonly content: string;
    readonly mode?: number;
    readonly owner?: string;
}

export interface PackageMirrorConfig {
    /** Package manager type. */
    readonly type: PackageManagerType;
    /** Available packages. */
    readonly packages: readonly PackageDefinition[];
    /** Packages pre-installed in the base image. */
    readonly installed?: readonly string[];
}

// ── Factory ────────────────────────────────────────────────────

export function createPackageMirror(config: PackageMirrorConfig): PackageMirrorCommands {
    const packages = new Map<string, PackageDefinition>();
    for (const pkg of config.packages) {
        packages.set(pkg.name, pkg);
    }

    const installed = new Set<string>(config.installed ?? []);

    // ── APK commands ───────────────────────────────────────────

    function apkAdd(args: readonly string[], ctx: CommandContext): ShellResult {
        const pkgNames = args.filter(a => !a.startsWith('-'));
        if (pkgNames.length === 0) return { output: 'Usage: apk add PACKAGE...\n', exitCode: 1 };

        const output: string[] = [];

        for (const name of pkgNames) {
            const pkg = packages.get(name);
            if (pkg === undefined) {
                output.push(`ERROR: unable to select packages:`);
                output.push(`  ${name} (no such package):`);
                return { output: output.join('\n') + '\n', exitCode: 1 };
            }

            // Check dependencies
            if (pkg.dependencies !== undefined) {
                for (const dep of pkg.dependencies) {
                    if (!installed.has(dep)) {
                        const depPkg = packages.get(dep);
                        if (depPkg !== undefined) {
                            installPackage(depPkg, ctx, output);
                        }
                    }
                }
            }

            installPackage(pkg, ctx, output);
        }

        output.push('OK: packages installed');
        return { output: output.join('\n') + '\n', exitCode: 0 };
    }

    function apkSearch(args: readonly string[], _ctx: CommandContext): ShellResult {
        const query = args.find(a => !a.startsWith('-')) ?? '';
        const results: string[] = [];

        for (const pkg of packages.values()) {
            if (pkg.name.includes(query) || pkg.description.toLowerCase().includes(query.toLowerCase())) {
                results.push(`${pkg.name}-${pkg.version} - ${pkg.description}`);
            }
        }

        if (results.length === 0) return { output: '', exitCode: 0 };
        return { output: results.join('\n') + '\n', exitCode: 0 };
    }

    function apkInfo(args: readonly string[], _ctx: CommandContext): ShellResult {
        const name = args.find(a => !a.startsWith('-'));
        if (name === undefined) {
            // List installed packages
            const lines = [...installed].map(n => {
                const pkg = packages.get(n);
                return pkg !== undefined ? `${pkg.name}-${pkg.version}` : n;
            });
            return { output: lines.join('\n') + '\n', exitCode: 0 };
        }

        const pkg = packages.get(name);
        if (pkg === undefined) return { output: `${name}: not installed\n`, exitCode: 1 };

        return {
            output: [
                `${pkg.name}-${pkg.version} description:`,
                pkg.description,
                ``,
                `${pkg.name}-${pkg.version} installed size:`,
                pkg.size ?? '1.2 MB',
            ].join('\n') + '\n',
            exitCode: 0,
        };
    }

    function installPackage(pkg: PackageDefinition, ctx: CommandContext, output: string[]): void {
        if (installed.has(pkg.name)) {
            output.push(`(${pkg.name} is already installed)`);
            return;
        }

        output.push(`(1/1) Installing ${pkg.name} (${pkg.version})`);

        // Write package files to VFS
        for (const [path, file] of pkg.files) {
            ctx.vfs.writeFile(path, file.content, {
                mode: file.mode,
                owner: file.owner,
            });
        }

        installed.add(pkg.name);
    }

    // ── APT commands ───────────────────────────────────────────

    function aptInstall(args: readonly string[], ctx: CommandContext): ShellResult {
        const pkgNames = args.filter(a => !a.startsWith('-'));
        if (pkgNames.length === 0) return { output: 'E: Unable to locate package\n', exitCode: 100 };

        const output: string[] = [
            'Reading package lists... Done',
            'Building dependency tree... Done',
        ];

        for (const name of pkgNames) {
            const pkg = packages.get(name);
            if (pkg === undefined) {
                output.push(`E: Unable to locate package ${name}`);
                return { output: output.join('\n') + '\n', exitCode: 100 };
            }

            output.push(`The following NEW packages will be installed:`);
            output.push(`  ${pkg.name}`);
            output.push(`0 upgraded, 1 newly installed, 0 to remove.`);
            output.push(`Setting up ${pkg.name} (${pkg.version}) ...`);

            installPackage(pkg, ctx, output);
        }

        return { output: output.join('\n') + '\n', exitCode: 0 };
    }

    // ── PIP commands ───────────────────────────────────────────

    function pipInstall(args: readonly string[], ctx: CommandContext): ShellResult {
        const pkgNames = args.filter(a => !a.startsWith('-'));
        if (pkgNames.length === 0) return { output: 'Usage: pip install PACKAGE...\n', exitCode: 1 };

        const output: string[] = [];

        for (const name of pkgNames) {
            const pkg = packages.get(name);
            if (pkg === undefined) {
                output.push(`ERROR: Could not find a version that satisfies the requirement ${name}`);
                return { output: output.join('\n') + '\n', exitCode: 1 };
            }

            output.push(`Collecting ${pkg.name}==${pkg.version}`);
            output.push(`  Downloading ${pkg.name}-${pkg.version}.tar.gz (${pkg.size ?? '1.2 MB'})`);
            output.push(`Installing collected packages: ${pkg.name}`);

            installPackage(pkg, ctx, output);
        }

        output.push(`Successfully installed ${pkgNames.join(' ')}`);
        return { output: output.join('\n') + '\n', exitCode: 0 };
    }

    // ── NPM commands ───────────────────────────────────────────

    function npmInstall(args: readonly string[], ctx: CommandContext): ShellResult {
        const pkgNames = args.filter(a => !a.startsWith('-'));
        if (pkgNames.length === 0) return { output: 'Usage: npm install PACKAGE...\n', exitCode: 1 };

        const output: string[] = [];

        for (const name of pkgNames) {
            const pkg = packages.get(name);
            if (pkg === undefined) {
                output.push(`npm ERR! code E404`);
                output.push(`npm ERR! 404 Not Found - GET https://registry.npmjs.org/${name}`);
                return { output: output.join('\n') + '\n', exitCode: 1 };
            }

            output.push(`+ ${pkg.name}@${pkg.version}`);
            output.push(`added 1 package in 0.5s`);

            installPackage(pkg, ctx, output);
        }

        return { output: output.join('\n') + '\n', exitCode: 0 };
    }

    // ── Build command handlers ─────────────────────────────────

    const commandHandlers = new Map<string, CommandHandler>();

    switch (config.type) {
        case 'apk':
            commandHandlers.set('apk', (args, ctx) => {
                const subcommand = args[0];
                const subArgs = args.slice(1);
                switch (subcommand) {
                    case 'add': return apkAdd(subArgs, ctx);
                    case 'search': return apkSearch(subArgs, ctx);
                    case 'info': return apkInfo(subArgs, ctx);
                    case 'update': return { output: 'fetch https://dl-cdn.alpinelinux.org/alpine/v3.18/main\nOK: 1234 distinct packages available\n', exitCode: 0 };
                    default: return { output: `apk: unknown command: ${subcommand ?? ''}\n`, exitCode: 1 };
                }
            });
            break;

        case 'apt':
            commandHandlers.set('apt', (args, ctx) => {
                const subcommand = args[0];
                const subArgs = args.slice(1);
                switch (subcommand) {
                    case 'install': return aptInstall(subArgs, ctx);
                    case 'update': return { output: 'Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease\nReading package lists... Done\n', exitCode: 0 };
                    case 'search': return apkSearch(subArgs, ctx); // Reuse search logic
                    default: return { output: `E: Invalid operation ${subcommand ?? ''}\n`, exitCode: 100 };
                }
            });
            commandHandlers.set('apt-get', commandHandlers.get('apt')!);
            break;

        case 'pip':
            commandHandlers.set('pip', (args, ctx) => {
                const subcommand = args[0];
                const subArgs = args.slice(1);
                switch (subcommand) {
                    case 'install': return pipInstall(subArgs, ctx);
                    case 'list': {
                        const lines = [...installed].map(n => {
                            const p = packages.get(n);
                            return p !== undefined ? `${p.name} ${p.version}` : n;
                        });
                        return { output: 'Package    Version\n---------- -------\n' + lines.join('\n') + '\n', exitCode: 0 };
                    }
                    default: return { output: `Unknown command: ${subcommand ?? ''}\n`, exitCode: 1 };
                }
            });
            commandHandlers.set('pip3', commandHandlers.get('pip')!);
            break;

        case 'npm':
            commandHandlers.set('npm', (args, ctx) => {
                const subcommand = args[0];
                const subArgs = args.slice(1);
                switch (subcommand) {
                    case 'install':
                    case 'i': return npmInstall(subArgs, ctx);
                    case 'list':
                    case 'ls': {
                        const lines = [...installed].map(n => {
                            const p = packages.get(n);
                            return p !== undefined ? `├── ${p.name}@${p.version}` : `├── ${n}`;
                        });
                        return { output: '/var/www\n' + lines.join('\n') + '\n', exitCode: 0 };
                    }
                    default: return { output: `Unknown command: "${subcommand ?? ''}"\n`, exitCode: 1 };
                }
            });
            break;

        default:
            break;
    }

    return {
        commands: commandHandlers,
        isInstalled(name: string): boolean { return installed.has(name); },
        getPackage(name: string): PackageDefinition | undefined { return packages.get(name); },
        getInstalled(): readonly string[] { return [...installed]; },
    };
}

// ── Return type ────────────────────────────────────────────────

export interface PackageMirrorCommands {
    /** Command handlers to register with the shell. */
    readonly commands: ReadonlyMap<string, CommandHandler>;
    /** Check if a package is installed. */
    isInstalled(name: string): boolean;
    /** Get a package definition by name. */
    getPackage(name: string): PackageDefinition | undefined;
    /** Get all installed package names. */
    getInstalled(): readonly string[];
}
