/**
 * VARIANT — Credential Ecosystem Generator
 *
 * Auto-generates realistic credential files from WorldSpec data:
 *   - /etc/passwd
 *   - /etc/shadow (with hashed passwords)
 *   - /etc/group
 *   - ~/.ssh/authorized_keys
 *   - ~/.ssh/id_rsa (private keys)
 *   - ~/.bash_history (command history breadcrumbs)
 *   - ~/.bashrc, ~/.profile
 *   - Application config files (.env, database configs)
 *   - /etc/hostname, /etc/hosts, /etc/resolv.conf
 *
 * Level designers configure:
 *   - Users (username, password, groups, sudo, shell)
 *   - SSH key pairs (which machines trust which)
 *   - Bash history (breadcrumbs — previous commands that hint at vulns)
 *   - Application credentials (DB passwords, API keys, JWT secrets)
 *   - Network config (hostname, hosts entries, DNS)
 *   - Custom config files (nginx, apache, my.cnf, etc.)
 *
 * DESIGN: Pure functions. Input → VFS overlay. No side effects.
 * All output is configurable. Nothing is hardcoded except default
 * file formats (which match real Linux conventions).
 *
 * SECURITY: Passwords are stored as SHA-512 hashes in /etc/shadow,
 * exactly like a real system. Level designers provide plaintext in
 * the WorldSpec; this generator hashes them.
 */

import type { VFSOverlay, VFSOverlayEntry } from '../vfs/types';

// ── Types ──────────────────────────────────────────────────────

export interface CredentialEcosystem {
    /** System users. */
    readonly users: readonly SystemUser[];
    /** Hostname for this machine. */
    readonly hostname: string;
    /** Domain name (optional). */
    readonly domain?: string;
    /** /etc/hosts entries. */
    readonly hosts?: readonly HostEntry[];
    /** DNS servers. */
    readonly nameservers?: readonly string[];
    /** SSH trust relationships between users/machines. */
    readonly sshTrust?: readonly SSHTrust[];
    /** Bash history entries per user. Breadcrumbs! */
    readonly bashHistory?: ReadonlyMap<string, readonly string[]>;
    /** Application credential files. */
    readonly appCredentials?: readonly AppCredentialFile[];
    /** Custom config files (nginx.conf, my.cnf, etc.). */
    readonly configFiles?: ReadonlyMap<string, ConfigFile>;
    /** MOTD (Message of the day). */
    readonly motd?: string;
    /** System services for /etc/init.d or systemd. */
    readonly services?: readonly ServiceEntry[];
    /** Crontab entries per user. */
    readonly crontabs?: ReadonlyMap<string, readonly string[]>;
}

export interface SystemUser {
    readonly username: string;
    readonly password?: string;        // Plaintext — will be hashed for /etc/shadow
    readonly uid: number;
    readonly gid: number;
    readonly gecos?: string;           // Full name / description
    readonly home: string;
    readonly shell: string;
    readonly groups?: readonly string[];
    readonly sudo?: boolean;
    readonly locked?: boolean;         // Account locked (! in shadow)
    /** Extra dotfiles for this user's home directory. */
    readonly dotfiles?: ReadonlyMap<string, string>;
}

export interface HostEntry {
    readonly ip: string;
    readonly hostname: string;
    readonly aliases?: readonly string[];
}

export interface SSHTrust {
    /** User who has the private key. */
    readonly fromUser: string;
    /** User whose authorized_keys gets the public key. */
    readonly toUser: string;
    /** Key type. Default: 'ssh-rsa'. */
    readonly keyType?: string;
    /** Key comment. Default: fromUser@hostname. */
    readonly comment?: string;
    /**
     * Fake key material. We generate deterministic but
     * realistic-looking keys. NOT cryptographically valid—
     * they just need to look real in `cat ~/.ssh/id_rsa`.
     */
    readonly keyId?: string;
}

export interface AppCredentialFile {
    /** File path (e.g., '/var/www/.env'). */
    readonly path: string;
    /** File format. */
    readonly format: 'env' | 'json' | 'yaml' | 'ini' | 'xml' | 'raw';
    /** Key-value pairs. */
    readonly values: ReadonlyMap<string, string>;
    /** File owner. */
    readonly owner?: string;
    /** File mode. Default: 0o600. */
    readonly mode?: number;
}

export interface ConfigFile {
    /** Full file content. */
    readonly content: string;
    readonly owner?: string;
    readonly group?: string;
    readonly mode?: number;
}

export interface ServiceEntry {
    readonly name: string;
    readonly description: string;
    readonly command: string;
    readonly user?: string;
    readonly enabled?: boolean;
}

// ── Generator ──────────────────────────────────────────────────

export function generateCredentialEcosystem(config: CredentialEcosystem): VFSOverlay {
    const files = new Map<string, VFSOverlayEntry>();

    // ── /etc/passwd ────────────────────────────────────────────
    const passwdLines: string[] = [];
    // Always include system accounts
    passwdLines.push('root:x:0:0:root:/root:/bin/sh');
    passwdLines.push('daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin');
    passwdLines.push('bin:x:2:2:bin:/bin:/usr/sbin/nologin');
    passwdLines.push('sys:x:3:3:sys:/dev:/usr/sbin/nologin');
    passwdLines.push('nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin');
    passwdLines.push('sshd:x:74:74:sshd:/var/run/sshd:/usr/sbin/nologin');

    for (const user of config.users) {
        if (user.username === 'root') {
            // Override root entry
            passwdLines[0] = `root:x:0:0:${user.gecos ?? 'root'}:${user.home}:${user.shell}`;
        } else {
            passwdLines.push(
                `${user.username}:x:${user.uid}:${user.gid}:${user.gecos ?? ''}:${user.home}:${user.shell}`
            );
        }
    }
    files.set('/etc/passwd', { content: passwdLines.join('\n') + '\n', mode: 0o644 });

    // ── /etc/shadow ────────────────────────────────────────────
    const shadowLines: string[] = [];
    const daysEpoch = Math.floor(Date.now() / 86400000) - 30; // 30 days ago

    for (const user of config.users) {
        const hash = user.password !== undefined && !user.locked
            ? hashPassword(user.password)
            : user.locked ? '!' : '*';
        shadowLines.push(`${user.username}:${hash}:${daysEpoch}:0:99999:7:::`);
    }
    // System accounts
    shadowLines.push(`daemon:*:${daysEpoch}:0:99999:7:::`);
    shadowLines.push(`bin:*:${daysEpoch}:0:99999:7:::`);
    shadowLines.push(`nobody:*:${daysEpoch}:0:99999:7:::`);
    shadowLines.push(`sshd:*:${daysEpoch}:0:99999:7:::`);

    files.set('/etc/shadow', { content: shadowLines.join('\n') + '\n', mode: 0o640, owner: 'root', group: 'shadow' });

    // ── /etc/group ─────────────────────────────────────────────
    const groupMap = new Map<string, string[]>();
    groupMap.set('root', []);
    groupMap.set('daemon', []);
    groupMap.set('sudo', []);
    groupMap.set('www-data', []);
    groupMap.set('shadow', []);

    for (const user of config.users) {
        if (user.groups !== undefined) {
            for (const group of user.groups) {
                if (!groupMap.has(group)) groupMap.set(group, []);
                groupMap.get(group)!.push(user.username);
            }
        }
        if (user.sudo === true) {
            if (!groupMap.has('sudo')) groupMap.set('sudo', []);
            groupMap.get('sudo')!.push(user.username);
        }
    }

    const groupLines: string[] = [];
    let gid = 0;
    for (const [name, members] of groupMap) {
        groupLines.push(`${name}:x:${gid}:${members.join(',')}`);
        gid++;
    }
    files.set('/etc/group', { content: groupLines.join('\n') + '\n', mode: 0o644 });

    // ── /etc/hostname ──────────────────────────────────────────
    files.set('/etc/hostname', { content: config.hostname + '\n' });

    // ── /etc/hosts ─────────────────────────────────────────────
    const hostsLines = [
        '127.0.0.1\tlocalhost',
        `127.0.1.1\t${config.hostname}${config.domain ? '.' + config.domain + '\t' + config.hostname : ''}`,
    ];
    if (config.hosts !== undefined) {
        for (const entry of config.hosts) {
            const aliases = entry.aliases !== undefined ? '\t' + entry.aliases.join('\t') : '';
            hostsLines.push(`${entry.ip}\t${entry.hostname}${aliases}`);
        }
    }
    files.set('/etc/hosts', { content: hostsLines.join('\n') + '\n' });

    // ── /etc/resolv.conf ───────────────────────────────────────
    const nameservers = config.nameservers ?? ['8.8.8.8', '8.8.4.4'];
    const resolvLines = nameservers.map(ns => `nameserver ${ns}`);
    if (config.domain !== undefined) resolvLines.unshift(`search ${config.domain}`);
    files.set('/etc/resolv.conf', { content: resolvLines.join('\n') + '\n' });

    // ── User home directories ──────────────────────────────────
    for (const user of config.users) {
        const home = user.home;

        // .bashrc
        files.set(`${home}/.bashrc`, {
            content: generateBashrc(user, config.hostname),
            owner: user.username,
            mode: 0o644,
        });

        // .profile
        files.set(`${home}/.profile`, {
            content: generateProfile(user),
            owner: user.username,
            mode: 0o644,
        });

        // .bash_history — breadcrumbs!
        if (config.bashHistory !== undefined) {
            const history = config.bashHistory.get(user.username);
            if (history !== undefined && history.length > 0) {
                files.set(`${home}/.bash_history`, {
                    content: history.join('\n') + '\n',
                    owner: user.username,
                    mode: 0o600,
                });
            }
        }

        // Custom dotfiles
        if (user.dotfiles !== undefined) {
            for (const [name, content] of user.dotfiles) {
                files.set(`${home}/${name}`, {
                    content,
                    owner: user.username,
                    mode: 0o644,
                });
            }
        }
    }

    // ── SSH keys ───────────────────────────────────────────────
    if (config.sshTrust !== undefined) {
        // Collect authorized_keys per user
        const authorizedKeys = new Map<string, string[]>();
        // Collect private keys per user
        const privateKeys = new Map<string, string>();

        for (const trust of config.sshTrust) {
            const keyType = trust.keyType ?? 'ssh-rsa';
            const comment = trust.comment ?? `${trust.fromUser}@${config.hostname}`;
            const keyId = trust.keyId ?? `${trust.fromUser}-${trust.toUser}`;

            const { publicKey, privateKey } = generateFakeSSHKeyPair(keyId, keyType, comment);

            // Public key goes into target user's authorized_keys
            if (!authorizedKeys.has(trust.toUser)) authorizedKeys.set(trust.toUser, []);
            authorizedKeys.get(trust.toUser)!.push(publicKey);

            // Private key goes into source user's .ssh/
            privateKeys.set(trust.fromUser, privateKey);
        }

        for (const user of config.users) {
            const home = user.home;

            // Write authorized_keys
            const pubKeys = authorizedKeys.get(user.username);
            if (pubKeys !== undefined && pubKeys.length > 0) {
                files.set(`${home}/.ssh/authorized_keys`, {
                    content: pubKeys.join('\n') + '\n',
                    owner: user.username,
                    mode: 0o600,
                });
            }

            // Write private key
            const privKey = privateKeys.get(user.username);
            if (privKey !== undefined) {
                files.set(`${home}/.ssh/id_rsa`, {
                    content: privKey,
                    owner: user.username,
                    mode: 0o600,
                });
            }

            // SSH config
            files.set(`${home}/.ssh/config`, {
                content: '# SSH client configuration\nHost *\n    StrictHostKeyChecking no\n    UserKnownHostsFile /dev/null\n',
                owner: user.username,
                mode: 0o600,
            });
        }
    }

    // ── SSH server config ──────────────────────────────────────
    files.set('/etc/ssh/sshd_config', {
        content: generateSSHDConfig(),
        mode: 0o644,
    });

    // ── Application credential files ───────────────────────────
    if (config.appCredentials !== undefined) {
        for (const cred of config.appCredentials) {
            const content = formatAppCredentials(cred);
            files.set(cred.path, {
                content,
                owner: cred.owner,
                mode: cred.mode ?? 0o600,
            });
        }
    }

    // ── Custom config files ────────────────────────────────────
    if (config.configFiles !== undefined) {
        for (const [path, cfg] of config.configFiles) {
            files.set(path, {
                content: cfg.content,
                owner: cfg.owner,
                group: cfg.group,
                mode: cfg.mode ?? 0o644,
            });
        }
    }

    // ── /etc/motd ──────────────────────────────────────────────
    if (config.motd !== undefined) {
        files.set('/etc/motd', { content: config.motd + '\n' });
    }

    // ── sudoers ────────────────────────────────────────────────
    const sudoers = ['root ALL=(ALL:ALL) ALL', '%sudo ALL=(ALL:ALL) ALL', ''];
    for (const user of config.users) {
        if (user.sudo === true) {
            sudoers.push(`${user.username} ALL=(ALL:ALL) NOPASSWD: ALL`);
        }
    }
    files.set('/etc/sudoers', { content: sudoers.join('\n') + '\n', mode: 0o440, owner: 'root' });

    // ── Crontabs ───────────────────────────────────────────────
    if (config.crontabs !== undefined) {
        for (const [user, entries] of config.crontabs) {
            files.set(`/var/spool/cron/crontabs/${user}`, {
                content: `# crontab for ${user}\n` + entries.join('\n') + '\n',
                owner: user,
                mode: 0o600,
            });
        }
    }

    // ── Service init scripts ───────────────────────────────────
    if (config.services !== undefined) {
        for (const svc of config.services) {
            files.set(`/etc/init.d/${svc.name}`, {
                content: generateInitScript(svc),
                mode: 0o755,
            });
        }
    }

    // ── System directories ─────────────────────────────────────
    // Ensure critical dirs exist (create empty marker files)
    const criticalDirs = ['/tmp', '/var/tmp', '/var/log', '/var/run', '/proc', '/dev'];
    for (const dir of criticalDirs) {
        if (!files.has(`${dir}/.keep`)) {
            files.set(`${dir}/.keep`, { content: '' });
        }
    }

    return { files };
}

// ── Helpers ────────────────────────────────────────────────────

/**
 * Hash a password to SHA-512 crypt format.
 * This is a simplified version — real systems use crypt(3).
 * We generate deterministic, realistic-looking hashes.
 * NOT cryptographically valid, but identical format.
 */
function hashPassword(password: string): string {
    // Generate a deterministic salt from the password
    const salt = deterministicBase64(password, 16);
    // Generate a deterministic hash from password + salt
    const hash = deterministicBase64(password + salt, 86);
    return `$6$${salt}$${hash}`;
}

/**
 * Generate deterministic base64-like string from input.
 * Uses a simple hash — NOT cryptographically secure.
 * Just needs to LOOK like a real hash.
 */
function deterministicBase64(input: string, length: number): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./';
    let hash = 0;
    for (let i = 0; i < input.length; i++) {
        hash = ((hash << 5) - hash + input.charCodeAt(i)) | 0;
    }
    let result = '';
    for (let i = 0; i < length; i++) {
        hash = ((hash * 1103515245 + 12345) | 0) >>> 0;
        result += chars[hash % chars.length];
    }
    return result;
}

function generateFakeSSHKeyPair(
    keyId: string,
    keyType: string,
    comment: string,
): { publicKey: string; privateKey: string } {
    const keyData = deterministicBase64(keyId, 372);
    const pubKeyData = deterministicBase64(keyId + '-pub', 172);

    const publicKey = `${keyType} ${pubKeyData} ${comment}`;
    const privateKey = [
        '-----BEGIN OPENSSH PRIVATE KEY-----',
        ...chunkString(keyData, 70),
        '-----END OPENSSH PRIVATE KEY-----',
        '',
    ].join('\n');

    return { publicKey, privateKey };
}

function chunkString(str: string, size: number): string[] {
    const chunks: string[] = [];
    for (let i = 0; i < str.length; i += size) {
        chunks.push(str.slice(i, i + size));
    }
    return chunks;
}

function generateBashrc(user: SystemUser, hostname: string): string {
    const promptChar = user.username === 'root' ? '#' : '$';
    return [
        '# ~/.bashrc',
        '',
        'export PS1="\\u@' + hostname + ':\\w' + promptChar + ' "',
        'export EDITOR=vi',
        'export PAGER=less',
        '',
        'alias ll="ls -la"',
        'alias la="ls -a"',
        'alias l="ls -CF"',
        '',
        '# History',
        'HISTSIZE=1000',
        'HISTFILESIZE=2000',
        'HISTCONTROL=ignoredups:ignorespace',
        '',
    ].join('\n');
}

function generateProfile(_user: SystemUser): string {
    return [
        '# ~/.profile',
        '',
        `if [ -f "$HOME/.bashrc" ]; then`,
        `    . "$HOME/.bashrc"`,
        'fi',
        '',
        `PATH="$HOME/bin:$HOME/.local/bin:$PATH"`,
        '',
    ].join('\n');
}

function generateSSHDConfig(): string {
    return [
        '# OpenSSH Server Configuration',
        'Port 22',
        'Protocol 2',
        'HostKey /etc/ssh/ssh_host_rsa_key',
        'HostKey /etc/ssh/ssh_host_ecdsa_key',
        'HostKey /etc/ssh/ssh_host_ed25519_key',
        '',
        'PermitRootLogin yes',
        'PasswordAuthentication yes',
        'PubkeyAuthentication yes',
        'AuthorizedKeysFile .ssh/authorized_keys',
        '',
        'ChallengeResponseAuthentication no',
        'UsePAM yes',
        '',
        'X11Forwarding no',
        'PrintMotd yes',
        'AcceptEnv LANG LC_*',
        'Subsystem sftp /usr/lib/openssh/sftp-server',
        '',
    ].join('\n');
}

function formatAppCredentials(cred: AppCredentialFile): string {
    switch (cred.format) {
        case 'env': {
            const lines: string[] = [];
            for (const [key, value] of cred.values) {
                lines.push(`${key}=${value}`);
            }
            return lines.join('\n') + '\n';
        }
        case 'json': {
            const obj: Record<string, string> = {};
            for (const [key, value] of cred.values) {
                obj[key] = value;
            }
            return JSON.stringify(obj, null, 2) + '\n';
        }
        case 'yaml': {
            const lines: string[] = [];
            for (const [key, value] of cred.values) {
                lines.push(`${key}: "${value}"`);
            }
            return lines.join('\n') + '\n';
        }
        case 'ini': {
            const lines: string[] = ['[default]'];
            for (const [key, value] of cred.values) {
                lines.push(`${key} = ${value}`);
            }
            return lines.join('\n') + '\n';
        }
        case 'xml': {
            const lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<config>'];
            for (const [key, value] of cred.values) {
                lines.push(`  <${key}>${value}</${key}>`);
            }
            lines.push('</config>');
            return lines.join('\n') + '\n';
        }
        case 'raw': {
            return [...cred.values.values()].join('\n') + '\n';
        }
    }
}

function generateInitScript(svc: ServiceEntry): string {
    return [
        '#!/bin/sh',
        `### BEGIN INIT INFO`,
        `# Provides:          ${svc.name}`,
        `# Required-Start:    $remote_fs $syslog`,
        `# Required-Stop:     $remote_fs $syslog`,
        `# Default-Start:     2 3 4 5`,
        `# Default-Stop:      0 1 6`,
        `# Short-Description: ${svc.description}`,
        `### END INIT INFO`,
        '',
        `DAEMON="${svc.command}"`,
        `DAEMON_USER="${svc.user ?? 'root'}"`,
        '',
        'case "$1" in',
        '    start)',
        '        echo "Starting ${svc.name}..."',
        '        ;;',
        '    stop)',
        '        echo "Stopping ${svc.name}..."',
        '        ;;',
        '    restart)',
        '        $0 stop',
        '        $0 start',
        '        ;;',
        '    *)',
        `        echo "Usage: $0 {start|stop|restart}"`,
        '        exit 1',
        '        ;;',
        'esac',
        '',
    ].join('\n');
}
