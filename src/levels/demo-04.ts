/**
 * VARIANT — Demo Level 04: SSH Tunnel
 *
 * Two-machine scenario: player starts on a jump-box (DMZ) with weak SSH
 * credentials. Discover MySQL credentials in .bash_history, then connect
 * to the internal database server and extract the flag from the secrets table.
 *
 * Difficulty: Intermediate (medium)
 * Skills: SSH, credential discovery, lateral movement, MySQL
 * MITRE: T1021.004 (Remote Services: SSH), T1552.001 (Unsecured Credentials: Bash History)
 * Time: ~12 minutes
 */

import type { WorldSpec } from '../core/world/types';

const BASH_HISTORY = `cd /var/log
tail -f auth.log
mysql -h 10.0.2.20 -u app_ro -p'Re@d0nly_Int3rnal_2024!' -e "SELECT 1"
exit
`;

const SSH_CONFIG = `# Jump-box SSH config - do not expose to internet in production
Host *
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
`;

const AUTH_LOG = `Mar  7 08:12:33 jump-box sshd[1234]: Accepted password for operator from 10.0.1.100 port 54321 ssh2
Mar  7 08:12:33 jump-box sshd[1234]: pam_unix(sshd:session): session opened for user operator(uid=1000)
Mar  7 08:45:01 jump-box sshd[1250]: Received disconnect from 10.0.1.100 port 54321:11: disconnected by user
`;

const OPERATOR_PROFILE = `export PS1="\\[\\e[32m\\]operator@jump-box\\[\\e[0m\\]:\\[\\e[34m\\]\\w\\[\\e[0m\\]\\$ "
echo ""
echo "\\e[33m[SSH TUNNEL MISSION]\\e[0m"
echo "You are on the DMZ jump-box. The internal DB is only reachable from this subnet."
echo "Objective: Find MySQL credentials and extract the flag from the internal database."
echo ""
echo "\\e[90mHint: Operators often leave credentials in shell history\\e[0m"
echo ""
`;

const MYSQL_SECRETS_EXPORT = `-- Export from internal-db, database 'appdb', table 'secrets'
-- WARNING: Sensitive data - restrict access

+----+------------------------------------------+---------------------+
| id | flag_value                              | created_at          |
+----+------------------------------------------+---------------------+
|  1 | VARIANT{ssh_tunnel_mysql_secrets_2024}   | 2024-03-01 10:00:00 |
+----+------------------------------------------+---------------------+
`;

const FLAG_CONTENT = `VARIANT{ssh_tunnel_mysql_secrets_2024}
`;

export const DEMO_04: WorldSpec = {
    version: '2.0',
    trust: 'community',

    meta: {
        title: 'SSH Tunnel',
        scenario: 'You have access to a DMZ jump-box with weak SSH credentials. The internal database server is only reachable from the jump-box subnet. Find MySQL credentials left in shell history, then pivot to the database and extract the flag.',
        briefing: [
            'SSH TUNNEL SCENARIO',
            '',
            'You start on the jump-box (jump-box, 10.0.1.20 / 10.0.2.10).',
            'This host has two NICs: DMZ (10.0.1.0/24) and internal (10.0.2.0/24).',
            'The internal database server (internal-db, 10.0.2.20) runs MySQL on 3306',
            'and is only accessible from the internal segment.',
            '',
            'OBJECTIVES:',
            '  a) Locate MySQL credentials on the jump-box (check shell history)',
            '  b) Connect from the jump-box to internal-db MySQL',
            '  c) Extract the flag from the secrets table',
            '',
            'You are logged in as operator. Start by enumerating the filesystem.',
        ],
        difficulty: 'medium',
        mode: 'attack',
        vulnClasses: ['unsecured-credentials', 'lateral-movement', 'weak-authentication'],
        tags: ['SSH', 'tunneling', 'MySQL', 'lateral-movement', 'intermediate'],
        estimatedMinutes: 12,
        author: {
            name: 'Santh',
            id: 'santh-official',
            type: 'santh',
        },
    },

    machines: {
        'jump-box': {
            hostname: 'jump-box',
            image: 'alpine-nginx',
            memoryMB: 64,
            role: 'player',

            user: {
                username: 'operator',
                password: 'operator123',
                shell: '/bin/sh',
                home: '/home/operator',
                groups: ['operator'],
                sudo: false,
            },

            users: [
                {
                    username: 'root',
                    password: 'r00tJumpB0x!',
                    shell: '/bin/sh',
                    home: '/root',
                    sudo: true,
                },
            ],

            interfaces: [
                { ip: '10.0.1.20', segment: 'dmz' },
                { ip: '10.0.2.10', segment: 'internal' },
            ],

            files: {
                '/home/operator/.bash_history': {
                    content: BASH_HISTORY,
                    owner: 'operator',
                    mode: 0o600,
                },
                '/home/operator/.ssh/config': {
                    content: SSH_CONFIG,
                    owner: 'operator',
                    mode: 0o600,
                },
                '/var/log/auth.log': {
                    content: AUTH_LOG,
                    owner: 'root',
                    mode: 0o640,
                },
                '/home/operator/.profile': {
                    content: OPERATOR_PROFILE,
                    owner: 'operator',
                    mode: 0o644,
                },
                '/etc/hosts': {
                    content: `127.0.0.1 localhost
10.0.2.20 internal-db internal-db.corp.local
`,
                    owner: 'root',
                    mode: 0o644,
                },
            },

            services: [
                { name: 'sshd', command: '/usr/sbin/sshd -D', ports: [22], autostart: true },
            ],

            processes: [
                { name: 'sshd', pid: 1, user: 'root', cpu: 0.0, mem: 1.2 },
                { name: 'cron', pid: 23, user: 'root', cpu: 0.0, mem: 0.5 },
            ],
        },

        'internal-db': {
            hostname: 'internal-db',
            image: 'alpine-mysql',
            memoryMB: 128,
            role: 'infrastructure',

            users: [
                {
                    username: 'root',
                    password: 'MySq1_R00t_Int3rnal!',
                    shell: '/bin/sh',
                    home: '/root',
                    sudo: true,
                },
                {
                    username: 'app_ro',
                    shell: '/bin/sh',
                    home: '/home/app_ro',
                    groups: ['mysql'],
                },
            ],

            interfaces: [
                { ip: '10.0.2.20', segment: 'internal' },
            ],

            files: {
                '/tmp/secrets_export.txt': {
                    content: MYSQL_SECRETS_EXPORT,
                    owner: 'app_ro',
                    mode: 0o600,
                },
                '/root/flag.txt': {
                    content: FLAG_CONTENT,
                    owner: 'root',
                    mode: 0o600,
                },
            },

            services: [
                {
                    name: 'mysqld',
                    command: 'mysqld --user=mysql',
                    ports: [3306],
                    autostart: true,
                    config: {
                        database: 'appdb',
                        tables: ['secrets'],
                    },
                },
                { name: 'sshd', command: '/usr/sbin/sshd -D', ports: [22], autostart: true },
            ],

            processes: [
                { name: 'mysqld', pid: 10, user: 'mysql', cpu: 0.5, mem: 45 },
                { name: 'sshd', pid: 25, user: 'root', cpu: 0.0, mem: 1.2 },
            ],
        },
    },

    startMachine: 'jump-box',

    network: {
        segments: [
            { id: 'dmz', subnet: '10.0.1.0/24', gateway: '10.0.1.1' },
            { id: 'internal', subnet: '10.0.2.0/24', gateway: '10.0.2.1' },
        ],
        edges: [],
    },

    credentials: [
        {
            id: 'mysql-internal',
            type: 'database-password',
            value: 'Re@d0nly_Int3rnal_2024!',
            foundAt: {
                machine: 'jump-box',
                path: '/home/operator/.bash_history',
                method: 'Discover MySQL credentials in operator .bash_history',
            },
            validAt: {
                machine: 'internal-db',
                service: 'mysqld',
                user: 'app_ro',
                port: 3306,
            },
        },
        {
            id: 'flag-secret',
            type: 'password',
            value: 'VARIANT{ssh_tunnel_mysql_secrets_2024}',
            foundAt: {
                machine: 'internal-db',
                service: 'mysqld',
                method: 'SELECT flag_value FROM appdb.secrets',
            },
            validAt: {
                machine: 'internal-db',
                service: 'mysqld',
                user: 'app_ro',
                port: 3306,
            },
        },
    ],

    objectives: [
        {
            id: 'find-bash-history',
            title: 'Locate Bash History',
            description: 'Find the operator .bash_history file containing MySQL credentials',
            type: 'find-file',
            required: true,
            order: 1,
            details: {
                kind: 'find-file',
                machine: 'jump-box',
                path: '/home/operator/.bash_history',
            },
        },
        {
            id: 'find-mysql-cred',
            title: 'Discover MySQL Credentials',
            description: 'Extract the MySQL app_ro password from shell history',
            type: 'credential-find',
            required: true,
            order: 2,
            details: {
                kind: 'credential-find',
                credentialId: 'mysql-internal',
            },
        },
        {
            id: 'pivot-to-internal-db',
            title: 'Pivot to Internal Database',
            description: 'Connect from jump-box to internal-db MySQL',
            type: 'lateral-move',
            required: true,
            order: 3,
            details: {
                kind: 'lateral-move',
                fromMachine: 'jump-box',
                toMachine: 'internal-db',
            },
        },
        {
            id: 'extract-flag',
            title: 'Extract Flag from Secrets Table',
            description: 'Query the secrets table on internal-db and obtain the flag',
            type: 'credential-find',
            required: true,
            order: 4,
            details: {
                kind: 'credential-find',
                credentialId: 'flag-secret',
            },
        },
    ],

    modules: ['objective-detector', 'scoring-engine'],

    scoring: {
        maxScore: 100,
        timeBonus: true,
        stealthBonus: false,
        hintPenalty: 15,
        tiers: [
            { name: 'MASTERY', minScore: 90, color: '#D4A03A' },
            { name: 'PROFICIENT', minScore: 70, color: '#f1fa8c' },
            { name: 'COMPLETE', minScore: 50, color: '#6272a4' },
        ],
    },

    hints: [
        'Shell history is usually in the user home directory: ~/.bash_history or ~/.history',
        'The MySQL host for the internal DB is on the internal segment (10.0.2.x)',
        'From the jump-box you can run: mysql -h 10.0.2.20 -u app_ro -p',
        'The flag is in the appdb.secrets table.',
    ],
};
