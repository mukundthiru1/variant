/**
 * VARIANT — Demo Level 02: Lateral Movement Lab
 *
 * A three-machine lateral movement / privilege escalation scenario.
 * Player starts on a web server, pivots via exposed SSH key to the
 * internal DB server, extracts admin credentials from MySQL, then
 * SSHs to the admin workstation to read the flag.
 *
 * Difficulty: Medium
 * Skills: Enumeration, credential harvesting, pivoting, SSH
 * Time: ~15 minutes
 */

import type { WorldSpec } from '../core/world/types';

// Realistic RSA 2048-bit private key (PEM) — deploy key left in backup dir
const DEPLOY_SSH_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcdS3F5fC8J9nH5xK7mN2pQwR1vL8sT4yU6hGj
FkD9aB2cE3dR5sW7xY0zA1bC4eF6gH8iJ0kL2mN4oP6qR8sT0uV2wX4yZ6aB
8cD0eF2gH4iJ6kL8mN0oP2qR4sT6uV8wX0yZ2aB4cD6eF8gH0iJ2kL4mN6oP
8qR0sT2uV4wX6yZ8aB0cD2eF4gH6iJ8kL0mN2oP4qR6sT8uV0wX2yZ4aB6cD
8eF0gH2iJ4kL6mN8oP0qR2sT4uV6wX8yZ0aB2cD4eF6gH8iJ0kL2mN4oP6qR
8sT0uV2wX4yZ6aB8cD0eF2gH4iJ6kL8mN0oP2qR4sT6uV8wX0yZ2aB4cD6eF
8gH0iJ2kL4mN6oP8qR0sT2uV4wX6yZ8aB0cD2eF4gH6iJ8kL0mN2oP4qR6sT
8uV0wX2yZ4aB6cD8eF0gH2iJ4kL6mN8oP0qR2sT4uV6wX8yZ0aB2cD4eF6gH
8iJ0kL2mN4oP6qR8sT0uV2wX4yZ6aB8cD0eF2gH4iJ6kL8mN0oP2qR4sT6uV
8wX0yZ2aB4cD6eF8gH0iJ2kL4mN6oP8qR0sT2uV4wX6yZ8aB0cD2eF4gH6iJ
8kL0mN2oP4qR6sT8uV0wX2yZ4aB6cD8eF0gH2iJ4kL6mN8oP0qR2sT4uV6wX
8yZ0aB2cD4eF6gH8iJ0kL2mN4oP6qR8sT0uV2wX4yZ6aB8cD0eF2gH4iJ6kL
8mN0oP2qR4sT6uV8wX0yZ2aB4cD6eF8gH0iJ2kL4mN6oP8qR0sT2uV4wX6yZ
8aB0cD2eF4gH6iJ8kL0mN2oP4qR6sT8uV0wX2yZ4aB6cD8eF0gH2iJ4kL6mN
8oP0qR2sT4uV6wX8yZ0aB2cD4eF6gH8iJ0kL2mN4oP6qR8sT0uV2wX4yZ6aB
8cD0eF2gH4iJ6kL8mN0oP2qR4sT6uV8wX0yZ2aB4cD6eF8gH0iJ2kL4mN6oP
8qR0sT2uV4wX6yZ8aB0cD2eF4gH6iJ8kL0mN2oP4qR6sT8uV0wX2yZ4aB6cD
8eF0gH2iJ4kL6mN8oP0qR2sT4uV6wX8yZ0aB2cD4eF6gH8iJ0kL2mN4oP6qR
AgMBAAE=
-----END RSA PRIVATE KEY-----`;

const NGINX_CONF = `server {
    listen 80;
    server_name web-server.lab.local;

    root /var/www/html;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }

    location /status {
        return 200 'ok';
        add_header Content-Type text/plain;
    }
}`;

const WEBAPP_INDEX = `<!DOCTYPE html>
<html>
<head><title>Internal Portal - Dev</title></head>
<body>
<h1>Internal Dev Portal</h1>
<p>Environment: staging. Database: db-server (internal only).</p>
<p>Backup scripts run nightly; check /var/backups on this host for deploy keys.</p>
</body>
</html>`;

const AUTH_LOG = `Mar  6 08:12:33 web-server sshd[1234]: Accepted password for analyst from 10.0.2.1 port 54321 ssh2
Mar  6 08:12:33 web-server sshd[1234]: pam_unix(sshd:session): session opened for user analyst(uid=1000)
Mar  6 09:00:01 web-server sshd[1250]: Received disconnect from 10.0.2.1 port 54321:11: disconnected by user
Mar  6 09:00:01 web-server sshd[1250]: Disconnected from user analyst 10.0.2.1 port 54321
`;

const PROFILE_WEB = `export PS1="\\[\\e[32m\\]analyst@web-server\\[\\e[0m\\]:\\[\\e[34m\\]\\w\\[\\e[0m\\]\\$ "
echo ""
echo "\\e[33m[MISSION]\\e[0m Lateral Movement Lab — start from this host."
echo "\\e[90mHint: Check the backup directory on the web server\\e[0m"
echo ""`;

// MySQL users table content (exported for simulation — engine may present via mysql client)
const MYSQL_USERS_EXPORT = `-- Table: users (application credential store)
-- WARNING: Contains plaintext passwords for legacy app compatibility

+----+-------+------------------+---------------------------+--------+
| id | user  | password         | email                     | role   |
+----+-------+------------------+---------------------------+--------+
|  1 | admin | Mgmt_Reuse_2024! | admin@lab.local           | admin  |
|  2 | deploy| (uses SSH key)   | deploy@lab.local          | deploy |
|  3 | app   | app_db_secret    | app@lab.local             | user   |
+----+-------+------------------+---------------------------+--------+
`;

const FLAG_CONTENT = `VARIANT{lateral_movement_lab_complete}
`;

export const DEMO_02: WorldSpec = {
    version: '2.0',
    trust: 'curated',

    meta: {
        title: 'Lateral Movement Lab',
        scenario: 'A three-machine environment: web server, internal DB server, and admin workstation. Pivot using an exposed SSH key, extract credentials from the database, and reach the flag on the admin host.',
        briefing: [
            'LATERAL MOVEMENT LAB',
            '',
            'You have initial access to the web server (web-server, 10.0.2.10).',
            'The internal subnet 10.0.2.0/24 also hosts the DB server (10.0.2.20).',
            'The management subnet 10.0.3.0/24 hosts the admin workstation (10.0.3.10),',
            'reachable from the DB server.',
            '',
            'OBJECTIVES:',
            '  a) Find the exposed SSH private key on the web server',
            '  b) Use the key to pivot to the DB server',
            '  c) Extract admin credentials from the database',
            '  d) SSH to the admin workstation using those credentials',
            '  e) Read the flag at /root/flag.txt',
            '  f) [Bonus] Clean up your tracks (delete auth.log entries)',
            '',
            'Start by enumerating the web server filesystem.',
        ],
        difficulty: 'medium',
        mode: 'attack',
        vulnClasses: ['information-disclosure', 'credential-reuse', 'lateral-movement'],
        tags: ['lateral-movement', 'pivoting', 'ssh', 'mysql', 'medium', 'multi-machine'],
        estimatedMinutes: 15,
        author: {
            name: 'Santh',
            id: 'santh-official',
            type: 'santh',
        },
    },

    machines: {
        'web-server': {
            hostname: 'web-server',
            image: 'alpine-nginx',
            memoryMB: 64,
            role: 'player',

            user: {
                username: 'analyst',
                password: 'analyst',
                shell: '/bin/sh',
                home: '/home/analyst',
                groups: ['analyst'],
                sudo: false,
            },

            users: [
                {
                    username: 'root',
                    password: 'r00tW3bS3rv3r!',
                    shell: '/bin/sh',
                    home: '/root',
                    sudo: true,
                },
                {
                    username: 'www-data',
                    shell: '/usr/sbin/nologin',
                    home: '/var/www',
                    groups: ['www-data'],
                },
            ],

            interfaces: [
                { ip: '10.0.2.10', segment: 'internal' },
            ],

            files: {
                '/var/www/html/index.html': {
                    content: WEBAPP_INDEX,
                    owner: 'www-data',
                    mode: 0o644,
                },
                '/var/backups/id_rsa': {
                    content: DEPLOY_SSH_KEY,
                    owner: 'root',
                    mode: 0o600,
                },
                '/var/backups/README.txt': {
                    content: 'Nightly backups. Deploy key stored here for ansible — DO NOT commit to git.\n',
                    owner: 'root',
                    mode: 0o644,
                },
                '/etc/nginx/conf.d/default.conf': {
                    content: NGINX_CONF,
                    owner: 'root',
                    mode: 0o644,
                },
                '/var/log/auth.log': {
                    content: AUTH_LOG,
                    owner: 'root',
                    mode: 0o640,
                },
                '/home/analyst/.profile': {
                    content: PROFILE_WEB,
                    owner: 'analyst',
                    mode: 0o644,
                },
            },

            services: [
                { name: 'nginx', command: 'nginx -g "daemon off;"', ports: [80], autostart: true },
                { name: 'sshd', command: '/usr/sbin/sshd -D', ports: [22], autostart: true },
            ],

            processes: [
                { name: 'nginx: master', pid: 1, user: 'root', cpu: 0.1, mem: 2.3 },
                { name: 'nginx: worker', pid: 45, user: 'www-data', cpu: 0.3, mem: 1.8 },
                { name: 'sshd', pid: 23, user: 'root', cpu: 0.0, mem: 1.2 },
            ],
        },

        'db-server': {
            hostname: 'db-server',
            image: 'alpine-mysql',
            memoryMB: 128,
            role: 'infrastructure',

            users: [
                {
                    username: 'root',
                    password: 'MySq1_R00t_DB!',
                    shell: '/bin/sh',
                    home: '/root',
                    sudo: true,
                },
                {
                    username: 'deploy',
                    shell: '/bin/sh',
                    home: '/home/deploy',
                    groups: ['deploy'],
                },
            ],

            interfaces: [
                { ip: '10.0.2.20', segment: 'internal' },
                { ip: '10.0.3.20', segment: 'management' },
            ],

            files: {
                '/home/deploy/.ssh/authorized_keys': {
                    content: 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDRndVLkklx1LcXl8Lwn2cfnEruY3alDBHW8vyxPjJTqEaMWQP1oHZwTd1HmxbvFjTMDVsLeFgH8iJ0kL2mN4oP6qR8sT0uV2wX4yZ6aB8cD0eF2gH4iJ6kL8mN0oP2qR4sT6uV8wX0yZ2aB4cD6eF8gH0iJ2kL4mN6oP8qR0sT2uV4wX6yZ8aB0cD2eF4gH6iJ8kL0mN2oP4qR6sT8uV0wX2yZ4aB6cD8eF0gH2iJ4kL6mN8oP0qR2sT4uV6wX8yZ0aB2cD4eF6gH8iJ0kL2mN4oP6qR deploy@web-server\n',
                    owner: 'deploy',
                    mode: 0o600,
                },
                '/tmp/users_export.txt': {
                    content: MYSQL_USERS_EXPORT,
                    owner: 'deploy',
                    mode: 0o600,
                },
            },

            services: [
                { name: 'mysqld', command: 'mysqld --user=mysql', ports: [3306], autostart: true },
                { name: 'sshd', command: '/usr/sbin/sshd -D', ports: [22], autostart: true },
            ],

            processes: [
                { name: 'mysqld', pid: 10, user: 'mysql', cpu: 0.5, mem: 45 },
                { name: 'sshd', pid: 25, user: 'root', cpu: 0.0, mem: 1.2 },
            ],
        },

        'admin-workstation': {
            hostname: 'admin-workstation',
            image: 'alpine-nginx',
            memoryMB: 64,
            role: 'target',

            users: [
                {
                    username: 'root',
                    password: 'Mgmt_Reuse_2024!',
                    shell: '/bin/sh',
                    home: '/root',
                    sudo: true,
                },
                {
                    username: 'admin',
                    password: 'Mgmt_Reuse_2024!',
                    shell: '/bin/bash',
                    home: '/home/admin',
                    groups: ['admin', 'sudo'],
                },
            ],

            interfaces: [
                { ip: '10.0.3.10', segment: 'management' },
            ],

            files: {
                '/root/flag.txt': {
                    content: FLAG_CONTENT,
                    owner: 'root',
                    mode: 0o600,
                },
            },

            services: [
                { name: 'sshd', command: '/usr/sbin/sshd -D', ports: [22], autostart: true },
            ],

            processes: [
                { name: 'sshd', pid: 1, user: 'root', cpu: 0.0, mem: 1.2 },
            ],
        },
    },

    startMachine: 'web-server',

    network: {
        segments: [
            { id: 'internal', subnet: '10.0.2.0/24', gateway: '10.0.2.1' },
            { id: 'management', subnet: '10.0.3.0/24', gateway: '10.0.3.1' },
        ],
        edges: [],
    },

    credentials: [
        {
            id: 'deploy-ssh-key',
            type: 'ssh-key',
            value: DEPLOY_SSH_KEY,
            foundAt: {
                machine: 'web-server',
                path: '/var/backups/id_rsa',
                method: 'Read the private key from the backup directory on the web server',
            },
            validAt: {
                machine: 'db-server',
                service: 'ssh',
                user: 'deploy',
                port: 22,
            },
        },
        {
            id: 'admin-cred',
            type: 'password',
            value: 'Mgmt_Reuse_2024!',
            foundAt: {
                machine: 'db-server',
                service: 'mysql',
                method: 'Extract admin credentials from the users table in the database',
            },
            validAt: {
                machine: 'admin-workstation',
                service: 'ssh',
                user: 'admin',
                port: 22,
            },
        },
    ],

    objectives: [
        {
            id: 'find-ssh-key',
            title: 'Find Exposed SSH Key',
            description: 'Locate the SSH private key in the web server backup directory',
            type: 'find-file',
            required: true,
            order: 1,
            details: {
                kind: 'find-file',
                machine: 'web-server',
                path: '/var/backups/id_rsa',
            },
        },
        {
            id: 'pivot-to-db',
            title: 'Pivot to DB Server',
            description: 'Use the SSH key to access the database server',
            type: 'lateral-move',
            required: true,
            order: 2,
            details: {
                kind: 'lateral-move',
                fromMachine: 'web-server',
                toMachine: 'db-server',
            },
        },
        {
            id: 'extract-admin-cred',
            title: 'Extract Admin Credentials',
            description: 'Get the admin password from the database',
            type: 'credential-find',
            required: true,
            order: 3,
            details: {
                kind: 'credential-find',
                credentialId: 'admin-cred',
            },
        },
        {
            id: 'pivot-to-admin',
            title: 'Pivot to Admin Workstation',
            description: 'SSH to the admin workstation using the extracted credentials',
            type: 'lateral-move',
            required: true,
            order: 4,
            details: {
                kind: 'lateral-move',
                fromMachine: 'db-server',
                toMachine: 'admin-workstation',
            },
        },
        {
            id: 'read-flag',
            title: 'Read the Flag',
            description: 'Read the flag file at /root/flag.txt on the admin workstation',
            type: 'find-file',
            required: true,
            order: 5,
            details: {
                kind: 'find-file',
                machine: 'admin-workstation',
                path: '/root/flag.txt',
            },
        },
        {
            id: 'bonus-cleanup',
            title: 'Clean Up Tracks',
            description: 'Delete or alter auth.log entries on the web server',
            type: 'custom',
            required: false,
            order: 6,
            reward: 15,
            details: {
                kind: 'custom',
                evaluator: 'auth-log-cleanup',
                params: { machine: 'web-server', path: '/var/log/auth.log' },
            },
        },
    ],

    modules: ['objective-detector', 'scoring-engine'],

    scoring: {
        maxScore: 100,
        timeBonus: true,
        stealthBonus: true,
        hintPenalty: 15,
        tiers: [
            { name: 'MASTERY', minScore: 90, color: '#D4A03A' },
            { name: 'PROFICIENT', minScore: 70, color: '#f1fa8c' },
            { name: 'COMPLETE', minScore: 50, color: '#6272a4' },
        ],
    },

    hints: [
        'Check the backup directory on the web server',
        'SSH keys can open more than one door',
        'Databases often store credentials',
    ],
};
