/**
 * VARIANT — Demo Level 01: The Leak
 *
 * A single-machine level. The player boots into a web server
 * that has a leaked database backup in an exposed directory.
 * The objective is to find the admin credentials.
 *
 * Difficulty: Beginner
 * Skills: Directory enumeration, file inspection
 * Time: ~5 minutes
 */

import type { WorldSpec } from '../core/world/types';

const MIGRATE_SCRIPT = `#!/bin/bash
# Migration script - TEMPORARY - DELETE AFTER USE
# Created by: webmaster
# Date: 2024-01-14

# Admin credentials for initial setup
ADMIN_USER="admin"
ADMIN_PASS="Sup3r_S3cur3_Admin_2024!"

# Create admin account
HASH=$(python3 -c "import bcrypt; print(bcrypt.hashpw(b'$ADMIN_PASS', bcrypt.gensalt()).decode())")

mysql -u root -p"$DB_ROOT_PASS" meridian_portal \\
  -e "INSERT INTO users (username, password_hash, email, role) \\
      VALUES ('$ADMIN_USER', '$HASH', 'admin@meridian-tech.local', 'admin')"

echo "Admin account created successfully"
# TODO: Delete this file after migration
`;

const DB_DUMP = `-- MySQL dump 10.13  Distrib 8.0.36
-- Server version: 8.0.36

CREATE DATABASE IF NOT EXISTS meridian_portal;
USE meridian_portal;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  email VARCHAR(128),
  role ENUM('admin', 'user', 'viewer') DEFAULT 'user',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- WARNING: These are bcrypt hashes but the plaintext was
-- found in the migration script. See /var/www/html/backup/migrate.sh

INSERT INTO users (username, password_hash, email, role) VALUES
  ('admin', '$2b$10$K3x5JGHZ4YJfP9Q8vK7Xl.RqN6c5TpMk2wZyGJYqXPCL8h3V5mGi6', 'admin@meridian-tech.local', 'admin'),
  ('jsmith', '$2b$10$8K1pQ9xL3vN2mH5yJ7XwO.GqM4c3TpRk1wZyFJYqXPBL7h2V4mFi5', 'jsmith@meridian-tech.local', 'user'),
  ('mwilson', '$2b$10$L4x6KIHZ5ZKgQ0R9wL8Ym.SrO7d6UrQl3xAzHKZrYQDM9i4W6nHj7', 'mwilson@meridian-tech.local', 'viewer');
`;

const NGINX_CONF = `server {
    listen 80;
    server_name meridian-web;

    root /var/www/html;
    index index.html;

    # NOTE: backup directory should be restricted
    # TODO: Add authentication before go-live
    location /backup/ {
        autoindex on;
    }

    location / {
        try_files $uri $uri/ =404;
    }
}`;

const ACCESS_LOG = `10.0.1.5 - - [15/Jan/2024:08:23:15 +0000] "GET / HTTP/1.1" 200 182
10.0.1.5 - - [15/Jan/2024:08:23:18 +0000] "GET /favicon.ico HTTP/1.1" 404 153
10.0.1.12 - - [15/Jan/2024:09:45:02 +0000] "GET / HTTP/1.1" 200 182
10.0.1.12 - - [15/Jan/2024:09:45:05 +0000] "GET /admin HTTP/1.1" 404 153
10.0.1.12 - - [15/Jan/2024:09:45:08 +0000] "GET /backup/ HTTP/1.1" 200 340
10.0.1.12 - - [15/Jan/2024:09:45:12 +0000] "GET /backup/db_dump_2024-01-15.sql HTTP/1.1" 200 1248`;

const PROFILE = `export PS1="\\[\\e[32m\\]analyst@meridian-web\\[\\e[0m\\]:\\[\\e[34m\\]\\w\\[\\e[0m\\]\\$ "
echo ""
echo "\\e[33m[MISSION BRIEFING]\\e[0m"
echo "Target: Meridian Technologies web server"
echo "Objective: Find admin credentials from exposed backups"
echo ""
echo "\\e[90mHint: Start with the web server configuration\\e[0m"
echo ""`;

export const DEMO_01: WorldSpec = {
    version: '2.0',
    trust: 'community',

    meta: {
        title: 'The Leak',
        scenario: 'A company web server has an exposed backup directory. Find the admin credentials before the server admin rotates them.',
        briefing: [
            'INTELLIGENCE REPORT:',
            '',
            'Target: Meridian Technologies web server',
            'Hostname: meridian-web',
            'IP: 10.0.1.10',
            '',
            'Our OSINT team has identified that the target runs nginx',
            'and recently suffered a misconfiguration that exposed',
            'internal directories. The sysadmin is aware and will',
            'rotate credentials within the hour.',
            '',
            'OBJECTIVE: Locate and extract the admin credentials',
            'from the exposed backup before they are rotated.',
            '',
            'You have shell access to the target machine.',
            'Start by examining the web server configuration.',
        ],
        difficulty: 'beginner',
        mode: 'attack',
        vulnClasses: ['information-disclosure', 'backup-exposure'],
        tags: ['web', 'enumeration', 'beginner', 'single-machine'],
        estimatedMinutes: 5,
        author: {
            name: 'Santh',
            id: 'santh-official',
            type: 'santh',
        },
    },

    machines: {
        'web-server': {
            hostname: 'meridian-web',
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
                    password: 'r00tM3ridian2024!',
                    shell: '/bin/sh',
                    home: '/root',
                    sudo: true,
                },
                {
                    username: 'webmaster',
                    password: 'W3bm@ster_2024',
                    shell: '/bin/sh',
                    home: '/home/webmaster',
                    groups: ['www-data'],
                },
            ],

            interfaces: [
                { ip: '10.0.1.10', segment: 'corporate' },
            ],

            files: {
                '/var/www/html/index.html': {
                    content: '<h1>Welcome to Meridian Technologies</h1><p>Internal portal coming soon.</p>',
                    owner: 'www-data',
                    mode: 0o644,
                },
                '/var/www/html/backup/db_dump_2024-01-15.sql': {
                    content: DB_DUMP,
                    owner: 'www-data',
                    mode: 0o644,
                },
                '/var/www/html/backup/migrate.sh': {
                    content: MIGRATE_SCRIPT,
                    owner: 'webmaster',
                    mode: 0o755,
                },
                '/etc/nginx/conf.d/default.conf': {
                    content: NGINX_CONF,
                    owner: 'root',
                    mode: 0o644,
                },
                '/var/log/nginx/access.log': {
                    content: ACCESS_LOG,
                    owner: 'www-data',
                    mode: 0o644,
                },
                '/home/analyst/.profile': {
                    content: PROFILE,
                    owner: 'analyst',
                    mode: 0o644,
                },
            },

            services: [
                { name: 'nginx', command: 'nginx -g "daemon off;"', ports: [80, 443], autostart: true },
                { name: 'sshd', command: '/usr/sbin/sshd -D', ports: [22], autostart: true },
            ],

            processes: [
                { name: 'init', pid: 1, user: 'root', cpu: 0.0, mem: 1.1 },
                { name: 'sshd', pid: 18, user: 'root', cpu: 0.0, mem: 1.2 },
                { name: 'crond', pid: 29, user: 'root', cpu: 0.0, mem: 0.4 },
                { name: 'nginx: master', pid: 42, user: 'root', cpu: 0.1, mem: 2.3 },
                { name: 'nginx: worker', pid: 45, user: 'www-data', cpu: 0.3, mem: 1.8 },
            ],

            crontab: [
                {
                    schedule: '0 */6 * * *',
                    command: '/usr/local/bin/rotate-creds.sh',
                    user: 'root',
                },
            ],
        },
    },

    startMachine: 'web-server',

    network: {
        segments: [
            { id: 'corporate', subnet: '10.0.1.0/24', gateway: '10.0.1.1' },
        ],
        edges: [],
    },

    credentials: [
        {
            id: 'admin-cred',
            type: 'password',
            value: 'Sup3r_S3cur3_Admin_2024!',
            foundAt: {
                machine: 'web-server',
                path: '/var/www/html/backup/migrate.sh',
                method: 'Read the migration script in the exposed backup directory',
            },
            validAt: {
                machine: 'web-server',
                service: 'web-portal',
                user: 'admin',
                port: 80,
            },
        },
    ],

    objectives: [
        {
            id: 'find-backup',
            title: 'Locate Exposed Backups',
            description: 'Find the exposed backup directory on the web server',
            type: 'find-file',
            required: true,
            order: 1,
            details: {
                kind: 'find-file',
                machine: 'web-server',
                path: '/var/www/html/backup/db_dump_2024-01-15.sql',
            },
        },
        {
            id: 'find-admin-cred',
            title: 'Extract Admin Credentials',
            description: 'Find the plaintext admin password in the migration script',
            type: 'credential-find',
            required: true,
            order: 2,
            details: {
                kind: 'credential-find',
                credentialId: 'admin-cred',
            },
        },
        {
            id: 'bonus-escalate',
            title: 'Privilege Escalation',
            description: 'Escalate to root on the web server',
            type: 'escalate',
            required: false,
            order: 3,
            reward: 25,
            details: {
                kind: 'escalate',
                machine: 'web-server',
                fromUser: 'analyst',
                toUser: 'root',
            },
        },
    ],

    modules: ['objective-detector', 'scoring-engine', 'network-monitor', 'fs-monitor', 'process-monitor'],

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
        'Start by looking at the web server configuration: /etc/nginx/conf.d/',
        'The nginx config shows a directory listing is enabled for /backup/',
        'Check the files in /var/www/html/backup/ — one has plaintext credentials',
    ],
};
