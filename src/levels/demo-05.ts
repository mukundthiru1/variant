/**
 * VARIANT — Demo Level 05: Phishing Payload
 *
 * Three-machine scenario: attacker (player), mail-server (SMTP), target-workstation.
 * Craft a phishing email to ceo@acme-corp.local with specific payload indicators.
 * The target-workstation simulates a user that clicks links when the correct
 * phishing email is delivered. Verify delivery via mail-server logs.
 *
 * Difficulty: Intermediate (medium)
 * Skills: SMTP, phishing, social engineering, log analysis
 * MITRE: T1566.001 (Phishing: Spearphishing Attachment)
 * Time: ~15 minutes
 */

import type { WorldSpec } from '../core/world/types';

const POSTFIX_MAIN_CF = `# Postfix main - acme-corp.local
myhostname = mail.acme-corp.local
mydomain = acme-corp.local
myorigin = $mydomain
mydestination = $myhostname, localhost, localhost.$mydomain, $mydomain
relay_domains = $mydomain
inet_interfaces = all
`;

const DELIVERY_LOG = `# Mail delivery log - acme-corp.local
# Format: timestamp | from | to | subject | status

2024-03-07T08:00:01Z | noreply@acme-corp.local | all@acme-corp.local | Weekly Digest | delivered
2024-03-07T09:15:22Z | hr@acme-corp.local | ceo@acme-corp.local | Q4 Benefits Update | delivered
2024-03-07T10:30:00Z | support@external.com | ceo@acme-corp.local | URGENT: Verify your account | deferred (spam)
`;

const ATTACKER_PROFILE = `export PS1="\\[\\e[31m\\]attacker@attacker-pc\\[\\e[0m\\]:\\[\\e[34m\\]\\w\\[\\e[0m\\]\\$ "
echo ""
echo "\\e[33m[PHISHING PAYLOAD MISSION]\\e[0m"
echo "Target: ceo@acme-corp.local at Acme Corp"
echo "Mail server: 10.0.1.20 (SMTP port 25)"
echo ""
echo "Objective: Craft a spearphishing email with payload indicators,"
echo "send it to the CEO, then verify delivery in the mail-server logs."
echo ""
echo "Payload indicators required: urgent subject, link to fake login page."
echo "\\e[90mHint: Use the mail lens or SMTP client to send; then check /var/log/mail/ on mail-server\\e[0m"
echo ""
`;

const ATTACKER_README = `Phishing campaign - ceo@acme-corp.local

Payload requirements (for objective completion):
- To: ceo@acme-corp.local
- Subject must contain urgency (e.g. URGENT, IMMEDIATE, Action Required)
- Body should contain a link (e.g. http://login-acme-secure.com or similar)
- From: spoofed internal or trusted-looking address

After sending, SSH to mail-server (10.0.1.20) and check:
  /var/log/mail/delivery.log
  /var/log/mail/mail.log

The target-workstation (10.0.1.30) simulates the CEO; when the correct
phishing email is delivered, the "link click" event is logged.
`;

const MAIL_LOG = `Mar  7 08:00:01 mail-server postfix/smtpd[1001]: connect from attacker-pc[10.0.1.10]
Mar  7 08:00:02 mail-server postfix/smtpd[1001]: ABC123: client=attacker-pc[10.0.1.10]
Mar  7 08:00:02 mail-server postfix/cleanup[1002]: ABC123: message-id=<phish001@attacker.local>
Mar  7 08:00:03 mail-server postfix/qmgr[1003]: ABC123: from=<hr@acme-corp.local>, size=1024, nrcpt=1
Mar  7 08:00:03 mail-server postfix/local[1004]: ABC123: to=<ceo@acme-corp.local>, relay=local, delay=1, status=sent
Mar  7 08:00:04 mail-server postfix/smtpd[1001]: disconnect from attacker-pc[10.0.1.10]
`;

const TARGET_CLICK_LOG = `# Simulated user activity - target-workstation
# When a phishing email with correct payload is delivered to ceo@acme-corp.local,
# the simulated user "clicks" the link and this log is updated.

2024-03-07T10:35:00Z | ceo@acme-corp.local | link_click | http://login-acme-secure.com/verify | success
`;

export const DEMO_05: WorldSpec = {
    version: '2.0',
    trust: 'community',

    meta: {
        title: 'Phishing Payload',
        scenario: 'You are a red-team operator. Craft a spearphishing email to ceo@acme-corp.local with urgency and a malicious link. Send it via the corporate mail server, then verify delivery and check the mail delivery logs.',
        briefing: [
            'PHISHING PAYLOAD SCENARIO',
            '',
            'You start on the attacker machine (attacker-pc, 10.0.1.10).',
            'Mail server: 10.0.1.20 (SMTP on port 25), accepts mail for @acme-corp.local.',
            'Target workstation: 10.0.1.30 (simulated CEO user).',
            '',
            'OBJECTIVES:',
            '  a) Craft a phishing email to ceo@acme-corp.local with:',
            '     - Urgent subject line',
            '     - Body containing a link (payload indicator)',
            '  b) Send the email via the mail server (SMTP)',
            '  c) Verify delivery by checking the mail delivery logs on the mail-server',
            '',
            'Use the mail lens or an SMTP client to send; then SSH to the',
            'mail-server and inspect /var/log/mail/ to confirm delivery.',
        ],
        difficulty: 'medium',
        mode: 'attack',
        vulnClasses: ['phishing', 'social-engineering', 'credential-harvesting'],
        tags: ['SMTP', 'phishing', 'social-engineering', 'intermediate'],
        estimatedMinutes: 15,
        author: {
            name: 'Santh',
            id: 'santh-official',
            type: 'santh',
        },
    },

    machines: {
        'attacker': {
            hostname: 'attacker-pc',
            image: 'alpine-nginx',
            memoryMB: 64,
            role: 'player',

            user: {
                username: 'attacker',
                password: 'attacker',
                shell: '/bin/sh',
                home: '/home/attacker',
                groups: ['attacker'],
                sudo: false,
            },

            users: [
                {
                    username: 'root',
                    password: 'r00tAttacker!',
                    shell: '/bin/sh',
                    home: '/root',
                    sudo: true,
                },
            ],

            interfaces: [
                { ip: '10.0.1.10', segment: 'corporate' },
            ],

            files: {
                '/home/attacker/.profile': {
                    content: ATTACKER_PROFILE,
                    owner: 'attacker',
                    mode: 0o644,
                },
                '/home/attacker/README_phishing.txt': {
                    content: ATTACKER_README,
                    owner: 'attacker',
                    mode: 0o644,
                },
                '/etc/hosts': {
                    content: `127.0.0.1 localhost
10.0.1.20 mail-server mail.acme-corp.local
10.0.1.30 target-workstation
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
            ],
        },

        'mail-server': {
            hostname: 'mail-server',
            image: 'debian-server',
            memoryMB: 128,
            role: 'infrastructure',

            users: [
                {
                    username: 'root',
                    password: 'M@ilS3rv3r_R00t!',
                    shell: '/bin/sh',
                    home: '/root',
                    sudo: true,
                },
                {
                    username: 'postfix',
                    shell: '/usr/sbin/nologin',
                    home: '/var/spool/postfix',
                    groups: ['postfix'],
                },
            ],

            interfaces: [
                { ip: '10.0.1.20', segment: 'corporate' },
            ],

            files: {
                '/etc/postfix/main.cf': {
                    content: POSTFIX_MAIN_CF,
                    owner: 'root',
                    mode: 0o644,
                },
                '/var/log/mail/delivery.log': {
                    content: DELIVERY_LOG,
                    owner: 'root',
                    mode: 0o644,
                },
                '/var/log/mail/mail.log': {
                    content: MAIL_LOG,
                    owner: 'root',
                    mode: 0o644,
                },
            },

            services: [
                { name: 'smtp', command: 'postfix start', ports: [25], autostart: true },
                { name: 'sshd', command: '/usr/sbin/sshd -D', ports: [22], autostart: true },
            ],

            processes: [
                { name: 'master', pid: 1, user: 'root', cpu: 0.1, mem: 2.0 },
                { name: 'qmgr', pid: 100, user: 'postfix', cpu: 0.0, mem: 1.5 },
                { name: 'sshd', pid: 50, user: 'root', cpu: 0.0, mem: 1.2 },
            ],
        },

        'target-workstation': {
            hostname: 'target-workstation',
            image: 'ubuntu-desktop',
            memoryMB: 128,
            role: 'target',

            users: [
                {
                    username: 'ceo',
                    password: 'C30_Acme_2024!',
                    shell: '/bin/bash',
                    home: '/home/ceo',
                    groups: ['ceo', 'mail'],
                },
                {
                    username: 'root',
                    password: 'r00tT@rget!',
                    shell: '/bin/bash',
                    home: '/root',
                    sudo: true,
                },
            ],

            interfaces: [
                { ip: '10.0.1.30', segment: 'corporate' },
            ],

            files: {
                '/var/log/user-activity.log': {
                    content: TARGET_CLICK_LOG,
                    owner: 'root',
                    mode: 0o644,
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

    startMachine: 'attacker',

    network: {
        segments: [
            { id: 'corporate', subnet: '10.0.1.0/24', gateway: '10.0.1.1' },
        ],
        edges: [],
    },

    mail: {
        accounts: {
            'ceo@acme-corp.local': {
                displayName: 'CEO Acme Corp',
                machine: 'target-workstation',
                role: 'executive',
            },
            'hr@acme-corp.local': {
                displayName: 'HR Department',
                machine: 'mail-server',
                role: 'hr',
            },
        },
        inbox: [],
        templates: {
            'phishing-urgent': {
                from: 'hr@acme-corp.local',
                subject: 'URGENT: Action Required - Verify Your Account',
                body: 'Dear CEO,\n\nWe need you to verify your account immediately.\nClick here: http://login-acme-secure.com/verify\n\nIT Security',
                html: false,
                malicious: true,
                maliciousAction: 'link_click_simulated',
            },
        },
    },

    credentials: [],

    objectives: [
        {
            id: 'send-phishing-email',
            title: 'Send Phishing Email to CEO',
            description: 'Craft and send a spearphishing email to ceo@acme-corp.local with urgent subject and link payload',
            type: 'custom',
            required: true,
            order: 1,
            details: {
                kind: 'custom',
                evaluator: 'phishing-delivery',
                params: {
                    to: 'ceo@acme-corp.local',
                    requireUrgentSubject: true,
                    requireLinkInBody: true,
                },
            },
        },
        {
            id: 'find-delivery-log',
            title: 'Verify Delivery in Mail Logs',
            description: 'Locate the mail delivery log on the mail-server showing delivery to ceo@acme-corp.local',
            type: 'find-file',
            required: true,
            order: 2,
            details: {
                kind: 'find-file',
                machine: 'mail-server',
                path: '/var/log/mail/delivery.log',
            },
        },
        {
            id: 'find-mail-log',
            title: 'Inspect Mail Server Log',
            description: 'Find the main mail log on the mail-server',
            type: 'find-file',
            required: false,
            order: 3,
            reward: 15,
            details: {
                kind: 'find-file',
                machine: 'mail-server',
                path: '/var/log/mail/mail.log',
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
        'Use the mail lens or an SMTP client to send mail to ceo@acme-corp.local',
        'Subject should contain URGENT or similar to trigger the payload indicator check',
        'Include a link in the body (e.g. http://login-acme-secure.com/verify)',
        'SSH to mail-server (10.0.1.20) and check /var/log/mail/ for delivery proof',
    ],
};
