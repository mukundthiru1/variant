/**
 * VARIANT — Misconfiguration Template Catalog
 *
 * Pre-built security misconfigurations ready for level designers to use.
 * Each template generates realistic files, configs, and clues.
 */

import type {
    MisconfigCatalog,
    MisconfigCatalogStats,
    MisconfigCategory,
    MisconfigSeverity,
    MisconfigTemplate,
} from './types';

// ── Built-in Templates ──────────────────────────────────────────

function createBuiltinTemplates(): MisconfigTemplate[] {
    return [
        // ── Authentication ──────────────────────────────────────
        {
            id: 'MISC-0001', name: 'Default SSH Root Password',
            description: 'SSH server allows root login with a default/weak password.',
            realWorldContext: 'Common on IoT devices, appliances, and hastily provisioned servers. Shodan finds thousands of these daily.',
            category: 'authentication', severity: 'critical',
            mitreTechniques: ['T1078', 'T1110.001'],
            cweIds: ['CWE-521', 'CWE-798'],
            files: {
                '/etc/ssh/sshd_config': {
                    content: [
                        'Port 22', 'PermitRootLogin yes', 'PasswordAuthentication yes',
                        'MaxAuthTries 10', 'LoginGraceTime 120',
                        '# TODO: Disable root login before production',
                    ].join('\n'),
                    mode: 0o644, owner: 'root',
                },
            },
            clues: [
                { location: 'config', path: '/etc/ssh/sshd_config', content: 'PermitRootLogin yes', visibility: 3 },
                { location: 'log', path: '/var/log/auth.log', content: 'Jan 15 03:22:14 server sshd[1234]: Accepted password for root from 10.0.1.50 port 54321', visibility: 4 },
            ],
            detectionHints: ['Check sshd_config for PermitRootLogin', 'Review auth.log for root SSH logins'],
            remediation: ['Set PermitRootLogin to no', 'Use SSH key authentication only', 'Set PasswordAuthentication to no'],
            tags: ['ssh', 'root', 'password', 'default-creds'],
            applicableRoles: ['target', 'defend', 'infrastructure'],
        },
        {
            id: 'MISC-0002', name: 'Hardcoded Database Credentials',
            description: 'Database credentials stored in plaintext in application configuration files.',
            realWorldContext: 'One of the most common findings in penetration tests. Developers commit .env files or config.php with production database passwords.',
            category: 'authentication', severity: 'high',
            mitreTechniques: ['T1552', 'T1078'],
            cweIds: ['CWE-798', 'CWE-256'],
            files: {
                '/var/www/html/.env': {
                    content: [
                        'APP_ENV=production', 'APP_DEBUG=true', 'APP_KEY=base64:Vm1DSk1PSXhIR0Z5VWR...',
                        '', 'DB_HOST=10.0.1.20', 'DB_PORT=3306', 'DB_DATABASE=app_production',
                        'DB_USERNAME=app_admin', 'DB_PASSWORD=Pr0duct!0n_DB_2024',
                        '', 'REDIS_HOST=10.0.1.21', 'REDIS_PASSWORD=R3d!s_C@che_Key',
                    ].join('\n'),
                    mode: 0o644, owner: 'www-data',
                },
                '/var/www/html/config/database.php': {
                    content: [
                        '<?php', 'return [',
                        "    'default' => 'mysql',",
                        "    'connections' => [",
                        "        'mysql' => [",
                        "            'host' => env('DB_HOST', '10.0.1.20'),",
                        "            'database' => env('DB_DATABASE', 'app_production'),",
                        "            'username' => env('DB_USERNAME', 'app_admin'),",
                        "            // FIXME: Remove hardcoded fallback",
                        "            'password' => env('DB_PASSWORD', 'Pr0duct!0n_DB_2024'),",
                        '        ],', '    ],', '];',
                    ].join('\n'),
                    mode: 0o644, owner: 'www-data',
                },
            },
            clues: [
                { location: 'file', path: '/var/www/html/.env', content: 'DB_PASSWORD=Pr0duct!0n_DB_2024', visibility: 4 },
                { location: 'config', path: '/var/www/html/config/database.php', content: 'FIXME: Remove hardcoded fallback', visibility: 3 },
            ],
            detectionHints: ['Search for .env files in web roots', 'Grep for DB_PASSWORD in config files', 'Check file permissions on config files'],
            remediation: ['Use environment variables or vault service', 'Restrict .env file permissions to 0o600', 'Add .env to .gitignore', 'Use HashiCorp Vault or AWS Secrets Manager'],
            tags: ['database', 'credentials', 'hardcoded', 'env-file'],
            applicableRoles: ['target', 'defend'],
        },
        {
            id: 'MISC-0003', name: 'Weak JWT Secret',
            description: 'JWT tokens signed with a weak/guessable secret key.',
            realWorldContext: 'Applications using "secret", "password", or short keys for JWT signing. Tools like jwt_tool crack these instantly.',
            category: 'authentication', severity: 'critical',
            mitreTechniques: ['T1078', 'T1190'],
            cweIds: ['CWE-326', 'CWE-347'],
            files: {
                '/var/www/html/config/auth.js': {
                    content: [
                        "const jwt = require('jsonwebtoken');",
                        '',
                        '// TODO: Move to environment variable',
                        "const JWT_SECRET = 'super_secret_key_123';",
                        '',
                        'function generateToken(user) {',
                        '    return jwt.sign({ userId: user.id, role: user.role }, JWT_SECRET, { expiresIn: "24h" });',
                        '}',
                        '',
                        'function verifyToken(token) {',
                        '    return jwt.verify(token, JWT_SECRET);',
                        '}',
                        '',
                        'module.exports = { generateToken, verifyToken };',
                    ].join('\n'),
                    mode: 0o644, owner: 'www-data',
                },
            },
            clues: [
                { location: 'file', path: '/var/www/html/config/auth.js', content: "JWT_SECRET = 'super_secret_key_123'", visibility: 4 },
            ],
            detectionHints: ['Search for JWT_SECRET in source code', 'Check if JWT secret is in environment or hardcoded'],
            remediation: ['Use a cryptographically random secret (256+ bits)', 'Store in environment variable or secrets manager', 'Use RS256 with proper key management'],
            tags: ['jwt', 'authentication', 'weak-secret', 'web'],
            applicableRoles: ['target'],
        },

        // ── Authorization ───────────────────────────────────────
        {
            id: 'MISC-0010', name: 'World-Readable Shadow File',
            description: '/etc/shadow file has incorrect permissions allowing any user to read password hashes.',
            realWorldContext: 'Happens after misconfigured backups, bad chmod commands, or privilege mismanagement.',
            category: 'file-permissions', severity: 'critical',
            mitreTechniques: ['T1003', 'T1552'],
            cweIds: ['CWE-732', 'CWE-276'],
            files: {
                '/etc/shadow': {
                    content: [
                        'root:$6$rounds=65536$sa1tV4lu3$H4sh3dP4ssw0rd:19000:0:99999:7:::',
                        'daemon:*:19000:0:99999:7:::',
                        'www-data:$6$rounds=65536$w3bSalt$W3bUserH4sh:19000:0:99999:7:::',
                        'admin:$6$rounds=65536$adm1nSlt$Adm1nP4ssH4sh:19000:0:99999:7:::',
                    ].join('\n'),
                    mode: 0o644, owner: 'root',  // Should be 0o640
                },
            },
            clues: [
                { location: 'log', path: '/var/log/syslog', content: 'WARNING: /etc/shadow has insecure permissions', visibility: 3 },
            ],
            detectionHints: ['Check permissions on /etc/shadow (should be 640 or 000)', 'Run: ls -la /etc/shadow'],
            remediation: ['chmod 640 /etc/shadow', 'chown root:shadow /etc/shadow'],
            tags: ['shadow', 'password-hashes', 'permissions', 'linux'],
            applicableRoles: ['target', 'defend'],
        },
        {
            id: 'MISC-0011', name: 'SUID Binary Misconfiguration',
            description: 'Common binaries with SUID bit set, enabling privilege escalation via GTFOBins.',
            realWorldContext: 'Administrators set SUID on utilities for convenience, creating trivial privesc paths.',
            category: 'file-permissions', severity: 'high',
            mitreTechniques: ['T1548.001'],
            cweIds: ['CWE-269'],
            files: {
                '/usr/bin/find': { content: '#!/bin/sh\n# find binary (SUID)', mode: 0o4755, owner: 'root' },
                '/usr/bin/vim': { content: '#!/bin/sh\n# vim binary (SUID)', mode: 0o4755, owner: 'root' },
                '/usr/bin/python3': { content: '#!/bin/sh\n# python3 binary (SUID)', mode: 0o4755, owner: 'root' },
            },
            clues: [
                { location: 'file', path: '/tmp/.enum_results', content: 'find /usr/bin -perm -4000 2>/dev/null\n/usr/bin/find\n/usr/bin/vim\n/usr/bin/python3', visibility: 2 },
            ],
            detectionHints: ['Run: find / -perm -4000 2>/dev/null', 'Compare SUID binaries against known-good baseline'],
            remediation: ['Remove SUID bit: chmod u-s /usr/bin/find', 'Use sudo with restricted commands instead of SUID'],
            tags: ['suid', 'privesc', 'gtfobins', 'linux'],
            applicableRoles: ['target'],
        },

        // ── Network ─────────────────────────────────────────────
        {
            id: 'MISC-0020', name: 'No Firewall Rules',
            description: 'All iptables chains set to ACCEPT with no filtering rules.',
            realWorldContext: 'Common on internal servers where "the network firewall will handle it." Until it does not.',
            category: 'network', severity: 'high',
            mitreTechniques: ['T1046', 'T1021'],
            files: {
                '/etc/iptables/rules.v4': {
                    content: [
                        '*filter', ':INPUT ACCEPT [0:0]', ':FORWARD ACCEPT [0:0]', ':OUTPUT ACCEPT [0:0]',
                        '# No rules configured', 'COMMIT',
                    ].join('\n'),
                    mode: 0o644, owner: 'root',
                },
            },
            clues: [
                { location: 'config', path: '/etc/iptables/rules.v4', content: '# No rules configured', visibility: 3 },
            ],
            detectionHints: ['Run: iptables -L -n', 'Check for default ACCEPT policy on all chains'],
            remediation: ['Implement default-deny policy', 'Only allow required ports', 'Enable logging for dropped packets'],
            tags: ['firewall', 'iptables', 'open-ports', 'network'],
            applicableRoles: ['target', 'defend', 'infrastructure'],
        },
        {
            id: 'MISC-0021', name: 'DNS Zone Transfer Allowed',
            description: 'DNS server allows zone transfers to any host, leaking internal network topology.',
            realWorldContext: 'Allows attackers to enumerate all internal hostnames, IPs, and service records.',
            category: 'network', severity: 'medium',
            mitreTechniques: ['T1590.002'],
            files: {
                '/etc/bind/named.conf.options': {
                    content: [
                        'options {', '    directory "/var/cache/bind";',
                        '    allow-transfer { any; };  // INSECURE: allows zone transfer to anyone',
                        '    allow-query { any; };',
                        '    recursion yes;',
                        '};',
                    ].join('\n'),
                    mode: 0o644, owner: 'root',
                },
            },
            clues: [
                { location: 'config', path: '/etc/bind/named.conf.options', content: 'allow-transfer { any; };', visibility: 3 },
            ],
            detectionHints: ['Check DNS config for allow-transfer setting', 'Test: dig axfr @target domain.com'],
            remediation: ['Set allow-transfer to specific secondary DNS IPs only', 'Use TSIG keys for zone transfers'],
            tags: ['dns', 'zone-transfer', 'enumeration', 'network'],
            applicableRoles: ['infrastructure'],
        },

        // ── Service Misconfiguration ────────────────────────────
        {
            id: 'MISC-0030', name: 'Nginx Directory Listing Enabled',
            description: 'Nginx autoindex on, exposing directory contents including backups and configs.',
            realWorldContext: 'Extremely common — autoindex is enabled for convenience and forgotten in production.',
            category: 'service', severity: 'medium',
            mitreTechniques: ['T1083', 'T1190'],
            cweIds: ['CWE-548'],
            files: {
                '/etc/nginx/conf.d/default.conf': {
                    content: [
                        'server {', '    listen 80;', '    server_name _;',
                        '    root /var/www/html;', '    index index.html;',
                        '', '    location / {', '        autoindex on;  # INSECURE: directory listing',
                        '        try_files $uri $uri/ =404;', '    }', '}',
                    ].join('\n'),
                    mode: 0o644, owner: 'root',
                },
            },
            clues: [
                { location: 'config', path: '/etc/nginx/conf.d/default.conf', content: 'autoindex on;', visibility: 4 },
            ],
            detectionHints: ['Check nginx config for autoindex directive', 'Browse to directories and check for listing'],
            remediation: ['Set autoindex off', 'Add authentication for sensitive directories'],
            tags: ['nginx', 'directory-listing', 'web', 'enumeration'],
            applicableRoles: ['target', 'defend'],
        },
        {
            id: 'MISC-0031', name: 'MySQL Remote Root Access',
            description: 'MySQL allows root login from any host with a weak password.',
            realWorldContext: 'Default MySQL installations sometimes bind to 0.0.0.0 with no host restriction on root.',
            category: 'service', severity: 'critical',
            mitreTechniques: ['T1078', 'T1190'],
            cweIds: ['CWE-798', 'CWE-250'],
            files: {
                '/etc/mysql/mysql.conf.d/mysqld.cnf': {
                    content: [
                        '[mysqld]', 'bind-address = 0.0.0.0  # Listening on all interfaces',
                        'skip-networking = false', 'port = 3306',
                        '# WARNING: root can connect from any host',
                    ].join('\n'),
                    mode: 0o644, owner: 'root',
                },
            },
            clues: [
                { location: 'config', path: '/etc/mysql/mysql.conf.d/mysqld.cnf', content: 'bind-address = 0.0.0.0', visibility: 4 },
                { location: 'log', path: '/var/log/mysql/error.log', content: "[Warning] 'root'@'10.0.1.50' has connected without SSL", visibility: 3 },
            ],
            detectionHints: ['Check bind-address in MySQL config', 'Query: SELECT user, host FROM mysql.user WHERE user="root"'],
            remediation: ['Bind to 127.0.0.1 or specific internal IP', 'Remove root@% user', 'Require SSL for remote connections'],
            tags: ['mysql', 'database', 'remote-access', 'root'],
            applicableRoles: ['target', 'infrastructure'],
        },
        {
            id: 'MISC-0032', name: 'Redis No Authentication',
            description: 'Redis instance with no password, accessible from the network.',
            realWorldContext: 'Redis defaults to no authentication. When exposed to the network, attackers can read all data, write SSH keys, or get RCE.',
            category: 'service', severity: 'critical',
            mitreTechniques: ['T1078', 'T1190', 'T1098.004'],
            cweIds: ['CWE-306'],
            files: {
                '/etc/redis/redis.conf': {
                    content: [
                        'bind 0.0.0.0', 'port 6379', 'protected-mode no',
                        '# requirepass is not set — no authentication required',
                        'tcp-backlog 511', 'timeout 0',
                    ].join('\n'),
                    mode: 0o644, owner: 'redis',
                },
            },
            clues: [
                { location: 'config', path: '/etc/redis/redis.conf', content: 'protected-mode no', visibility: 4 },
            ],
            detectionHints: ['Check if requirepass is set in redis.conf', 'Test: redis-cli -h target INFO'],
            remediation: ['Set requirepass with a strong password', 'Bind to 127.0.0.1', 'Enable protected-mode'],
            tags: ['redis', 'no-auth', 'exposed', 'rce'],
            applicableRoles: ['target', 'infrastructure'],
        },

        // ── Encryption / TLS ────────────────────────────────────
        {
            id: 'MISC-0040', name: 'Expired TLS Certificate',
            description: 'Web server using an expired TLS certificate.',
            realWorldContext: 'Certificate expiration is one of the top causes of outages and security warnings. Users trained to click through warnings.',
            category: 'encryption', severity: 'medium',
            mitreTechniques: ['T1557'],
            cweIds: ['CWE-295'],
            files: {
                '/etc/nginx/ssl/server.crt': {
                    content: '-----BEGIN CERTIFICATE-----\n[EXPIRED CERTIFICATE DATA]\n-----END CERTIFICATE-----',
                    mode: 0o644, owner: 'root',
                },
                '/etc/nginx/conf.d/ssl.conf': {
                    content: [
                        'server {', '    listen 443 ssl;',
                        '    ssl_certificate /etc/nginx/ssl/server.crt;',
                        '    ssl_certificate_key /etc/nginx/ssl/server.key;',
                        '    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;  # INSECURE: TLS 1.0/1.1 enabled',
                        '    ssl_ciphers ALL:!aNULL;  # INSECURE: allows weak ciphers',
                        '}',
                    ].join('\n'),
                    mode: 0o644, owner: 'root',
                },
            },
            clues: [
                { location: 'config', path: '/etc/nginx/conf.d/ssl.conf', content: 'TLSv1 TLSv1.1', visibility: 4 },
                { location: 'log', path: '/var/log/nginx/error.log', content: 'SSL: error:0A000086:SSL routines::certificate verify failed', visibility: 3 },
            ],
            detectionHints: ['Check certificate expiry: openssl x509 -in cert.crt -noout -dates', 'Check for TLS 1.0/1.1 support'],
            remediation: ['Renew certificate', 'Disable TLS 1.0 and 1.1', 'Use strong cipher suites only'],
            tags: ['tls', 'certificate', 'expired', 'weak-ciphers'],
            applicableRoles: ['target', 'defend'],
        },

        // ── Logging ─────────────────────────────────────────────
        {
            id: 'MISC-0050', name: 'Audit Logging Disabled',
            description: 'System audit logging (auditd) is disabled, preventing forensic analysis.',
            realWorldContext: 'Attackers disable logging as first action. Defenders who find logging disabled know something happened.',
            category: 'logging', severity: 'high',
            mitreTechniques: ['T1070', 'T1562.001'],
            cweIds: ['CWE-778'],
            files: {
                '/etc/audit/auditd.conf': {
                    content: [
                        '# Audit daemon configuration',
                        'log_file = /var/log/audit/audit.log',
                        'log_format = ENRICHED',
                        'max_log_file = 8',
                        'num_logs = 5',
                        'priority_boost = 4',
                        'disp_qos = lossy',
                        'dispatcher = /sbin/audispd',
                        'name_format = HOSTNAME',
                    ].join('\n'),
                    mode: 0o640, owner: 'root',
                },
                '/etc/default/auditd': {
                    content: 'AUDITD_ENABLED=0\n# Service disabled by admin on 2024-01-10\n',
                    mode: 0o644, owner: 'root',
                },
            },
            clues: [
                { location: 'config', path: '/etc/default/auditd', content: 'AUDITD_ENABLED=0', visibility: 3 },
                { location: 'log', path: '/var/log/syslog', content: 'auditd[]: Cannot open audit log file /var/log/audit/audit.log', visibility: 2 },
            ],
            detectionHints: ['Check if auditd service is running', 'Check AUDITD_ENABLED in /etc/default/auditd'],
            remediation: ['Set AUDITD_ENABLED=1', 'Start auditd service', 'Configure audit rules for critical file access'],
            tags: ['logging', 'audit', 'disabled', 'forensics'],
            applicableRoles: ['defend'],
        },

        // ── Container ───────────────────────────────────────────
        {
            id: 'MISC-0060', name: 'Privileged Docker Container',
            description: 'Container running with --privileged flag, enabling full host access.',
            realWorldContext: 'Developers use --privileged for convenience. A compromised container can trivially escape to the host.',
            category: 'container', severity: 'critical',
            mitreTechniques: ['T1611', 'T1006'],
            files: {
                '/proc/1/status': {
                    content: [
                        'Name:   bash', 'Umask:  0022', 'State:  S (sleeping)',
                        'CapEff: 0000003fffffffff',  // All capabilities
                    ].join('\n'),
                    mode: 0o444, owner: 'root',
                },
                '/.dockerenv': { content: '', mode: 0o644, owner: 'root' },
                '/var/run/docker.sock': { content: '# Docker socket mounted from host', mode: 0o666, owner: 'root' },
            },
            clues: [
                { location: 'file', path: '/.dockerenv', content: '', visibility: 3 },
                { location: 'file', path: '/var/run/docker.sock', content: 'Docker socket mounted from host', visibility: 4 },
                { location: 'process', content: 'CapEff: 0000003fffffffff (all capabilities)', visibility: 2 },
            ],
            detectionHints: ['Check for /.dockerenv', 'Check /proc/1/status for capabilities', 'Check if Docker socket is mounted'],
            remediation: ['Remove --privileged flag', 'Drop all capabilities and add only needed ones', 'Do not mount Docker socket into containers'],
            tags: ['docker', 'privileged', 'container-escape', 'capabilities'],
            applicableRoles: ['target'],
        },

        // ── Cloud ───────────────────────────────────────────────
        {
            id: 'MISC-0070', name: 'Cloud Metadata Service Exposed',
            description: 'IMDS (Instance Metadata Service) accessible from within the application, enabling SSRF-to-credential theft.',
            realWorldContext: 'The Capital One breach (2019) exploited SSRF to hit the AWS metadata service and steal IAM credentials.',
            category: 'cloud', severity: 'critical',
            mitreTechniques: ['T1552.007', 'T1190'],
            cweIds: ['CWE-918'],
            files: {
                '/etc/cloud/cloud.cfg': {
                    content: [
                        'datasource:', '  Ec2:', '    metadata_urls: [ "http://169.254.169.254" ]',
                        '    # IMDSv1 enabled (no token required)', '    http_put_response_hop_limit: 1',
                    ].join('\n'),
                    mode: 0o644, owner: 'root',
                },
            },
            serviceOverrides: {
                'http': { ssrf_targets: ['http://169.254.169.254/latest/meta-data/iam/security-credentials/'] },
            },
            clues: [
                { location: 'env', content: 'AWS_DEFAULT_REGION=us-east-1', visibility: 2 },
                { location: 'config', path: '/etc/cloud/cloud.cfg', content: 'IMDSv1 enabled', visibility: 3 },
            ],
            detectionHints: ['Check if 169.254.169.254 is accessible from within the application', 'Verify IMDSv2 is enforced'],
            remediation: ['Enforce IMDSv2 (require token)', 'Block 169.254.169.254 in application-level firewall', 'Use VPC endpoints instead of public metadata'],
            tags: ['cloud', 'aws', 'imds', 'ssrf', 'metadata'],
            applicableRoles: ['target'],
        },

        // ── Application ─────────────────────────────────────────
        {
            id: 'MISC-0080', name: 'Debug Mode in Production',
            description: 'Application running in debug mode, exposing stack traces, env vars, and internal paths.',
            realWorldContext: 'Django/Laravel/Flask debug pages leak database credentials, secret keys, and full source paths.',
            category: 'application', severity: 'high',
            mitreTechniques: ['T1190', 'T1552'],
            cweIds: ['CWE-215', 'CWE-209'],
            files: {
                '/var/www/html/.env': {
                    content: [
                        'APP_ENV=production', 'APP_DEBUG=true  # DANGER: debug mode in production!',
                        'APP_KEY=base64:k3yD4t4H3r3...', 'APP_URL=http://10.0.1.10',
                    ].join('\n'),
                    mode: 0o644, owner: 'www-data',
                },
            },
            clues: [
                { location: 'file', path: '/var/www/html/.env', content: 'APP_DEBUG=true', visibility: 4 },
            ],
            detectionHints: ['Check for APP_DEBUG=true in .env files', 'Try triggering an error page to see debug output'],
            remediation: ['Set APP_DEBUG=false in production', 'Use custom error handlers', 'Never expose stack traces to users'],
            tags: ['debug', 'production', 'stack-trace', 'info-leak'],
            applicableRoles: ['target'],
        },
        {
            id: 'MISC-0081', name: 'Missing Security Headers',
            description: 'Web application missing critical security headers (CSP, HSTS, X-Frame-Options).',
            realWorldContext: 'Enables XSS, clickjacking, and MIME-type attacks. Easily detected by security scanners.',
            category: 'application', severity: 'medium',
            mitreTechniques: ['T1059.007', 'T1190'],
            cweIds: ['CWE-693', 'CWE-1021'],
            files: {
                '/etc/nginx/conf.d/security-headers.conf': {
                    content: [
                        '# Security headers — INCOMPLETE',
                        '# Missing: Content-Security-Policy',
                        '# Missing: Strict-Transport-Security',
                        '# Missing: X-Frame-Options',
                        '# Missing: X-Content-Type-Options',
                        'add_header X-Powered-By "PHP/7.4";  # INSECURE: version disclosure',
                    ].join('\n'),
                    mode: 0o644, owner: 'root',
                },
            },
            clues: [
                { location: 'config', path: '/etc/nginx/conf.d/security-headers.conf', content: '# Security headers — INCOMPLETE', visibility: 3 },
            ],
            detectionHints: ['Check response headers with curl -I', 'Look for missing CSP, HSTS, X-Frame-Options'],
            remediation: ['Add Content-Security-Policy header', 'Add Strict-Transport-Security header', 'Add X-Frame-Options: DENY', 'Remove X-Powered-By header'],
            tags: ['headers', 'csp', 'hsts', 'xss', 'clickjacking'],
            applicableRoles: ['target', 'defend'],
        },
        {
            id: 'MISC-0082', name: 'CORS Wildcard Configuration',
            description: 'CORS configured with Access-Control-Allow-Origin: * allowing any domain.',
            realWorldContext: 'Allows malicious websites to make authenticated requests to the API.',
            category: 'application', severity: 'high',
            mitreTechniques: ['T1190'],
            cweIds: ['CWE-942'],
            files: {
                '/etc/nginx/conf.d/cors.conf': {
                    content: [
                        'location /api/ {',
                        '    add_header Access-Control-Allow-Origin *;',
                        '    add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS";',
                        '    add_header Access-Control-Allow-Headers "Authorization, Content-Type";',
                        '    add_header Access-Control-Allow-Credentials true;  # DANGEROUS with wildcard origin',
                        '}',
                    ].join('\n'),
                    mode: 0o644, owner: 'root',
                },
            },
            clues: [
                { location: 'config', path: '/etc/nginx/conf.d/cors.conf', content: 'Access-Control-Allow-Origin *', visibility: 4 },
            ],
            detectionHints: ['Check CORS headers in API responses', 'Look for wildcard origin with credentials'],
            remediation: ['Whitelist specific trusted origins', 'Never use Allow-Credentials with wildcard origin'],
            tags: ['cors', 'api', 'web', 'cross-origin'],
            applicableRoles: ['target'],
        },
    ];
}

// ── Factory ─────────────────────────────────────────────────────

export function createMisconfigCatalog(): MisconfigCatalog {
    const templates = new Map<string, MisconfigTemplate>();

    for (const t of createBuiltinTemplates()) {
        templates.set(t.id, Object.freeze(t));
    }

    return {
        get(id: string): MisconfigTemplate | null {
            return templates.get(id) ?? null;
        },

        list(): readonly MisconfigTemplate[] {
            return Object.freeze([...templates.values()]);
        },

        listByCategory(category: MisconfigCategory): readonly MisconfigTemplate[] {
            return Object.freeze(
                [...templates.values()].filter(t => t.category === category)
            );
        },

        listBySeverity(severity: MisconfigSeverity): readonly MisconfigTemplate[] {
            return Object.freeze(
                [...templates.values()].filter(t => t.severity === severity)
            );
        },

        listByMitreTechnique(techniqueId: string): readonly MisconfigTemplate[] {
            return Object.freeze(
                [...templates.values()].filter(t => t.mitreTechniques.includes(techniqueId))
            );
        },

        search(query: string): readonly MisconfigTemplate[] {
            const lower = query.toLowerCase();
            return Object.freeze(
                [...templates.values()].filter(t =>
                    t.id.toLowerCase().includes(lower) ||
                    t.name.toLowerCase().includes(lower) ||
                    t.description.toLowerCase().includes(lower) ||
                    t.tags.some(tag => tag.toLowerCase().includes(lower))
                )
            );
        },

        addTemplate(template: MisconfigTemplate): void {
            templates.set(template.id, Object.freeze(template));
        },

        getStats(): MisconfigCatalogStats {
            const byCategory: Record<string, number> = {};
            const bySeverity: Record<string, number> = {};
            const techniques = new Set<string>();

            for (const t of templates.values()) {
                byCategory[t.category] = (byCategory[t.category] ?? 0) + 1;
                bySeverity[t.severity] = (bySeverity[t.severity] ?? 0) + 1;
                for (const m of t.mitreTechniques) techniques.add(m);
            }

            return Object.freeze({
                totalTemplates: templates.size,
                byCategory,
                bySeverity,
                uniqueMitreTechniques: techniques.size,
            });
        },
    };
}
