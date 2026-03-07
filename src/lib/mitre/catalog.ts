/**
 * VARIANT — MITRE ATT&CK Catalog
 *
 * Complete, queryable catalog of all MITRE ATT&CK techniques
 * relevant to VARIANT simulation. This is the single source of truth.
 *
 * Every technique entry maps to:
 * - Which VARIANT engines can simulate it
 * - Which VARIANT detection engines can detect it
 * - Platform applicability
 * - Detection difficulty
 *
 * Level designers use this catalog to:
 * - Browse available techniques for their scenarios
 * - Ensure MITRE coverage across their levels
 * - Map attack chains to real-world TTPs
 */

import type {
    MitreCatalog,
    MitreCatalogStats,
    MitreCoverageReport,
    MitrePlatform,
    MitreTactic,
    TacticCoverage,
    TechniqueEntry,
} from './types';

// ── Built-in Technique Database ─────────────────────────────────

function createBuiltinTechniques(): TechniqueEntry[] {
    return [
        // ── Reconnaissance ──────────────────────────────────────
        {
            id: 'T1595', name: 'Active Scanning',
            description: 'Adversaries scan victim IP blocks to gather information for targeting.',
            tactics: ['reconnaissance'], platforms: ['network'],
            variantEngines: { 'pcap': 'Port scan detection', 'ids': 'Scan signature matching' },
            variantDetections: { 'pcap': 'port-scan-anomaly', 'siem': 'scan-detection' },
            detectionDifficulty: 'easy', dataSources: ['Network Traffic: Network Traffic Flow'],
            simulationSupport: 'full', tags: ['scanning', 'recon', 'network'],
        },
        {
            id: 'T1595.001', name: 'Scanning IP Blocks', parent: 'T1595',
            description: 'Scan IP ranges to identify live hosts and open ports.',
            tactics: ['reconnaissance'], platforms: ['network'],
            variantEngines: { 'pcap': 'SYN scan simulation', 'lateral': 'Host discovery' },
            variantDetections: { 'pcap': 'syn-scan-detect', 'ids': 'nmap-signature' },
            detectionDifficulty: 'easy', dataSources: ['Network Traffic: Network Traffic Flow'],
            simulationSupport: 'full', tags: ['nmap', 'scanning', 'port-scan'],
        },
        {
            id: 'T1592', name: 'Gather Victim Host Information',
            description: 'Gather information about victim hosts for targeting.',
            tactics: ['reconnaissance'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: {},
            variantDetections: {},
            detectionDifficulty: 'very-hard', dataSources: ['Internet Scan: Response Content'],
            simulationSupport: 'detection-only', tags: ['osint', 'recon'],
        },

        // ── Initial Access ──────────────────────────────────────
        {
            id: 'T1190', name: 'Exploit Public-Facing Application',
            description: 'Exploit vulnerabilities in internet-facing applications.',
            tactics: ['initial-access'], platforms: ['linux', 'windows', 'network', 'containers'],
            variantEngines: { 'detection': 'SQLi/XSS/SSRF engines', 'waf': 'WAF bypass simulation', 'services': 'Vulnerable service handlers' },
            variantDetections: { 'detection': 'sqli/xss/ssrf/cmdi/path-traversal', 'waf': 'request-blocking', 'siem': 'exploit-detection' },
            detectionDifficulty: 'moderate', dataSources: ['Application Log: Application Log Content', 'Network Traffic: Network Traffic Content'],
            simulationSupport: 'full', tags: ['web', 'exploit', 'sqli', 'xss', 'rce'],
        },
        {
            id: 'T1133', name: 'External Remote Services',
            description: 'Leverage external remote services (VPN, RDP, SSH) for initial access.',
            tactics: ['initial-access', 'persistence'], platforms: ['linux', 'windows'],
            variantEngines: { 'lateral': 'SSH/RDP connection simulation', 'vpn': 'VPN tunnel simulation' },
            variantDetections: { 'audit': 'login-tracking', 'siem': 'remote-access-monitoring' },
            detectionDifficulty: 'moderate', dataSources: ['Logon Session: Logon Session Creation', 'Network Traffic: Network Traffic Flow'],
            simulationSupport: 'full', tags: ['remote-access', 'ssh', 'rdp', 'vpn'],
        },
        {
            id: 'T1078', name: 'Valid Accounts',
            description: 'Obtain and abuse credentials of existing accounts.',
            tactics: ['initial-access', 'persistence', 'privilege-escalation', 'defense-evasion'],
            platforms: ['linux', 'windows', 'macos', 'cloud', 'containers'],
            variantEngines: { 'audit': 'Login tracking', 'creds': 'Credential graph traversal', 'oauth': 'OAuth token abuse' },
            variantDetections: { 'audit': 'brute-force-detection', 'siem': 'anomalous-login' },
            detectionDifficulty: 'hard', dataSources: ['Logon Session: Logon Session Creation', 'User Account: User Account Authentication'],
            simulationSupport: 'full', tags: ['credentials', 'authentication', 'abuse'],
        },
        {
            id: 'T1566', name: 'Phishing',
            description: 'Send phishing messages to gain access to victim systems.',
            tactics: ['initial-access'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: {},
            variantDetections: {},
            detectionDifficulty: 'moderate', dataSources: ['Application Log: Application Log Content', 'Network Traffic: Network Traffic Content'],
            simulationSupport: 'planned', tags: ['social-engineering', 'email', 'phishing'],
        },
        {
            id: 'T1566.001', name: 'Spearphishing Attachment', parent: 'T1566',
            description: 'Send spearphishing emails with malicious attachments.',
            tactics: ['initial-access'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: {},
            variantDetections: {},
            detectionDifficulty: 'moderate', dataSources: ['Application Log: Application Log Content'],
            simulationSupport: 'planned', tags: ['social-engineering', 'email', 'attachment'],
        },

        // ── Execution ───────────────────────────────────────────
        {
            id: 'T1059', name: 'Command and Scripting Interpreter',
            description: 'Abuse command and script interpreters to execute commands.',
            tactics: ['execution'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'shell': 'Shell command execution', 'edr': 'Process monitoring', 'memory': 'Shellcode detection' },
            variantDetections: { 'edr': 'suspicious-command', 'detection': 'cmdi-detection', 'siem': 'command-execution' },
            detectionDifficulty: 'easy', dataSources: ['Command: Command Execution', 'Process: Process Creation'],
            simulationSupport: 'full', tags: ['shell', 'scripting', 'command-execution'],
        },
        {
            id: 'T1059.001', name: 'PowerShell', parent: 'T1059',
            description: 'Abuse PowerShell commands and scripts for execution.',
            tactics: ['execution'], platforms: ['windows'],
            variantEngines: { 'edr': 'PowerShell monitoring' },
            variantDetections: { 'edr': 'powershell-suspicious' },
            detectionDifficulty: 'easy', dataSources: ['Command: Command Execution', 'Script: Script Execution'],
            simulationSupport: 'partial', tags: ['powershell', 'windows', 'scripting'],
        },
        {
            id: 'T1059.004', name: 'Unix Shell', parent: 'T1059',
            description: 'Abuse Unix shell commands and scripts for execution.',
            tactics: ['execution'], platforms: ['linux', 'macos'],
            variantEngines: { 'shell': 'Bash/sh execution', 'edr': 'Shell monitoring' },
            variantDetections: { 'edr': 'shell-suspicious', 'siem': 'bash-execution' },
            detectionDifficulty: 'easy', dataSources: ['Command: Command Execution', 'Process: Process Creation'],
            simulationSupport: 'full', tags: ['bash', 'shell', 'linux'],
        },
        {
            id: 'T1059.007', name: 'JavaScript', parent: 'T1059',
            description: 'Abuse JavaScript for execution.',
            tactics: ['execution'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'detection': 'XSS engine' },
            variantDetections: { 'detection': 'xss-detection', 'waf': 'xss-blocking' },
            detectionDifficulty: 'moderate', dataSources: ['Command: Command Execution', 'Script: Script Execution'],
            simulationSupport: 'full', tags: ['javascript', 'xss', 'browser'],
        },
        {
            id: 'T1204', name: 'User Execution',
            description: 'Adversary relies on user interaction to execute malicious content.',
            tactics: ['execution'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'edr': 'User execution tracking' },
            variantDetections: { 'edr': 'suspicious-file-execution' },
            detectionDifficulty: 'moderate', dataSources: ['File: File Creation', 'Process: Process Creation'],
            simulationSupport: 'partial', tags: ['social-engineering', 'user-interaction'],
        },
        {
            id: 'T1047', name: 'Windows Management Instrumentation',
            description: 'Abuse WMI for execution of commands on remote systems.',
            tactics: ['execution'], platforms: ['windows'],
            variantEngines: { 'lateral': 'WMI pivot simulation' },
            variantDetections: { 'edr': 'wmi-execution' },
            detectionDifficulty: 'moderate', dataSources: ['Command: Command Execution', 'Network Traffic: Network Connection Creation'],
            simulationSupport: 'full', tags: ['wmi', 'windows', 'remote-execution'],
        },

        // ── Persistence ─────────────────────────────────────────
        {
            id: 'T1053', name: 'Scheduled Task/Job',
            description: 'Abuse task scheduling for persistent execution.',
            tactics: ['persistence', 'privilege-escalation', 'execution'],
            platforms: ['linux', 'windows', 'macos', 'containers'],
            variantEngines: { 'persistence': 'Cron/at/systemd-timer installation', 'edr': 'Scheduled task monitoring' },
            variantDetections: { 'persistence': 'sig/cron-user,sig/cron-system,sig/at-job', 'edr': 'scheduled-task' },
            detectionDifficulty: 'easy', dataSources: ['Scheduled Job: Scheduled Job Creation', 'Command: Command Execution'],
            simulationSupport: 'full', tags: ['persistence', 'scheduled-task', 'cron'],
        },
        {
            id: 'T1053.002', name: 'At', parent: 'T1053',
            description: 'Abuse the at utility for one-time task scheduling.',
            tactics: ['persistence', 'privilege-escalation', 'execution'], platforms: ['linux', 'macos', 'windows'],
            variantEngines: { 'persistence': 'at-job installation' },
            variantDetections: { 'persistence': 'sig/at-job' },
            detectionDifficulty: 'easy', dataSources: ['Scheduled Job: Scheduled Job Creation'],
            simulationSupport: 'full', tags: ['at', 'one-time', 'scheduled'],
        },
        {
            id: 'T1053.003', name: 'Cron', parent: 'T1053',
            description: 'Abuse the cron utility for recurring task scheduling.',
            tactics: ['persistence', 'privilege-escalation', 'execution'], platforms: ['linux', 'macos'],
            variantEngines: { 'persistence': 'Cron job installation' },
            variantDetections: { 'persistence': 'sig/cron-user,sig/cron-system' },
            detectionDifficulty: 'easy', dataSources: ['Scheduled Job: Scheduled Job Creation', 'File: File Modification'],
            simulationSupport: 'full', tags: ['cron', 'linux', 'scheduled'],
        },
        {
            id: 'T1053.005', name: 'Scheduled Task', parent: 'T1053',
            description: 'Abuse Windows Task Scheduler for persistent execution.',
            tactics: ['persistence', 'privilege-escalation', 'execution'], platforms: ['windows'],
            variantEngines: { 'lateral': 'Remote scheduled task creation' },
            variantDetections: { 'edr': 'scheduled-task-creation' },
            detectionDifficulty: 'easy', dataSources: ['Scheduled Job: Scheduled Job Creation'],
            simulationSupport: 'partial', tags: ['schtasks', 'windows', 'scheduled'],
        },
        {
            id: 'T1053.006', name: 'Systemd Timers', parent: 'T1053',
            description: 'Abuse systemd timers for persistent scheduled execution.',
            tactics: ['persistence', 'privilege-escalation', 'execution'], platforms: ['linux'],
            variantEngines: { 'persistence': 'Systemd timer installation' },
            variantDetections: { 'persistence': 'sig/systemd-timer' },
            detectionDifficulty: 'easy', dataSources: ['Scheduled Job: Scheduled Job Creation'],
            simulationSupport: 'full', tags: ['systemd', 'timer', 'linux'],
        },
        {
            id: 'T1543', name: 'Create or Modify System Process',
            description: 'Create or modify system-level processes for persistence.',
            tactics: ['persistence', 'privilege-escalation'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'persistence': 'Service creation', 'lateral': 'Remote service creation' },
            variantDetections: { 'persistence': 'sig/systemd-service', 'edr': 'service-creation' },
            detectionDifficulty: 'moderate', dataSources: ['Service: Service Creation', 'Process: Process Creation'],
            simulationSupport: 'full', tags: ['service', 'persistence', 'system-process'],
        },
        {
            id: 'T1543.002', name: 'Systemd Service', parent: 'T1543',
            description: 'Create or modify systemd services for persistence.',
            tactics: ['persistence', 'privilege-escalation'], platforms: ['linux'],
            variantEngines: { 'persistence': 'Systemd service unit installation' },
            variantDetections: { 'persistence': 'sig/systemd-service' },
            detectionDifficulty: 'moderate', dataSources: ['Service: Service Creation', 'File: File Creation'],
            simulationSupport: 'full', tags: ['systemd', 'service', 'linux'],
        },
        {
            id: 'T1543.003', name: 'Windows Service', parent: 'T1543',
            description: 'Create or modify Windows services for persistence.',
            tactics: ['persistence', 'privilege-escalation'], platforms: ['windows'],
            variantEngines: { 'lateral': 'Remote service creation via sc.exe' },
            variantDetections: { 'edr': 'service-creation' },
            detectionDifficulty: 'moderate', dataSources: ['Service: Service Creation'],
            simulationSupport: 'partial', tags: ['windows-service', 'sc.exe'],
        },
        {
            id: 'T1505', name: 'Server Software Component',
            description: 'Abuse server software components for persistence.',
            tactics: ['persistence'], platforms: ['linux', 'windows'],
            variantEngines: { 'persistence': 'Web shell installation' },
            variantDetections: { 'persistence': 'sig/web-shell', 'siem': 'web-shell-detection' },
            detectionDifficulty: 'moderate', dataSources: ['File: File Creation', 'Network Traffic: Network Traffic Content'],
            simulationSupport: 'full', tags: ['web-shell', 'server-software'],
        },
        {
            id: 'T1505.003', name: 'Web Shell', parent: 'T1505',
            description: 'Install web shells for persistent remote access.',
            tactics: ['persistence'], platforms: ['linux', 'windows'],
            variantEngines: { 'persistence': 'Web shell file placement', 'services': 'HTTP service with web shell' },
            variantDetections: { 'persistence': 'sig/web-shell', 'siem': 'web-shell-upload' },
            detectionDifficulty: 'moderate', dataSources: ['Application Log: Application Log Content', 'File: File Creation'],
            simulationSupport: 'full', tags: ['web-shell', 'php', 'jsp', 'asp'],
        },
        {
            id: 'T1098', name: 'Account Manipulation',
            description: 'Manipulate accounts to maintain persistence.',
            tactics: ['persistence', 'privilege-escalation'], platforms: ['linux', 'windows', 'macos', 'cloud'],
            variantEngines: { 'persistence': 'SSH key addition', 'ldap': 'LDAP account manipulation' },
            variantDetections: { 'persistence': 'sig/ssh-authorized-key', 'audit': 'account-modification' },
            detectionDifficulty: 'moderate', dataSources: ['User Account: User Account Modification'],
            simulationSupport: 'full', tags: ['accounts', 'ssh-key', 'manipulation'],
        },
        {
            id: 'T1098.004', name: 'SSH Authorized Keys', parent: 'T1098',
            description: 'Add SSH public keys for persistent access.',
            tactics: ['persistence', 'privilege-escalation'], platforms: ['linux', 'macos'],
            variantEngines: { 'persistence': 'SSH authorized key installation' },
            variantDetections: { 'persistence': 'sig/ssh-authorized-key' },
            detectionDifficulty: 'easy', dataSources: ['File: File Modification'],
            simulationSupport: 'full', tags: ['ssh', 'authorized-keys', 'linux'],
        },
        {
            id: 'T1546', name: 'Event Triggered Execution',
            description: 'Establish persistence via event-triggered execution mechanisms.',
            tactics: ['persistence', 'privilege-escalation'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'persistence': 'Udev rule, git hook, bashrc installation' },
            variantDetections: { 'persistence': 'sig/udev-rule,sig/git-hook,sig/bashrc-backdoor' },
            detectionDifficulty: 'moderate', dataSources: ['File: File Creation', 'File: File Modification'],
            simulationSupport: 'full', tags: ['event-triggered', 'hooks', 'bashrc'],
        },
        {
            id: 'T1546.004', name: 'Unix Shell Configuration Modification', parent: 'T1546',
            description: 'Modify shell configuration files (.bashrc, .profile) for persistence.',
            tactics: ['persistence', 'privilege-escalation'], platforms: ['linux', 'macos'],
            variantEngines: { 'persistence': 'Bashrc/profile backdoor installation' },
            variantDetections: { 'persistence': 'sig/bashrc-backdoor' },
            detectionDifficulty: 'easy', dataSources: ['File: File Modification'],
            simulationSupport: 'full', tags: ['bashrc', 'profile', 'shell-config'],
        },
        {
            id: 'T1547', name: 'Boot or Logon Autostart Execution',
            description: 'Configure programs to run at boot or logon for persistence.',
            tactics: ['persistence', 'privilege-escalation'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'persistence': 'Kernel module, init script installation' },
            variantDetections: { 'persistence': 'sig/kernel-module,sig/init-script,sig/rc-local' },
            detectionDifficulty: 'moderate', dataSources: ['File: File Creation', 'Module: Module Load'],
            simulationSupport: 'full', tags: ['autostart', 'boot', 'kernel-module'],
        },
        {
            id: 'T1547.006', name: 'Kernel Modules and Extensions', parent: 'T1547',
            description: 'Load malicious kernel modules for rootkit functionality.',
            tactics: ['persistence', 'privilege-escalation'], platforms: ['linux', 'macos'],
            variantEngines: { 'persistence': 'Kernel module installation' },
            variantDetections: { 'persistence': 'sig/kernel-module' },
            detectionDifficulty: 'hard', dataSources: ['Module: Module Load', 'File: File Creation'],
            simulationSupport: 'full', tags: ['rootkit', 'kernel', 'lkm'],
        },
        {
            id: 'T1556', name: 'Modify Authentication Process',
            description: 'Modify authentication mechanisms for credential access and persistence.',
            tactics: ['persistence', 'credential-access', 'defense-evasion'],
            platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'persistence': 'PAM module installation', 'pam': 'PAM authentication simulation' },
            variantDetections: { 'persistence': 'sig/pam-backdoor' },
            detectionDifficulty: 'hard', dataSources: ['File: File Modification', 'Logon Session: Logon Session Creation'],
            simulationSupport: 'full', tags: ['pam', 'authentication', 'backdoor'],
        },
        {
            id: 'T1556.003', name: 'Pluggable Authentication Modules', parent: 'T1556',
            description: 'Modify PAM configuration or install malicious PAM modules.',
            tactics: ['persistence', 'credential-access', 'defense-evasion'], platforms: ['linux', 'macos'],
            variantEngines: { 'persistence': 'PAM module backdoor', 'pam': 'PAM stack simulation' },
            variantDetections: { 'persistence': 'sig/pam-backdoor' },
            detectionDifficulty: 'hard', dataSources: ['File: File Modification'],
            simulationSupport: 'full', tags: ['pam', 'linux', 'authentication-bypass'],
        },
        {
            id: 'T1574', name: 'Hijack Execution Flow',
            description: 'Hijack the way programs load code to execute malicious payloads.',
            tactics: ['persistence', 'privilege-escalation', 'defense-evasion'],
            platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'persistence': 'LD_PRELOAD hijacking' },
            variantDetections: { 'persistence': 'sig/ld-preload' },
            detectionDifficulty: 'hard', dataSources: ['File: File Creation', 'Module: Module Load'],
            simulationSupport: 'full', tags: ['hijack', 'ld-preload', 'dll'],
        },
        {
            id: 'T1574.006', name: 'Dynamic Linker Hijacking', parent: 'T1574',
            description: 'Hijack dynamic linker via LD_PRELOAD or /etc/ld.so.preload.',
            tactics: ['persistence', 'privilege-escalation', 'defense-evasion'], platforms: ['linux', 'macos'],
            variantEngines: { 'persistence': 'LD_PRELOAD hijack installation' },
            variantDetections: { 'persistence': 'sig/ld-preload' },
            detectionDifficulty: 'hard', dataSources: ['File: File Creation', 'Module: Module Load'],
            simulationSupport: 'full', tags: ['ld-preload', 'shared-library', 'hijack'],
        },
        {
            id: 'T1037', name: 'Boot or Logon Initialization Scripts',
            description: 'Use scripts that run during boot or logon for persistence.',
            tactics: ['persistence', 'privilege-escalation'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'persistence': 'init-script, rc-local, motd-script installation' },
            variantDetections: { 'persistence': 'sig/init-script,sig/rc-local,sig/motd-script' },
            detectionDifficulty: 'easy', dataSources: ['File: File Modification', 'Process: Process Creation'],
            simulationSupport: 'full', tags: ['init', 'rc.local', 'motd', 'boot-script'],
        },
        {
            id: 'T1037.004', name: 'RC Scripts', parent: 'T1037',
            description: 'Abuse rc.local and init.d scripts for persistence.',
            tactics: ['persistence', 'privilege-escalation'], platforms: ['linux', 'macos'],
            variantEngines: { 'persistence': 'RC local and init script installation' },
            variantDetections: { 'persistence': 'sig/init-script,sig/rc-local' },
            detectionDifficulty: 'easy', dataSources: ['File: File Modification'],
            simulationSupport: 'full', tags: ['rc.local', 'init.d', 'linux'],
        },

        // ── Privilege Escalation ────────────────────────────────
        {
            id: 'T1548', name: 'Abuse Elevation Control Mechanism',
            description: 'Bypass elevation controls to gain higher privileges.',
            tactics: ['privilege-escalation', 'defense-evasion'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'pam': 'Sudo/SUID abuse simulation', 'audit': 'Privilege escalation detection' },
            variantDetections: { 'audit': 'privilege-escalation', 'siem': 'privesc-detection' },
            detectionDifficulty: 'moderate', dataSources: ['Command: Command Execution', 'Process: Process Creation'],
            simulationSupport: 'full', tags: ['sudo', 'suid', 'privesc'],
        },
        {
            id: 'T1548.001', name: 'Setuid and Setgid', parent: 'T1548',
            description: 'Abuse setuid/setgid binaries for privilege escalation.',
            tactics: ['privilege-escalation', 'defense-evasion'], platforms: ['linux', 'macos'],
            variantEngines: { 'pam': 'SUID binary exploitation (GTFOBins)' },
            variantDetections: { 'pam': 'suid-exploitation-detect' },
            detectionDifficulty: 'moderate', dataSources: ['File: File Metadata', 'Process: Process Creation'],
            simulationSupport: 'full', tags: ['suid', 'setuid', 'gtfobins', 'linux'],
        },
        {
            id: 'T1548.003', name: 'Sudo and Sudo Caching', parent: 'T1548',
            description: 'Abuse sudo privileges or cached sudo tokens.',
            tactics: ['privilege-escalation', 'defense-evasion'], platforms: ['linux', 'macos'],
            variantEngines: { 'pam': 'Sudo exploitation and caching abuse' },
            variantDetections: { 'pam': 'sudo-abuse-detect' },
            detectionDifficulty: 'moderate', dataSources: ['Command: Command Execution'],
            simulationSupport: 'full', tags: ['sudo', 'privesc', 'linux'],
        },

        // ── Defense Evasion ─────────────────────────────────────
        {
            id: 'T1070', name: 'Indicator Removal',
            description: 'Delete or modify artifacts to remove evidence of activity.',
            tactics: ['defense-evasion'], platforms: ['linux', 'windows', 'macos', 'containers'],
            variantEngines: { 'audit': 'Log tampering detection', 'stealth': 'Anti-forensics simulation' },
            variantDetections: { 'audit': 'log-clearing', 'siem': 'evidence-destruction' },
            detectionDifficulty: 'moderate', dataSources: ['File: File Deletion', 'File: File Modification'],
            simulationSupport: 'full', tags: ['anti-forensics', 'log-clearing', 'evasion'],
        },
        {
            id: 'T1070.001', name: 'Clear Windows Event Logs', parent: 'T1070',
            description: 'Clear Windows Event Logs to remove evidence.',
            tactics: ['defense-evasion'], platforms: ['windows'],
            variantEngines: { 'audit': 'Event log clearing detection' },
            variantDetections: { 'audit': 'event-log-clear' },
            detectionDifficulty: 'easy', dataSources: ['Command: Command Execution'],
            simulationSupport: 'full', tags: ['event-log', 'windows', 'log-clearing'],
        },
        {
            id: 'T1014', name: 'Rootkit',
            description: 'Use rootkits to hide malicious activity from system defenses.',
            tactics: ['defense-evasion'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'memory': 'Rootkit signature detection', 'persistence': 'Kernel module rootkit' },
            variantDetections: { 'memory': 'rootkit-signature', 'persistence': 'sig/kernel-module' },
            detectionDifficulty: 'very-hard', dataSources: ['File: File Creation', 'Module: Module Load'],
            simulationSupport: 'full', tags: ['rootkit', 'kernel', 'hiding'],
        },
        {
            id: 'T1027', name: 'Obfuscated Files or Information',
            description: 'Obfuscate content to evade detection.',
            tactics: ['defense-evasion'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'stealth': 'Encoding/obfuscation simulation' },
            variantDetections: { 'edr': 'obfuscation-detection' },
            detectionDifficulty: 'moderate', dataSources: ['File: File Creation'],
            simulationSupport: 'partial', tags: ['obfuscation', 'encoding', 'steganography'],
        },
        {
            id: 'T1027.003', name: 'Steganography', parent: 'T1027',
            description: 'Hide data within image or audio files.',
            tactics: ['defense-evasion'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'exfiltration': 'Steganographic exfiltration channel' },
            variantDetections: {},
            detectionDifficulty: 'very-hard', dataSources: ['File: File Creation'],
            simulationSupport: 'partial', tags: ['steganography', 'data-hiding'],
        },

        // ── Credential Access ───────────────────────────────────
        {
            id: 'T1110', name: 'Brute Force',
            description: 'Use brute force to attempt access to accounts.',
            tactics: ['credential-access'], platforms: ['linux', 'windows', 'macos', 'cloud'],
            variantEngines: { 'audit': 'Brute force simulation and detection' },
            variantDetections: { 'audit': 'brute-force-detect', 'siem': 'brute-force-alert' },
            detectionDifficulty: 'trivial', dataSources: ['User Account: User Account Authentication'],
            simulationSupport: 'full', tags: ['brute-force', 'password', 'authentication'],
        },
        {
            id: 'T1110.001', name: 'Password Guessing', parent: 'T1110',
            description: 'Attempt to guess passwords for user accounts.',
            tactics: ['credential-access'], platforms: ['linux', 'windows', 'macos', 'cloud'],
            variantEngines: { 'audit': 'Failed login tracking' },
            variantDetections: { 'siem': 'brute-force-detection' },
            detectionDifficulty: 'trivial', dataSources: ['User Account: User Account Authentication'],
            simulationSupport: 'full', tags: ['password-guessing', 'brute-force'],
        },
        {
            id: 'T1003', name: 'OS Credential Dumping',
            description: 'Dump credentials from the operating system.',
            tactics: ['credential-access'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'memory': 'Memory credential extraction', 'edr': 'Credential dump detection' },
            variantDetections: { 'edr': 'credential-dump', 'memory': 'credential-extraction' },
            detectionDifficulty: 'moderate', dataSources: ['Command: Command Execution', 'Process: Process Access'],
            simulationSupport: 'full', tags: ['credential-dump', 'mimikatz', 'hashdump'],
        },
        {
            id: 'T1003.001', name: 'LSASS Memory', parent: 'T1003',
            description: 'Access LSASS process memory for credential extraction.',
            tactics: ['credential-access'], platforms: ['windows'],
            variantEngines: { 'edr': 'LSASS access monitoring' },
            variantDetections: { 'edr': 'lsass-access' },
            detectionDifficulty: 'easy', dataSources: ['Process: Process Access'],
            simulationSupport: 'partial', tags: ['lsass', 'mimikatz', 'windows'],
        },
        {
            id: 'T1552', name: 'Unsecured Credentials',
            description: 'Search for insecurely stored credentials.',
            tactics: ['credential-access'], platforms: ['linux', 'windows', 'macos', 'cloud', 'containers'],
            variantEngines: { 'creds': 'Credential graph', 'pcap': 'Cleartext credential detection' },
            variantDetections: { 'pcap': 'cleartext-credential' },
            detectionDifficulty: 'hard', dataSources: ['File: File Access', 'Command: Command Execution'],
            simulationSupport: 'full', tags: ['credentials', 'hardcoded', 'cleartext'],
        },
        {
            id: 'T1552.004', name: 'Private Keys', parent: 'T1552',
            description: 'Search for private cryptographic keys on compromised systems.',
            tactics: ['credential-access'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'memory': 'Private key extraction from memory' },
            variantDetections: {},
            detectionDifficulty: 'hard', dataSources: ['File: File Access'],
            simulationSupport: 'full', tags: ['private-key', 'ssh-key', 'certificate'],
        },
        {
            id: 'T1552.007', name: 'Container API', parent: 'T1552',
            description: 'Access container APIs to retrieve credentials.',
            tactics: ['credential-access'], platforms: ['containers'],
            variantEngines: { 'pcap': 'Container API credential detection' },
            variantDetections: { 'pcap': 'container-api-credential' },
            detectionDifficulty: 'moderate', dataSources: ['Network Traffic: Network Traffic Content'],
            simulationSupport: 'partial', tags: ['container', 'api', 'kubernetes'],
        },
        {
            id: 'T1558', name: 'Steal or Forge Kerberos Tickets',
            description: 'Steal or forge Kerberos tickets for lateral movement.',
            tactics: ['credential-access'], platforms: ['windows'],
            variantEngines: { 'lateral': 'Kerberos ticket simulation', 'ldap': 'Kerberoasting/AS-REP' },
            variantDetections: { 'ldap': 'kerberos-attack-detect' },
            detectionDifficulty: 'hard', dataSources: ['Active Directory: Active Directory Credential Request'],
            simulationSupport: 'full', tags: ['kerberos', 'golden-ticket', 'silver-ticket'],
        },
        {
            id: 'T1558.001', name: 'Golden Ticket', parent: 'T1558',
            description: 'Forge TGTs using the KRBTGT hash for persistent domain access.',
            tactics: ['credential-access'], platforms: ['windows'],
            variantEngines: { 'lateral': 'Golden ticket pivot simulation' },
            variantDetections: { 'ldap': 'golden-ticket-detect' },
            detectionDifficulty: 'hard', dataSources: ['Active Directory: Active Directory Credential Request'],
            simulationSupport: 'full', tags: ['golden-ticket', 'kerberos', 'domain-admin'],
        },
        {
            id: 'T1558.002', name: 'Silver Ticket', parent: 'T1558',
            description: 'Forge service tickets for targeted service access.',
            tactics: ['credential-access'], platforms: ['windows'],
            variantEngines: { 'lateral': 'Silver ticket pivot simulation' },
            variantDetections: { 'ldap': 'silver-ticket-detect' },
            detectionDifficulty: 'hard', dataSources: ['Active Directory: Active Directory Credential Request'],
            simulationSupport: 'full', tags: ['silver-ticket', 'kerberos', 'service-ticket'],
        },
        {
            id: 'T1558.003', name: 'Kerberoasting', parent: 'T1558',
            description: 'Request service tickets to crack offline for service account credentials.',
            tactics: ['credential-access'], platforms: ['windows'],
            variantEngines: { 'ldap': 'Kerberoasting simulation' },
            variantDetections: { 'ldap': 'kerberoasting-detect' },
            detectionDifficulty: 'moderate', dataSources: ['Active Directory: Active Directory Credential Request'],
            simulationSupport: 'full', tags: ['kerberoasting', 'kerberos', 'service-account'],
        },
        {
            id: 'T1558.004', name: 'AS-REP Roasting', parent: 'T1558',
            description: 'Request AS-REP for accounts without pre-authentication.',
            tactics: ['credential-access'], platforms: ['windows'],
            variantEngines: { 'ldap': 'AS-REP roasting simulation' },
            variantDetections: { 'ldap': 'asrep-roasting-detect' },
            detectionDifficulty: 'moderate', dataSources: ['Active Directory: Active Directory Credential Request'],
            simulationSupport: 'full', tags: ['asrep-roasting', 'kerberos', 'no-preauth'],
        },

        // ── Discovery ───────────────────────────────────────────
        {
            id: 'T1046', name: 'Network Service Discovery',
            description: 'Discover services running on remote hosts.',
            tactics: ['discovery'], platforms: ['linux', 'windows', 'macos', 'network'],
            variantEngines: { 'pcap': 'Port scan analysis', 'lateral': 'Service discovery' },
            variantDetections: { 'pcap': 'port-scan-detect', 'siem': 'service-scan' },
            detectionDifficulty: 'easy', dataSources: ['Network Traffic: Network Traffic Flow'],
            simulationSupport: 'full', tags: ['nmap', 'port-scan', 'service-discovery'],
        },
        {
            id: 'T1083', name: 'File and Directory Discovery',
            description: 'Enumerate files and directories on compromised systems.',
            tactics: ['discovery'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'shell': 'ls/find/dir simulation', 'detection': 'Path traversal engine' },
            variantDetections: { 'detection': 'path-traversal' },
            detectionDifficulty: 'hard', dataSources: ['Command: Command Execution'],
            simulationSupport: 'full', tags: ['enumeration', 'directory-listing', 'files'],
        },

        // ── Lateral Movement ────────────────────────────────────
        {
            id: 'T1021', name: 'Remote Services',
            description: 'Use legitimate remote services for lateral movement.',
            tactics: ['lateral-movement'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'lateral': 'Full lateral movement simulation' },
            variantDetections: { 'lateral': 'pivot-tracking', 'siem': 'lateral-movement' },
            detectionDifficulty: 'moderate', dataSources: ['Logon Session: Logon Session Creation', 'Network Traffic: Network Traffic Flow'],
            simulationSupport: 'full', tags: ['remote-services', 'lateral', 'pivot'],
        },
        {
            id: 'T1021.001', name: 'Remote Desktop Protocol', parent: 'T1021',
            description: 'Use RDP for lateral movement between Windows hosts.',
            tactics: ['lateral-movement'], platforms: ['windows'],
            variantEngines: { 'lateral': 'RDP pivot simulation' },
            variantDetections: { 'siem': 'rdp-lateral-movement' },
            detectionDifficulty: 'easy', dataSources: ['Logon Session: Logon Session Creation'],
            simulationSupport: 'full', tags: ['rdp', 'windows', 'remote-desktop'],
        },
        {
            id: 'T1021.002', name: 'SMB/Windows Admin Shares', parent: 'T1021',
            description: 'Use SMB and Windows admin shares for lateral movement.',
            tactics: ['lateral-movement'], platforms: ['windows'],
            variantEngines: { 'lateral': 'PSExec/SMBExec pivot simulation' },
            variantDetections: { 'siem': 'smb-lateral' },
            detectionDifficulty: 'moderate', dataSources: ['Network Traffic: Network Traffic Flow', 'Logon Session: Logon Session Creation'],
            simulationSupport: 'full', tags: ['smb', 'psexec', 'smbexec', 'admin-shares'],
        },
        {
            id: 'T1021.003', name: 'Distributed Component Object Model', parent: 'T1021',
            description: 'Use DCOM for remote code execution and lateral movement.',
            tactics: ['lateral-movement'], platforms: ['windows'],
            variantEngines: { 'lateral': 'DCOM pivot simulation' },
            variantDetections: {},
            detectionDifficulty: 'moderate', dataSources: ['Network Traffic: Network Traffic Flow'],
            simulationSupport: 'full', tags: ['dcom', 'windows', 'com'],
        },
        {
            id: 'T1021.004', name: 'SSH', parent: 'T1021',
            description: 'Use SSH for remote access and lateral movement.',
            tactics: ['lateral-movement'], platforms: ['linux', 'macos'],
            variantEngines: { 'lateral': 'SSH pivot simulation', 'services': 'SSH service handler' },
            variantDetections: { 'siem': 'ssh-lateral', 'audit': 'ssh-login-tracking' },
            detectionDifficulty: 'moderate', dataSources: ['Logon Session: Logon Session Creation', 'Network Traffic: Network Traffic Flow'],
            simulationSupport: 'full', tags: ['ssh', 'linux', 'remote-access'],
        },
        {
            id: 'T1021.006', name: 'Windows Remote Management', parent: 'T1021',
            description: 'Use WinRM for remote command execution.',
            tactics: ['lateral-movement'], platforms: ['windows'],
            variantEngines: { 'lateral': 'WinRM pivot simulation' },
            variantDetections: {},
            detectionDifficulty: 'moderate', dataSources: ['Logon Session: Logon Session Creation'],
            simulationSupport: 'full', tags: ['winrm', 'windows', 'powershell-remoting'],
        },
        {
            id: 'T1550', name: 'Use Alternate Authentication Material',
            description: 'Use stolen authentication material for lateral movement.',
            tactics: ['lateral-movement', 'defense-evasion'], platforms: ['windows'],
            variantEngines: { 'lateral': 'PTH/PTT/Overpass-the-Hash simulation' },
            variantDetections: { 'lateral': 'alternate-auth-detect' },
            detectionDifficulty: 'hard', dataSources: ['Logon Session: Logon Session Creation'],
            simulationSupport: 'full', tags: ['pass-the-hash', 'pass-the-ticket', 'authentication'],
        },
        {
            id: 'T1550.002', name: 'Pass the Hash', parent: 'T1550',
            description: 'Use stolen NTLM hashes to authenticate without cracking.',
            tactics: ['lateral-movement', 'defense-evasion'], platforms: ['windows'],
            variantEngines: { 'lateral': 'Pass-the-Hash pivot' },
            variantDetections: { 'siem': 'pth-detection' },
            detectionDifficulty: 'hard', dataSources: ['Logon Session: Logon Session Creation'],
            simulationSupport: 'full', tags: ['pass-the-hash', 'ntlm', 'hash'],
        },
        {
            id: 'T1550.003', name: 'Pass the Ticket', parent: 'T1550',
            description: 'Use stolen Kerberos tickets for authentication.',
            tactics: ['lateral-movement', 'defense-evasion'], platforms: ['windows'],
            variantEngines: { 'lateral': 'Pass-the-Ticket pivot' },
            variantDetections: {},
            detectionDifficulty: 'hard', dataSources: ['Logon Session: Logon Session Creation'],
            simulationSupport: 'full', tags: ['pass-the-ticket', 'kerberos'],
        },
        {
            id: 'T1570', name: 'Lateral Tool Transfer',
            description: 'Transfer tools between systems in a compromised environment.',
            tactics: ['lateral-movement'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'lateral': 'Tool transfer simulation', 'edr': 'Transfer detection' },
            variantDetections: { 'edr': 'lateral-tool-transfer' },
            detectionDifficulty: 'moderate', dataSources: ['Network Traffic: Network Traffic Flow', 'File: File Creation'],
            simulationSupport: 'full', tags: ['tool-transfer', 'staging', 'lateral'],
        },
        {
            id: 'T1563', name: 'Remote Service Session Hijacking',
            description: 'Hijack existing remote service sessions.',
            tactics: ['lateral-movement'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'lateral': 'SSH/RDP session hijack simulation' },
            variantDetections: {},
            detectionDifficulty: 'hard', dataSources: ['Logon Session: Logon Session Creation'],
            simulationSupport: 'full', tags: ['session-hijack', 'ssh-hijack'],
        },
        {
            id: 'T1563.001', name: 'SSH Hijacking', parent: 'T1563',
            description: 'Hijack existing SSH sessions via agent forwarding or ControlMaster.',
            tactics: ['lateral-movement'], platforms: ['linux', 'macos'],
            variantEngines: { 'lateral': 'SSH hijack/agent forwarding pivot' },
            variantDetections: {},
            detectionDifficulty: 'hard', dataSources: ['Logon Session: Logon Session Creation'],
            simulationSupport: 'full', tags: ['ssh-hijack', 'agent-forwarding'],
        },

        // ── Collection ──────────────────────────────────────────
        {
            id: 'T1005', name: 'Data from Local System',
            description: 'Collect data of interest from the local system.',
            tactics: ['collection'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'shell': 'File read/copy simulation' },
            variantDetections: {},
            detectionDifficulty: 'hard', dataSources: ['File: File Access', 'Command: Command Execution'],
            simulationSupport: 'full', tags: ['data-collection', 'local-files'],
        },
        {
            id: 'T1119', name: 'Automated Collection',
            description: 'Use automated techniques to collect internal data.',
            tactics: ['collection'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: {},
            variantDetections: {},
            detectionDifficulty: 'moderate', dataSources: ['Command: Command Execution', 'Script: Script Execution'],
            simulationSupport: 'planned', tags: ['automated', 'collection', 'scripted'],
        },

        // ── Command and Control ─────────────────────────────────
        {
            id: 'T1071', name: 'Application Layer Protocol',
            description: 'Communicate using application layer protocols to avoid detection.',
            tactics: ['command-and-control'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'pcap': 'C2 traffic analysis', 'vpn': 'Tunneled C2' },
            variantDetections: { 'pcap': 'c2-beacon-detect' },
            detectionDifficulty: 'moderate', dataSources: ['Network Traffic: Network Traffic Content'],
            simulationSupport: 'full', tags: ['c2', 'http', 'dns', 'application-protocol'],
        },
        {
            id: 'T1071.001', name: 'Web Protocols', parent: 'T1071',
            description: 'Use HTTP/S for C2 communication.',
            tactics: ['command-and-control'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'exfiltration': 'HTTPS-based C2 channel' },
            variantDetections: { 'pcap': 'http-c2-detect' },
            detectionDifficulty: 'moderate', dataSources: ['Network Traffic: Network Traffic Content'],
            simulationSupport: 'full', tags: ['http', 'https', 'c2', 'web'],
        },
        {
            id: 'T1071.004', name: 'DNS', parent: 'T1071',
            description: 'Use DNS for C2 communication or data exfiltration.',
            tactics: ['command-and-control'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'exfiltration': 'DNS tunnel exfiltration', 'vpn': 'DNS tunnel simulation', 'edr': 'DNS anomaly detection' },
            variantDetections: { 'pcap': 'dns-tunnel-detect', 'edr': 'dns-c2' },
            detectionDifficulty: 'moderate', dataSources: ['Network Traffic: Network Traffic Content'],
            simulationSupport: 'full', tags: ['dns', 'tunnel', 'c2', 'exfiltration'],
        },
        {
            id: 'T1090', name: 'Proxy',
            description: 'Use proxies to direct network traffic between systems.',
            tactics: ['command-and-control'], platforms: ['linux', 'windows', 'macos', 'network'],
            variantEngines: { 'proxy': 'Proxy chain simulation', 'vpn': 'SOCKS/HTTP proxy tunnels' },
            variantDetections: { 'proxy': 'proxy-chain-detect' },
            detectionDifficulty: 'moderate', dataSources: ['Network Traffic: Network Traffic Flow'],
            simulationSupport: 'full', tags: ['proxy', 'socks', 'http-proxy'],
        },
        {
            id: 'T1090.001', name: 'Internal Proxy', parent: 'T1090',
            description: 'Use an internal proxy to forward traffic within the network.',
            tactics: ['command-and-control'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'vpn': 'SOCKS4/5 proxy simulation' },
            variantDetections: {},
            detectionDifficulty: 'moderate', dataSources: ['Network Traffic: Network Traffic Flow'],
            simulationSupport: 'full', tags: ['socks4', 'socks5', 'internal-proxy'],
        },
        {
            id: 'T1090.002', name: 'External Proxy', parent: 'T1090',
            description: 'Use an external proxy to obfuscate traffic.',
            tactics: ['command-and-control'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'vpn': 'HTTP CONNECT proxy simulation' },
            variantDetections: {},
            detectionDifficulty: 'moderate', dataSources: ['Network Traffic: Network Traffic Flow'],
            simulationSupport: 'full', tags: ['http-connect', 'external-proxy'],
        },
        {
            id: 'T1090.003', name: 'Multi-hop Proxy', parent: 'T1090',
            description: 'Use multi-hop proxies (Tor, I2P) for anonymization.',
            tactics: ['command-and-control'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'vpn': 'Tor/I2P tunnel simulation' },
            variantDetections: {},
            detectionDifficulty: 'hard', dataSources: ['Network Traffic: Network Traffic Flow'],
            simulationSupport: 'full', tags: ['tor', 'i2p', 'anonymization'],
        },
        {
            id: 'T1572', name: 'Protocol Tunneling',
            description: 'Tunnel traffic through another protocol to avoid detection.',
            tactics: ['command-and-control'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'vpn': 'IPSec/OpenVPN/WireGuard/SSH/GRE tunnel simulation' },
            variantDetections: { 'pcap': 'tunnel-detection' },
            detectionDifficulty: 'moderate', dataSources: ['Network Traffic: Network Traffic Flow'],
            simulationSupport: 'full', tags: ['tunnel', 'vpn', 'ipsec', 'wireguard', 'openvpn'],
        },
        {
            id: 'T1095', name: 'Non-Application Layer Protocol',
            description: 'Use non-application layer protocols (ICMP, UDP) for C2.',
            tactics: ['command-and-control'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'vpn': 'ICMP tunnel simulation' },
            variantDetections: { 'pcap': 'icmp-tunnel-detect' },
            detectionDifficulty: 'moderate', dataSources: ['Network Traffic: Network Traffic Flow'],
            simulationSupport: 'full', tags: ['icmp', 'tunnel', 'non-standard'],
        },

        // ── Exfiltration ────────────────────────────────────────
        {
            id: 'T1041', name: 'Exfiltration Over C2 Channel',
            description: 'Exfiltrate data over the existing C2 channel.',
            tactics: ['exfiltration'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'exfiltration': 'C2 channel exfiltration' },
            variantDetections: { 'siem': 'data-exfiltration' },
            detectionDifficulty: 'moderate', dataSources: ['Network Traffic: Network Traffic Content'],
            simulationSupport: 'full', tags: ['exfiltration', 'c2', 'data-theft'],
        },
        {
            id: 'T1048', name: 'Exfiltration Over Alternative Protocol',
            description: 'Exfiltrate data using protocols other than the C2 channel.',
            tactics: ['exfiltration'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'exfiltration': 'Multi-protocol exfiltration simulation (15+ channels)' },
            variantDetections: { 'pcap': 'data-exfiltration-detect', 'siem': 'exfil-alert' },
            detectionDifficulty: 'moderate', dataSources: ['Network Traffic: Network Traffic Flow', 'Network Traffic: Network Traffic Content'],
            simulationSupport: 'full', tags: ['exfiltration', 'alternative-protocol'],
        },
        {
            id: 'T1048.002', name: 'Exfiltration Over Asymmetric Encrypted Non-C2 Protocol', parent: 'T1048',
            description: 'Exfiltrate data over encrypted channels like HTTPS or SFTP.',
            tactics: ['exfiltration'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'exfiltration': 'SFTP/SCP encrypted exfiltration' },
            variantDetections: {},
            detectionDifficulty: 'hard', dataSources: ['Network Traffic: Network Traffic Flow'],
            simulationSupport: 'full', tags: ['encrypted', 'sftp', 'scp', 'exfiltration'],
        },
        {
            id: 'T1048.003', name: 'Exfiltration Over Unencrypted Non-C2 Protocol', parent: 'T1048',
            description: 'Exfiltrate data over unencrypted protocols (HTTP, FTP, SMTP).',
            tactics: ['exfiltration'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'exfiltration': 'HTTP/FTP/SMTP/ICMP/raw-TCP exfiltration' },
            variantDetections: { 'pcap': 'cleartext-exfil', 'siem': 'unencrypted-exfil' },
            detectionDifficulty: 'easy', dataSources: ['Network Traffic: Network Traffic Content'],
            simulationSupport: 'full', tags: ['http', 'ftp', 'smtp', 'cleartext', 'exfiltration'],
        },
        {
            id: 'T1567', name: 'Exfiltration Over Web Service',
            description: 'Exfiltrate data to cloud storage or web services.',
            tactics: ['exfiltration'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'exfiltration': 'Cloud storage exfiltration' },
            variantDetections: {},
            detectionDifficulty: 'hard', dataSources: ['Network Traffic: Network Traffic Content'],
            simulationSupport: 'full', tags: ['cloud', 'web-service', 'exfiltration'],
        },
        {
            id: 'T1567.002', name: 'Exfiltration to Cloud Storage', parent: 'T1567',
            description: 'Exfiltrate data to cloud storage services (S3, GCS, etc.).',
            tactics: ['exfiltration'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'exfiltration': 'Cloud storage upload simulation' },
            variantDetections: {},
            detectionDifficulty: 'hard', dataSources: ['Network Traffic: Network Traffic Content'],
            simulationSupport: 'full', tags: ['cloud-storage', 's3', 'gcs', 'exfiltration'],
        },
        {
            id: 'T1052', name: 'Exfiltration Over Physical Medium',
            description: 'Exfiltrate data via physical medium (USB, etc.).',
            tactics: ['exfiltration'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'exfiltration': 'USB exfiltration simulation' },
            variantDetections: {},
            detectionDifficulty: 'moderate', dataSources: ['Drive: Drive Creation'],
            simulationSupport: 'partial', tags: ['usb', 'physical', 'exfiltration'],
        },
        {
            id: 'T1052.001', name: 'Exfiltration over USB', parent: 'T1052',
            description: 'Exfiltrate data by copying to a USB device.',
            tactics: ['exfiltration'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'exfiltration': 'USB drive exfiltration channel' },
            variantDetections: {},
            detectionDifficulty: 'moderate', dataSources: ['Drive: Drive Creation', 'File: File Access'],
            simulationSupport: 'partial', tags: ['usb', 'removable-media'],
        },

        // ── Impact ──────────────────────────────────────────────
        {
            id: 'T1489', name: 'Service Stop',
            description: 'Stop or disable services to cause impact.',
            tactics: ['impact'], platforms: ['linux', 'windows'],
            variantEngines: {},
            variantDetections: { 'siem': 'service-stop' },
            detectionDifficulty: 'easy', dataSources: ['Service: Service Metadata'],
            simulationSupport: 'detection-only', tags: ['service-stop', 'disruption'],
        },
        {
            id: 'T1486', name: 'Data Encrypted for Impact',
            description: 'Encrypt data on target systems to interrupt availability.',
            tactics: ['impact'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: {},
            variantDetections: {},
            detectionDifficulty: 'easy', dataSources: ['File: File Modification', 'File: File Creation'],
            simulationSupport: 'planned', tags: ['ransomware', 'encryption', 'impact'],
        },

        // ── Container-Specific ──────────────────────────────────
        {
            id: 'T1611', name: 'Escape to Host',
            description: 'Break out of a container to access the underlying host.',
            tactics: ['privilege-escalation'], platforms: ['containers'],
            variantEngines: { 'container': 'Container escape simulation (privileged, mount, socket)' },
            variantDetections: { 'container': 'container-escape-detect' },
            detectionDifficulty: 'moderate', dataSources: ['Container: Container Creation'],
            simulationSupport: 'full', tags: ['container', 'escape', 'docker', 'breakout'],
        },
        {
            id: 'T1006', name: 'Direct Volume Access',
            description: 'Access logical drives directly to bypass access controls.',
            tactics: ['defense-evasion'], platforms: ['windows', 'containers'],
            variantEngines: { 'container': 'Host filesystem access via mount' },
            variantDetections: { 'container': 'direct-volume-detect' },
            detectionDifficulty: 'moderate', dataSources: ['Drive: Drive Access'],
            simulationSupport: 'partial', tags: ['volume', 'direct-access', 'bypass'],
        },

        // ── Network Attacks ─────────────────────────────────────
        {
            id: 'T1557', name: 'Adversary-in-the-Middle',
            description: 'Position between two endpoints to intercept/modify traffic.',
            tactics: ['credential-access', 'collection'], platforms: ['linux', 'windows', 'macos', 'network'],
            variantEngines: { 'tls': 'MitM certificate validation', 'pcap': 'ARP spoofing detection' },
            variantDetections: { 'tls': 'mitm-cert-detect', 'pcap': 'arp-spoof-detect' },
            detectionDifficulty: 'moderate', dataSources: ['Network Traffic: Network Traffic Content'],
            simulationSupport: 'full', tags: ['mitm', 'arp-spoofing', 'interception'],
        },
        {
            id: 'T1557.002', name: 'ARP Cache Poisoning', parent: 'T1557',
            description: 'Poison ARP caches to redirect traffic through attacker.',
            tactics: ['credential-access', 'collection'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'pcap': 'ARP spoofing simulation and detection' },
            variantDetections: { 'pcap': 'arp-poisoning-detect' },
            detectionDifficulty: 'easy', dataSources: ['Network Traffic: Network Traffic Flow'],
            simulationSupport: 'full', tags: ['arp', 'spoofing', 'cache-poisoning'],
        },

        // ── Process Injection ───────────────────────────────────
        {
            id: 'T1055', name: 'Process Injection',
            description: 'Inject code into processes to evade defenses and elevate privileges.',
            tactics: ['privilege-escalation', 'defense-evasion'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'memory': 'Process injection simulation' },
            variantDetections: { 'memory': 'injection-detect', 'edr': 'process-injection' },
            detectionDifficulty: 'hard', dataSources: ['Process: Process Access', 'Process: Process Modification'],
            simulationSupport: 'full', tags: ['injection', 'process', 'evasion'],
        },
        {
            id: 'T1055.001', name: 'Dynamic-link Library Injection', parent: 'T1055',
            description: 'Inject DLLs into process address space.',
            tactics: ['privilege-escalation', 'defense-evasion'], platforms: ['windows'],
            variantEngines: { 'memory': 'DLL injection simulation' },
            variantDetections: { 'memory': 'dll-injection-detect' },
            detectionDifficulty: 'hard', dataSources: ['Process: Process Access'],
            simulationSupport: 'full', tags: ['dll-injection', 'windows'],
        },
        {
            id: 'T1055.012', name: 'Process Hollowing', parent: 'T1055',
            description: 'Create a process in suspended state and replace its memory.',
            tactics: ['privilege-escalation', 'defense-evasion'], platforms: ['windows'],
            variantEngines: { 'memory': 'Process hollowing simulation' },
            variantDetections: { 'memory': 'hollowing-detect' },
            detectionDifficulty: 'hard', dataSources: ['Process: Process Access'],
            simulationSupport: 'full', tags: ['process-hollowing', 'windows', 'evasion'],
        },

        // ── Additional Sub-techniques ───────────────────────────────
        {
            id: 'T1059.003', name: 'Windows Command Shell', parent: 'T1059',
            description: 'Abuse Windows cmd.exe for command execution.',
            tactics: ['execution'], platforms: ['windows'],
            variantEngines: { 'shell': 'CMD.exe execution', 'edr': 'CMD monitoring' },
            variantDetections: { 'edr': 'cmd-suspicious', 'siem': 'cmd-execution' },
            detectionDifficulty: 'easy', dataSources: ['Command: Command Execution', 'Process: Process Creation'],
            simulationSupport: 'full', tags: ['cmd', 'command-prompt', 'windows'],
        },

        // ── Impact: Inhibit System Recovery ────────────────────────
        {
            id: 'T1490', name: 'Inhibit System Recovery',
            description: 'Delete backups, shadow copies, or other recovery mechanisms.',
            tactics: ['impact'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: {},
            variantDetections: { 'siem': 'backup-deletion', 'audit': 'shadow-copy-clear' },
            detectionDifficulty: 'easy', dataSources: ['File: File Deletion', 'Process: Process Creation'],
            simulationSupport: 'partial', tags: ['backup', 'shadow-copy', 'recovery', 'ransomware'],
        },

        // ── Defense Evasion: Indicator Removal ────────────────────
        {
            id: 'T1070.003', name: 'Clear Command History', parent: 'T1070',
            description: 'Clear bash history or Windows PowerShell history.',
            tactics: ['defense-evasion'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'audit': 'History clearing detection' },
            variantDetections: { 'audit': 'history-clear' },
            detectionDifficulty: 'easy', dataSources: ['Command: Command Execution'],
            simulationSupport: 'full', tags: ['history', 'bash-history', 'log-clearing', 'anti-forensics'],
        },

        // ── Command and Control: Ingress Tool Transfer ───────────
        {
            id: 'T1105', name: 'Ingress Tool Transfer',
            description: 'Transfer tools or other files from external systems.',
            tactics: ['command-and-control'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'lateral': 'Tool transfer simulation', 'edr': 'Download detection' },
            variantDetections: { 'edr': 'suspicious-download', 'siem': 'tool-transfer' },
            detectionDifficulty: 'moderate', dataSources: ['File: File Creation', 'Network Traffic: Network Traffic Flow'],
            simulationSupport: 'full', tags: ['tool-transfer', 'download', 'wget', 'curl', 'staging'],
        },

        // ── Command and Control: Non-Standard Port ───────────────
        {
            id: 'T1571', name: 'Non-Standard Port',
            description: 'Use non-standard ports for C2 communication.',
            tactics: ['command-and-control'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'pcap': 'Non-standard port detection', 'vpn': 'Custom port tunneling' },
            variantDetections: { 'pcap': 'nonstandard-port', 'siem': 'anomalous-port' },
            detectionDifficulty: 'moderate', dataSources: ['Network Traffic: Network Traffic Flow'],
            simulationSupport: 'full', tags: ['non-standard-port', 'c2', 'custom-port'],
        },

        // ── Credential Access: Additional Sub-techniques ───────────
        {
            id: 'T1003.006', name: 'DCSync', parent: 'T1003',
            description: 'Perform DCSync to dump password hashes from domain controller.',
            tactics: ['credential-access'], platforms: ['windows'],
            variantEngines: { 'ldap': 'DCSync simulation' },
            variantDetections: { 'ldap': 'dcsync-detect', 'siem': 'dcsync-attack' },
            detectionDifficulty: 'hard', dataSources: ['Active Directory: Active Directory Credential Request'],
            simulationSupport: 'full', tags: ['dcsync', 'mimikatz', 'ntds', 'domain-controller'],
        },

        // ── Credential Access: Valid Accounts Sub-techniques ───────
        {
            id: 'T1078.001', name: 'Default Accounts', parent: 'T1078',
            description: 'Abuse default accounts (guest, administrator) for access.',
            tactics: ['initial-access', 'persistence', 'privilege-escalation', 'defense-evasion'],
            platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'audit': 'Default account usage tracking' },
            variantDetections: { 'audit': 'default-account-use' },
            detectionDifficulty: 'moderate', dataSources: ['User Account: User Account Authentication'],
            simulationSupport: 'full', tags: ['default-account', 'guest', 'administrator'],
        },
        {
            id: 'T1078.003', name: 'Local Accounts', parent: 'T1078',
            description: 'Abuse local user accounts for access.',
            tactics: ['initial-access', 'persistence', 'privilege-escalation', 'defense-evasion'],
            platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'audit': 'Local account usage tracking' },
            variantDetections: { 'audit': 'local-account-access' },
            detectionDifficulty: 'moderate', dataSources: ['User Account: User Account Authentication'],
            simulationSupport: 'full', tags: ['local-account', 'local-user'],
        },
        {
            id: 'T1078.004', name: 'Cloud Accounts', parent: 'T1078',
            description: 'Abuse cloud accounts (AWS, Azure, GCP) for access.',
            tactics: ['initial-access', 'persistence', 'privilege-escalation', 'defense-evasion'],
            platforms: ['cloud'],
            variantEngines: { 'oauth': 'Cloud account abuse simulation' },
            variantDetections: { 'siem': 'cloud-account-anomaly' },
            detectionDifficulty: 'hard', dataSources: ['User Account: User Account Authentication'],
            simulationSupport: 'full', tags: ['cloud-account', 'aws', 'azure', 'gcp', 'iam'],
        },

        // ── Credential Access: Brute Force Sub-techniques ─────────
        {
            id: 'T1110.003', name: 'Password Spraying', parent: 'T1110',
            description: 'Try a single password against many accounts.',
            tactics: ['credential-access'], platforms: ['linux', 'windows', 'macos', 'cloud'],
            variantEngines: { 'audit': 'Password spraying detection' },
            variantDetections: { 'audit': 'password-spray-detect', 'siem': 'spray-alert' },
            detectionDifficulty: 'moderate', dataSources: ['User Account: User Account Authentication'],
            simulationSupport: 'full', tags: ['password-spraying', 'brute-force', 'account-lockout'],
        },
        {
            id: 'T1110.004', name: 'Credential Stuffing', parent: 'T1110',
            description: 'Use stolen credential pairs against multiple services.',
            tactics: ['credential-access'], platforms: ['linux', 'windows', 'macos', 'cloud'],
            variantEngines: { 'audit': 'Credential stuffing detection' },
            variantDetections: { 'siem': 'credential-stuffing' },
            detectionDifficulty: 'hard', dataSources: ['User Account: User Account Authentication'],
            simulationSupport: 'partial', tags: ['credential-stuffing', 'credential-reuse', 'account-takeover'],
        },

        // ── Application Layer Protocol Sub-techniques ──────────────
        {
            id: 'T1071.002', name: 'File Transfer Protocols', parent: 'T1071',
            description: 'Use FTP, SFTP, or other file transfer protocols for C2.',
            tactics: ['command-and-control'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'exfiltration': 'FTP-based C2/exfiltration' },
            variantDetections: { 'pcap': 'ftp-c2-detect' },
            detectionDifficulty: 'moderate', dataSources: ['Network Traffic: Network Traffic Content'],
            simulationSupport: 'full', tags: ['ftp', 'sftp', 'c2', 'file-transfer'],
        },

        // ── Defense Evasion: Impair Defenses ──────────────────────
        {
            id: 'T1562', name: 'Impair Defenses',
            description: 'Disable or modify security measures to evade detection.',
            tactics: ['defense-evasion'], platforms: ['linux', 'windows', 'macos', 'containers'],
            variantEngines: { 'stealth': 'Security disable simulation', 'edr': 'EDR evasion' },
            variantDetections: { 'siem': 'security-disabled', 'audit': 'defense-impairment' },
            detectionDifficulty: 'moderate', dataSources: ['Process: Process Creation', 'Service: Service Modification'],
            simulationSupport: 'full', tags: ['defense-evasion', 'disable-security', 'tampering'],
        },
        {
            id: 'T1562.001', name: 'Disable or Modify Tools', parent: 'T1562',
            description: 'Disable security tools (AV, EDR, firewall).',
            tactics: ['defense-evasion'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'stealth': 'AV/EDR termination simulation' },
            variantDetections: { 'edr': 'tool-termination', 'siem': 'av-disabled' },
            detectionDifficulty: 'moderate', dataSources: ['Process: Process Creation', 'Service: Service Stop'],
            simulationSupport: 'full', tags: ['av-bypass', 'edr-evasion', 'firewall-disable'],
        },
        {
            id: 'T1562.004', name: 'Disable or Modify System Logs', parent: 'T1562',
            description: 'Disable or modify system logging to hide activity.',
            tactics: ['defense-evasion'], platforms: ['linux', 'windows', 'macos'],
            variantEngines: { 'audit': 'Log tampering simulation' },
            variantDetections: { 'audit': 'log-disable-detect', 'siem': 'logging-disabled' },
            detectionDifficulty: 'moderate', dataSources: ['Command: Command Execution', 'Service: Service Modification'],
            simulationSupport: 'full', tags: ['log-tampering', 'syslog-disable', 'windows-eventlog-disable'],
        },
    ];
}

// ── Factory ─────────────────────────────────────────────────────

export function createMitreCatalog(): MitreCatalog {
    const techniques = new Map<string, TechniqueEntry>();

    for (const t of createBuiltinTechniques()) {
        techniques.set(t.id, Object.freeze(t));
    }

    const catalog: MitreCatalog = {
        getTechnique(id: string): TechniqueEntry | null {
            return techniques.get(id) ?? null;
        },

        listTechniques(): readonly TechniqueEntry[] {
            return Object.freeze([...techniques.values()]);
        },

        listByTactic(tactic: MitreTactic): readonly TechniqueEntry[] {
            return Object.freeze(
                [...techniques.values()].filter(t => t.tactics.includes(tactic))
            );
        },

        listByPlatform(platform: MitrePlatform): readonly TechniqueEntry[] {
            return Object.freeze(
                [...techniques.values()].filter(t => t.platforms.includes(platform))
            );
        },

        listByEngine(engineName: string): readonly TechniqueEntry[] {
            return Object.freeze(
                [...techniques.values()].filter(t => engineName in t.variantEngines)
            );
        },

        listDetectable(): readonly TechniqueEntry[] {
            return Object.freeze(
                [...techniques.values()].filter(t => Object.keys(t.variantDetections).length > 0)
            );
        },

        listSubTechniques(parentId: string): readonly TechniqueEntry[] {
            return Object.freeze(
                [...techniques.values()].filter(t => t.parent === parentId)
            );
        },

        search(query: string): readonly TechniqueEntry[] {
            const lower = query.toLowerCase();
            return Object.freeze(
                [...techniques.values()].filter(t =>
                    t.id.toLowerCase().includes(lower) ||
                    t.name.toLowerCase().includes(lower) ||
                    t.description.toLowerCase().includes(lower) ||
                    t.tags.some(tag => tag.toLowerCase().includes(lower))
                )
            );
        },

        listTactics(): readonly MitreTactic[] {
            const tactics = new Set<MitreTactic>();
            for (const t of techniques.values()) {
                for (const tac of t.tactics) tactics.add(tac);
            }
            return Object.freeze([...tactics]);
        },

        addCustomTechnique(entry: TechniqueEntry): void {
            techniques.set(entry.id, Object.freeze(entry));
        },

        getStats(): MitreCatalogStats {
            const byTactic: Record<string, number> = {};
            const bySupport: Record<string, number> = {};
            const byPlatform: Record<string, number> = {};
            let subs = 0;
            let detectable = 0;

            for (const t of techniques.values()) {
                if (t.parent !== undefined) subs++;
                if (Object.keys(t.variantDetections).length > 0) detectable++;

                bySupport[t.simulationSupport] = (bySupport[t.simulationSupport] ?? 0) + 1;

                for (const tac of t.tactics) {
                    byTactic[tac] = (byTactic[tac] ?? 0) + 1;
                }
                for (const plat of t.platforms) {
                    byPlatform[plat] = (byPlatform[plat] ?? 0) + 1;
                }
            }

            return Object.freeze({
                totalTechniques: techniques.size - subs,
                totalSubTechniques: subs,
                byTactic,
                bySimulationSupport: bySupport,
                byPlatform,
                totalDetectable: detectable,
            });
        },

        getCoverage(): MitreCoverageReport {
            const tacticMap = new Map<MitreTactic, { total: number; full: number; partial: number; detection: number; planned: number }>();

            for (const t of techniques.values()) {
                for (const tac of t.tactics) {
                    const entry = tacticMap.get(tac) ?? { total: 0, full: 0, partial: 0, detection: 0, planned: 0 };
                    entry.total++;
                    switch (t.simulationSupport) {
                        case 'full': entry.full++; break;
                        case 'partial': entry.partial++; break;
                        case 'detection-only': entry.detection++; break;
                        case 'planned': entry.planned++; break;
                    }
                    tacticMap.set(tac, entry);
                }
            }

            const byTactic: TacticCoverage[] = [];
            for (const [tactic, data] of tacticMap) {
                const coveragePercent = data.total > 0
                    ? Math.round(((data.full + data.partial * 0.5 + data.detection * 0.25) / data.total) * 100)
                    : 0;
                byTactic.push(Object.freeze({
                    tactic,
                    totalTechniques: data.total,
                    fullSupport: data.full,
                    partialSupport: data.partial,
                    detectionOnly: data.detection,
                    planned: data.planned,
                    coveragePercent,
                }));
            }

            let totalFull = 0;
            let totalDetectable = 0;
            for (const t of techniques.values()) {
                if (t.simulationSupport === 'full' || t.simulationSupport === 'partial') totalFull++;
                if (Object.keys(t.variantDetections).length > 0) totalDetectable++;
            }

            return Object.freeze({
                byTactic: Object.freeze(byTactic),
                overallSimulatable: Math.round((totalFull / techniques.size) * 100),
                overallDetectable: Math.round((totalDetectable / techniques.size) * 100),
            });
        },
    };

    return catalog;
}
