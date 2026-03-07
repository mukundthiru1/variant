import type { EngineEvent, EventBus, Unsubscribe } from '../core/events';
import type { Capability, Module, SimulationContext } from '../core/modules';

const MODULE_ID = 'threat-intel';
const MODULE_VERSION = '1.0.0';

const MODULE_CAPABILITIES = [
    { name: 'threat-intel' },
    { name: 'mitre-att&ck' },
] as const satisfies readonly Capability[];

const KILL_CHAIN_ORDER = [
    'Reconnaissance',
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Discovery',
    'Lateral Movement',
    'Collection',
    'C2',
    'Exfiltration',
    'Impact',
] as const;

export type KillChainPhaseName = typeof KILL_CHAIN_ORDER[number];

export interface MitreTechnique {
    readonly id: string;
    readonly name: string;
    readonly tactic: string;
    readonly phase: KillChainPhaseName;
    readonly description: string;
}

export interface KillChainPhase {
    readonly name: KillChainPhaseName;
    readonly order: number;
    readonly observed: boolean;
    readonly firstSeen: number | null;
    readonly techniques: readonly string[];
}

export interface CVEEntry {
    readonly id: string;
    readonly description: string;
    readonly cvss: number;
    readonly affectedSoftware: readonly string[];
    readonly affectedVersions: readonly string[];
    readonly technique: string;
}

export interface TechniqueDetection {
    readonly technique: MitreTechnique;
    readonly eventType: EngineEvent['type'];
    readonly timestamp: number;
}

export interface ThreatIntelService {
    detectTechnique(event: EngineEvent): MitreTechnique | null;
    getKillChainProgress(): readonly KillChainPhase[];
    matchCVE(software: string, version: string): readonly CVEEntry[];
    getTechniqueChain(): readonly TechniqueDetection[];
    getKnownTechniques(): readonly MitreTechnique[];
    getKnownCVEs(): readonly CVEEntry[];
    getStats(): { readonly eventsProcessed: number; readonly techniquesDetected: number; readonly phasesObserved: number };
}

const MITRE_TECHNIQUES: readonly MitreTechnique[] = [
    { id: 'T1595', name: 'Active Scanning', tactic: 'reconnaissance', phase: 'Reconnaissance', description: 'Actively probing targets for exposed services and weaknesses.' },
    { id: 'T1590', name: 'Gather Victim Network Information', tactic: 'reconnaissance', phase: 'Reconnaissance', description: 'Collecting network details before engagement.' },
    { id: 'T1592', name: 'Gather Victim Host Information', tactic: 'reconnaissance', phase: 'Reconnaissance', description: 'Collecting host-level details of the target environment.' },
    { id: 'T1583', name: 'Acquire Infrastructure', tactic: 'resource-development', phase: 'Reconnaissance', description: 'Preparing attacker infrastructure for campaigns.' },
    { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'initial-access', phase: 'Initial Access', description: 'Exploiting internet-facing applications for initial foothold.' },
    { id: 'T1133', name: 'External Remote Services', tactic: 'initial-access', phase: 'Initial Access', description: 'Abusing externally exposed remote management services.' },
    { id: 'T1566', name: 'Phishing', tactic: 'initial-access', phase: 'Initial Access', description: 'Using phishing lures to gain access.' },
    { id: 'T1078', name: 'Valid Accounts', tactic: 'defense-evasion', phase: 'Initial Access', description: 'Using valid credentials to blend into normal activity.' },
    { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'execution', phase: 'Execution', description: 'Executing commands through shells or script interpreters.' },
    { id: 'T1204', name: 'User Execution', tactic: 'execution', phase: 'Execution', description: 'Relying on user interaction to run malicious content.' },
    { id: 'T1106', name: 'Native API', tactic: 'execution', phase: 'Execution', description: 'Executing behavior through native platform APIs.' },
    { id: 'T1053', name: 'Scheduled Task/Job', tactic: 'execution', phase: 'Persistence', description: 'Using schedulers such as cron or task scheduler.' },
    { id: 'T1543', name: 'Create or Modify System Process', tactic: 'persistence', phase: 'Persistence', description: 'Creating services/system processes for persistence.' },
    { id: 'T1505', name: 'Server Software Component', tactic: 'persistence', phase: 'Persistence', description: 'Installing malicious server-side components.' },
    { id: 'T1098', name: 'Account Manipulation', tactic: 'persistence', phase: 'Persistence', description: 'Manipulating account state (such as adding SSH keys).' },
    { id: 'T1547', name: 'Boot or Logon Autostart Execution', tactic: 'persistence', phase: 'Persistence', description: 'Using startup folders and autorun keys for persistence.' },
    { id: 'T1548', name: 'Abuse Elevation Control Mechanism', tactic: 'privilege-escalation', phase: 'Privilege Escalation', description: 'Abusing sudo/UAC/setuid-like elevation controls.' },
    { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'privilege-escalation', phase: 'Privilege Escalation', description: 'Elevating privileges through exploit primitives.' },
    { id: 'T1134', name: 'Access Token Manipulation', tactic: 'privilege-escalation', phase: 'Privilege Escalation', description: 'Manipulating security tokens for elevated context.' },
    { id: 'T1070', name: 'Indicator Removal on Host', tactic: 'defense-evasion', phase: 'Defense Evasion', description: 'Deleting or modifying artifacts to hide activity.' },
    { id: 'T1027', name: 'Obfuscated/Compressed Files and Information', tactic: 'defense-evasion', phase: 'Defense Evasion', description: 'Obfuscating payloads or commands to evade detections.' },
    { id: 'T1218', name: 'System Binary Proxy Execution', tactic: 'defense-evasion', phase: 'Defense Evasion', description: 'Using trusted binaries to proxy execution.' },
    { id: 'T1552', name: 'Unsecured Credentials', tactic: 'credential-access', phase: 'Credential Access', description: 'Discovering credentials in files, scripts, and configs.' },
    { id: 'T1003', name: 'OS Credential Dumping', tactic: 'credential-access', phase: 'Credential Access', description: 'Dumping credentials from SAM, LSASS, shadow, or NTDS.' },
    { id: 'T1110', name: 'Brute Force', tactic: 'credential-access', phase: 'Credential Access', description: 'Repeated authentication attempts to guess credentials.' },
    { id: 'T1555', name: 'Credentials from Password Stores', tactic: 'credential-access', phase: 'Credential Access', description: 'Harvesting credentials from local stores.' },
    { id: 'T1558', name: 'Steal or Forge Kerberos Tickets', tactic: 'credential-access', phase: 'Credential Access', description: 'Using forged or stolen Kerberos tickets.' },
    { id: 'T1087', name: 'Account Discovery', tactic: 'discovery', phase: 'Discovery', description: 'Enumerating local or domain accounts.' },
    { id: 'T1082', name: 'System Information Discovery', tactic: 'discovery', phase: 'Discovery', description: 'Collecting OS and hardware context.' },
    { id: 'T1018', name: 'Remote System Discovery', tactic: 'discovery', phase: 'Discovery', description: 'Finding reachable hosts and services.' },
    { id: 'T1049', name: 'System Network Connections Discovery', tactic: 'discovery', phase: 'Discovery', description: 'Listing active connections and listeners.' },
    { id: 'T1518', name: 'Software Discovery', tactic: 'discovery', phase: 'Discovery', description: 'Enumerating installed software and packages.' },
    { id: 'T1046', name: 'Network Service Discovery', tactic: 'discovery', phase: 'Discovery', description: 'Scanning hosts and ports to discover services.' },
    { id: 'T1021', name: 'Remote Services', tactic: 'lateral-movement', phase: 'Lateral Movement', description: 'Moving laterally via SSH, RDP, SMB, and remote admin protocols.' },
    { id: 'T1570', name: 'Lateral Tool Transfer', tactic: 'lateral-movement', phase: 'Lateral Movement', description: 'Transferring payloads and tools between hosts.' },
    { id: 'T1563', name: 'Remote Service Session Hijacking', tactic: 'lateral-movement', phase: 'Lateral Movement', description: 'Hijacking active remote sessions.' },
    { id: 'T1534', name: 'Internal Spearphishing', tactic: 'lateral-movement', phase: 'Lateral Movement', description: 'Using compromised internal accounts to pivot.' },
    { id: 'T1213', name: 'Data from Information Repositories', tactic: 'collection', phase: 'Collection', description: 'Collecting data from internal repositories and shares.' },
    { id: 'T1005', name: 'Data from Local System', tactic: 'collection', phase: 'Collection', description: 'Collecting target files from local host storage.' },
    { id: 'T1074', name: 'Data Staged', tactic: 'collection', phase: 'Collection', description: 'Staging data before exfiltration.' },
    { id: 'T1119', name: 'Automated Collection', tactic: 'collection', phase: 'Collection', description: 'Automating recurring collection actions.' },
    { id: 'T1071', name: 'Application Layer Protocol', tactic: 'command-and-control', phase: 'C2', description: 'Using web, DNS, or other app protocols for C2.' },
    { id: 'T1095', name: 'Non-Application Layer Protocol', tactic: 'command-and-control', phase: 'C2', description: 'Using lower-layer protocols for C2 traffic.' },
    { id: 'T1001', name: 'Data Obfuscation', tactic: 'command-and-control', phase: 'C2', description: 'Obfuscating C2 traffic to avoid detection.' },
    { id: 'T1573', name: 'Encrypted Channel', tactic: 'command-and-control', phase: 'C2', description: 'Using encryption on C2 channels.' },
    { id: 'T1568', name: 'Dynamic Resolution', tactic: 'command-and-control', phase: 'C2', description: 'Using dynamic DNS/fast-flux for C2 reachability.' },
    { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'exfiltration', phase: 'Exfiltration', description: 'Exfiltrating data over existing C2 communication.' },
    { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', tactic: 'exfiltration', phase: 'Exfiltration', description: 'Using alternate protocols for exfiltration.' },
    { id: 'T1567', name: 'Exfiltration Over Web Service', tactic: 'exfiltration', phase: 'Exfiltration', description: 'Using cloud/web services for exfiltration.' },
    { id: 'T1537', name: 'Transfer Data to Cloud Account', tactic: 'exfiltration', phase: 'Exfiltration', description: 'Transferring stolen data into attacker cloud tenancy.' },
    { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'impact', phase: 'Impact', description: 'Encrypting data to disrupt operations.' },
    { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'impact', phase: 'Impact', description: 'Blocking or removing recovery mechanisms.' },
    { id: 'T1489', name: 'Service Stop', tactic: 'impact', phase: 'Impact', description: 'Stopping critical services to degrade operations.' },
    { id: 'T1496', name: 'Resource Hijacking', tactic: 'impact', phase: 'Impact', description: 'Abusing victim resources for attacker workloads.' },
    { id: 'T1498', name: 'Network Denial of Service', tactic: 'impact', phase: 'Impact', description: 'Disrupting network availability.' },
];

const TECHNIQUE_BY_ID = new Map(MITRE_TECHNIQUES.map((technique) => [technique.id, technique] as const));

const CVE_DATABASE: readonly CVEEntry[] = [
    { id: 'CVE-2021-44228', description: 'Log4Shell remote code execution in Log4j2.', cvss: 10.0, affectedSoftware: ['log4j', 'apache log4j'], affectedVersions: ['<2.15.0'], technique: 'T1190' },
    { id: 'CVE-2017-0144', description: 'EternalBlue SMBv1 remote code execution.', cvss: 8.1, affectedSoftware: ['windows smb', 'smbv1', 'microsoft windows'], affectedVersions: ['<10.0.15063'], technique: 'T1021' },
    { id: 'CVE-2019-0708', description: 'BlueKeep RDP remote code execution.', cvss: 9.8, affectedSoftware: ['windows rdp', 'remote desktop services'], affectedVersions: ['<6.1.7601.24441'], technique: 'T1133' },
    { id: 'CVE-2020-1472', description: 'Zerologon Netlogon elevation vulnerability.', cvss: 10.0, affectedSoftware: ['windows server', 'netlogon', 'active directory'], affectedVersions: ['<2020-08-patch'], technique: 'T1068' },
    { id: 'CVE-2021-34527', description: 'PrintNightmare remote code execution.', cvss: 8.8, affectedSoftware: ['windows print spooler', 'windows server'], affectedVersions: ['<2021-07-patch'], technique: 'T1068' },
    { id: 'CVE-2021-26855', description: 'ProxyLogon SSRF and auth bypass in Exchange.', cvss: 9.1, affectedSoftware: ['microsoft exchange'], affectedVersions: ['<2021-03-patch'], technique: 'T1190' },
    { id: 'CVE-2021-41773', description: 'Apache HTTP Server path traversal/RCE chain.', cvss: 7.5, affectedSoftware: ['apache http server', 'httpd'], affectedVersions: ['2.4.49'], technique: 'T1190' },
    { id: 'CVE-2022-22965', description: 'Spring4Shell RCE in Spring Core.', cvss: 9.8, affectedSoftware: ['spring core', 'spring framework'], affectedVersions: ['<5.3.18'], technique: 'T1190' },
    { id: 'CVE-2022-1388', description: 'F5 BIG-IP iControl REST auth bypass/RCE.', cvss: 9.8, affectedSoftware: ['f5 big-ip'], affectedVersions: ['<16.1.2.2'], technique: 'T1190' },
    { id: 'CVE-2022-30190', description: 'Follina MSDT remote code execution.', cvss: 7.8, affectedSoftware: ['microsoft office', 'windows'], affectedVersions: ['<2022-06-patch'], technique: 'T1204' },
    { id: 'CVE-2023-23397', description: 'Outlook NTLM credential leak via crafted reminder.', cvss: 9.8, affectedSoftware: ['microsoft outlook'], affectedVersions: ['<2023-03-patch'], technique: 'T1552' },
    { id: 'CVE-2023-34362', description: 'MOVEit Transfer SQLi leading to remote code execution.', cvss: 9.8, affectedSoftware: ['moveit transfer'], affectedVersions: ['<2023-05-patch'], technique: 'T1190' },
    { id: 'CVE-2023-3519', description: 'Citrix ADC/Gateway unauthenticated code execution.', cvss: 9.8, affectedSoftware: ['citrix adc', 'citrix gateway'], affectedVersions: ['<13.1-49.13'], technique: 'T1190' },
    { id: 'CVE-2023-4966', description: 'CitrixBleed information disclosure in NetScaler.', cvss: 9.4, affectedSoftware: ['citrix netscaler', 'citrix adc'], affectedVersions: ['<13.1-49.15'], technique: 'T1552' },
    { id: 'CVE-2023-20198', description: 'Cisco IOS XE Web UI privilege escalation/account injection.', cvss: 10.0, affectedSoftware: ['cisco ios xe'], affectedVersions: ['<17.9.4a'], technique: 'T1098' },
    { id: 'CVE-2018-13379', description: 'FortiOS SSL VPN path traversal credential leak.', cvss: 9.8, affectedSoftware: ['fortios', 'fortigate ssl vpn'], affectedVersions: ['<6.0.5'], technique: 'T1003' },
    { id: 'CVE-2014-0160', description: 'Heartbleed TLS memory disclosure.', cvss: 7.5, affectedSoftware: ['openssl'], affectedVersions: ['<1.0.1g'], technique: 'T1552' },
    { id: 'CVE-2017-5638', description: 'Apache Struts Jakarta parser RCE.', cvss: 10.0, affectedSoftware: ['apache struts'], affectedVersions: ['<2.3.32'], technique: 'T1190' },
    { id: 'CVE-2019-11510', description: 'Pulse Secure VPN file disclosure.', cvss: 10.0, affectedSoftware: ['pulse secure vpn'], affectedVersions: ['<9.0R3'], technique: 'T1552' },
    { id: 'CVE-2020-5902', description: 'F5 BIG-IP TMUI RCE.', cvss: 9.8, affectedSoftware: ['f5 big-ip'], affectedVersions: ['<15.1.0.4'], technique: 'T1190' },
    { id: 'CVE-2021-22005', description: 'VMware vCenter Server file upload RCE.', cvss: 9.8, affectedSoftware: ['vmware vcenter'], affectedVersions: ['<7.0U2c'], technique: 'T1190' },
    { id: 'CVE-2024-3400', description: 'PAN-OS command injection in GlobalProtect gateway.', cvss: 10.0, affectedSoftware: ['pan-os', 'palo alto firewall'], affectedVersions: ['<10.2.9-h1'], technique: 'T1190' },
];

interface InternalState {
    recentCredentialTimestamp: number;
    failedLoginsByPrincipal: Map<string, number[]>;
    scannedPortsBySource: Map<string, Map<number, number>>;
    chain: TechniqueDetection[];
    phaseInfo: Map<KillChainPhaseName, { firstSeen: number | null; techniques: Set<string> }>;
    eventsProcessed: number;
}

const CREDENTIAL_WINDOW_MS = 5 * 60_000;
const BRUTE_FORCE_WINDOW_MS = 2 * 60_000;
const SCAN_WINDOW_MS = 90_000;

function createState(): InternalState {
    return {
        recentCredentialTimestamp: 0,
        failedLoginsByPrincipal: new Map(),
        scannedPortsBySource: new Map(),
        chain: [],
        phaseInfo: new Map(KILL_CHAIN_ORDER.map((name) => [name, { firstSeen: null, techniques: new Set<string>() }] as const)),
        eventsProcessed: 0,
    };
}

function normalize(value: string): string {
    return value.trim().toLowerCase();
}

function safeDecode(value: string): string {
    try {
        return decodeURIComponent(value);
    } catch {
        return value;
    }
}

function compareVersions(left: string, right: string): number {
    const leftParts = left.split(/[^a-z0-9]+/i).filter(Boolean);
    const rightParts = right.split(/[^a-z0-9]+/i).filter(Boolean);
    const len = Math.max(leftParts.length, rightParts.length);
    for (let i = 0; i < len; i++) {
        const l = leftParts[i] ?? '0';
        const r = rightParts[i] ?? '0';
        const ln = Number(l);
        const rn = Number(r);
        if (!Number.isNaN(ln) && !Number.isNaN(rn)) {
            if (ln !== rn) return ln > rn ? 1 : -1;
            continue;
        }
        if (l !== r) return l > r ? 1 : -1;
    }
    return 0;
}

function versionMatches(version: string, rules: readonly string[]): boolean {
    if (rules.length === 0) return true;
    return rules.some((rule) => {
        const normalized = normalize(rule);
        if (normalized === '*' || normalized === 'any') return true;
        if (normalized.startsWith('<=')) return compareVersions(version, normalized.slice(2)) <= 0;
        if (normalized.startsWith('<')) return compareVersions(version, normalized.slice(1)) < 0;
        if (normalized.startsWith('>=')) return compareVersions(version, normalized.slice(2)) >= 0;
        if (normalized.startsWith('>')) return compareVersions(version, normalized.slice(1)) > 0;
        return compareVersions(version, normalized) === 0;
    });
}

function lookupTechnique(id: string): MitreTechnique | null {
    return TECHNIQUE_BY_ID.get(id) ?? null;
}

function detectTechniqueInternal(event: EngineEvent, state: InternalState): MitreTechnique | null {
    const now = event.timestamp;

    switch (event.type) {
        case 'auth:credential-found':
        case 'credential:registered':
            state.recentCredentialTimestamp = now;
            return lookupTechnique('T1552');

        case 'credential:validated':
            return lookupTechnique('T1078');

        case 'auth:login': {
            const principal = `${event.machine}:${event.user}:${event.service}`;
            if (!event.success) {
                const existing = state.failedLoginsByPrincipal.get(principal) ?? [];
                const trimmed = existing.filter((ts) => now - ts <= BRUTE_FORCE_WINDOW_MS);
                trimmed.push(now);
                state.failedLoginsByPrincipal.set(principal, trimmed);
                if (trimmed.length >= 5) return lookupTechnique('T1110');
                return null;
            }

            if (now - state.recentCredentialTimestamp <= CREDENTIAL_WINDOW_MS) {
                return lookupTechnique('T1078');
            }

            const svc = normalize(event.service);
            if (svc.includes('ssh') || svc.includes('rdp') || svc.includes('winrm') || svc.includes('smb')) {
                return lookupTechnique('T1021');
            }

            return lookupTechnique('T1078');
        }

        case 'auth:escalate':
            return lookupTechnique(event.method.toLowerCase().includes('sudo') ? 'T1548' : 'T1068');

        case 'fs:read': {
            const path = normalize(event.path);
            if (path.includes('/etc/shadow') || path.includes('/sam') || path.includes('ntds.dit')) {
                return lookupTechnique('T1003');
            }
            if (path.includes('id_rsa') || path.includes('credentials') || path.includes('secrets')) {
                return lookupTechnique('T1552');
            }
            if (path.includes('/proc/net') || path.includes('/etc/hosts')) {
                return lookupTechnique('T1049');
            }
            return null;
        }

        case 'fs:write': {
            const path = normalize(event.path);
            if (path.includes('/cron') || path.endsWith('/crontab')) return lookupTechnique('T1053');
            if (path.includes('authorized_keys') || path.includes('/etc/passwd')) return lookupTechnique('T1098');
            if (path.includes('/etc/systemd/') || path.includes('/etc/init.d')) return lookupTechnique('T1543');
            return null;
        }

        case 'fs:exec': {
            const command = normalize(`${event.path} ${event.args.join(' ')}`);
            if (command.includes('bash') || command.includes('sh ') || command.includes('powershell') || command.includes('cmd.exe') || command.includes('python') || command.includes('perl')) {
                return lookupTechnique('T1059');
            }
            if (command.includes('nmap') || command.includes('masscan') || command.includes(' -p')) {
                return lookupTechnique('T1046');
            }
            return null;
        }

        case 'net:connect': {
            const source = normalize(event.source);
            const byPort = state.scannedPortsBySource.get(source) ?? new Map<number, number>();
            byPort.set(event.port, now);
            for (const [port, ts] of byPort.entries()) {
                if (now - ts > SCAN_WINDOW_MS) byPort.delete(port);
            }
            state.scannedPortsBySource.set(source, byPort);

            if (byPort.size >= 6) return lookupTechnique('T1046');
            if ([22, 3389, 445, 5985, 5986].includes(event.port)) return lookupTechnique('T1021');
            return null;
        }

        case 'net:dns': {
            const query = normalize(event.query);
            if (query.includes('ddns') || query.includes('dyn') || query.includes('c2') || query.includes('beacon')) {
                return lookupTechnique('T1071');
            }
            return null;
        }

        case 'net:request': {
            const url = normalize(event.url);
            const decodedUrl = normalize(safeDecode(event.url));
            const method = normalize(event.method);
            const exploitTokens = ['../', 'union select', "' or '1'='1", 'cmd=', 'jndi:', '/wp-json', '/phpmyadmin'];
            if (exploitTokens.some((token) => url.includes(token) || decodedUrl.includes(token))) {
                return lookupTechnique('T1190');
            }
            const c2Tokens = ['beacon', '/gate.php', '/heartbeat', '/api/ping', '/c2', 'command=checkin'];
            if (c2Tokens.some((token) => url.includes(token) || decodedUrl.includes(token))) {
                return lookupTechnique('T1071');
            }
            if (method === 'post' && (url.includes('upload') || url.includes('exfil') || url.includes('archive'))) {
                return lookupTechnique('T1041');
            }
            return null;
        }

        case 'defense:breach':
            return lookupTechnique('T1498');

        case 'sim:gameover':
            return lookupTechnique('T1486');

        default:
            return null;
    }
}

function buildPhaseSnapshot(state: InternalState): readonly KillChainPhase[] {
    return KILL_CHAIN_ORDER.map((name, index) => {
        const phase = state.phaseInfo.get(name)!;
        return {
            name,
            order: index,
            observed: phase.firstSeen !== null,
            firstSeen: phase.firstSeen,
            techniques: Object.freeze([...phase.techniques]),
        };
    });
}

function matchCVEInternal(software: string, version: string): readonly CVEEntry[] {
    const softwareNeedle = normalize(software);
    const normalizedVersion = normalize(version);
    return CVE_DATABASE.filter((entry) => {
        const softwareMatch = entry.affectedSoftware.some((candidate) => softwareNeedle.includes(normalize(candidate)) || normalize(candidate).includes(softwareNeedle));
        if (!softwareMatch) return false;
        return versionMatches(normalizedVersion, entry.affectedVersions);
    });
}

function recordDetection(state: InternalState, technique: MitreTechnique, event: EngineEvent): TechniqueDetection {
    const detection: TechniqueDetection = {
        technique,
        eventType: event.type,
        timestamp: event.timestamp,
    };
    state.chain.push(detection);

    const phase = state.phaseInfo.get(technique.phase)!;
    if (phase.firstSeen === null) phase.firstSeen = event.timestamp;
    phase.techniques.add(technique.id);

    return detection;
}

export function createThreatIntelModule(eventBus: EventBus): Module {
    const state = createState();
    const unsubs: Unsubscribe[] = [];

    const service: ThreatIntelService = {
        detectTechnique(event: EngineEvent): MitreTechnique | null {
            return detectTechniqueInternal(event, state);
        },
        getKillChainProgress(): readonly KillChainPhase[] {
            return buildPhaseSnapshot(state);
        },
        matchCVE(software: string, version: string): readonly CVEEntry[] {
            return matchCVEInternal(software, version);
        },
        getTechniqueChain(): readonly TechniqueDetection[] {
            return Object.freeze([...state.chain]);
        },
        getKnownTechniques(): readonly MitreTechnique[] {
            return MITRE_TECHNIQUES;
        },
        getKnownCVEs(): readonly CVEEntry[] {
            return CVE_DATABASE;
        },
        getStats(): { readonly eventsProcessed: number; readonly techniquesDetected: number; readonly phasesObserved: number } {
            const phasesObserved = buildPhaseSnapshot(state).filter((phase) => phase.observed).length;
            return {
                eventsProcessed: state.eventsProcessed,
                techniquesDetected: state.chain.length,
                phasesObserved,
            };
        },
    };

    return {
        id: MODULE_ID,
        type: 'service',
        version: MODULE_VERSION,
        description: 'Threat intelligence mapping for MITRE ATT&CK techniques, kill chain progression, and CVE correlation.',
        provides: MODULE_CAPABILITIES,
        requires: [] as readonly Capability[],

        init(context: SimulationContext): void {
            if (!context.services.has('threat-intel')) {
                context.services.register('threat-intel', service);
            }

            unsubs.push(eventBus.onPrefix('*', (event) => {
                state.eventsProcessed += 1;
                const technique = detectTechniqueInternal(event, state);
                if (technique === null) return;

                const detection = recordDetection(state, technique, event);
                eventBus.emit({
                    type: 'custom:technique-detected',
                    timestamp: event.timestamp,
                    data: {
                        technique,
                        eventType: detection.eventType,
                        killChain: buildPhaseSnapshot(state),
                        chainLength: state.chain.length,
                    },
                });
            }));

            unsubs.push(eventBus.onPrefix('custom:', (event) => {
                if (event.type === 'custom:threat-intel-query') {
                    eventBus.emit({
                        type: 'custom:threat-intel-query-result',
                        timestamp: Date.now(),
                        data: {
                            techniques: state.chain,
                            killChain: buildPhaseSnapshot(state),
                            stats: service.getStats(),
                        },
                    });
                    return;
                }

                if (event.type === 'custom:threat-intel-cve-match') {
                    const payload = (typeof event.data === 'object' && event.data !== null) ? event.data as { software?: string; version?: string } : {};
                    const software = payload.software ?? '';
                    const version = payload.version ?? '';
                    eventBus.emit({
                        type: 'custom:threat-intel-cve-match-result',
                        timestamp: Date.now(),
                        data: {
                            software,
                            version,
                            matches: matchCVEInternal(software, version),
                        },
                    });
                }
            }));

            eventBus.emit({
                type: 'sim:alert',
                source: MODULE_ID,
                message: `Threat Intel module loaded (${MITRE_TECHNIQUES.length} ATT&CK techniques, ${CVE_DATABASE.length} CVEs).`,
                timestamp: Date.now(),
            });
        },

        destroy(): void {
            for (const unsub of unsubs) unsub();
            unsubs.length = 0;
        },
    };
}
