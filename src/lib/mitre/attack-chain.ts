/**
 * VARIANT — Attack Chain Composer
 *
 * Helps level designers define multi-step attack paths
 * with automatic MITRE ATT&CK mapping. Each chain represents
 * a realistic attack scenario from initial access to objective.
 *
 * Level designers compose chains using the fluent builder API,
 * then validate them against the MITRE catalog to ensure
 * all techniques are real and all dependencies are satisfiable.
 */

import type {
    AttackChain,
    AttackChainStep,
    MitreCatalog,
    MitreTactic,
} from './types';

// ── Composer Interface ──────────────────────────────────────────

export interface AttackChainComposer {
    /** Start a new chain. */
    create(id: string, name: string, description: string): ChainBuilder;

    /** Validate an existing chain against the MITRE catalog. */
    validate(chain: AttackChain): ChainValidationResult;

    /** Get pre-built attack chain templates. */
    getTemplates(): readonly AttackChain[];

    /** Calculate difficulty based on detection risk and technique complexity. */
    estimateDifficulty(chain: AttackChain): 'beginner' | 'intermediate' | 'advanced' | 'expert';
}

export interface ChainBuilder {
    /** Add a step to the chain. */
    addStep(step: Omit<AttackChainStep, 'order'>): ChainBuilder;

    /** Set the overall difficulty. If not called, difficulty is auto-estimated. */
    difficulty(level: 'beginner' | 'intermediate' | 'advanced' | 'expert'): ChainBuilder;

    /** Add tags. */
    tags(tags: readonly string[]): ChainBuilder;

    /** Build and freeze the chain. */
    build(): AttackChain;
}

export interface ChainValidationResult {
    readonly valid: boolean;
    readonly errors: readonly string[];
    readonly warnings: readonly string[];
    readonly mitreCoverage: {
        readonly tactics: readonly MitreTactic[];
        readonly techniques: readonly string[];
        readonly missingFromCatalog: readonly string[];
    };
}

// ── Pre-built Templates ─────────────────────────────────────────

function createTemplates(): AttackChain[] {
    return [
        {
            id: 'chain/web-to-root',
            name: 'Web Application to Root',
            description: 'Exploit a web vulnerability, find credentials, escalate to root.',
            steps: [
                {
                    order: 1, description: 'Scan target web application for vulnerabilities',
                    techniqueId: 'T1595', tactic: 'reconnaissance',
                    detectionRisk: 'medium', artifacts: ['Network scan logs', 'IDS alerts'],
                    prerequisites: [],
                },
                {
                    order: 2, description: 'Exploit SQL injection in login form',
                    techniqueId: 'T1190', tactic: 'initial-access',
                    targetMachine: 'web-server', detectionRisk: 'high',
                    artifacts: ['WAF logs', 'Application error logs', 'Database query logs'],
                    prerequisites: [1],
                },
                {
                    order: 3, description: 'Execute commands via SQL injection to get shell',
                    techniqueId: 'T1059.004', tactic: 'execution',
                    targetMachine: 'web-server', detectionRisk: 'high',
                    artifacts: ['Process creation logs', 'Shell history'],
                    prerequisites: [2],
                },
                {
                    order: 4, description: 'Find database credentials in configuration files',
                    techniqueId: 'T1552', tactic: 'credential-access',
                    targetMachine: 'web-server', detectionRisk: 'low',
                    artifacts: ['File access logs'],
                    prerequisites: [3],
                },
                {
                    order: 5, description: 'Escalate to root via SUID binary',
                    techniqueId: 'T1548.001', tactic: 'privilege-escalation',
                    targetMachine: 'web-server', detectionRisk: 'medium',
                    artifacts: ['Process creation with elevated privileges', 'Auth logs'],
                    prerequisites: [3],
                },
            ],
            tacticsUsed: ['reconnaissance', 'initial-access', 'execution', 'credential-access', 'privilege-escalation'],
            techniquesUsed: ['T1595', 'T1190', 'T1059.004', 'T1552', 'T1548.001'],
            difficulty: 'intermediate',
            tags: ['web', 'sqli', 'privesc', 'linux', 'single-host'],
        },
        {
            id: 'chain/ad-domain-takeover',
            name: 'Active Directory Domain Takeover',
            description: 'From initial foothold to domain admin via Kerberos attacks and lateral movement.',
            steps: [
                {
                    order: 1, description: 'Compromise workstation via phishing or exploit',
                    techniqueId: 'T1190', tactic: 'initial-access',
                    targetMachine: 'workstation', detectionRisk: 'medium',
                    artifacts: ['Exploit logs', 'AV alerts'],
                    prerequisites: [],
                },
                {
                    order: 2, description: 'Dump cached credentials from memory',
                    techniqueId: 'T1003', tactic: 'credential-access',
                    targetMachine: 'workstation', detectionRisk: 'high',
                    artifacts: ['LSASS access logs', 'EDR alerts'],
                    prerequisites: [1],
                },
                {
                    order: 3, description: 'Enumerate services for Kerberoasting targets',
                    techniqueId: 'T1558.003', tactic: 'credential-access',
                    targetMachine: 'domain-controller', detectionRisk: 'medium',
                    artifacts: ['Kerberos TGS requests', 'AD query logs'],
                    prerequisites: [1],
                },
                {
                    order: 4, description: 'Lateral movement via Pass-the-Hash to file server',
                    techniqueId: 'T1550.002', tactic: 'lateral-movement',
                    sourceMachine: 'workstation', targetMachine: 'file-server',
                    credential: 'ntlm-hash', detectionRisk: 'high',
                    artifacts: ['NTLM auth logs', 'SMB session logs'],
                    prerequisites: [2],
                },
                {
                    order: 5, description: 'Install persistence via scheduled task',
                    techniqueId: 'T1053.005', tactic: 'persistence',
                    targetMachine: 'file-server', detectionRisk: 'medium',
                    artifacts: ['Scheduled task creation event', 'Task Scheduler logs'],
                    prerequisites: [4],
                },
                {
                    order: 6, description: 'Forge Golden Ticket for domain admin access',
                    techniqueId: 'T1558.001', tactic: 'credential-access',
                    targetMachine: 'domain-controller', detectionRisk: 'low',
                    artifacts: ['Anomalous TGT lifetime', 'Cross-realm referral anomaly'],
                    prerequisites: [3, 4],
                },
                {
                    order: 7, description: 'Access domain controller with forged ticket',
                    techniqueId: 'T1021.002', tactic: 'lateral-movement',
                    sourceMachine: 'file-server', targetMachine: 'domain-controller',
                    detectionRisk: 'low',
                    artifacts: ['SMB admin share access', 'Logon event'],
                    prerequisites: [6],
                },
            ],
            tacticsUsed: ['initial-access', 'credential-access', 'lateral-movement', 'persistence'],
            techniquesUsed: ['T1190', 'T1003', 'T1558.003', 'T1550.002', 'T1053.005', 'T1558.001', 'T1021.002'],
            difficulty: 'expert',
            tags: ['active-directory', 'kerberos', 'lateral-movement', 'domain-admin', 'windows'],
        },
        {
            id: 'chain/linux-persistence-hunt',
            name: 'Linux Persistence Hunt (Blue Team)',
            description: 'Detect and remove multiple persistence mechanisms on a compromised Linux server.',
            steps: [
                {
                    order: 1, description: 'Scan for unauthorized cron jobs',
                    techniqueId: 'T1053.003', tactic: 'persistence',
                    targetMachine: 'compromised-server', detectionRisk: 'low',
                    artifacts: ['Crontab entries', 'cron.d files'],
                    prerequisites: [],
                },
                {
                    order: 2, description: 'Check for web shells in web root',
                    techniqueId: 'T1505.003', tactic: 'persistence',
                    targetMachine: 'compromised-server', detectionRisk: 'low',
                    artifacts: ['PHP/JSP files with eval/exec patterns'],
                    prerequisites: [],
                },
                {
                    order: 3, description: 'Inspect SSH authorized_keys for rogue keys',
                    techniqueId: 'T1098.004', tactic: 'persistence',
                    targetMachine: 'compromised-server', detectionRisk: 'low',
                    artifacts: ['Unauthorized SSH public keys'],
                    prerequisites: [],
                },
                {
                    order: 4, description: 'Audit systemd services for malicious units',
                    techniqueId: 'T1543.002', tactic: 'persistence',
                    targetMachine: 'compromised-server', detectionRisk: 'low',
                    artifacts: ['Suspicious .service files'],
                    prerequisites: [],
                },
                {
                    order: 5, description: 'Check .bashrc files for backdoor commands',
                    techniqueId: 'T1546.004', tactic: 'persistence',
                    targetMachine: 'compromised-server', detectionRisk: 'low',
                    artifacts: ['Reverse shell commands in shell profiles'],
                    prerequisites: [],
                },
                {
                    order: 6, description: 'Detect LD_PRELOAD hijacking',
                    techniqueId: 'T1574.006', tactic: 'persistence',
                    targetMachine: 'compromised-server', detectionRisk: 'low',
                    artifacts: ['/etc/ld.so.preload entries'],
                    prerequisites: [],
                },
            ],
            tacticsUsed: ['persistence'],
            techniquesUsed: ['T1053.003', 'T1505.003', 'T1098.004', 'T1543.002', 'T1546.004', 'T1574.006'],
            difficulty: 'intermediate',
            tags: ['blue-team', 'persistence', 'linux', 'hunt', 'defense'],
        },
        {
            id: 'chain/data-exfil-stealth',
            name: 'Stealthy Data Exfiltration',
            description: 'Collect sensitive data and exfiltrate through covert channels.',
            steps: [
                {
                    order: 1, description: 'Access target system via SSH with stolen keys',
                    techniqueId: 'T1021.004', tactic: 'lateral-movement',
                    sourceMachine: 'jump-box', targetMachine: 'database-server',
                    detectionRisk: 'low',
                    artifacts: ['SSH auth log', 'Session creation event'],
                    prerequisites: [],
                },
                {
                    order: 2, description: 'Collect sensitive data from local database',
                    techniqueId: 'T1005', tactic: 'collection',
                    targetMachine: 'database-server', detectionRisk: 'low',
                    artifacts: ['Database query logs', 'File access timestamps'],
                    prerequisites: [1],
                },
                {
                    order: 3, description: 'Stage data in temporary location',
                    techniqueId: 'T1074', tactic: 'collection',
                    targetMachine: 'database-server', detectionRisk: 'low',
                    artifacts: ['Temp file creation', 'Unusual file in /tmp'],
                    prerequisites: [2],
                },
                {
                    order: 4, description: 'Exfiltrate via DNS tunneling',
                    techniqueId: 'T1048.003', tactic: 'exfiltration',
                    targetMachine: 'database-server', detectionRisk: 'medium',
                    artifacts: ['Unusual DNS query volume', 'Long DNS TXT records', 'DNS to unusual domains'],
                    prerequisites: [3],
                },
            ],
            tacticsUsed: ['lateral-movement', 'collection', 'exfiltration'],
            techniquesUsed: ['T1021.004', 'T1005', 'T1074', 'T1048.003'],
            difficulty: 'advanced',
            tags: ['exfiltration', 'dns-tunnel', 'stealth', 'data-theft'],
        },
        {
            id: 'chain/container-escape',
            name: 'Container Escape to Host',
            description: 'Break out of a Docker container and compromise the host system.',
            steps: [
                {
                    order: 1, description: 'Discover container environment (Docker socket, capabilities)',
                    techniqueId: 'T1083', tactic: 'discovery',
                    targetMachine: 'container', detectionRisk: 'low',
                    artifacts: ['File enumeration logs'],
                    prerequisites: [],
                },
                {
                    order: 2, description: 'Escape container via mounted Docker socket',
                    techniqueId: 'T1611', tactic: 'privilege-escalation',
                    sourceMachine: 'container', targetMachine: 'host',
                    detectionRisk: 'high',
                    artifacts: ['Docker API calls', 'New container creation event', 'Host process creation'],
                    prerequisites: [1],
                },
                {
                    order: 3, description: 'Install persistence on host via cron',
                    techniqueId: 'T1053.003', tactic: 'persistence',
                    targetMachine: 'host', detectionRisk: 'medium',
                    artifacts: ['New crontab entry', 'File creation in cron.d'],
                    prerequisites: [2],
                },
                {
                    order: 4, description: 'Access host filesystem directly',
                    techniqueId: 'T1006', tactic: 'defense-evasion',
                    targetMachine: 'host', detectionRisk: 'low',
                    artifacts: ['Direct device access logs'],
                    prerequisites: [2],
                },
            ],
            tacticsUsed: ['discovery', 'privilege-escalation', 'persistence', 'defense-evasion'],
            techniquesUsed: ['T1083', 'T1611', 'T1053.003', 'T1006'],
            difficulty: 'advanced',
            tags: ['container', 'docker', 'escape', 'host-compromise'],
        },
    ];
}

// ── Factory ─────────────────────────────────────────────────────

export function createAttackChainComposer(catalog: MitreCatalog): AttackChainComposer {
    const templates = createTemplates().map(t => Object.freeze(t));

    const composer: AttackChainComposer = {
        create(id: string, name: string, description: string): ChainBuilder {
            const steps: AttackChainStep[] = [];
            let explicitDifficulty: 'beginner' | 'intermediate' | 'advanced' | 'expert' | null = null;
            let chainTags: readonly string[] = [];

            const builder: ChainBuilder = {
                addStep(step: Omit<AttackChainStep, 'order'>): ChainBuilder {
                    steps.push({ ...step, order: steps.length + 1 });
                    return builder;
                },

                difficulty(level: 'beginner' | 'intermediate' | 'advanced' | 'expert'): ChainBuilder {
                    explicitDifficulty = level;
                    return builder;
                },

                tags(t: readonly string[]): ChainBuilder {
                    chainTags = t;
                    return builder;
                },

                build(): AttackChain {
                    const tacticsUsed = [...new Set(steps.map(s => s.tactic))];
                    const techniquesUsed = [...new Set(steps.map(s => s.techniqueId))];

                    const chain: AttackChain = {
                        id, name, description,
                        steps: Object.freeze(steps.map(s => Object.freeze(s))),
                        tacticsUsed: Object.freeze(tacticsUsed),
                        techniquesUsed: Object.freeze(techniquesUsed),
                        difficulty: explicitDifficulty ?? composer.estimateDifficulty({
                            id, name, description,
                            steps, tacticsUsed, techniquesUsed,
                            difficulty: 'intermediate', tags: chainTags,
                        }),
                        tags: Object.freeze([...chainTags]),
                    };

                    return Object.freeze(chain);
                },
            };

            return builder;
        },

        validate(chain: AttackChain): ChainValidationResult {
            const errors: string[] = [];
            const warnings: string[] = [];
            const missingFromCatalog: string[] = [];
            const allTactics = new Set<MitreTactic>();
            const allTechniques = new Set<string>();

            if (chain.steps.length === 0) {
                errors.push('Attack chain has no steps');
            }

            for (const step of chain.steps) {
                const technique = catalog.getTechnique(step.techniqueId);
                if (technique === null) {
                    missingFromCatalog.push(step.techniqueId);
                    warnings.push(`Step ${step.order}: Technique '${step.techniqueId}' not found in MITRE catalog`);
                } else {
                    if (!technique.tactics.includes(step.tactic)) {
                        warnings.push(`Step ${step.order}: Technique '${step.techniqueId}' is not typically associated with tactic '${step.tactic}'`);
                    }
                    if (technique.simulationSupport === 'planned') {
                        warnings.push(`Step ${step.order}: Technique '${step.techniqueId}' simulation support is 'planned' (not yet available)`);
                    }
                    allTechniques.add(step.techniqueId);
                }
                allTactics.add(step.tactic);

                // Validate prerequisites reference valid step orders
                for (const prereq of step.prerequisites) {
                    if (prereq >= step.order) {
                        errors.push(`Step ${step.order}: Prerequisite ${prereq} must come before step ${step.order}`);
                    }
                    if (!chain.steps.some(s => s.order === prereq)) {
                        errors.push(`Step ${step.order}: Prerequisite ${prereq} references non-existent step`);
                    }
                }
            }

            // Check for circular dependencies
            const visited = new Set<number>();
            const recursing = new Set<number>();
            function hasCycle(stepOrder: number): boolean {
                if (recursing.has(stepOrder)) return true;
                if (visited.has(stepOrder)) return false;
                visited.add(stepOrder);
                recursing.add(stepOrder);
                const step = chain.steps.find(s => s.order === stepOrder);
                if (step !== undefined) {
                    for (const prereq of step.prerequisites) {
                        if (hasCycle(prereq)) return true;
                    }
                }
                recursing.delete(stepOrder);
                return false;
            }
            for (const step of chain.steps) {
                visited.clear();
                recursing.clear();
                if (hasCycle(step.order)) {
                    errors.push(`Circular dependency detected involving step ${step.order}`);
                    break;
                }
            }

            return Object.freeze({
                valid: errors.length === 0,
                errors: Object.freeze(errors),
                warnings: Object.freeze(warnings),
                mitreCoverage: Object.freeze({
                    tactics: Object.freeze([...allTactics]),
                    techniques: Object.freeze([...allTechniques]),
                    missingFromCatalog: Object.freeze(missingFromCatalog),
                }),
            });
        },

        getTemplates(): readonly AttackChain[] {
            return Object.freeze(templates);
        },

        estimateDifficulty(chain: AttackChain): 'beginner' | 'intermediate' | 'advanced' | 'expert' {
            let score = 0;

            // More steps = harder
            score += Math.min(chain.steps.length * 0.5, 3);

            // More unique tactics = harder
            score += chain.tacticsUsed.length * 0.3;

            // High detection risk steps add difficulty
            for (const step of chain.steps) {
                switch (step.detectionRisk) {
                    case 'low': score += 0.3; break;
                    case 'medium': score += 0.2; break;
                    case 'high': score += 0.1; break;
                    case 'critical': break; // Easy to detect = easier for defender, harder for attacker
                }

                // Hard-to-detect techniques require more skill
                const technique = catalog.getTechnique(step.techniqueId);
                if (technique !== null) {
                    switch (technique.detectionDifficulty) {
                        case 'trivial': break;
                        case 'easy': score += 0.1; break;
                        case 'moderate': score += 0.2; break;
                        case 'hard': score += 0.4; break;
                        case 'very-hard': score += 0.6; break;
                    }
                }
            }

            if (score < 2) return 'beginner';
            if (score < 4) return 'intermediate';
            if (score < 6) return 'advanced';
            return 'expert';
        },
    };

    return composer;
}
