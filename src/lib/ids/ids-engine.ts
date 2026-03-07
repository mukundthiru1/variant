/**
 * VARIANT — IDS/IPS Rules Engine
 *
 * Snort/Suricata-compatible signature matching engine.
 * Evaluates network traffic against detection rules with
 * content matching, PCRE, flow tracking, and thresholds.
 *
 * What it does:
 *   - Parses Snort-format rule strings
 *   - Evaluates packets against content matches with offset/depth/distance/within
 *   - Supports PCRE patterns
 *   - Supports HTTP-aware matching (uri, header, body, method)
 *   - Threshold and rate limiting per source/destination
 *   - Generates structured alerts with matched content evidence
 *   - Formats rules back to Snort syntax
 *
 * SWAPPABILITY: Implements IDSEngine. Replace this file.
 */

import type {
    IDSEngine,
    IDSRule,
    IDSRuleOptions,
    IDSContentMatch,
    IDSPacket,
    IDSAlert,
    IDSSeverity,
    IDSStats,
    IDSAction,
} from './types';

// ── Factory ────────────────────────────────────────────────

export function createIDSEngine(): IDSEngine {
    const rules = new Map<number, IDSRule>();
    const alerts: IDSAlert[] = [];
    let nextAlertId = 1;
    let packetsEvaluated = 0;
    const ruleHits = new Map<number, number>();

    // Threshold tracking: `${sid}:${trackKey}` → { count, windowStart }
    const thresholdState = new Map<string, { count: number; windowStart: number }>();

    function matchContent(packet: IDSPacket, matches: readonly IDSContentMatch[]): { matched: boolean; matchedTexts: string[] } {
        const matchedTexts: string[] = [];
        let searchBuffer = packet.payload;
        let lastMatchEnd = 0;

        for (const cm of matches) {
            // Select the right buffer for HTTP-aware matching
            let buffer = searchBuffer;
            if (cm.http_uri && packet.httpUri !== undefined) {
                buffer = packet.httpUri;
            } else if (cm.http_header && packet.httpHeaders !== undefined) {
                buffer = Object.entries(packet.httpHeaders).map(([k, v]) => `${k}: ${v}`).join('\r\n');
            } else if (cm.http_body && packet.httpBody !== undefined) {
                buffer = packet.httpBody;
            } else if (cm.http_method && packet.httpMethod !== undefined) {
                buffer = packet.httpMethod;
            }

            // Apply offset/depth constraints
            let searchStart = 0;
            let searchEnd = buffer.length;

            if (cm.offset !== undefined) {
                searchStart = cm.offset;
            }
            if (cm.depth !== undefined) {
                searchEnd = Math.min(buffer.length, searchStart + cm.depth);
            }
            if (cm.distance !== undefined) {
                searchStart = lastMatchEnd + cm.distance;
            }
            if (cm.within !== undefined && cm.distance !== undefined) {
                searchEnd = Math.min(buffer.length, searchStart + cm.within);
            }

            const searchRegion = buffer.slice(searchStart, searchEnd);
            const pattern = cm.nocase ? cm.pattern.toLowerCase() : cm.pattern;
            const region = cm.nocase ? searchRegion.toLowerCase() : searchRegion;

            const found = region.indexOf(pattern);

            if (cm.negated) {
                if (found !== -1) return { matched: false, matchedTexts };
            } else {
                if (found === -1) return { matched: false, matchedTexts };
                matchedTexts.push(cm.pattern);
                lastMatchEnd = searchStart + found + cm.pattern.length;
            }
        }

        return { matched: true, matchedTexts };
    }

    function matchPCRE(packet: IDSPacket, patterns: readonly string[]): boolean {
        for (const pcreStr of patterns) {
            // Parse Snort PCRE: /pattern/flags
            const match = pcreStr.match(/^\/(.+)\/([ismxUHP]*)$/);
            if (match === null) continue;

            const pattern = match[1]!;
            const flags = match[2] ?? '';

            let regexFlags = '';
            if (flags.includes('i')) regexFlags += 'i';
            if (flags.includes('s')) regexFlags += 's';
            if (flags.includes('m')) regexFlags += 'm';

            // Determine which buffer to search
            let buffer = packet.payload;
            if (flags.includes('U') && packet.httpUri !== undefined) {
                buffer = packet.httpUri;
            } else if (flags.includes('H') && packet.httpHeaders !== undefined) {
                buffer = Object.entries(packet.httpHeaders).map(([k, v]) => `${k}: ${v}`).join('\r\n');
            } else if (flags.includes('P') && packet.httpBody !== undefined) {
                buffer = packet.httpBody;
            }

            try {
                const regex = new RegExp(pattern, regexFlags);
                if (!regex.test(buffer)) return false;
            } catch {
                return false;
            }
        }
        return true;
    }

    function matchFlow(packet: IDSPacket, flow: string): boolean {
        const flowParts = flow.split(',').map(s => s.trim());
        for (const part of flowParts) {
            if (part === 'established' && packet.flow !== 'established') return false;
            if (part === 'to_server' && packet.flow !== 'to_server' && packet.flow !== 'established') return false;
            if (part === 'to_client' && packet.flow !== 'to_client') return false;
        }
        return true;
    }

    function matchesNetwork(ip: string, ruleSpec: string): boolean {
        if (ruleSpec === 'any' || ruleSpec === '$HOME_NET' || ruleSpec === '$EXTERNAL_NET') return true;
        if (ruleSpec.startsWith('!')) {
            return !matchesNetwork(ip, ruleSpec.slice(1));
        }
        if (ruleSpec.includes('/')) {
            // CIDR
            return matchesCIDR(ip, ruleSpec);
        }
        return ip === ruleSpec;
    }

    function matchesCIDR(ip: string, cidr: string): boolean {
        const [network, bits] = cidr.split('/');
        if (network === undefined || bits === undefined) return false;
        const mask = parseInt(bits, 10);
        const ipNum = ipToNum(ip);
        const netNum = ipToNum(network);
        if (ipNum === null || netNum === null) return false;
        const maskBits = mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0;
        return (ipNum & maskBits) === (netNum & maskBits);
    }

    function ipToNum(ip: string): number | null {
        const parts = ip.split('.');
        if (parts.length !== 4) return null;
        let n = 0;
        for (const p of parts) {
            const v = parseInt(p, 10);
            if (isNaN(v) || v < 0 || v > 255) return null;
            n = (n << 8) | v;
        }
        return n >>> 0;
    }

    function matchesPort(port: number, rulePort: string): boolean {
        if (rulePort === 'any') return true;
        if (rulePort.startsWith('!')) return !matchesPort(port, rulePort.slice(1));
        if (rulePort.includes(':')) {
            const [low, high] = rulePort.split(':');
            const lo = parseInt(low ?? '0', 10);
            const hi = parseInt(high ?? '65535', 10);
            return port >= lo && port <= hi;
        }
        if (rulePort.includes(',')) {
            return rulePort.split(',').some(p => matchesPort(port, p.trim()));
        }
        return port === parseInt(rulePort, 10);
    }

    function checkThreshold(rule: IDSRule, packet: IDSPacket): boolean {
        const threshold = rule.options.threshold;
        if (threshold === undefined) return true;

        const trackKey = threshold.track === 'by_src'
            ? `${rule.sid}:src:${packet.sourceIP}`
            : `${rule.sid}:dst:${packet.destIP}`;

        const state = thresholdState.get(trackKey);
        const now = packet.timestamp;

        if (state === undefined || (now - state.windowStart) > threshold.seconds * 1000) {
            thresholdState.set(trackKey, { count: 1, windowStart: now });
            return threshold.type === 'limit' ? true : threshold.count <= 1;
        }

        state.count++;

        switch (threshold.type) {
            case 'limit':
                return state.count <= threshold.count;
            case 'threshold':
                return state.count >= threshold.count;
            case 'both':
                return state.count === threshold.count;
        }
    }

    function evaluateRule(rule: IDSRule, packet: IDSPacket): IDSAlert | null {
        // Protocol match
        if (rule.protocol !== 'ip' && rule.protocol !== packet.protocol) return null;

        // Network match
        if (!matchesNetwork(packet.sourceIP, rule.sourceIP)) return null;
        if (!matchesNetwork(packet.destIP, rule.destIP)) return null;
        if (!matchesPort(packet.sourcePort, rule.sourcePort)) return null;
        if (!matchesPort(packet.destPort, rule.destPort)) return null;

        // Bidirectional check
        if (rule.direction === '<>') {
            const reverseMatch =
                matchesNetwork(packet.destIP, rule.sourceIP) &&
                matchesNetwork(packet.sourceIP, rule.destIP) &&
                matchesPort(packet.destPort, rule.sourcePort) &&
                matchesPort(packet.sourcePort, rule.destPort);
            if (!reverseMatch && !matchesNetwork(packet.sourceIP, rule.sourceIP)) return null;
        }

        // Flow match
        if (rule.options.flow !== undefined) {
            if (!matchFlow(packet, rule.options.flow)) return null;
        }

        // Content match
        let matchedContent: string[] = [];
        if (rule.options.content !== undefined && rule.options.content.length > 0) {
            const result = matchContent(packet, rule.options.content);
            if (!result.matched) return null;
            matchedContent = result.matchedTexts;
        }

        // PCRE match
        if (rule.options.pcre !== undefined && rule.options.pcre.length > 0) {
            if (!matchPCRE(packet, rule.options.pcre)) return null;
        }

        // Threshold check
        if (!checkThreshold(rule, packet)) return null;

        // Rule matched — generate alert
        const priority = rule.options.priority ?? 3;
        const severity = (priority <= 1 ? 1 : priority <= 2 ? 2 : priority <= 3 ? 3 : 4) as IDSSeverity;

        return {
            id: `ids-alert-${nextAlertId++}`,
            sid: rule.sid,
            rev: rule.rev,
            message: rule.options.msg ?? `Rule SID:${rule.sid} matched`,
            severity,
            classtype: rule.options.classtype ?? 'unknown',
            timestamp: packet.timestamp,
            tick: packet.tick,
            sourceIP: packet.sourceIP,
            sourcePort: packet.sourcePort,
            destIP: packet.destIP,
            destPort: packet.destPort,
            protocol: packet.protocol,
            payload: packet.payload.slice(0, 256),
            matchedContent,
            action: rule.action,
            references: rule.options.reference ?? [],
        };
    }

    return {
        addRule(rule: IDSRule): void {
            rules.set(rule.sid, rule);
        },

        addRules(newRules: readonly IDSRule[]): void {
            for (const rule of newRules) {
                rules.set(rule.sid, rule);
            }
        },

        parseAndAdd(ruleString: string): IDSRule | null {
            const rule = parseSnortRule(ruleString);
            if (rule !== null) {
                rules.set(rule.sid, rule);
            }
            return rule;
        },

        removeRule(sid: number): boolean {
            return rules.delete(sid);
        },

        setRuleEnabled(sid: number, enabled: boolean): boolean {
            const rule = rules.get(sid);
            if (rule === undefined) return false;
            rules.set(sid, { ...rule, enabled });
            return true;
        },

        evaluate(packet: IDSPacket): readonly IDSAlert[] {
            packetsEvaluated++;
            const newAlerts: IDSAlert[] = [];

            for (const rule of rules.values()) {
                if (!rule.enabled) continue;

                const alert = evaluateRule(rule, packet);
                if (alert !== null) {
                    ruleHits.set(rule.sid, (ruleHits.get(rule.sid) ?? 0) + 1);
                    alerts.push(alert);
                    newAlerts.push(alert);
                }
            }

            return newAlerts;
        },

        getRules(): readonly IDSRule[] {
            return [...rules.values()];
        },

        getAlerts(): readonly IDSAlert[] {
            return [...alerts];
        },

        getAlertsBySeverity(severity: IDSSeverity): readonly IDSAlert[] {
            return alerts.filter(a => a.severity === severity);
        },

        ruleCount(): number {
            return rules.size;
        },

        alertCount(): number {
            return alerts.length;
        },

        resetAlerts(): void {
            alerts.length = 0;
            nextAlertId = 1;
        },

        formatRule(rule: IDSRule): string {
            const parts: string[] = [
                rule.action,
                rule.protocol,
                rule.sourceIP,
                rule.sourcePort,
                rule.direction,
                rule.destIP,
                rule.destPort,
            ];

            const opts: string[] = [];
            if (rule.options.msg !== undefined) opts.push(`msg:"${rule.options.msg}"`);
            if (rule.options.content !== undefined) {
                for (const c of rule.options.content) {
                    let s = `content:"${c.pattern}"`;
                    if (c.nocase) s += '; nocase';
                    if (c.offset !== undefined) s += `; offset:${c.offset}`;
                    if (c.depth !== undefined) s += `; depth:${c.depth}`;
                    if (c.distance !== undefined) s += `; distance:${c.distance}`;
                    if (c.within !== undefined) s += `; within:${c.within}`;
                    if (c.http_uri) s += '; http_uri';
                    if (c.http_header) s += '; http_header';
                    if (c.http_body) s += '; http_body';
                    if (c.http_method) s += '; http_method';
                    opts.push(s);
                }
            }
            if (rule.options.pcre !== undefined) {
                for (const p of rule.options.pcre) opts.push(`pcre:"${p}"`);
            }
            if (rule.options.flow !== undefined) opts.push(`flow:${rule.options.flow}`);
            if (rule.options.classtype !== undefined) opts.push(`classtype:${rule.options.classtype}`);
            if (rule.options.priority !== undefined) opts.push(`priority:${rule.options.priority}`);
            opts.push(`sid:${rule.sid}`);
            opts.push(`rev:${rule.rev}`);

            return `${parts.join(' ')} (${opts.join('; ')};)`;
        },

        getStats(): IDSStats {
            const alertsBySeverity: Record<number, number> = { 1: 0, 2: 0, 3: 0, 4: 0 };
            for (const a of alerts) {
                alertsBySeverity[a.severity] = (alertsBySeverity[a.severity] ?? 0) + 1;
            }

            return {
                totalRules: rules.size,
                enabledRules: [...rules.values()].filter(r => r.enabled).length,
                totalAlerts: alerts.length,
                alertsBySeverity,
                packetsEvaluated,
                ruleHits: Object.fromEntries(ruleHits),
            };
        },
    };
}

// ── Snort Rule Parser ──────────────────────────────────────

function parseSnortRule(raw: string): IDSRule | null {
    const trimmed = raw.trim();
    if (trimmed === '' || trimmed.startsWith('#')) return null;

    // Split header and options
    const optStart = trimmed.indexOf('(');
    if (optStart === -1) return null;

    const header = trimmed.slice(0, optStart).trim();
    const optSection = trimmed.slice(optStart + 1, trimmed.lastIndexOf(')')).trim();

    const headerParts = header.split(/\s+/);
    if (headerParts.length < 7) return null;

    const action = headerParts[0] as IDSAction;
    const protocol = headerParts[1] ?? 'ip';
    const sourceIP = headerParts[2] ?? 'any';
    const sourcePort = headerParts[3] ?? 'any';
    const direction = headerParts[4] as '->' | '<>';
    const destIP = headerParts[5] ?? 'any';
    const destPort = headerParts[6] ?? 'any';

    // Parse options
    const options = parseRuleOptions(optSection);

    // Extract SID
    const sidStr = findOption(optSection, 'sid');
    const revStr = findOption(optSection, 'rev');
    const sid = sidStr !== null ? parseInt(sidStr, 10) : 0;
    const rev = revStr !== null ? parseInt(revStr, 10) : 1;

    if (isNaN(sid) || sid === 0) return null;

    return {
        sid,
        rev: isNaN(rev) ? 1 : rev,
        action,
        protocol,
        sourceIP,
        sourcePort,
        direction: direction === '<>' ? '<>' : '->',
        destIP,
        destPort,
        options,
        enabled: true,
        raw: trimmed,
    };
}

function findOption(optSection: string, key: string): string | null {
    const regex = new RegExp(`${key}\\s*:\\s*([^;]+)`);
    const match = optSection.match(regex);
    return match !== null ? match[1]!.trim() : null;
}

function parseRuleOptions(optSection: string): IDSRuleOptions {
    const msg = findOption(optSection, 'msg')?.replace(/^"/, '').replace(/"$/, '');
    const flow = findOption(optSection, 'flow') ?? undefined;
    const classtype = findOption(optSection, 'classtype') ?? undefined;
    const priorityStr = findOption(optSection, 'priority');
    const priority = priorityStr !== null ? parseInt(priorityStr, 10) : undefined;

    // Parse content matches
    const content: IDSContentMatch[] = [];
    const contentRegex = /content\s*:\s*"([^"]*)"([^;]*(?:;[^;]*)*?)(?=content\s*:|pcre\s*:|sid\s*:|$)/g;
    let contentMatch: RegExpExecArray | null;

    while ((contentMatch = contentRegex.exec(optSection)) !== null) {
        const pattern = contentMatch[1]!;
        const modifiers = contentMatch[2] ?? '';

        const cm: IDSContentMatch = {
            pattern,
            nocase: modifiers.includes('nocase'),
            http_uri: modifiers.includes('http_uri'),
            http_header: modifiers.includes('http_header'),
            http_body: modifiers.includes('http_body'),
            http_method: modifiers.includes('http_method'),
        };
        content.push(cm);
    }

    // Parse PCRE
    const pcre: string[] = [];
    const pcreRegex = /pcre\s*:\s*"([^"]+)"/g;
    let pcreMatch: RegExpExecArray | null;
    while ((pcreMatch = pcreRegex.exec(optSection)) !== null) {
        pcre.push(pcreMatch[1]!);
    }

    // Parse references
    const references: string[] = [];
    const refRegex = /reference\s*:\s*([^;]+)/g;
    let refMatch: RegExpExecArray | null;
    while ((refMatch = refRegex.exec(optSection)) !== null) {
        references.push(refMatch[1]!.trim());
    }

    return {
        ...(msg !== undefined ? { msg } : {}),
        ...(content.length > 0 ? { content } : {}),
        ...(pcre.length > 0 ? { pcre } : {}),
        ...(flow !== undefined ? { flow } : {}),
        ...(classtype !== undefined ? { classtype } : {}),
        ...(priority !== undefined && !isNaN(priority) ? { priority } : {}),
        ...(references.length > 0 ? { reference: references } : {}),
    };
}

// ── Built-in Rule Sets ─────────────────────────────────────

/**
 * Create common IDS rules for web attack detection.
 */
export function createWebAttackRules(): readonly IDSRule[] {
    return [
        {
            sid: 1000001, rev: 1, action: 'alert', protocol: 'http',
            sourceIP: 'any', sourcePort: 'any', direction: '->', destIP: 'any', destPort: 'any',
            options: {
                msg: 'SQL Injection attempt - UNION SELECT',
                content: [{ pattern: 'union', nocase: true }, { pattern: 'select', nocase: true, distance: 0, within: 20 }],
                flow: 'established,to_server',
                classtype: 'web-application-attack',
                priority: 1,
                reference: ['cve,2021-0000'],
            },
            enabled: true,
        },
        {
            sid: 1000002, rev: 1, action: 'alert', protocol: 'http',
            sourceIP: 'any', sourcePort: 'any', direction: '->', destIP: 'any', destPort: 'any',
            options: {
                msg: 'XSS attempt - script tag',
                content: [{ pattern: '<script', nocase: true }],
                flow: 'established,to_server',
                classtype: 'web-application-attack',
                priority: 2,
            },
            enabled: true,
        },
        {
            sid: 1000003, rev: 1, action: 'alert', protocol: 'http',
            sourceIP: 'any', sourcePort: 'any', direction: '->', destIP: 'any', destPort: 'any',
            options: {
                msg: 'Path traversal attempt',
                content: [{ pattern: '../', nocase: false }],
                pcre: ['/\\.\\.\\/.*\\.\\.\\/.*\\.\\.\\/.*\\.\\.\\//'],
                flow: 'established,to_server',
                classtype: 'web-application-attack',
                priority: 1,
            },
            enabled: true,
        },
        {
            sid: 1000004, rev: 1, action: 'alert', protocol: 'http',
            sourceIP: 'any', sourcePort: 'any', direction: '->', destIP: 'any', destPort: 'any',
            options: {
                msg: 'Command injection attempt - semicolon',
                content: [{ pattern: ';', nocase: false }],
                pcre: ['/;\\s*(ls|cat|id|whoami|uname|wget|curl|nc|bash|sh|python|perl)/i'],
                flow: 'established,to_server',
                classtype: 'web-application-attack',
                priority: 1,
            },
            enabled: true,
        },
        {
            sid: 1000005, rev: 1, action: 'alert', protocol: 'http',
            sourceIP: 'any', sourcePort: 'any', direction: '->', destIP: 'any', destPort: 'any',
            options: {
                msg: 'Web shell upload attempt',
                content: [{ pattern: 'multipart/form-data', http_header: true, nocase: true }],
                pcre: ['/filename="[^"]*\\.(php|jsp|asp|aspx|py|pl|sh|cgi)"/i'],
                flow: 'established,to_server',
                classtype: 'web-application-attack',
                priority: 1,
            },
            enabled: true,
        },
        {
            sid: 1000006, rev: 1, action: 'alert', protocol: 'tcp',
            sourceIP: 'any', sourcePort: 'any', direction: '->', destIP: 'any', destPort: '22',
            options: {
                msg: 'SSH brute force attempt',
                threshold: { type: 'threshold', track: 'by_src', count: 5, seconds: 60 },
                classtype: 'attempted-admin',
                priority: 2,
            },
            enabled: true,
        },
        {
            sid: 1000007, rev: 1, action: 'alert', protocol: 'http',
            sourceIP: 'any', sourcePort: 'any', direction: '->', destIP: 'any', destPort: 'any',
            options: {
                msg: 'SSRF attempt - internal IP in parameter',
                pcre: ['/(?:127\\.0\\.0\\.1|10\\.\\d+\\.\\d+\\.\\d+|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d+\\.\\d+|192\\.168\\.\\d+\\.\\d+|169\\.254\\.169\\.254)/'],
                flow: 'established,to_server',
                classtype: 'web-application-attack',
                priority: 1,
            },
            enabled: true,
        },
        {
            sid: 1000008, rev: 1, action: 'alert', protocol: 'dns',
            sourceIP: 'any', sourcePort: 'any', direction: '->', destIP: 'any', destPort: '53',
            options: {
                msg: 'DNS zone transfer attempt (AXFR)',
                content: [{ pattern: 'AXFR', nocase: true }],
                classtype: 'attempted-recon',
                priority: 2,
            },
            enabled: true,
        },
    ];
}
