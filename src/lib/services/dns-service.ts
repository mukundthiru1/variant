/**
 * VARIANT — DNS Service Handler
 *
 * Air-gapped DNS that resolves only VARIANT domains.
 * Both for machine-to-machine resolution (Simulacra) and
 * player tool usage (dig, nslookup, host).
 *
 * What it does:
 *   - Resolves VARIANT network IPs from WorldSpec config
 *   - Resolves VARIANT Internet domains (fake cloud, package repo, etc.)
 *   - Returns NXDOMAIN for anything outside the VARIANT namespace
 *   - Supports A, AAAA, MX, TXT, NS, SOA, PTR records
 *   - Emits events for DNS query logging
 *   - Generates /var/log/syslog DNS entries
 *   - Zone transfer (AXFR) support for recon training
 *
 * EXTENSIBILITY: All behavior configurable via ServiceConfig.config:
 *   - zones: Custom DNS zone records
 *   - allowZoneTransfer: Whether AXFR is permitted (recon training)
 *   - ttl: Default TTL for responses
 *   - recursion: Whether recursive queries are enabled
 *   - forwarders: Upstream DNS (always null in air-gapped mode)
 *   - poisonedRecords: Records intentionally wrong (DNS poisoning training)
 */

import type { ServiceHandler, ServiceRequest, ServiceResponse, ServiceContext } from './types';
import type { ServiceConfig } from '../../core/world/types';

// ── DNS Config ─────────────────────────────────────────────────

interface DNSConfig {
    readonly allowZoneTransfer: boolean;
    readonly defaultTTL: number;
    readonly recursion: boolean;
    readonly port: number;
    readonly logFile: string;
}

function resolveDNSConfig(config: ServiceConfig): DNSConfig {
    const c = config.config ?? {};
    return {
        allowZoneTransfer: (c['allowZoneTransfer'] as boolean) ?? false,
        defaultTTL: (c['ttl'] as number) ?? 3600,
        recursion: (c['recursion'] as boolean) ?? true,
        port: config.ports[0] ?? 53,
        logFile: (c['logFile'] as string) ?? '/var/log/syslog',
    };
}

// ── DNS Record Types ───────────────────────────────────────────

export type DNSRecordType = 'A' | 'AAAA' | 'MX' | 'TXT' | 'NS' | 'SOA' | 'PTR' | 'CNAME' | 'SRV';

export interface DNSRecord {
    readonly name: string;
    readonly type: DNSRecordType;
    readonly value: string;
    readonly ttl?: number;
    readonly priority?: number;       // MX priority
    readonly poisoned?: boolean;     // intentionally wrong (for training)
}

// ── DNS Zone ───────────────────────────────────────────────────

export interface DNSZone {
    readonly domain: string;
    readonly records: readonly DNSRecord[];
    readonly soa?: {
        readonly primary: string;
        readonly email: string;
        readonly serial: number;
        readonly refresh: number;
        readonly retry: number;
        readonly expire: number;
        readonly minimum: number;
    };
}

// ── DNS Service Handler ────────────────────────────────────────

export function createDNSService(
    config: ServiceConfig,
    zones?: readonly DNSZone[],
): ServiceHandler {
    const dnsConfig = resolveDNSConfig(config);
    const recordMap = new Map<string, DNSRecord[]>();

    // Build the lookup map from zones
    if (zones !== undefined) {
        for (const zone of zones) {
            for (const record of zone.records) {
                const key = `${record.name}:${record.type}`;
                const existing = recordMap.get(key) ?? [];
                existing.push(record);
                recordMap.set(key, existing);
            }
        }
    }

    return {
        name: 'dns',
        port: dnsConfig.port,
        protocol: 'udp',

        start(ctx: ServiceContext): void {
            ctx.emit({
                type: 'service:custom',
                service: 'dns',
                action: 'started',
                details: {
                    port: dnsConfig.port,
                    zones: zones?.map(z => z.domain) ?? [],
                    recordCount: recordMap.size,
                },
            });
        },

        handle(request: ServiceRequest, ctx: ServiceContext): ServiceResponse | null {
            const query = parseDNSQuery(request.payloadText);
            if (query === null) return null;

            // AXFR zone transfer
            if (query.type === 'AXFR') {
                if (!dnsConfig.allowZoneTransfer) {
                    writeDNSLog(ctx, request.sourceIP, query.name, 'AXFR', 'REFUSED');

                    ctx.emit({
                        type: 'dns:query',
                        domain: query.name,
                        queryType: 'AXFR',
                        sourceIP: request.sourceIP,
                        result: null,
                    });

                    return dnsResponse('REFUSED', query.name, query.type, []);
                }

                // Find the zone
                const zone = zones?.find(z => query.name.endsWith(z.domain));
                if (zone === undefined) {
                    return dnsResponse('NXDOMAIN', query.name, query.type, []);
                }

                writeDNSLog(ctx, request.sourceIP, query.name, 'AXFR', `${zone.records.length} records`);

                ctx.emit({
                    type: 'dns:query',
                    domain: query.name,
                    queryType: 'AXFR',
                    sourceIP: request.sourceIP,
                    result: `${zone.records.length} records transferred`,
                });

                return dnsResponse('NOERROR', query.name, query.type, zone.records, dnsConfig.defaultTTL);
            }

            // Standard query
            const key = `${query.name}:${query.type}`;
            const records = recordMap.get(key);

            if (records !== undefined && records.length > 0) {
                const result = records.map(r => r.value).join(', ');
                writeDNSLog(ctx, request.sourceIP, query.name, query.type, result);

                ctx.emit({
                    type: 'dns:query',
                    domain: query.name,
                    queryType: query.type,
                    sourceIP: request.sourceIP,
                    result,
                });

                return dnsResponse('NOERROR', query.name, query.type, records, dnsConfig.defaultTTL);
            }

            // Try wildcard match (*.domain.com)
            const parts = query.name.split('.');
            for (let i = 1; i < parts.length; i++) {
                const wildcard = `*.${parts.slice(i).join('.')}`;
                const wildcardKey = `${wildcard}:${query.type}`;
                const wildcardRecords = recordMap.get(wildcardKey);

                if (wildcardRecords !== undefined && wildcardRecords.length > 0) {
                    // Replace wildcard with actual name in response
                    const resolved = wildcardRecords.map(r => ({
                        ...r,
                        name: query.name,
                    }));

                    const result = resolved.map(r => r.value).join(', ');
                    writeDNSLog(ctx, request.sourceIP, query.name, query.type, result);

                    ctx.emit({
                        type: 'dns:query',
                        domain: query.name,
                        queryType: query.type,
                        sourceIP: request.sourceIP,
                        result,
                    });

                    return dnsResponse('NOERROR', query.name, query.type, resolved, dnsConfig.defaultTTL);
                }
            }

            // NXDOMAIN
            writeDNSLog(ctx, request.sourceIP, query.name, query.type, 'NXDOMAIN');

            ctx.emit({
                type: 'dns:query',
                domain: query.name,
                queryType: query.type,
                sourceIP: request.sourceIP,
                result: null,
            });

            return dnsResponse('NXDOMAIN', query.name, query.type, []);
        },

        stop(): void {
            recordMap.clear();
        },
    };

    // ── Internal helpers ─────────────────────────────────────

    function writeDNSLog(ctx: ServiceContext, sourceIP: string, domain: string, qtype: string, result: string): void {
        const timestamp = new Date().toUTCString();
        const entry = `${timestamp} ${ctx.hostname} named[${1000 + Math.floor(Math.random() * 9000)}]: ` +
            `client @0x${Math.floor(Math.random() * 0xffffff).toString(16)} ${sourceIP}#${Math.floor(Math.random() * 65535)}: ` +
            `query: ${domain} IN ${qtype} + (${result})`;

        try {
            const existing = ctx.vfs.readFile(dnsConfig.logFile);
            ctx.vfs.writeFile(dnsConfig.logFile, existing + '\n' + entry);
        } catch {
            ctx.vfs.writeFile(dnsConfig.logFile, entry);
        }
    }
}

// ── DNS Helpers ────────────────────────────────────────────────

interface DNSQuery {
    readonly name: string;
    readonly type: string;
}

/**
 * Parse a DNS query.
 * In the Simulacrum, DNS queries come as structured text:
 *   QUERY <type> <name>
 *   e.g., QUERY A www.megacorp.local
 */
function parseDNSQuery(text: string): DNSQuery | null {
    const trimmed = text.trim();
    if (!trimmed.startsWith('QUERY ')) return null;

    const parts = trimmed.split(' ');
    if (parts.length < 3) return null;

    return {
        type: (parts[1] ?? '').toUpperCase(),
        name: (parts[2] ?? '').toLowerCase(),
    };
}

/**
 * Build a DNS response.
 */
function dnsResponse(
    status: string,
    name: string,
    qtype: string,
    records: readonly DNSRecord[],
    defaultTTL = 3600,
): ServiceResponse {
    const lines: string[] = [];
    lines.push(`STATUS: ${status}`);
    lines.push(`QUERY: ${name} IN ${qtype}`);

    if (records.length > 0) {
        lines.push(`ANSWER SECTION:`);
        for (const r of records) {
            const ttl = r.ttl ?? defaultTTL;
            lines.push(`${r.name}\t${ttl}\tIN\t${r.type}\t${r.value}`);
        }
    }

    return {
        payload: new TextEncoder().encode(lines.join('\r\n') + '\r\n'),
        close: true,
    };
}

/**
 * Build a DNS zone from WorldSpec data.
 * Utility for level designers.
 */
export function buildZoneFromNetwork(
    domain: string,
    machines: ReadonlyMap<string, { hostname: string; interfaces: readonly { ip: string }[] }>,
): DNSZone {
    const records: DNSRecord[] = [];

    for (const [, machine] of machines) {
        for (const iface of machine.interfaces) {
            records.push({
                name: `${machine.hostname}.${domain}`,
                type: 'A',
                value: iface.ip,
            });
        }
    }

    // SOA record
    const soa = {
        primary: `ns1.${domain}`,
        email: `admin.${domain}`,
        serial: 2026030501,
        refresh: 3600,
        retry: 900,
        expire: 604800,
        minimum: 3600,
    };

    // NS record
    records.push({ name: domain, type: 'NS', value: `ns1.${domain}` });

    return { domain, records, soa };
}
