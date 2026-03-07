/**
 * VARIANT - Data Exfiltration Channels Module
 */

import type { Module, SimulationContext, Capability } from "../core/modules";
import type { EventBus, EngineEvent } from "../core/events";

export interface ExfilStats {
    totalBytes: number;
    channelsUsed: string[];
    detectionCount: number;
}

export interface DNSQuery {
    query: string;
    source: string;
    timestamp: number;
}

export interface HTTPRequest {
    url: string;
    method: string;
    bodySize: number;
    source: string;
    timestamp: number;
}

export interface ExfilIndicator {
    channel: string;
    confidence: number;
    detail: string;
    source: string;
    timestamp: number;
}

// Detection Functions (for blue team)

export function detectDNSTunneling(dnsQueries: DNSQuery[]): ExfilIndicator[] {
    const indicators: ExfilIndicator[] = [];
    const queryCounts = new Map<string, number>();

    for (const q of dnsQueries) {
        const parts = q.query.split(".");
        if (parts.length > 2) {
            const subdomain = parts[0] || "";
            // Detect unusually long subdomains (entropy analysis proxy)
            if (subdomain.length > 30) {
                indicators.push({
                    channel: "DNS tunneling",
                    confidence: 0.8,
                    detail: `Unusually long subdomain detected: ${subdomain.substring(0, 15)}...`,
                    source: q.source,
                    timestamp: q.timestamp,
                });
            }

            const baseDomain = parts.slice(1).join(".");
            const count = (queryCounts.get(baseDomain) || 0) + 1;
            queryCounts.set(baseDomain, count);

            // Detect high query rate per domain
            if (count > 50) {
                indicators.push({
                    channel: "DNS tunneling",
                    confidence: 0.9,
                    detail: `High query rate for domain: ${baseDomain}`,
                    source: q.source,
                    timestamp: q.timestamp,
                });
                // Reset count to avoid spamming alerts for the same domain batch
                queryCounts.set(baseDomain, 0);
            }
        }
    }
    return indicators;
}

export function detectHTTPExfil(httpRequests: HTTPRequest[]): ExfilIndicator[] {
    const indicators: ExfilIndicator[] = [];
    for (const req of httpRequests) {
        // Detect large POST bodies to unknown hosts
        if (req.method === "POST" && req.bodySize > 10000) {
            indicators.push({
                channel: "HTTP exfil",
                confidence: 0.85,
                detail: `Large POST body (${req.bodySize} bytes) to ${req.url}`,
                source: req.source,
                timestamp: req.timestamp,
            });
        }
        
        // Detect base64 in URLs or headers (approximated via URL check)
        if (req.url.includes("base64") || /([A-Za-z0-9+/]{40,})/.test(req.url)) {
            indicators.push({
                channel: "Base64 in headers/URL",
                confidence: 0.9,
                detail: `Base64 encoded data found in URL: ${req.url.substring(0, 30)}...`,
                source: req.source,
                timestamp: req.timestamp,
            });
        }

        // Additional checks for specific exfil patterns
        if (req.url.includes(".git/info/lfs") || req.url.includes("git-receive-pack")) {
            indicators.push({
                channel: "Git push",
                confidence: 0.95,
                detail: `Git push to external repo: ${req.url}`,
                source: req.source,
                timestamp: req.timestamp,
            });
        }

        if (req.url.includes("s3.amazonaws.com") && req.method === "PUT") {
            indicators.push({
                channel: "Cloud upload",
                confidence: 0.8,
                detail: `Suspicious upload to cloud storage: ${req.url}`,
                source: req.source,
                timestamp: req.timestamp,
            });
        }
    }
    return indicators;
}

export function detectDataTransfer(events: EngineEvent[]): ExfilIndicator[] {
    const indicators: ExfilIndicator[] = [];
    const fileReads = new Map<string, number>();

    for (const ev of events) {
        if (ev.type === "fs:read") {
            fileReads.set(ev.machine, ev.timestamp);
        } else if (ev.type === "net:request" || ev.type === "net:connect" || ev.type === "net:dns") {
            const source = "source" in ev ? ev.source : ("machine" in ev ? (ev as any).machine : "");
            if (source) {
                const lastRead = fileReads.get(source);
                if (lastRead !== undefined && (ev.timestamp - lastRead) < 5000) {
                    indicators.push({
                        channel: "Data transfer",
                        confidence: 0.75,
                        detail: `Network activity detected shortly after file read on ${source}`,
                        source: source,
                        timestamp: ev.timestamp,
                    });
                    fileReads.delete(source);
                }
            }
        }
    }

    return indicators;
}

// Module Interface

export interface ExfilModule extends Module {
    getExfilStats(): ExfilStats;
}

export function createExfilModule(eventBus: EventBus): ExfilModule {
    const MODULE_ID = "exfil-channels";
    const MODULE_VERSION = "1.0.0";

    const stats: ExfilStats = {
        totalBytes: 0,
        channelsUsed: [],
        detectionCount: 0,
    };

    const recentDns: DNSQuery[] = [];
    const recentHttp: HTTPRequest[] = [];
    const recentEvents: EngineEvent[] = [];
    const unsubs: Array<() => void> = [];

    function addChannel(channel: string) {
        if (!stats.channelsUsed.includes(channel)) {
            stats.channelsUsed.push(channel);
        }
    }

    function processIndicators(indicators: ExfilIndicator[]) {
        for (const ind of indicators) {
            stats.detectionCount++;
            
            eventBus.emit({
                type: "defense:alert",
                machine: ind.source,
                ruleId: "exfil-detected",
                severity: "high",
                detail: ind.detail,
                timestamp: ind.timestamp,
            });

            eventBus.emit({
                type: "objective:progress",
                objectiveId: "exfil-data",
                detail: `Exfiltration detected via ${ind.channel}`,
                timestamp: ind.timestamp,
            });
        }
    }

    return {
        id: MODULE_ID,
        type: "engine",
        version: MODULE_VERSION,
        description: "Simulates and detects data exfiltration channels",
        provides: [{ name: "exfiltration" }, { name: "data-transfer" }] as readonly Capability[],
        requires: [] as readonly Capability[],

        getExfilStats() {
            return {
                totalBytes: stats.totalBytes,
                channelsUsed: [...stats.channelsUsed],
                detectionCount: stats.detectionCount,
            };
        },

        init(context: SimulationContext): void {
            const handleGeneralEvent = (event: EngineEvent) => {
                recentEvents.push(event);
                if (recentEvents.length > 500) recentEvents.shift();

                const indicators = detectDataTransfer(recentEvents);
                processIndicators(indicators);
                
                if (indicators.length > 0) {
                    // clear processed network events to avoid duplicate alerts
                    recentEvents.length = 0;
                }
            };

            unsubs.push(eventBus.on("net:dns", (event) => {
                handleGeneralEvent(event);

                const query: DNSQuery = { query: event.query, source: event.source, timestamp: event.timestamp };
                recentDns.push(query);
                if (recentDns.length > 200) recentDns.shift();

                // Track bytes (rough estimate)
                if (event.query.length > 20) {
                    stats.totalBytes += event.query.length;
                    addChannel("DNS tunneling");
                }

                const indicators = detectDNSTunneling(recentDns);
                processIndicators(indicators);
                
                if (indicators.length > 0) {
                    recentDns.length = 0;
                }
            }));

            unsubs.push(eventBus.on("net:request", (event) => {
                handleGeneralEvent(event);

                // Approximate body size for testing purposes
                const bodySize = event.method === "POST" ? 15000 : 0; 
                
                const req: HTTPRequest = {
                    url: event.url,
                    method: event.method,
                    bodySize,
                    source: event.source,
                    timestamp: event.timestamp
                };
                recentHttp.push(req);
                if (recentHttp.length > 200) recentHttp.shift();

                if (bodySize > 0 || req.url.length > 100) {
                    stats.totalBytes += bodySize > 0 ? bodySize : req.url.length;
                    addChannel("HTTP exfil");
                }

                const indicators = detectHTTPExfil(recentHttp);
                processIndicators(indicators);
                
                if (indicators.length > 0) {
                    recentHttp.length = 0;
                }
            }));

            unsubs.push(eventBus.on("fs:read", handleGeneralEvent));
            unsubs.push(eventBus.on("net:connect", handleGeneralEvent));

            context.events.emit({
                type: "sim:alert",
                source: MODULE_ID,
                message: "Exfiltration channels module initialized.",
                timestamp: Date.now()
            });
        },

        destroy(): void {
            for (const unsub of unsubs) {
                unsub();
            }
            unsubs.length = 0;
        }
    };
}
