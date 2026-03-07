import { describe, it, expect, beforeEach } from "vitest";
import { createExfilModule, detectDNSTunneling, detectHTTPExfil, detectDataTransfer } from "../../src/modules/exfil-module";
import type { DNSQuery, HTTPRequest } from "../../src/modules/exfil-module";
import { createEventBus } from "../helpers";
import type { SimulationContext } from "../../src/core/modules";
import type { EngineEvent } from "../../src/core/events";

describe("Exfiltration Channels Module", () => {
    
    describe("detectDNSTunneling", () => {
        it("detects unusually long subdomains", () => {
            const queries: DNSQuery[] = [
                { query: "normal.example.com", source: "vm-1", timestamp: 1000 },
                { query: "a".repeat(35) + ".evil.com", source: "vm-1", timestamp: 1010 },
            ];
            const indicators = detectDNSTunneling(queries);
            expect(indicators).toHaveLength(1);
            expect(indicators[0]?.channel).toBe("DNS tunneling");
            expect(indicators[0]?.source).toBe("vm-1");
        });

        it("detects high query rate", () => {
            const queries: DNSQuery[] = [];
            for (let i = 0; i < 55; i++) {
                queries.push({ query: `data${i}.tunnel.com`, source: "vm-2", timestamp: 1000 + i });
            }
            const indicators = detectDNSTunneling(queries);
            expect(indicators.some(i => i.detail.includes("High query rate"))).toBe(true);
        });
    });

    describe("detectHTTPExfil", () => {
        it("detects large POST requests", () => {
            const reqs: HTTPRequest[] = [
                { url: "http://example.com/upload", method: "POST", bodySize: 15000, source: "vm-1", timestamp: 1000 },
                { url: "http://example.com/view", method: "GET", bodySize: 0, source: "vm-1", timestamp: 1010 },
            ];
            const indicators = detectHTTPExfil(reqs);
            expect(indicators).toHaveLength(1);
            expect(indicators[0]?.detail).toContain("Large POST body");
        });

        it("detects base64 encoded data in URLs", () => {
            const reqs: HTTPRequest[] = [
                { url: "http://evil.com/q?data=VGVzdERhdGExMjM0NTY3ODkwVGVzdERhdGExMjM0NTY3ODkw", method: "GET", bodySize: 0, source: "vm-3", timestamp: 2000 }
            ];
            const indicators = detectHTTPExfil(reqs);
            expect(indicators).toHaveLength(1);
            expect(indicators[0]?.channel).toBe("Base64 in headers/URL");
        });

        it("detects git push to external repos", () => {
            const reqs: HTTPRequest[] = [
                { url: "https://github.com/evil/repo.git/info/lfs", method: "POST", bodySize: 500, source: "vm-4", timestamp: 3000 }
            ];
            const indicators = detectHTTPExfil(reqs);
            expect(indicators).toHaveLength(1);
            expect(indicators[0]?.channel).toBe("Git push");
        });

        it("detects cloud uploads", () => {
            const reqs: HTTPRequest[] = [
                { url: "https://s3.amazonaws.com/evil-bucket/data", method: "PUT", bodySize: 500, source: "vm-5", timestamp: 4000 }
            ];
            const indicators = detectHTTPExfil(reqs);
            expect(indicators).toHaveLength(1);
            expect(indicators[0]?.channel).toBe("Cloud upload");
        });
    });

    describe("detectDataTransfer", () => {
        it("correlates file read with subsequent network request", () => {
            const events: EngineEvent[] = [
                { type: "fs:read", machine: "vm-target", path: "/etc/shadow", user: "root", timestamp: 1000 },
                { type: "net:request", source: "vm-target", destination: "1.1.1.1", url: "http://evil.com", method: "POST", timestamp: 3000 }
            ];
            const indicators = detectDataTransfer(events);
            expect(indicators).toHaveLength(1);
            expect(indicators[0]?.channel).toBe("Data transfer");
            expect(indicators[0]?.source).toBe("vm-target");
        });

        it("ignores network activity that happens long after file read", () => {
            const events: EngineEvent[] = [
                { type: "fs:read", machine: "vm-target", path: "/etc/shadow", user: "root", timestamp: 1000 },
                { type: "net:request", source: "vm-target", destination: "1.1.1.1", url: "http://evil.com", method: "POST", timestamp: 10000 }
            ];
            const indicators = detectDataTransfer(events);
            expect(indicators).toHaveLength(0);
        });
    });

    describe("ExfilModule integration", () => {
        let bus: ReturnType<typeof createEventBus>;
        let module: ReturnType<typeof createExfilModule>;
        let mockContext: SimulationContext;

        beforeEach(() => {
            bus = createEventBus();
            module = createExfilModule(bus);
            mockContext = {
                events: bus,
                vms: new Map(),
                fabric: {} as any,
                world: {} as any,
                tick: 0,
                services: {} as any,
            };
            module.init(mockContext);
        });

        it("tracks stats and emits alerts upon DNS tunneling", () => {
            let emittedAlert = false;
            bus.on("defense:alert", () => { emittedAlert = true; });
            
            // Send a single long DNS query to trigger detection
            bus.emit({
                type: "net:dns",
                query: "a".repeat(40) + ".evil.com",
                result: "1.2.3.4",
                source: "vm-10",
                timestamp: 1000
            });

            const stats = module.getExfilStats();
            expect(stats.detectionCount).toBe(1);
            expect(stats.channelsUsed).toContain("DNS tunneling");
            expect(stats.totalBytes).toBeGreaterThan(40);

            // Verify defense alert was emitted
            expect(emittedAlert).toBe(true);
        });

        it("tracks stats and emits alerts upon HTTP exfil", () => {
            let emittedAlert = false;
            bus.on("defense:alert", () => { emittedAlert = true; });
            
            bus.emit({
                type: "net:request",
                url: "http://evil.com/upload",
                method: "POST",
                source: "vm-11",
                destination: "evil.com",
                timestamp: 2000
            });

            const stats = module.getExfilStats();
            expect(stats.detectionCount).toBeGreaterThan(0);
            expect(stats.channelsUsed).toContain("HTTP exfil");
            expect(stats.totalBytes).toBeGreaterThan(0);

            expect(emittedAlert).toBe(true);
        });

        it("correlates events for data transfer alerts", () => {
            let emittedAlert = false;
            bus.on("defense:alert", () => { emittedAlert = true; });

            bus.emit({
                type: "fs:read",
                machine: "vm-12",
                path: "/secret.txt",
                user: "admin",
                timestamp: 100
            });

            bus.emit({
                type: "net:connect",
                source: "vm-12",
                host: "evil.com",
                port: 443,
                protocol: "tcp",
                timestamp: 200
            });

            const stats = module.getExfilStats();
            expect(stats.detectionCount).toBeGreaterThan(0);
            expect(emittedAlert).toBe(true);
        });
        
        it("tracks multiple channels simultaneously", () => {
            bus.emit({
                type: "net:dns",
                query: "a".repeat(40) + ".evil.com",
                result: "1.2.3.4",
                source: "vm-10",
                timestamp: 1000
            });
            
            bus.emit({
                type: "net:request",
                url: "http://evil.com/upload",
                method: "POST",
                source: "vm-11",
                destination: "evil.com",
                timestamp: 2000
            });
            
            const stats = module.getExfilStats();
            expect(stats.channelsUsed).toContain("DNS tunneling");
            expect(stats.channelsUsed).toContain("HTTP exfil");
            expect(stats.channelsUsed).toHaveLength(2);
            expect(stats.detectionCount).toBe(2);
        });
        
        it("destroys subscriptions without errors", () => {
            module.destroy();
            // Triggering events after destroy should not throw or change stats
            bus.emit({
                type: "net:dns",
                query: "a".repeat(40) + ".evil.com",
                result: "1.2.3.4",
                source: "vm-10",
                timestamp: 1000
            });
            const stats = module.getExfilStats();
            expect(stats.detectionCount).toBe(0);
        });
    });
});
