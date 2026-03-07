/**
 * VARIANT — Data Exfiltration Engine
 *
 * Simulates data exfiltration with:
 * - Multiple channel types with bandwidth/detection profiles
 * - DLP rule enforcement
 * - Chunking and throttling simulation
 * - Artifact generation for detection training
 *
 * All operations are synchronous and pure-data.
 */

import type {
    ExfiltrationEngine,
    ExfilChannel,
    SensitiveData,
    ExfilAttempt,
    ExfilResult,
    ExfilArtifact,
    ChannelConfig,
    DLPRule,
} from './types';

// ── Helpers ───────────────────────────────────────────────

let dataCounter = 0;
let exfilCounter = 0;

function generateDataId(): string {
    return `data-${++dataCounter}`;
}

function generateExfilId(): string {
    return `exfil-${++exfilCounter}`;
}

const CHANNEL_CONFIGS: Record<string, ChannelConfig> = {
    dns_tunnel: {
        channel: 'dns_tunnel', maxBandwidthBps: 5_000, maxChunkSize: 253,
        encrypted: false, detectionRisk: 'medium', mitreTechnique: 'T1048.003', requiresNetwork: true,
    },
    http_post: {
        channel: 'http_post', maxBandwidthBps: 10_000_000, maxChunkSize: 10_000_000,
        encrypted: false, detectionRisk: 'medium', mitreTechnique: 'T1048.003', requiresNetwork: true,
    },
    https_post: {
        channel: 'https_post', maxBandwidthBps: 10_000_000, maxChunkSize: 10_000_000,
        encrypted: true, detectionRisk: 'low', mitreTechnique: 'T1048.002', requiresNetwork: true,
    },
    http_get_params: {
        channel: 'http_get_params', maxBandwidthBps: 500_000, maxChunkSize: 2_000,
        encrypted: false, detectionRisk: 'medium', mitreTechnique: 'T1048.003', requiresNetwork: true,
    },
    icmp_tunnel: {
        channel: 'icmp_tunnel', maxBandwidthBps: 10_000, maxChunkSize: 1_400,
        encrypted: false, detectionRisk: 'high', mitreTechnique: 'T1048.003', requiresNetwork: true,
    },
    dns_over_https: {
        channel: 'dns_over_https', maxBandwidthBps: 50_000, maxChunkSize: 500,
        encrypted: true, detectionRisk: 'low', mitreTechnique: 'T1071.004', requiresNetwork: true,
    },
    cloud_storage: {
        channel: 'cloud_storage', maxBandwidthBps: 50_000_000, maxChunkSize: 100_000_000,
        encrypted: true, detectionRisk: 'low', mitreTechnique: 'T1567.002', requiresNetwork: true,
    },
    email_attachment: {
        channel: 'email_attachment', maxBandwidthBps: 1_000_000, maxChunkSize: 25_000_000,
        encrypted: false, detectionRisk: 'high', mitreTechnique: 'T1048.003', requiresNetwork: true,
    },
    email_body: {
        channel: 'email_body', maxBandwidthBps: 100_000, maxChunkSize: 100_000,
        encrypted: false, detectionRisk: 'high', mitreTechnique: 'T1048.003', requiresNetwork: true,
    },
    usb: {
        channel: 'usb', maxBandwidthBps: 100_000_000, maxChunkSize: 1_000_000_000,
        encrypted: false, detectionRisk: 'medium', mitreTechnique: 'T1052.001', requiresNetwork: false,
    },
    steganography: {
        channel: 'steganography', maxBandwidthBps: 1_000, maxChunkSize: 50_000,
        encrypted: false, detectionRisk: 'low', mitreTechnique: 'T1027.003', requiresNetwork: true,
    },
    smb_share: {
        channel: 'smb_share', maxBandwidthBps: 50_000_000, maxChunkSize: 100_000_000,
        encrypted: false, detectionRisk: 'medium', mitreTechnique: 'T1048.003', requiresNetwork: true,
    },
    ftp: {
        channel: 'ftp', maxBandwidthBps: 10_000_000, maxChunkSize: 100_000_000,
        encrypted: false, detectionRisk: 'high', mitreTechnique: 'T1048.003', requiresNetwork: true,
    },
    tor: {
        channel: 'tor', maxBandwidthBps: 500_000, maxChunkSize: 10_000_000,
        encrypted: true, detectionRisk: 'high', mitreTechnique: 'T1048.002', requiresNetwork: true,
    },
    websocket: {
        channel: 'websocket', maxBandwidthBps: 10_000_000, maxChunkSize: 10_000_000,
        encrypted: true, detectionRisk: 'low', mitreTechnique: 'T1071.001', requiresNetwork: true,
    },
};

function generateArtifacts(channel: ExfilChannel, dest: string, bytes: number): ExfilArtifact[] {
    const artifacts: ExfilArtifact[] = [];

    switch (channel) {
        case 'dns_tunnel':
            artifacts.push(
                { type: 'dns_query', description: `Unusually long DNS queries to ${dest}`, detectable: true, ioc: dest },
                { type: 'network_flow', description: `High volume DNS traffic (${bytes} bytes encoded)`, detectable: true },
            );
            break;
        case 'http_post':
        case 'https_post':
            artifacts.push(
                { type: 'http_request', description: `POST request to ${dest} (${bytes} bytes)`, detectable: true, ioc: dest },
                { type: 'network_flow', description: `Outbound data transfer to ${dest}`, detectable: channel === 'http_post' },
            );
            break;
        case 'icmp_tunnel':
            artifacts.push(
                { type: 'network_flow', description: `Anomalous ICMP traffic with payload data to ${dest}`, detectable: true, ioc: dest },
            );
            break;
        case 'cloud_storage':
            artifacts.push(
                { type: 'http_request', description: `Upload to cloud storage service`, detectable: true },
                { type: 'file_access', description: `Sensitive file read before upload`, detectable: true },
            );
            break;
        case 'email_attachment':
        case 'email_body':
            artifacts.push(
                { type: 'email', description: `Email sent to ${dest} with sensitive data`, detectable: true, ioc: dest },
            );
            break;
        case 'usb':
            artifacts.push(
                { type: 'file_access', description: `File copied to removable media`, detectable: true },
                { type: 'process', description: `USB device write operation`, detectable: true },
            );
            break;
        default:
            artifacts.push(
                { type: 'network_flow', description: `Data transfer via ${channel} to ${dest}`, detectable: true },
            );
    }

    return artifacts;
}

// ── Factory ──────────────────────────────────────────────

export function createExfiltrationEngine(): ExfiltrationEngine {
    const dataItems = new Map<string, SensitiveData>();
    const dlpRules = new Map<string, DLPRule>();
    const history: ExfilResult[] = [];
    const channelsUsed = new Set<string>();
    let dlpTriggered = 0;

    const engine: ExfiltrationEngine = {
        addData(input) {
            const id = generateDataId();
            const data: SensitiveData = Object.freeze({ ...input, id });
            dataItems.set(id, data);
            return data;
        },

        getData(id) {
            return dataItems.get(id) ?? null;
        },

        listData() {
            return Object.freeze(Array.from(dataItems.values()));
        },

        exfiltrate(attempt: ExfilAttempt): ExfilResult {
            const id = generateExfilId();
            const data = dataItems.get(attempt.dataId);

            if (!data) {
                const result: ExfilResult = Object.freeze({
                    id, attempt, success: false,
                    reason: `Data ${attempt.dataId} not found`,
                    bytesTransferred: 0, chunksUsed: 0, estimatedDurationTicks: 0,
                    detectionRisk: 'none', mitreTechnique: '', artifacts: [],
                });
                history.push(result);
                return result;
            }

            // Check DLP rules
            for (const rule of dlpRules.values()) {
                if (!rule.enabled) continue;
                if (rule.classification === data.classification || rule.classification === 'public') {
                    if (rule.blockedChannels.includes(attempt.channel)) {
                        dlpTriggered++;
                        const result: ExfilResult = Object.freeze({
                            id, attempt, success: false,
                            reason: `Blocked by DLP rule: ${rule.name}`,
                            bytesTransferred: 0, chunksUsed: 0, estimatedDurationTicks: 0,
                            detectionRisk: 'critical',
                            mitreTechnique: engine.getChannelConfig(attempt.channel).mitreTechnique,
                            artifacts: Object.freeze([
                                { type: 'process' as const, description: `DLP alert: ${rule.name} blocked ${attempt.channel}`, detectable: true },
                            ]),
                        });
                        history.push(result);
                        return result;
                    }
                }
            }

            // Calculate transfer parameters
            const config = engine.getChannelConfig(attempt.channel);
            const chunkSize = Math.min(attempt.chunkSizeBytes ?? config.maxChunkSize, config.maxChunkSize);
            const bandwidth = Math.min(attempt.throttleBps ?? config.maxBandwidthBps, config.maxBandwidthBps);
            const chunks = Math.ceil(data.sizeBytes / chunkSize);
            const durationSeconds = data.sizeBytes / bandwidth;
            const durationTicks = Math.max(1, Math.ceil(durationSeconds));

            // Adjust detection risk based on encryption and encoding
            let risk = config.detectionRisk;
            if (attempt.encrypted && !config.encrypted) {
                // Encryption lowers detection risk by one level
                const levels: Array<typeof risk> = ['none', 'low', 'medium', 'high', 'critical'];
                const idx = levels.indexOf(risk);
                if (idx > 0) risk = levels[idx - 1]!;
            }

            channelsUsed.add(attempt.channel);

            const artifacts = Object.freeze(generateArtifacts(attempt.channel, attempt.destination, data.sizeBytes));
            const result: ExfilResult = Object.freeze({
                id, attempt, success: true,
                reason: `Exfiltrated ${data.sizeBytes} bytes via ${attempt.channel}`,
                bytesTransferred: data.sizeBytes,
                chunksUsed: chunks,
                estimatedDurationTicks: durationTicks,
                detectionRisk: risk,
                mitreTechnique: config.mitreTechnique,
                artifacts,
            });
            history.push(result);
            return result;
        },

        addDLPRule(rule) {
            dlpRules.set(rule.id, rule);
        },

        removeDLPRule(id) {
            return dlpRules.delete(id);
        },

        getDLPRules() {
            return Object.freeze(Array.from(dlpRules.values()));
        },

        getChannelConfig(channel) {
            return CHANNEL_CONFIGS[channel] ?? {
                channel,
                maxBandwidthBps: 1_000_000,
                maxChunkSize: 1_000_000,
                encrypted: false,
                detectionRisk: 'medium' as const,
                mitreTechnique: 'T1048',
                requiresNetwork: true,
            };
        },

        getExfilHistory() {
            return Object.freeze([...history]);
        },

        getStats() {
            let totalBytes = 0;
            let successful = 0;
            let blocked = 0;
            for (const r of history) {
                if (r.success) {
                    successful++;
                    totalBytes += r.bytesTransferred;
                } else {
                    blocked++;
                }
            }
            return Object.freeze({
                totalDataItems: dataItems.size,
                totalExfilAttempts: history.length,
                successfulExfils: successful,
                blockedExfils: blocked,
                totalBytesExfiltrated: totalBytes,
                channelsUsed: Object.freeze(Array.from(channelsUsed)),
                dlpRulesTriggered: dlpTriggered,
            });
        },
    };

    return engine;
}
