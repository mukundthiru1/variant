/**
 * VARIANT — Log Generator tests
 */
import { describe, it, expect } from 'vitest';
import { generateLogs, NOISE_LIBRARIES } from '../../../src/lib/logs/types';

describe('LogGenerator', () => {
    const nowMs = new Date('2024-03-15T14:00:00Z').getTime();

    describe('auth.log generation', () => {
        it('generates auth log with signal and noise entries', () => {
            const result = generateLogs({
                hostname: 'web-01',
                nowMs,
                logs: [{
                    path: '/var/log/auth.log',
                    format: 'auth',
                    hoursBack: 24,
                    noisePerHour: 5,
                    signals: [
                        {
                            hoursAgo: 2,
                            message: 'Failed password for root from 192.168.1.200 port 22 ssh2',
                            service: 'sshd',
                            pid: 12345,
                        },
                        {
                            hoursAgo: 1,
                            message: 'Accepted password for root from 192.168.1.200 port 22 ssh2',
                            service: 'sshd',
                            pid: 12346,
                        },
                    ],
                    noiseTemplates: NOISE_LIBRARIES.authLog,
                }],
            });

            const authLog = result.files.get('/var/log/auth.log');
            expect(authLog).toBeDefined();
            const content = typeof authLog!.content === 'string' ? authLog!.content : '';

            // Signals are present
            expect(content).toContain('Failed password for root from 192.168.1.200');
            expect(content).toContain('Accepted password for root from 192.168.1.200');

            // Has noise entries too
            expect(content).toContain('web-01');

            // Multiple lines (noise + signal)
            const lines = content.trim().split('\n');
            expect(lines.length).toBeGreaterThan(10);
        });

        it('logs are sorted chronologically', () => {
            const result = generateLogs({
                hostname: 'web-01',
                nowMs,
                logs: [{
                    path: '/var/log/test.log',
                    format: 'syslog',
                    hoursBack: 2,
                    noisePerHour: 3,
                    signals: [
                        { hoursAgo: 1, message: 'SIGNAL_B', service: 'test' },
                        { hoursAgo: 0.5, message: 'SIGNAL_A', service: 'test' },
                    ],
                    noiseTemplates: [{ template: 'noise entry', service: 'test', weight: 1 }],
                }],
            });

            const content = typeof result.files.get('/var/log/test.log')!.content === 'string'
                ? result.files.get('/var/log/test.log')!.content as string : '';
            const lines = content.trim().split('\n');

            // SIGNAL_B (1 hour ago) should come before SIGNAL_A (30 min ago)
            const bIdx = lines.findIndex(l => l.includes('SIGNAL_B'));
            const aIdx = lines.findIndex(l => l.includes('SIGNAL_A'));
            expect(bIdx).toBeLessThan(aIdx);
        });
    });

    describe('apache access log', () => {
        it('generates realistic access log format', () => {
            const result = generateLogs({
                hostname: 'web-01',
                nowMs,
                logs: [{
                    path: '/var/log/apache2/access.log',
                    format: 'apache-access',
                    hoursBack: 1,
                    noisePerHour: 0,
                    signals: [{
                        hoursAgo: 0,
                        message: '',
                        sourceIP: '10.0.0.50',
                        method: 'GET',
                        httpPath: '/admin/login',
                        statusCode: 200,
                        responseSize: 4523,
                        userAgent: 'Mozilla/5.0',
                    }],
                    noiseTemplates: [],
                }],
            });

            const content = typeof result.files.get('/var/log/apache2/access.log')!.content === 'string'
                ? result.files.get('/var/log/apache2/access.log')!.content as string : '';
            expect(content).toContain('10.0.0.50');
            expect(content).toContain('GET /admin/login HTTP/1.1');
            expect(content).toContain('200');
            expect(content).toContain('4523');
        });
    });

    describe('deterministic output', () => {
        it('same config produces same logs', () => {
            const cfg = {
                hostname: 'test-host',
                nowMs,
                logs: [{
                    path: '/var/log/test.log',
                    format: 'syslog' as const,
                    hoursBack: 4,
                    noisePerHour: 10,
                    signals: [],
                    noiseTemplates: NOISE_LIBRARIES.syslog,
                }],
            };

            const result1 = generateLogs(cfg);
            const result2 = generateLogs(cfg);

            const content1 = typeof result1.files.get('/var/log/test.log')!.content === 'string'
                ? result1.files.get('/var/log/test.log')!.content : '';
            const content2 = typeof result2.files.get('/var/log/test.log')!.content === 'string'
                ? result2.files.get('/var/log/test.log')!.content : '';

            expect(content1).toBe(content2);
        });
    });

    describe('multiple log files', () => {
        it('generates multiple log files from single config', () => {
            const result = generateLogs({
                hostname: 'web-01',
                nowMs,
                logs: [
                    {
                        path: '/var/log/auth.log',
                        format: 'auth',
                        hoursBack: 1,
                        noisePerHour: 1,
                        signals: [],
                        noiseTemplates: NOISE_LIBRARIES.authLog,
                    },
                    {
                        path: '/var/log/syslog',
                        format: 'syslog',
                        hoursBack: 1,
                        noisePerHour: 1,
                        signals: [],
                        noiseTemplates: NOISE_LIBRARIES.syslog,
                    },
                ],
            });

            expect(result.files.has('/var/log/auth.log')).toBe(true);
            expect(result.files.has('/var/log/syslog')).toBe(true);
        });
    });

    describe('JSON format', () => {
        it('generates JSON-formatted log entries', () => {
            const result = generateLogs({
                hostname: 'api-01',
                nowMs,
                logs: [{
                    path: '/var/log/app.json',
                    format: 'json',
                    hoursBack: 1,
                    noisePerHour: 0,
                    signals: [{
                        hoursAgo: 0,
                        message: 'User authenticated successfully',
                        service: 'auth-service',
                        severity: 'info',
                    }],
                    noiseTemplates: [],
                }],
            });

            const content = typeof result.files.get('/var/log/app.json')!.content === 'string'
                ? result.files.get('/var/log/app.json')!.content as string : '';
            const parsed = JSON.parse(content.trim());
            expect(parsed.message).toBe('User authenticated successfully');
            expect(parsed.service).toBe('auth-service');
            expect(parsed.hostname).toBe('api-01');
        });
    });
});
