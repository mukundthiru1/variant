/**
 * VARIANT — NPC System tests
 */
import { describe, it, expect } from 'vitest';
import { expandNPCSchedule, NPC_TEMPLATES } from '../../../src/lib/npc/types';
import type { NPCDefinition } from '../../../src/lib/npc/types';

describe('NPC System', () => {
    describe('schedule expansion', () => {
        it('expands scheduled actions', () => {
            const npc: NPCDefinition = {
                id: 'test-npc',
                name: 'Test NPC',
                username: 'testuser',
                role: 'employee',
                machine: 'web-01',
                schedule: [
                    { tick: 10, type: { kind: 'login', method: 'ssh', success: true } },
                    { tick: 20, type: { kind: 'command', command: 'ls -la' } },
                    { tick: 30, type: { kind: 'logout' } },
                ],
            };

            const events = expandNPCSchedule(npc, 100);
            expect(events).toHaveLength(3);
            expect(events[0]!.tick).toBe(10);
            expect(events[1]!.tick).toBe(20);
            expect(events[2]!.tick).toBe(30);
        });

        it('expands recurring actions', () => {
            const npc: NPCDefinition = {
                id: 'cron-npc',
                name: 'Cron NPC',
                username: 'root',
                role: 'service-account',
                machine: 'web-01',
                schedule: [],
                recurring: [
                    {
                        intervalTicks: 10,
                        action: { kind: 'command', command: 'echo heartbeat' },
                        startTick: 0,
                        stopTick: 50,
                    },
                ],
            };

            const events = expandNPCSchedule(npc, 100);
            // 0, 10, 20, 30, 40, 50 = 6 events
            expect(events).toHaveLength(6);
        });

        it('events are sorted by tick', () => {
            const npc: NPCDefinition = {
                id: 'mixed-npc',
                name: 'Mixed NPC',
                username: 'admin',
                role: 'admin',
                machine: 'web-01',
                schedule: [
                    { tick: 50, type: { kind: 'logout' } },
                    { tick: 5, type: { kind: 'login', method: 'ssh', success: true } },
                ],
                recurring: [
                    {
                        intervalTicks: 20,
                        action: { kind: 'command', command: 'check' },
                        startTick: 10,
                        stopTick: 50,
                    },
                ],
            };

            const events = expandNPCSchedule(npc, 100);
            for (let i = 1; i < events.length; i++) {
                expect(events[i]!.tick).toBeGreaterThanOrEqual(events[i - 1]!.tick);
            }
        });
    });

    describe('NPC templates', () => {
        it('creates sysadmin NPC', () => {
            const admin = NPC_TEMPLATES.sysadmin('bob', 'web-01');
            expect(admin.role).toBe('admin');
            expect(admin.username).toBe('bob');
            expect(admin.schedule.length).toBeGreaterThan(0);
            expect(admin.recurring!.length).toBeGreaterThan(0);
        });

        it('creates employee NPC', () => {
            const employee = NPC_TEMPLATES.employee('alice', 'web-01');
            expect(employee.role).toBe('employee');
            expect(employee.username).toBe('alice');
            expect(employee.schedule.length).toBeGreaterThan(0);
        });

        it('creates brute force attacker NPC', () => {
            const attacker = NPC_TEMPLATES.bruteForceAttacker('web-01', '192.168.1.200');
            expect(attacker.role).toBe('attacker');
            expect(attacker.recurring!.length).toBeGreaterThan(0);

            // Expand and verify recurring attack events
            const events = expandNPCSchedule(attacker, 300);
            expect(events.length).toBeGreaterThan(0);
            // All events should have 'login' kind with success: false
            for (const event of events) {
                expect(event.action.kind).toBe('login');
            }
        });

        it('creates cron service NPC', () => {
            const cron = NPC_TEMPLATES.cronService('web-01', '/usr/sbin/logrotate', 60);
            expect(cron.role).toBe('service-account');
            expect(cron.recurring!.length).toBe(2); // command + log entry
        });

        it('expanded sysadmin has reasonable event count', () => {
            const admin = NPC_TEMPLATES.sysadmin('bob', 'web-01');
            const events = expandNPCSchedule(admin, 500);
            expect(events.length).toBeGreaterThan(5);
            expect(events.length).toBeLessThan(100);
        });
    });
});
