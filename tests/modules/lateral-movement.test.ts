import { describe, it, expect, beforeEach } from 'vitest';
import {
    createLateralMovementModule,
    validateMovement,
    recordPivot,
    getPivotChain,
    getAccessibleMachines,
    canReach,
    resetLateralMovementState,
    NetworkTopology
} from '../../src/modules/lateral-movement';
import type { CredentialEntry, MachineSpec } from '../../src/core/world/types';
import { createEventBus } from '../../src/core/event-bus';
import { createServiceLocator, SimulationContext } from '../../src/core/modules';

describe('Lateral Movement Engine', () => {
    beforeEach(() => {
        resetLateralMovementState();
    });

    const mockTopology: NetworkTopology = {
        machines: {
            'A': { interfaces: [{ segment: 'seg1', ip: '10.0.0.1' }] } as unknown as MachineSpec,
            'B': { interfaces: [{ segment: 'seg1', ip: '10.0.0.2' }, { segment: 'seg2', ip: '10.0.1.1' }] } as unknown as MachineSpec,
            'C': { interfaces: [{ segment: 'seg2', ip: '10.0.1.2' }] } as unknown as MachineSpec,
            'D': { interfaces: [{ segment: 'seg3', ip: '10.0.2.1' }] } as unknown as MachineSpec,
        },
        network: {
            segments: [],
            edges: [
                { from: 'seg2', to: 'seg3', ports: [22], bidirectional: false },
                { from: 'seg3', to: 'seg2', ports: [80], bidirectional: false }
            ]
        }
    };

    const credSshKey: CredentialEntry = {
        id: 'cred-key',
        type: 'ssh-key',
        value: 'key',
        foundAt: { machine: 'A' },
        validAt: { machine: 'B', service: 'ssh', user: 'root' }
    };

    const credPassword: CredentialEntry = {
        id: 'cred-pass',
        type: 'password',
        value: 'pass',
        foundAt: { machine: 'A' },
        validAt: { machine: 'C', service: 'ssh', user: 'admin' }
    };

    const credPassTheHash: CredentialEntry = {
        id: 'cred-hash',
        type: 'hash',
        value: 'hash',
        foundAt: { machine: 'B' },
        validAt: { machine: 'C', service: 'smb', user: 'admin' }
    };

    const credDatabaseLink: CredentialEntry = {
        id: 'cred-db',
        type: 'database-password',
        value: 'dbpass',
        foundAt: { machine: 'A' },
        validAt: { machine: 'B', service: 'mysql', user: 'dbadmin' }
    };

    const credMismatch: CredentialEntry = {
        ...credPassword,
        type: 'api-token' as any
    };

    const credWrongTarget: CredentialEntry = {
        ...credPassword,
        validAt: { machine: 'D', service: 'ssh', user: 'admin' }
    };

    describe('Network Reachability (canReach)', () => {
        it('returns true for same segment', () => {
            expect(canReach('A', 'B', 22, mockTopology)).toBe(true);
        });

        it('returns true across multi-hop (A -> seg1 -> B -> seg2 -> C)', () => {
            expect(canReach('A', 'C', 22, mockTopology)).toBe(true);
        });

        it('respects port filtering on edges (seg2 -> seg3 allows 22)', () => {
            expect(canReach('C', 'D', 22, mockTopology)).toBe(true);
        });

        it('respects port filtering on edges (seg2 -> seg3 blocks 80)', () => {
            expect(canReach('C', 'D', 80, mockTopology)).toBe(false);
        });

        it('respects directional edges (seg3 -> seg2 blocks 22)', () => {
            expect(canReach('D', 'C', 22, mockTopology)).toBe(false);
        });
        
        it('returns true if source and target are the same', () => {
            expect(canReach('A', 'A', 22, mockTopology)).toBe(true);
        });
    });

    describe('Movement Validation', () => {
        it('allows SSH key-based lateral movement', () => {
            const res = validateMovement('A', 'B', credSshKey, 'ssh-key', mockTopology);
            expect(res.success).toBe(true);
            expect(res.newAccess).toEqual({ machine: 'B', user: 'root', shell: '/bin/bash' });
            expect(res.events).toHaveLength(1);
            expect(res.events[0]?.type).toBe('auth:login');
        });

        it('allows Password-based SSH movement', () => {
            const res = validateMovement('A', 'C', credPassword, 'ssh-password', mockTopology);
            expect(res.success).toBe(true);
            expect(res.newAccess?.machine).toBe('C');
        });

        it('allows Pass-the-Hash', () => {
            const res = validateMovement('B', 'C', credPassTheHash, 'pass-the-hash', mockTopology);
            expect(res.success).toBe(true);
            expect(res.newAccess?.shell).toBe('cmd.exe');
        });

        it('fails on credential type mismatch', () => {
            const res = validateMovement('A', 'C', credMismatch, 'ssh-password', mockTopology);
            expect(res.success).toBe(false);
            expect(res.error).toContain('Credential type mismatch');
        });

        it('fails if credential is for different target machine', () => {
            const res = validateMovement('A', 'C', credWrongTarget, 'ssh-password', mockTopology);
            expect(res.success).toBe(false);
            expect(res.error).toContain('Credential not valid for target machine');
        });

        it('fails if network path is blocked', () => {
            // C -> D port 80 is blocked by edge
            const credPort80: CredentialEntry = {
                id: 'cred-http',
                type: 'cookie',
                value: 'sess',
                foundAt: { machine: 'C' },
                validAt: { machine: 'D', service: 'http', user: 'www-data' }
            };
            const res = validateMovement('C', 'D', credPort80, 'web-shell-pivot', mockTopology);
            expect(res.success).toBe(false);
            expect(res.error).toContain('Network path blocked');
        });
    });

    describe('Pivot Chain Tracking', () => {
        it('records and retrieves pivot chains', () => {
            recordPivot({ machine: 'A', user: 'user' }, { machine: 'B', user: 'root' }, 'ssh-key', 1);
            recordPivot({ machine: 'B', user: 'root' }, { machine: 'C', user: 'admin' }, 'ssh-password', 2);
            
            const chain = getPivotChain();
            expect(chain).toHaveLength(2);
            expect(chain[0]?.from.machine).toBe('A');
            expect(chain[1]?.to.machine).toBe('C');
        });

        it('getAccessibleMachines returns unique machines in the chain', () => {
            recordPivot({ machine: 'A', user: 'user' }, { machine: 'B', user: 'root' }, 'ssh-key', 1);
            recordPivot({ machine: 'B', user: 'root' }, { machine: 'C', user: 'admin' }, 'ssh-password', 2);
            
            const accessible = getAccessibleMachines();
            expect(accessible).toContain('A');
            expect(accessible).toContain('B');
            expect(accessible).toContain('C');
            expect(accessible.length).toBe(3);
        });
    });

    describe('Module Event Integration', () => {
        it('emits defense:alert when net:connect is blocked', () => {
            const bus = createEventBus(100);
            const module = createLateralMovementModule(bus);
            
            const context = {
                events: bus,
                world: { machines: mockTopology.machines, network: mockTopology.network },
                services: createServiceLocator(),
                tick: 1,
            } as any as SimulationContext;

            module.init(context);

            bus.emit({
                type: 'net:connect',
                source: 'C',
                host: 'D',
                port: 80,
                protocol: 'tcp',
                timestamp: Date.now()
            });

            const log = bus.getLog('defense:alert');
            expect(log).toHaveLength(1);
            expect((log[0] as any).detail).toContain('Blocked connection');
        });

        it('emits defense:alert for unusual lateral movement technique', () => {
            const bus = createEventBus(100);
            const module = createLateralMovementModule(bus);
            
            const context = {
                events: bus,
                world: { machines: mockTopology.machines, network: mockTopology.network },
                services: createServiceLocator(),
                tick: 1,
            } as any as SimulationContext;

            module.init(context);
            
            const service = context.services.get<any>('lateral-movement');
            service.validateMovement('A', 'B', credDatabaseLink, 'database-link');

            const log = bus.getLog('defense:alert');
            expect(log).toHaveLength(1);
            expect((log[0] as any).detail).toContain('Unusual lateral movement detected');
            expect((log[0] as any).ruleId).toBe('LM-UNUSUAL-TECHNIQUE');
        });
        
        it('does not emit defense:alert for standard ssh movement', () => {
            const bus = createEventBus(100);
            const module = createLateralMovementModule(bus);
            
            const context = {
                events: bus,
                world: { machines: mockTopology.machines, network: mockTopology.network },
                services: createServiceLocator(),
                tick: 1,
            } as any as SimulationContext;

            module.init(context);
            
            const service = context.services.get<any>('lateral-movement');
            service.validateMovement('A', 'B', credSshKey, 'ssh-key');

            const log = bus.getLog('defense:alert');
            expect(log).toHaveLength(0); // No alert for standard ssh
            
            const authLog = bus.getLog('auth:login');
            expect(authLog).toHaveLength(1); // Should still emit auth event
        });
    });
});
