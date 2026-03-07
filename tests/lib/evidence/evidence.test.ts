/**
 * VARIANT — Evidence Chain tests
 */
import { describe, it, expect } from 'vitest';
import { createEvidenceChain } from '../../../src/lib/evidence/evidence-chain';
import type { EvidenceData, EvidenceSessionMeta } from '../../../src/lib/evidence/types';

function makeData(summary: string, rawInput?: string): EvidenceData {
    const base: EvidenceData = { summary, details: { test: true } };
    if (rawInput !== undefined) return { ...base, rawInput };
    return base;
}

function makeSession(): EvidenceSessionMeta {
    return {
        sessionId: 'sess-001',
        levelId: 'level-01',
        startedAt: '2026-01-01T00:00:00Z',
        endedAt: '2026-01-01T01:00:00Z',
        totalTicks: 1000,
        playerId: 'player-1',
    };
}

describe('EvidenceChain', () => {
    it('starts empty', () => {
        const chain = createEvidenceChain();
        expect(chain.getLength()).toBe(0);
        expect(chain.getLatest()).toBeNull();
    });

    it('appends a block with correct genesis hash', () => {
        const chain = createEvidenceChain();
        const block = chain.append(1, 'command', 'web-01', makeData('ls -la'));

        expect(block.seq).toBe(0);
        expect(block.prevHash).toBe('0');
        expect(block.hash).toBeTruthy();
        expect(block.tick).toBe(1);
        expect(block.category).toBe('command');
        expect(block.machine).toBe('web-01');
    });

    it('links blocks via prevHash', () => {
        const chain = createEvidenceChain();
        const b0 = chain.append(1, 'command', 'web-01', makeData('ls'));
        const b1 = chain.append(2, 'file-access', 'web-01', makeData('read /etc/passwd'));

        expect(b1.prevHash).toBe(b0.hash);
        expect(b1.seq).toBe(1);
    });

    it('gets block by sequence number', () => {
        const chain = createEvidenceChain();
        chain.append(1, 'command', null, makeData('cmd-1'));
        chain.append(2, 'command', null, makeData('cmd-2'));

        expect(chain.getBlock(0)!.data.summary).toBe('cmd-1');
        expect(chain.getBlock(1)!.data.summary).toBe('cmd-2');
        expect(chain.getBlock(2)).toBeNull();
        expect(chain.getBlock(-1)).toBeNull();
    });

    it('gets latest block', () => {
        const chain = createEvidenceChain();
        chain.append(1, 'command', null, makeData('first'));
        chain.append(2, 'command', null, makeData('second'));

        expect(chain.getLatest()!.data.summary).toBe('second');
    });

    it('verifies valid chain', () => {
        const chain = createEvidenceChain();
        chain.append(1, 'command', 'web-01', makeData('ls'));
        chain.append(2, 'auth', 'web-01', makeData('login'));
        chain.append(3, 'network', null, makeData('connect'));

        const result = chain.verify();
        expect(result.valid).toBe(true);
        expect(result.blockCount).toBe(3);
        expect(result.firstInvalidBlock).toBeNull();
    });

    it('verifies empty chain', () => {
        const chain = createEvidenceChain();
        const result = chain.verify();
        expect(result.valid).toBe(true);
        expect(result.blockCount).toBe(0);
    });

    it('filters by category', () => {
        const chain = createEvidenceChain();
        chain.append(1, 'command', null, makeData('cmd'));
        chain.append(2, 'auth', null, makeData('login'));
        chain.append(3, 'command', null, makeData('cmd2'));

        const commands = chain.getBlocks({ categories: ['command'] });
        expect(commands.length).toBe(2);
    });

    it('filters by machine', () => {
        const chain = createEvidenceChain();
        chain.append(1, 'command', 'web-01', makeData('cmd'));
        chain.append(2, 'command', 'db-01', makeData('cmd'));
        chain.append(3, 'command', 'web-01', makeData('cmd'));

        const web = chain.getBlocks({ machine: 'web-01' });
        expect(web.length).toBe(2);
    });

    it('filters by tick range', () => {
        const chain = createEvidenceChain();
        chain.append(1, 'command', null, makeData('early'));
        chain.append(5, 'command', null, makeData('mid'));
        chain.append(10, 'command', null, makeData('late'));

        const mid = chain.getBlocks({ tickRange: [3, 7] });
        expect(mid.length).toBe(1);
        expect(mid[0]!.data.summary).toBe('mid');
    });

    it('filters by search text in summary', () => {
        const chain = createEvidenceChain();
        chain.append(1, 'command', null, makeData('ls -la /tmp'));
        chain.append(2, 'command', null, makeData('cat /etc/passwd'));
        chain.append(3, 'command', null, makeData('whoami'));

        const found = chain.getBlocks({ search: 'passwd' });
        expect(found.length).toBe(1);
    });

    it('filters by search text in rawInput', () => {
        const chain = createEvidenceChain();
        chain.append(1, 'command', null, makeData('executed command', 'nmap -sV 10.0.0.1'));
        chain.append(2, 'command', null, makeData('executed command', 'ping 8.8.8.8'));

        const found = chain.getBlocks({ search: 'nmap' });
        expect(found.length).toBe(1);
    });

    it('respects filter limit', () => {
        const chain = createEvidenceChain();
        for (let i = 0; i < 10; i++) {
            chain.append(i, 'command', null, makeData(`cmd-${i}`));
        }

        const limited = chain.getBlocks({ limit: 3 });
        expect(limited.length).toBe(3);
    });

    it('exports complete chain', () => {
        const chain = createEvidenceChain();
        chain.append(1, 'command', 'web-01', makeData('ls'));
        chain.append(2, 'auth', 'web-01', makeData('login'));

        const exported = chain.export(makeSession());
        expect(exported.version).toBe('1.0');
        expect(exported.session.sessionId).toBe('sess-001');
        expect(exported.blocks.length).toBe(2);
        expect(exported.exportHash).toBeTruthy();
    });

    it('export hash is deterministic for same data', () => {
        const chain = createEvidenceChain();
        chain.append(1, 'command', null, makeData('test'));

        const session = makeSession();
        const e1 = chain.export(session);
        const e2 = chain.export(session);
        expect(e1.exportHash).toBe(e2.exportHash);
    });

    it('fires onBlock handler', () => {
        const chain = createEvidenceChain();
        const received: string[] = [];
        chain.onBlock(block => received.push(block.data.summary));

        chain.append(1, 'command', null, makeData('first'));
        chain.append(2, 'command', null, makeData('second'));

        expect(received).toEqual(['first', 'second']);
    });

    it('unsubscribes onBlock handler', () => {
        const chain = createEvidenceChain();
        const received: string[] = [];
        const unsub = chain.onBlock(block => received.push(block.data.summary));

        chain.append(1, 'command', null, makeData('first'));
        unsub();
        chain.append(2, 'command', null, makeData('second'));

        expect(received).toEqual(['first']);
    });

    it('supports annotations', () => {
        const chain = createEvidenceChain();
        const block = chain.append(1, 'command', null, makeData('test'), 'This is important');
        expect(block.annotation).toBe('This is important');
    });

    it('null annotation by default', () => {
        const chain = createEvidenceChain();
        const block = chain.append(1, 'command', null, makeData('test'));
        expect(block.annotation).toBeNull();
    });

    it('null machine is valid', () => {
        const chain = createEvidenceChain();
        const block = chain.append(1, 'system', null, makeData('simulation started'));
        expect(block.machine).toBeNull();
    });

    it('clears the chain', () => {
        const chain = createEvidenceChain();
        chain.append(1, 'command', null, makeData('test'));
        chain.append(2, 'command', null, makeData('test2'));

        chain.clear();
        expect(chain.getLength()).toBe(0);
        expect(chain.getLatest()).toBeNull();
    });

    it('chain restarts cleanly after clear', () => {
        const chain = createEvidenceChain();
        chain.append(1, 'command', null, makeData('before'));
        chain.clear();

        const block = chain.append(1, 'command', null, makeData('after'));
        expect(block.seq).toBe(0);
        expect(block.prevHash).toBe('0');
    });

    it('handles many blocks without breaking chain', () => {
        const chain = createEvidenceChain();
        for (let i = 0; i < 100; i++) {
            chain.append(i, 'command', null, makeData(`cmd-${i}`));
        }

        expect(chain.getLength()).toBe(100);
        expect(chain.verify().valid).toBe(true);
    });

    it('different data produces different hashes', () => {
        const chain1 = createEvidenceChain();
        const chain2 = createEvidenceChain();

        const b1 = chain1.append(1, 'command', null, makeData('ls'));
        const b2 = chain2.append(1, 'command', null, makeData('pwd'));

        expect(b1.hash).not.toBe(b2.hash);
    });
});
