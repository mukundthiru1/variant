/**
 * VARIANT — Campaign Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createCampaignEngine } from '../../../src/lib/campaign/campaign-engine';
import type {
    CampaignDefinition,
    StateGrant,
    StateRequirement,
} from '../../../src/lib/campaign/types';

function makeLinearCampaign(): CampaignDefinition {
    return {
        id: 'linear-campaign',
        title: 'Linear Campaign',
        description: 'A simple linear campaign',
        author: 'test',
        difficulty: 'fixed',
        estimatedMinutes: 30,
        nodes: [
            { id: 'start', type: 'level', title: 'Start', description: 'First level', levelId: 'level-1' },
            { id: 'middle', type: 'level', title: 'Middle', description: 'Second level', levelId: 'level-2' },
            { id: 'end', type: 'level', title: 'End', description: 'Final level', levelId: 'level-3' },
        ],
        edges: [
            { id: 'e1', from: 'start', to: 'middle', condition: { kind: 'always' } },
            { id: 'e2', from: 'middle', to: 'end', condition: { kind: 'always' } },
        ],
        startNode: 'start',
        endNodes: ['end'],
        persistentState: [
            { key: 'reputation', type: 'number', defaultValue: 0, description: 'Player reputation' },
            { key: 'items', type: 'string[]', defaultValue: [], description: 'Collected items' },
        ],
        tags: ['test', 'linear'],
    };
}

function makeBranchingCampaign(): CampaignDefinition {
    return {
        id: 'branching-campaign',
        title: 'Branching Campaign',
        description: 'A campaign with choices',
        author: 'test',
        difficulty: 'adaptive',
        estimatedMinutes: 60,
        nodes: [
            { id: 'start', type: 'level', title: 'Start', description: 'First level' },
            { id: 'choice', type: 'choice', title: 'Choose Path', description: 'Pick a side' },
            { id: 'path-a', type: 'level', title: 'Path A', description: 'Stealth path', minScore: 50 },
            { id: 'path-b', type: 'level', title: 'Path B', description: 'Loud path' },
            { id: 'end-good', type: 'level', title: 'Good End', description: 'Good ending' },
            { id: 'end-bad', type: 'level', title: 'Bad End', description: 'Bad ending' },
        ],
        edges: [
            { id: 'e1', from: 'start', to: 'choice', condition: { kind: 'always' } },
            { id: 'e-stealth', from: 'choice', to: 'path-a', condition: { kind: 'choice', choiceId: 'stealth' } },
            { id: 'e-loud', from: 'choice', to: 'path-b', condition: { kind: 'choice', choiceId: 'loud' } },
            { id: 'e3', from: 'path-a', to: 'end-good', condition: { kind: 'always' } },
            { id: 'e4', from: 'path-b', to: 'end-bad', condition: { kind: 'always' } },
        ],
        startNode: 'start',
        endNodes: ['end-good', 'end-bad'],
        persistentState: [
            { key: 'stealth', type: 'number', defaultValue: 0, description: 'Stealth score' },
        ],
        tags: ['test', 'branching'],
    };
}

describe('CampaignEngine', () => {
    // ── Campaign Loading ──────────────────────────────────────────

    it('loads and retrieves campaigns', () => {
        const engine = createCampaignEngine();
        const campaign = makeLinearCampaign();
        engine.loadCampaign(campaign);

        expect(engine.getCampaign('linear-campaign')).toEqual(campaign);
        expect(engine.getCampaign('nonexistent')).toBeNull();
    });

    it('lists all loaded campaigns', () => {
        const engine = createCampaignEngine();
        engine.loadCampaign(makeLinearCampaign());
        engine.loadCampaign(makeBranchingCampaign());

        expect(engine.listCampaigns().length).toBe(2);
    });

    // ── Starting Campaigns ────────────────────────────────────────

    it('starts a campaign and returns initial progress', () => {
        const engine = createCampaignEngine();
        engine.loadCampaign(makeLinearCampaign());

        const progress = engine.start('linear-campaign');
        expect(progress).not.toBeNull();
        expect(progress!.campaignId).toBe('linear-campaign');
        expect(progress!.currentNode).toBe('start');
        expect(progress!.completedNodes.length).toBe(0);
        expect(progress!.totalScore).toBe(0);
        expect(progress!.path).toEqual(['start']);
        expect(progress!.completed).toBe(false);
    });

    it('initializes persistent state with defaults', () => {
        const engine = createCampaignEngine();
        engine.loadCampaign(makeLinearCampaign());

        const progress = engine.start('linear-campaign');
        expect(progress!.state['reputation']).toBe(0);
        expect(progress!.state['items']).toEqual([]);
    });

    it('returns null when starting unknown campaign', () => {
        const engine = createCampaignEngine();
        expect(engine.start('nonexistent')).toBeNull();
    });

    // ── Node Completion ───────────────────────────────────────────

    it('completes a node and returns available next nodes', () => {
        const engine = createCampaignEngine();
        engine.loadCampaign(makeLinearCampaign());
        engine.start('linear-campaign');

        const next = engine.completeNode('linear-campaign', 80);
        expect(next).toContain('middle');
        expect(next.length).toBe(1);
    });

    it('tracks score across completions', () => {
        const engine = createCampaignEngine();
        engine.loadCampaign(makeLinearCampaign());
        engine.start('linear-campaign');

        engine.completeNode('linear-campaign', 80);
        engine.advanceTo('linear-campaign', 'middle');
        engine.completeNode('linear-campaign', 90);

        const progress = engine.getProgress('linear-campaign');
        expect(progress!.totalScore).toBe(170);
        expect(progress!.scores['start']).toBe(80);
        expect(progress!.scores['middle']).toBe(90);
    });

    it('marks campaign completed at end node', () => {
        const engine = createCampaignEngine();
        engine.loadCampaign(makeLinearCampaign());
        engine.start('linear-campaign');

        engine.completeNode('linear-campaign', 80);
        engine.advanceTo('linear-campaign', 'middle');
        engine.completeNode('linear-campaign', 90);
        engine.advanceTo('linear-campaign', 'end');

        const next = engine.completeNode('linear-campaign', 100);
        expect(next.length).toBe(0);

        const progress = engine.getProgress('linear-campaign');
        expect(progress!.completed).toBe(true);
    });

    it('applies node grants on completion', () => {
        const engine = createCampaignEngine();
        const campaign = makeLinearCampaign();
        const withGrants: CampaignDefinition = {
            ...campaign,
            nodes: [
                {
                    ...campaign.nodes[0]!,
                    grants: [{ key: 'reputation', operation: 'add', value: 10 }],
                },
                campaign.nodes[1]!,
                campaign.nodes[2]!,
            ],
        };
        engine.loadCampaign(withGrants);
        engine.start('linear-campaign');

        engine.completeNode('linear-campaign', 50);
        const progress = engine.getProgress('linear-campaign');
        expect(progress!.state['reputation']).toBe(10);
    });

    it('applies additional grants passed to completeNode', () => {
        const engine = createCampaignEngine();
        engine.loadCampaign(makeLinearCampaign());
        engine.start('linear-campaign');

        const grants: StateGrant[] = [
            { key: 'items', operation: 'append', value: 'key-card' },
        ];
        engine.completeNode('linear-campaign', 50, grants);

        const progress = engine.getProgress('linear-campaign');
        expect(progress!.state['items']).toEqual(['key-card']);
    });

    it('returns empty for unknown campaign on completeNode', () => {
        const engine = createCampaignEngine();
        expect(engine.completeNode('nonexistent', 50).length).toBe(0);
    });

    // ── State Operations ──────────────────────────────────────────

    it('set operation overwrites state', () => {
        const engine = createCampaignEngine();
        engine.loadCampaign(makeLinearCampaign());
        engine.start('linear-campaign');

        engine.completeNode('linear-campaign', 10, [
            { key: 'reputation', operation: 'set', value: 100 },
        ]);

        expect(engine.getProgress('linear-campaign')!.state['reputation']).toBe(100);
    });

    it('subtract operation decreases numeric state', () => {
        const engine = createCampaignEngine();
        engine.loadCampaign(makeLinearCampaign());
        engine.start('linear-campaign');

        engine.completeNode('linear-campaign', 10, [
            { key: 'reputation', operation: 'add', value: 50 },
        ]);
        engine.advanceTo('linear-campaign', 'middle');
        engine.completeNode('linear-campaign', 10, [
            { key: 'reputation', operation: 'subtract', value: 20 },
        ]);

        expect(engine.getProgress('linear-campaign')!.state['reputation']).toBe(30);
    });

    it('remove operation filters array state', () => {
        const engine = createCampaignEngine();
        engine.loadCampaign(makeLinearCampaign());
        engine.start('linear-campaign');

        engine.completeNode('linear-campaign', 10, [
            { key: 'items', operation: 'append', value: 'key-card' },
            { key: 'items', operation: 'append', value: 'badge' },
        ]);
        engine.advanceTo('linear-campaign', 'middle');
        engine.completeNode('linear-campaign', 10, [
            { key: 'items', operation: 'remove', value: 'key-card' },
        ]);

        expect(engine.getProgress('linear-campaign')!.state['items']).toEqual(['badge']);
    });

    // ── Choices and Branching ─────────────────────────────────────

    it('makeChoice advances to the target node', () => {
        const engine = createCampaignEngine();
        engine.loadCampaign(makeBranchingCampaign());
        engine.start('branching-campaign');

        engine.completeNode('branching-campaign', 60);
        engine.advanceTo('branching-campaign', 'choice');

        const result = engine.makeChoice('branching-campaign', 'e-stealth');
        expect(result).toBe('path-a');

        const progress = engine.getProgress('branching-campaign');
        expect(progress!.currentNode).toBe('path-a');
        expect(progress!.path).toContain('path-a');
    });

    it('makeChoice returns null for invalid edge', () => {
        const engine = createCampaignEngine();
        engine.loadCampaign(makeBranchingCampaign());
        engine.start('branching-campaign');

        expect(engine.makeChoice('branching-campaign', 'nonexistent')).toBeNull();
    });

    it('makeChoice returns null for edge from wrong node', () => {
        const engine = createCampaignEngine();
        engine.loadCampaign(makeBranchingCampaign());
        engine.start('branching-campaign');

        // e-stealth is from 'choice', not 'start'
        expect(engine.makeChoice('branching-campaign', 'e-stealth')).toBeNull();
    });

    // ── Score-Gated Nodes ─────────────────────────────────────────

    it('blocks nodes below minScore', () => {
        const engine = createCampaignEngine();
        engine.loadCampaign(makeBranchingCampaign());
        engine.start('branching-campaign');

        // Complete start with low score (path-a requires minScore 50)
        engine.completeNode('branching-campaign', 30);
        engine.advanceTo('branching-campaign', 'choice');

        const available = engine.getAvailableNodes('branching-campaign');
        const pathA = available.find(n => n.id === 'path-a');
        expect(pathA).toBeUndefined(); // blocked by minScore
    });

    it('allows nodes when minScore is met', () => {
        const engine = createCampaignEngine();
        engine.loadCampaign(makeBranchingCampaign());
        engine.start('branching-campaign');

        engine.completeNode('branching-campaign', 60);
        engine.advanceTo('branching-campaign', 'choice');

        const available = engine.getAvailableNodes('branching-campaign');
        const pathA = available.find(n => n.id === 'path-a');
        expect(pathA).toBeDefined();
    });

    // ── State Requirements ────────────────────────────────────────

    it('checkRequirement validates state', () => {
        const engine = createCampaignEngine();
        engine.loadCampaign(makeLinearCampaign());
        engine.start('linear-campaign');

        engine.completeNode('linear-campaign', 10, [
            { key: 'reputation', operation: 'set', value: 50 },
        ]);

        const req: StateRequirement = { key: 'reputation', operator: '>=', value: 25 };
        expect(engine.checkRequirement('linear-campaign', req)).toBe(true);

        const failReq: StateRequirement = { key: 'reputation', operator: '>=', value: 100 };
        expect(engine.checkRequirement('linear-campaign', failReq)).toBe(false);
    });

    it('checkRequirement returns false for unknown campaign', () => {
        const engine = createCampaignEngine();
        const req: StateRequirement = { key: 'x', operator: '==', value: 1 };
        expect(engine.checkRequirement('nonexistent', req)).toBe(false);
    });

    it('checkRequirement handles contains operator', () => {
        const engine = createCampaignEngine();
        engine.loadCampaign(makeLinearCampaign());
        engine.start('linear-campaign');

        engine.completeNode('linear-campaign', 10, [
            { key: 'items', operation: 'append', value: 'key-card' },
        ]);

        expect(engine.checkRequirement('linear-campaign', {
            key: 'items', operator: 'contains', value: 'key-card',
        })).toBe(true);

        expect(engine.checkRequirement('linear-campaign', {
            key: 'items', operator: 'contains', value: 'badge',
        })).toBe(false);
    });

    // ── advanceTo ─────────────────────────────────────────────────

    it('advanceTo moves to a reachable node', () => {
        const engine = createCampaignEngine();
        engine.loadCampaign(makeLinearCampaign());
        engine.start('linear-campaign');

        engine.completeNode('linear-campaign', 80);
        expect(engine.advanceTo('linear-campaign', 'middle')).toBe(true);

        const progress = engine.getProgress('linear-campaign');
        expect(progress!.currentNode).toBe('middle');
    });

    it('advanceTo fails for unreachable node', () => {
        const engine = createCampaignEngine();
        engine.loadCampaign(makeLinearCampaign());
        engine.start('linear-campaign');

        // Can't skip directly to end from start
        expect(engine.advanceTo('linear-campaign', 'end')).toBe(false);
    });

    it('advanceTo fails for unknown campaign', () => {
        const engine = createCampaignEngine();
        expect(engine.advanceTo('nonexistent', 'node')).toBe(false);
    });

    // ── Graph Access ──────────────────────────────────────────────

    it('getGraph returns campaign graph', () => {
        const engine = createCampaignEngine();
        engine.loadCampaign(makeLinearCampaign());

        const graph = engine.getGraph('linear-campaign');
        expect(graph).not.toBeNull();
        expect(graph!.nodes.length).toBe(3);
        expect(graph!.edges.length).toBe(2);
    });

    it('getGraph returns null for unknown campaign', () => {
        const engine = createCampaignEngine();
        expect(engine.getGraph('nonexistent')).toBeNull();
    });

    // ── Reset and Clear ───────────────────────────────────────────

    it('resetProgress removes progress but keeps campaign', () => {
        const engine = createCampaignEngine();
        engine.loadCampaign(makeLinearCampaign());
        engine.start('linear-campaign');

        expect(engine.resetProgress('linear-campaign')).toBe(true);
        expect(engine.getProgress('linear-campaign')).toBeNull();
        expect(engine.getCampaign('linear-campaign')).not.toBeNull();
    });

    it('resetProgress returns false for unknown campaign', () => {
        const engine = createCampaignEngine();
        expect(engine.resetProgress('nonexistent')).toBe(false);
    });

    it('clear removes everything', () => {
        const engine = createCampaignEngine();
        engine.loadCampaign(makeLinearCampaign());
        engine.start('linear-campaign');

        engine.clear();

        expect(engine.getCampaign('linear-campaign')).toBeNull();
        expect(engine.getProgress('linear-campaign')).toBeNull();
        expect(engine.listCampaigns().length).toBe(0);
    });

    // ── Progress Immutability ─────────────────────────────────────

    it('getProgress returns a snapshot (not a reference)', () => {
        const engine = createCampaignEngine();
        engine.loadCampaign(makeLinearCampaign());
        engine.start('linear-campaign');

        const p1 = engine.getProgress('linear-campaign')!;
        engine.completeNode('linear-campaign', 100);
        const p2 = engine.getProgress('linear-campaign')!;

        // p1 should not have been mutated
        expect(p1.totalScore).toBe(0);
        expect(p2.totalScore).toBe(100);
    });

    // ── Edge Conditions ───────────────────────────────────────────

    it('score-gated edge blocks traversal below threshold', () => {
        const engine = createCampaignEngine();
        const campaign: CampaignDefinition = {
            id: 'score-gate',
            title: 'Score Gate',
            description: 'Test',
            author: 'test',
            difficulty: 'fixed',
            estimatedMinutes: 10,
            nodes: [
                { id: 'start', type: 'level', title: 'Start', description: 'S' },
                { id: 'bonus', type: 'level', title: 'Bonus', description: 'B' },
                { id: 'end', type: 'level', title: 'End', description: 'E' },
            ],
            edges: [
                { id: 'e1', from: 'start', to: 'bonus', condition: { kind: 'score', minScore: 100 } },
                { id: 'e2', from: 'start', to: 'end', condition: { kind: 'always' } },
            ],
            startNode: 'start',
            endNodes: ['end', 'bonus'],
            persistentState: [],
            tags: [],
        };
        engine.loadCampaign(campaign);
        engine.start('score-gate');

        // Low score — bonus should be blocked
        const next = engine.completeNode('score-gate', 50);
        expect(next).toContain('end');
        expect(next).not.toContain('bonus');
    });

    it('score-gated edge allows traversal above threshold', () => {
        const engine = createCampaignEngine();
        const campaign: CampaignDefinition = {
            id: 'score-gate',
            title: 'Score Gate',
            description: 'Test',
            author: 'test',
            difficulty: 'fixed',
            estimatedMinutes: 10,
            nodes: [
                { id: 'start', type: 'level', title: 'Start', description: 'S' },
                { id: 'bonus', type: 'level', title: 'Bonus', description: 'B' },
            ],
            edges: [
                { id: 'e1', from: 'start', to: 'bonus', condition: { kind: 'score', minScore: 100 } },
            ],
            startNode: 'start',
            endNodes: ['bonus'],
            persistentState: [],
            tags: [],
        };
        engine.loadCampaign(campaign);
        engine.start('score-gate');

        const next = engine.completeNode('score-gate', 150);
        expect(next).toContain('bonus');
    });

    it('grade-gated edge blocks traversal below grade threshold', () => {
        const engine = createCampaignEngine();
        const campaign: CampaignDefinition = {
            id: 'grade-gate',
            title: 'Grade Gate',
            description: 'Test',
            author: 'test',
            difficulty: 'fixed',
            estimatedMinutes: 10,
            nodes: [
                { id: 'start', type: 'level', title: 'Start', description: 'S' },
                { id: 'bonus', type: 'level', title: 'Bonus', description: 'B' },
                { id: 'end', type: 'level', title: 'End', description: 'E' },
            ],
            edges: [
                { id: 'e1', from: 'start', to: 'bonus', condition: { kind: 'grade', minGrade: 'A' } },
                { id: 'e2', from: 'start', to: 'end', condition: { kind: 'always' } },
            ],
            startNode: 'start',
            endNodes: ['end', 'bonus'],
            persistentState: [],
            tags: [],
        };
        engine.loadCampaign(campaign);
        engine.start('grade-gate');

        // Score 50 on one node → avg 50 → grade D → below A
        const next = engine.completeNode('grade-gate', 50);
        expect(next).toContain('end');
        expect(next).not.toContain('bonus');
    });

    it('grade-gated edge allows traversal at or above grade threshold', () => {
        const engine = createCampaignEngine();
        const campaign: CampaignDefinition = {
            id: 'grade-gate',
            title: 'Grade Gate',
            description: 'Test',
            author: 'test',
            difficulty: 'fixed',
            estimatedMinutes: 10,
            nodes: [
                { id: 'start', type: 'level', title: 'Start', description: 'S' },
                { id: 'bonus', type: 'level', title: 'Bonus', description: 'B' },
            ],
            edges: [
                { id: 'e1', from: 'start', to: 'bonus', condition: { kind: 'grade', minGrade: 'B' } },
            ],
            startNode: 'start',
            endNodes: ['bonus'],
            persistentState: [],
            tags: [],
        };
        engine.loadCampaign(campaign);
        engine.start('grade-gate');

        // Score 85 on one node → avg 85 → grade A → above B
        const next = engine.completeNode('grade-gate', 85);
        expect(next).toContain('bonus');
    });
});
