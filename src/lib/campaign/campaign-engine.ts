/**
 * VARIANT — Campaign Engine Implementation
 *
 * Multi-level story campaigns with branching, persistent state,
 * and narrative progression.
 *
 * SWAPPABILITY: Implements CampaignEngine. Replace this file.
 */

import type {
    CampaignEngine,
    CampaignDefinition,
    CampaignProgress,
    CampaignNode,
    CampaignEdge,
    StateRequirement,
    StateGrant,
} from './types';

function applyGrant(state: Record<string, unknown>, grant: StateGrant): void {
    switch (grant.operation) {
        case 'set':
            state[grant.key] = grant.value;
            break;
        case 'add': {
            const current = state[grant.key];
            if (typeof current === 'number' && typeof grant.value === 'number') {
                state[grant.key] = current + grant.value;
            }
            break;
        }
        case 'subtract': {
            const current = state[grant.key];
            if (typeof current === 'number' && typeof grant.value === 'number') {
                state[grant.key] = current - grant.value;
            }
            break;
        }
        case 'append': {
            const current = state[grant.key];
            if (Array.isArray(current)) {
                state[grant.key] = [...current, grant.value];
            } else {
                state[grant.key] = [grant.value];
            }
            break;
        }
        case 'remove': {
            const current = state[grant.key];
            if (Array.isArray(current)) {
                state[grant.key] = current.filter(v => v !== grant.value);
            }
            break;
        }
    }
}

function checkReq(state: Readonly<Record<string, unknown>>, req: StateRequirement): boolean {
    const value = state[req.key];
    switch (req.operator) {
        case '==': return value === req.value;
        case '!=': return value !== req.value;
        case '>': return typeof value === 'number' && typeof req.value === 'number' && value > req.value;
        case '<': return typeof value === 'number' && typeof req.value === 'number' && value < req.value;
        case '>=': return typeof value === 'number' && typeof req.value === 'number' && value >= req.value;
        case '<=': return typeof value === 'number' && typeof req.value === 'number' && value <= req.value;
        case 'contains': return Array.isArray(value) && value.includes(req.value);
    }
}

interface MutableProgress {
    campaignId: string;
    state: Record<string, unknown>;
    completedNodes: string[];
    currentNode: string;
    scores: Record<string, number>;
    totalScore: number;
    path: string[];
    completed: boolean;
    startedAt: string;
    lastPlayedAt: string;
}

const GRADE_ORDER: readonly string[] = ['F', 'D', 'C', 'C+', 'B', 'B+', 'A', 'A+', 'S'];

function gradeRank(grade: string): number {
    const idx = GRADE_ORDER.indexOf(grade);
    return idx >= 0 ? idx : 0;
}

export function createCampaignEngine(): CampaignEngine {
    const campaigns = new Map<string, CampaignDefinition>();
    const progress = new Map<string, MutableProgress>();

    function getNodeById(campaign: CampaignDefinition, nodeId: string): CampaignNode | null {
        return campaign.nodes.find(n => n.id === nodeId) ?? null;
    }

    function getOutEdges(campaign: CampaignDefinition, nodeId: string): readonly CampaignEdge[] {
        return campaign.edges.filter(e => e.from === nodeId);
    }

    function canTraverseEdge(edge: CampaignEdge, prog: MutableProgress): boolean {
        if (edge.condition === undefined) return true;
        switch (edge.condition.kind) {
            case 'always': return true;
            case 'score': return prog.totalScore >= edge.condition.minScore;
            case 'state': return prog.state[edge.condition.key] === edge.condition.value;
            case 'choice': return true; // choices are resolved via makeChoice
            case 'grade': {
                const currentGrade = deriveGrade(prog);
                return gradeRank(currentGrade) >= gradeRank(edge.condition.minGrade);
            }
        }
    }

    /** Derive a letter grade from the player's average score across completed nodes. */
    function deriveGrade(prog: MutableProgress): string {
        if (prog.completedNodes.length === 0) return 'F';
        const avg = prog.totalScore / prog.completedNodes.length;
        if (avg >= 97) return 'S';
        if (avg >= 93) return 'A+';
        if (avg >= 85) return 'A';
        if (avg >= 80) return 'B+';
        if (avg >= 70) return 'B';
        if (avg >= 65) return 'C+';
        if (avg >= 55) return 'C';
        if (avg >= 40) return 'D';
        return 'F';
    }

    function canAccessNode(node: CampaignNode, prog: MutableProgress): boolean {
        if (node.minScore !== undefined && prog.totalScore < node.minScore) return false;
        if (node.requires !== undefined) {
            for (const req of node.requires) {
                if (!checkReq(prog.state, req)) return false;
            }
        }
        return true;
    }

    function toProgress(p: MutableProgress): CampaignProgress {
        return {
            campaignId: p.campaignId,
            state: { ...p.state },
            completedNodes: [...p.completedNodes],
            currentNode: p.currentNode,
            scores: { ...p.scores },
            totalScore: p.totalScore,
            path: [...p.path],
            completed: p.completed,
            startedAt: p.startedAt,
            lastPlayedAt: p.lastPlayedAt,
        };
    }

    return {
        loadCampaign(campaign: CampaignDefinition): void {
            campaigns.set(campaign.id, campaign);
        },

        getCampaign(id: string): CampaignDefinition | null {
            return campaigns.get(id) ?? null;
        },

        listCampaigns(): readonly CampaignDefinition[] {
            return [...campaigns.values()];
        },

        start(campaignId: string): CampaignProgress | null {
            const campaign = campaigns.get(campaignId);
            if (campaign === undefined) return null;

            const state: Record<string, unknown> = {};
            for (const key of campaign.persistentState) {
                state[key.key] = key.defaultValue;
            }

            const now = new Date().toISOString();
            const prog: MutableProgress = {
                campaignId,
                state,
                completedNodes: [],
                currentNode: campaign.startNode,
                scores: {},
                totalScore: 0,
                path: [campaign.startNode],
                completed: false,
                startedAt: now,
                lastPlayedAt: now,
            };

            progress.set(campaignId, prog);
            return toProgress(prog);
        },

        getProgress(campaignId: string): CampaignProgress | null {
            const prog = progress.get(campaignId);
            if (prog === undefined) return null;
            return toProgress(prog);
        },

        completeNode(campaignId: string, score: number, grants?: readonly StateGrant[]): readonly string[] {
            const campaign = campaigns.get(campaignId);
            const prog = progress.get(campaignId);
            if (campaign === undefined || prog === undefined) return [];

            const nodeId = prog.currentNode;
            if (!prog.completedNodes.includes(nodeId)) {
                prog.completedNodes.push(nodeId);
            }

            prog.scores[nodeId] = score;
            prog.totalScore += score;
            prog.lastPlayedAt = new Date().toISOString();

            // Apply node grants
            const node = getNodeById(campaign, nodeId);
            if (node?.grants !== undefined) {
                for (const grant of node.grants) {
                    applyGrant(prog.state, grant);
                }
            }

            // Apply additional grants
            if (grants !== undefined) {
                for (const grant of grants) {
                    applyGrant(prog.state, grant);
                }
            }

            // Check if we reached an end node
            if (campaign.endNodes.includes(nodeId)) {
                prog.completed = true;
                return [];
            }

            // Return available next nodes
            const outEdges = getOutEdges(campaign, nodeId);
            const available: string[] = [];
            for (const edge of outEdges) {
                if (!canTraverseEdge(edge, prog)) continue;
                const targetNode = getNodeById(campaign, edge.to);
                if (targetNode !== null && canAccessNode(targetNode, prog)) {
                    available.push(edge.to);
                }
            }

            return available;
        },

        makeChoice(campaignId: string, edgeId: string): string | null {
            const campaign = campaigns.get(campaignId);
            const prog = progress.get(campaignId);
            if (campaign === undefined || prog === undefined) return null;

            const edge = campaign.edges.find(e => e.id === edgeId);
            if (edge === undefined || edge.from !== prog.currentNode) return null;

            const targetNode = getNodeById(campaign, edge.to);
            if (targetNode === null) return null;

            prog.currentNode = edge.to;
            prog.path.push(edge.to);
            prog.lastPlayedAt = new Date().toISOString();

            return edge.to;
        },

        getAvailableNodes(campaignId: string): readonly CampaignNode[] {
            const campaign = campaigns.get(campaignId);
            const prog = progress.get(campaignId);
            if (campaign === undefined || prog === undefined) return [];

            const outEdges = getOutEdges(campaign, prog.currentNode);
            const nodes: CampaignNode[] = [];

            for (const edge of outEdges) {
                if (!canTraverseEdge(edge, prog)) continue;
                const node = getNodeById(campaign, edge.to);
                if (node !== null && canAccessNode(node, prog)) {
                    nodes.push(node);
                }
            }

            return nodes;
        },

        advanceTo(campaignId: string, nodeId: string): boolean {
            const campaign = campaigns.get(campaignId);
            const prog = progress.get(campaignId);
            if (campaign === undefined || prog === undefined) return false;

            // Check if nodeId is reachable
            const outEdges = getOutEdges(campaign, prog.currentNode);
            const reachable = outEdges.some(e => e.to === nodeId && canTraverseEdge(e, prog));
            if (!reachable) return false;

            const node = getNodeById(campaign, nodeId);
            if (node === null || !canAccessNode(node, prog)) return false;

            prog.currentNode = nodeId;
            prog.path.push(nodeId);
            prog.lastPlayedAt = new Date().toISOString();

            return true;
        },

        checkRequirement(campaignId: string, req: StateRequirement): boolean {
            const prog = progress.get(campaignId);
            if (prog === undefined) return false;
            return checkReq(prog.state, req);
        },

        getGraph(campaignId: string): { nodes: readonly CampaignNode[]; edges: readonly CampaignEdge[] } | null {
            const campaign = campaigns.get(campaignId);
            if (campaign === undefined) return null;
            return { nodes: campaign.nodes, edges: campaign.edges };
        },

        resetProgress(campaignId: string): boolean {
            return progress.delete(campaignId);
        },

        clear(): void {
            campaigns.clear();
            progress.clear();
        },
    };
}
