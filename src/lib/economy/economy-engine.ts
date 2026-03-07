/**
 * VARIANT — Economy Engine Implementation
 *
 * Manages resource constraints: budget, staff, patch windows,
 * alert capacity, reputation. Every action has a cost.
 *
 * SWAPPABILITY: Implements EconomyEngine. Replace this file.
 */

import type {
    EconomyEngine,
    ResourceDefinition,
    ResourceState,
    ActionCost,
    RecurringFlow,
    ResourceTransaction,
    DepletionAction,
} from './types';

interface MutableResource {
    id: string;
    current: number;
    max: number;
    regenPerTick: number;
    spent: number;
    earned: number;
    depleted: boolean;
    onDepleted: DepletionAction | null;
}

interface MutableFlow {
    id: string;
    label: string;
    resourceId: string;
    amount: number;
    intervalTicks: number;
    active: boolean;
}

export function createEconomyEngine(): EconomyEngine {
    const resources = new Map<string, MutableResource>();
    const actionCosts = new Map<string, ActionCost>();
    const flows = new Map<string, MutableFlow>();
    const cooldowns = new Map<string, number>(); // actionId → tick when usable again
    const transactions: ResourceTransaction[] = [];
    const pendingDepletions: DepletionAction[] = [];

    const txHandlers = new Set<(tx: ResourceTransaction) => void>();
    const depletionHandlers = new Set<(resourceId: string, action: DepletionAction | null) => void>();

    function recordTransaction(tick: number, resourceId: string, amount: number, reason: string, actionId: string | null): ResourceTransaction {
        const res = resources.get(resourceId);
        const tx: ResourceTransaction = {
            tick,
            resourceId,
            amount,
            reason,
            actionId,
            balanceAfter: res !== undefined ? res.current : 0,
        };
        transactions.push(tx);
        for (const handler of txHandlers) {
            handler(tx);
        }
        return tx;
    }

    function checkDepletion(resourceId: string): void {
        const res = resources.get(resourceId);
        if (res === undefined) return;
        if (res.current <= 0 && !res.depleted) {
            res.depleted = true;
            if (res.onDepleted !== null) {
                pendingDepletions.push(res.onDepleted);
            }
            for (const handler of depletionHandlers) {
                handler(resourceId, res.onDepleted);
            }
        }
    }

    return {
        loadResources(definitions: readonly ResourceDefinition[]): void {
            for (const def of definitions) {
                resources.set(def.id, {
                    id: def.id,
                    current: def.initial,
                    max: def.max,
                    regenPerTick: def.regenPerTick,
                    spent: 0,
                    earned: 0,
                    depleted: false,
                    onDepleted: def.onDepleted,
                });
            }
        },

        loadActionCosts(costs: readonly ActionCost[]): void {
            for (const cost of costs) {
                actionCosts.set(cost.actionId, cost);
            }
        },

        loadRecurringFlows(flowDefs: readonly RecurringFlow[]): void {
            for (const flow of flowDefs) {
                flows.set(flow.id, {
                    id: flow.id,
                    label: flow.label,
                    resourceId: flow.resourceId,
                    amount: flow.amount,
                    intervalTicks: flow.intervalTicks,
                    active: flow.active,
                });
            }
        },

        getResource(id: string): ResourceState | null {
            const res = resources.get(id);
            if (res === undefined) return null;
            return {
                id: res.id,
                current: res.current,
                max: res.max,
                spent: res.spent,
                earned: res.earned,
                depleted: res.depleted,
            };
        },

        getAllResources(): readonly ResourceState[] {
            return [...resources.values()].map(res => ({
                id: res.id,
                current: res.current,
                max: res.max,
                spent: res.spent,
                earned: res.earned,
                depleted: res.depleted,
            }));
        },

        canAfford(actionId: string): boolean {
            const cost = actionCosts.get(actionId);
            if (cost === undefined) return false;

            for (const [resId, amount] of Object.entries(cost.costs)) {
                const res = resources.get(resId);
                if (res === undefined || res.current < amount) return false;
            }

            return true;
        },

        getActionCost(actionId: string): ActionCost | null {
            return actionCosts.get(actionId) ?? null;
        },

        spend(actionId: string, tick: number): boolean {
            const cost = actionCosts.get(actionId);
            if (cost === undefined) return false;

            // Check cooldown
            const cooldownUntil = cooldowns.get(actionId);
            if (cooldownUntil !== undefined && tick < cooldownUntil) return false;

            // Check affordability
            for (const [resId, amount] of Object.entries(cost.costs)) {
                const res = resources.get(resId);
                if (res === undefined || res.current < amount) return false;
            }

            // Deduct costs
            for (const [resId, amount] of Object.entries(cost.costs)) {
                const res = resources.get(resId)!;
                res.current = Math.max(0, res.current - amount);
                res.spent += amount;
                recordTransaction(tick, resId, -amount, `Action: ${cost.label}`, actionId);
                checkDepletion(resId);
            }

            // Apply produces
            if (cost.produces !== undefined) {
                for (const [resId, amount] of Object.entries(cost.produces)) {
                    const res = resources.get(resId);
                    if (res !== undefined) {
                        res.current = Math.min(res.max, res.current + amount);
                        res.earned += amount;
                        recordTransaction(tick, resId, amount, `Produced by: ${cost.label}`, actionId);
                    }
                }
            }

            // Set cooldown
            if (cost.cooldownTicks > 0) {
                cooldowns.set(actionId, tick + cost.cooldownTicks);
            }

            return true;
        },

        adjust(resourceId: string, amount: number, reason: string, tick: number): number {
            const res = resources.get(resourceId);
            if (res === undefined) return 0;

            const oldValue = res.current;
            res.current = Math.max(0, Math.min(res.max, res.current + amount));

            if (amount > 0) {
                res.earned += amount;
            } else {
                res.spent += Math.abs(amount);
            }

            recordTransaction(tick, resourceId, amount, reason, null);

            if (res.current <= 0 && oldValue > 0) {
                checkDepletion(resourceId);
            }

            return res.current;
        },

        tick(currentTick: number): readonly ResourceTransaction[] {
            const tickTxs: ResourceTransaction[] = [];
            pendingDepletions.length = 0;

            // Apply regeneration
            for (const res of resources.values()) {
                if (res.regenPerTick > 0 && res.current < res.max) {
                    const oldCurrent = res.current;
                    res.current = Math.min(res.max, res.current + res.regenPerTick);
                    const gained = res.current - oldCurrent;
                    if (gained > 0) {
                        res.earned += gained;
                        const tx = recordTransaction(currentTick, res.id, gained, 'Regeneration', null);
                        tickTxs.push(tx);
                    }
                }
            }

            // Apply recurring flows
            for (const flow of flows.values()) {
                if (!flow.active) continue;
                if (flow.intervalTicks <= 0) continue;
                if (currentTick % flow.intervalTicks !== 0) continue;

                const res = resources.get(flow.resourceId);
                if (res === undefined) continue;

                const oldCurrent = res.current;
                res.current = Math.max(0, Math.min(res.max, res.current + flow.amount));
                const delta = res.current - oldCurrent;

                if (delta !== 0) {
                    if (delta > 0) res.earned += delta;
                    else res.spent += Math.abs(delta);

                    const tx = recordTransaction(currentTick, flow.resourceId, delta, `Flow: ${flow.label}`, null);
                    tickTxs.push(tx);

                    if (res.current <= 0 && oldCurrent > 0) {
                        checkDepletion(flow.resourceId);
                    }
                }
            }

            return tickTxs;
        },

        getTransactions(resourceId?: string): readonly ResourceTransaction[] {
            if (resourceId === undefined) return [...transactions];
            return transactions.filter(tx => tx.resourceId === resourceId);
        },

        hasDepleted(): boolean {
            for (const res of resources.values()) {
                if (res.depleted) return true;
            }
            return false;
        },

        getDepletionEvents(): readonly DepletionAction[] {
            return [...pendingDepletions];
        },

        setFlowActive(flowId: string, active: boolean): boolean {
            const flow = flows.get(flowId);
            if (flow === undefined) return false;
            flow.active = active;
            return true;
        },

        onTransaction(handler: (tx: ResourceTransaction) => void): () => void {
            txHandlers.add(handler);
            return () => { txHandlers.delete(handler); };
        },

        onDepleted(handler: (resourceId: string, action: DepletionAction | null) => void): () => void {
            depletionHandlers.add(handler);
            return () => { depletionHandlers.delete(handler); };
        },

        reset(): void {
            resources.clear();
            actionCosts.clear();
            flows.clear();
            cooldowns.clear();
            transactions.length = 0;
            pendingDepletions.length = 0;
            txHandlers.clear();
            depletionHandlers.clear();
        },
    };
}
