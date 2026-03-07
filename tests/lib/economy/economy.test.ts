/**
 * VARIANT — Economy Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createEconomyEngine } from '../../../src/lib/economy/economy-engine';
import type { ResourceDefinition, ActionCost, RecurringFlow } from '../../../src/lib/economy/types';

function makeResource(overrides: Partial<ResourceDefinition> & { id: string }): ResourceDefinition {
    return {
        label: overrides.id,
        category: 'budget',
        initial: 1000,
        max: 2000,
        regenPerTick: 0,
        visible: true,
        unit: '$',
        onDepleted: null,
        ...overrides,
    };
}

function makeAction(overrides: Partial<ActionCost> & { actionId: string }): ActionCost {
    return {
        label: overrides.actionId,
        costs: {},
        cooldownTicks: 0,
        requireConfirmation: false,
        ...overrides,
    };
}

function makeFlow(overrides: Partial<RecurringFlow> & { id: string }): RecurringFlow {
    return {
        label: overrides.id,
        resourceId: 'budget',
        amount: -10,
        intervalTicks: 1,
        active: true,
        ...overrides,
    };
}

describe('EconomyEngine', () => {
    it('loads and retrieves resources', () => {
        const engine = createEconomyEngine();
        engine.loadResources([makeResource({ id: 'budget', initial: 500 })]);

        const res = engine.getResource('budget');
        expect(res).not.toBeNull();
        expect(res!.current).toBe(500);
        expect(res!.max).toBe(2000);
    });

    it('returns null for unknown resource', () => {
        const engine = createEconomyEngine();
        expect(engine.getResource('nonexistent')).toBeNull();
    });

    it('gets all resources', () => {
        const engine = createEconomyEngine();
        engine.loadResources([
            makeResource({ id: 'budget' }),
            makeResource({ id: 'staff' }),
        ]);
        expect(engine.getAllResources().length).toBe(2);
    });

    it('checks affordability', () => {
        const engine = createEconomyEngine();
        engine.loadResources([makeResource({ id: 'budget', initial: 100 })]);
        engine.loadActionCosts([
            makeAction({ actionId: 'cheap', costs: { budget: 50 } }),
            makeAction({ actionId: 'expensive', costs: { budget: 200 } }),
        ]);

        expect(engine.canAfford('cheap')).toBe(true);
        expect(engine.canAfford('expensive')).toBe(false);
        expect(engine.canAfford('nonexistent')).toBe(false);
    });

    it('spends resources on action', () => {
        const engine = createEconomyEngine();
        engine.loadResources([makeResource({ id: 'budget', initial: 100 })]);
        engine.loadActionCosts([makeAction({ actionId: 'scan', costs: { budget: 30 } })]);

        expect(engine.spend('scan', 1)).toBe(true);
        expect(engine.getResource('budget')!.current).toBe(70);
        expect(engine.getResource('budget')!.spent).toBe(30);
    });

    it('fails to spend when insufficient resources', () => {
        const engine = createEconomyEngine();
        engine.loadResources([makeResource({ id: 'budget', initial: 10 })]);
        engine.loadActionCosts([makeAction({ actionId: 'scan', costs: { budget: 50 } })]);

        expect(engine.spend('scan', 1)).toBe(false);
        expect(engine.getResource('budget')!.current).toBe(10);
    });

    it('applies action produces', () => {
        const engine = createEconomyEngine();
        engine.loadResources([
            makeResource({ id: 'budget', initial: 100 }),
            makeResource({ id: 'intel', initial: 0 }),
        ]);
        engine.loadActionCosts([makeAction({
            actionId: 'investigate',
            costs: { budget: 20 },
            produces: { intel: 5 },
        })]);

        engine.spend('investigate', 1);
        expect(engine.getResource('budget')!.current).toBe(80);
        expect(engine.getResource('intel')!.current).toBe(5);
    });

    it('respects cooldowns', () => {
        const engine = createEconomyEngine();
        engine.loadResources([makeResource({ id: 'budget', initial: 1000 })]);
        engine.loadActionCosts([makeAction({
            actionId: 'scan',
            costs: { budget: 10 },
            cooldownTicks: 5,
        })]);

        expect(engine.spend('scan', 1)).toBe(true);
        expect(engine.spend('scan', 3)).toBe(false); // still on cooldown
        expect(engine.spend('scan', 6)).toBe(true);  // cooldown expired
    });

    it('adjusts resources directly', () => {
        const engine = createEconomyEngine();
        engine.loadResources([makeResource({ id: 'rep', initial: 50, max: 100 })]);

        engine.adjust('rep', 20, 'bonus', 1);
        expect(engine.getResource('rep')!.current).toBe(70);
        expect(engine.getResource('rep')!.earned).toBe(20);

        engine.adjust('rep', -30, 'penalty', 2);
        expect(engine.getResource('rep')!.current).toBe(40);
        expect(engine.getResource('rep')!.spent).toBe(30);
    });

    it('clamps adjust to max', () => {
        const engine = createEconomyEngine();
        engine.loadResources([makeResource({ id: 'rep', initial: 90, max: 100 })]);

        engine.adjust('rep', 50, 'overflow', 1);
        expect(engine.getResource('rep')!.current).toBe(100);
    });

    it('clamps adjust to zero', () => {
        const engine = createEconomyEngine();
        engine.loadResources([makeResource({ id: 'rep', initial: 10 })]);

        engine.adjust('rep', -50, 'drain', 1);
        expect(engine.getResource('rep')!.current).toBe(0);
    });

    it('applies regeneration per tick', () => {
        const engine = createEconomyEngine();
        engine.loadResources([makeResource({ id: 'energy', initial: 50, max: 100, regenPerTick: 5 })]);

        engine.tick(1);
        expect(engine.getResource('energy')!.current).toBe(55);

        engine.tick(2);
        expect(engine.getResource('energy')!.current).toBe(60);
    });

    it('regen does not exceed max', () => {
        const engine = createEconomyEngine();
        engine.loadResources([makeResource({ id: 'energy', initial: 98, max: 100, regenPerTick: 5 })]);

        engine.tick(1);
        expect(engine.getResource('energy')!.current).toBe(100);
    });

    it('skips regen when at max', () => {
        const engine = createEconomyEngine();
        engine.loadResources([makeResource({ id: 'energy', initial: 100, max: 100, regenPerTick: 5 })]);

        const txs = engine.tick(1);
        expect(txs.length).toBe(0);
    });

    it('applies recurring flows', () => {
        const engine = createEconomyEngine();
        engine.loadResources([makeResource({ id: 'budget', initial: 100 })]);
        engine.loadRecurringFlows([makeFlow({ id: 'salary', resourceId: 'budget', amount: -10, intervalTicks: 1 })]);

        engine.tick(1);
        expect(engine.getResource('budget')!.current).toBe(90);

        engine.tick(2);
        expect(engine.getResource('budget')!.current).toBe(80);
    });

    it('recurring flow respects interval', () => {
        const engine = createEconomyEngine();
        engine.loadResources([makeResource({ id: 'budget', initial: 100 })]);
        engine.loadRecurringFlows([makeFlow({ id: 'rent', resourceId: 'budget', amount: -50, intervalTicks: 5 })]);

        engine.tick(1); // no effect (1 % 5 != 0)
        expect(engine.getResource('budget')!.current).toBe(100);

        engine.tick(5); // fires
        expect(engine.getResource('budget')!.current).toBe(50);

        engine.tick(10); // fires again
        expect(engine.getResource('budget')!.current).toBe(0);
    });

    it('inactive flows do not apply', () => {
        const engine = createEconomyEngine();
        engine.loadResources([makeResource({ id: 'budget', initial: 100 })]);
        engine.loadRecurringFlows([makeFlow({ id: 'salary', resourceId: 'budget', amount: -10, intervalTicks: 1, active: false })]);

        engine.tick(1);
        expect(engine.getResource('budget')!.current).toBe(100);
    });

    it('toggles flow active state', () => {
        const engine = createEconomyEngine();
        engine.loadResources([makeResource({ id: 'budget', initial: 100 })]);
        engine.loadRecurringFlows([makeFlow({ id: 'salary', resourceId: 'budget', amount: -10, intervalTicks: 1, active: false })]);

        engine.setFlowActive('salary', true);
        engine.tick(1);
        expect(engine.getResource('budget')!.current).toBe(90);

        engine.setFlowActive('salary', false);
        engine.tick(2);
        expect(engine.getResource('budget')!.current).toBe(90);
    });

    it('detects depletion', () => {
        const engine = createEconomyEngine();
        engine.loadResources([makeResource({ id: 'budget', initial: 10, onDepleted: { kind: 'game-over', reason: 'Bankrupt' } })]);

        engine.adjust('budget', -10, 'drain', 1);
        expect(engine.hasDepleted()).toBe(true);
    });

    it('fires depletion handler', () => {
        const engine = createEconomyEngine();
        engine.loadResources([makeResource({ id: 'budget', initial: 10, onDepleted: { kind: 'game-over', reason: 'Bankrupt' } })]);

        const depletions: string[] = [];
        engine.onDepleted((resId) => depletions.push(resId));

        engine.adjust('budget', -10, 'drain', 1);
        expect(depletions).toContain('budget');
    });

    it('records transactions', () => {
        const engine = createEconomyEngine();
        engine.loadResources([makeResource({ id: 'budget', initial: 100 })]);
        engine.loadActionCosts([makeAction({ actionId: 'scan', costs: { budget: 25 } })]);

        engine.spend('scan', 1);
        engine.adjust('budget', 10, 'bonus', 2);

        const txs = engine.getTransactions();
        expect(txs.length).toBe(2);
        expect(txs[0]!.amount).toBe(-25);
        expect(txs[1]!.amount).toBe(10);
    });

    it('filters transactions by resource', () => {
        const engine = createEconomyEngine();
        engine.loadResources([
            makeResource({ id: 'budget', initial: 100 }),
            makeResource({ id: 'staff', initial: 50 }),
        ]);

        engine.adjust('budget', -10, 'spend', 1);
        engine.adjust('staff', -5, 'assign', 1);
        engine.adjust('budget', -20, 'spend', 2);

        const budgetTxs = engine.getTransactions('budget');
        expect(budgetTxs.length).toBe(2);
    });

    it('fires transaction handler', () => {
        const engine = createEconomyEngine();
        engine.loadResources([makeResource({ id: 'budget', initial: 100 })]);

        const amounts: number[] = [];
        engine.onTransaction(tx => amounts.push(tx.amount));

        engine.adjust('budget', -30, 'spend', 1);
        expect(amounts).toEqual([-30]);
    });

    it('unsubscribes transaction handler', () => {
        const engine = createEconomyEngine();
        engine.loadResources([makeResource({ id: 'budget', initial: 100 })]);

        const amounts: number[] = [];
        const unsub = engine.onTransaction(tx => amounts.push(tx.amount));

        engine.adjust('budget', -10, 'a', 1);
        unsub();
        engine.adjust('budget', -10, 'b', 2);

        expect(amounts.length).toBe(1);
    });

    it('gets action cost', () => {
        const engine = createEconomyEngine();
        engine.loadActionCosts([makeAction({ actionId: 'scan', costs: { budget: 50 } })]);

        const cost = engine.getActionCost('scan');
        expect(cost).not.toBeNull();
        expect(cost!.costs['budget']).toBe(50);
        expect(engine.getActionCost('nonexistent')).toBeNull();
    });

    it('resets all state', () => {
        const engine = createEconomyEngine();
        engine.loadResources([makeResource({ id: 'budget', initial: 100 })]);
        engine.adjust('budget', -50, 'spend', 1);

        engine.reset();
        expect(engine.getResource('budget')).toBeNull();
        expect(engine.getAllResources().length).toBe(0);
        expect(engine.getTransactions().length).toBe(0);
    });

    it('multi-resource action requires all resources', () => {
        const engine = createEconomyEngine();
        engine.loadResources([
            makeResource({ id: 'budget', initial: 100 }),
            makeResource({ id: 'staff', initial: 2 }),
        ]);
        engine.loadActionCosts([makeAction({
            actionId: 'deploy-team',
            costs: { budget: 50, staff: 3 },
        })]);

        // Not enough staff
        expect(engine.canAfford('deploy-team')).toBe(false);
        expect(engine.spend('deploy-team', 1)).toBe(false);

        // Give more staff
        engine.adjust('staff', 5, 'hire', 1);
        expect(engine.canAfford('deploy-team')).toBe(true);
        expect(engine.spend('deploy-team', 2)).toBe(true);
    });

    it('getDepletionEvents returns pending depletions', () => {
        const engine = createEconomyEngine();
        engine.loadResources([makeResource({
            id: 'budget',
            initial: 5,
            onDepleted: { kind: 'game-over', reason: 'Out of funds' },
        })]);
        engine.loadRecurringFlows([makeFlow({ id: 'drain', resourceId: 'budget', amount: -10, intervalTicks: 1 })]);

        engine.tick(1);
        const events = engine.getDepletionEvents();
        expect(events.length).toBe(1);
        expect(events[0]!.kind).toBe('game-over');
    });
});
