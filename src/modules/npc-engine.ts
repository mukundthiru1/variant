/**
 * VARIANT — NPC Engine Module
 *
 * Drives NPC behavior during simulation. NPCs are defined in WorldSpec
 * and produce scheduled, recurring, and reactive actions that appear
 * in logs, process lists, and the event bus.
 *
 * EXTENSIBILITY:
 *   - NPCs defined via WorldSpec (declarative)
 *   - NPC templates registered via NPCTemplateRegistry
 *   - Custom NPC actions via NPCCustomAction
 *   - Reactive behaviors via NPCReaction (trigger → action)
 *
 * SWAPPABILITY: Implements Module interface. Replace this file.
 */

import type { Module, SimulationContext, Capability } from '../core/modules';
import type { Unsubscribe, EventBus } from '../core/events';
import type { NPCDefinition, NPCActionType, NPCReaction } from '../lib/npc/types';

// ── Module ID ──────────────────────────────────────────────

const MODULE_ID = 'npc-engine';
const MODULE_VERSION = '1.0.0';

// ── Config ────────────────────────────────────────────────

export interface NPCEngineConfig {
    /** NPC definitions to load. */
    readonly npcs?: readonly NPCDefinition[];
}

// ── Action Execution ───────────────────────────────────────

function executeNPCAction(
    npc: NPCDefinition,
    action: NPCActionType,
    events: EventBus,
): void {
    switch (action.kind) {
        case 'login':
            events.emit({
                type: 'auth:login',
                user: npc.username,
                machine: npc.machine,
                service: action.method,
                success: action.success,
                timestamp: Date.now(),
            });
            // Generate multiple attempts for failed brute-force
            if (!action.success && action.attempts !== undefined && action.attempts > 1) {
                for (let i = 1; i < action.attempts; i++) {
                    events.emit({
                        type: 'auth:login',
                        user: npc.username,
                        machine: npc.machine,
                        service: action.method,
                        success: false,
                        timestamp: Date.now() + i,
                    });
                }
            }
            break;

        case 'logout':
            events.emit({
                type: 'custom:npc-logout',
                data: { npcId: npc.id, machine: npc.machine, user: npc.username },
                timestamp: Date.now(),
            });
            break;

        case 'command':
            events.emit({
                type: 'fs:exec',
                machine: npc.machine,
                path: action.command.split(' ')[0] ?? action.command,
                args: action.command.split(' ').slice(1),
                user: npc.username,
                timestamp: Date.now(),
            });
            break;

        case 'file-modify':
            events.emit({
                type: 'fs:write',
                machine: npc.machine,
                path: action.path,
                user: npc.username,
                timestamp: Date.now(),
            });
            break;

        case 'log':
            events.emit({
                type: 'custom:npc-log',
                data: {
                    npcId: npc.id,
                    machine: npc.machine,
                    logFile: action.logFile,
                    message: action.message,
                },
                timestamp: Date.now(),
            });
            break;

        case 'alert':
            events.emit({
                type: 'sim:alert',
                source: `npc:${npc.id}`,
                message: `[${action.severity.toUpperCase()}] ${action.message}`,
                timestamp: Date.now(),
            });
            break;

        case 'attack':
            events.emit({
                type: 'custom:npc-attack',
                data: {
                    npcId: npc.id,
                    attackType: action.attackType,
                    target: action.target,
                    logEntries: action.logEntries,
                },
                timestamp: Date.now(),
            });
            // If attack has a success event, emit it
            if (action.successEvent !== undefined) {
                events.emit({
                    type: 'defense:breach',
                    machine: action.target,
                    vector: action.attackType,
                    attacker: npc.username,
                    timestamp: Date.now(),
                });
            }
            break;

        case 'send-email':
            events.emit({
                type: 'custom:npc-email',
                data: {
                    npcId: npc.id,
                    from: action.from,
                    to: action.to,
                    subject: action.subject,
                    body: action.body,
                    malicious: action.malicious ?? false,
                },
                timestamp: Date.now(),
            });
            break;

        case 'network':
            events.emit({
                type: 'net:connect',
                host: action.target,
                port: action.port,
                source: npc.machine,
                protocol: action.protocol,
                timestamp: Date.now(),
            });
            break;

        case 'custom':
            events.emit({
                type: `custom:npc-${action.action}`,
                data: { npcId: npc.id, params: action.params },
                timestamp: Date.now(),
            });
            break;
    }
}

// ── Factory ────────────────────────────────────────────────

export function createNPCEngine(engineConfig?: NPCEngineConfig): Module {
    const cfg = engineConfig ?? {};
    const unsubscribers: Unsubscribe[] = [];
    let npcs: NPCDefinition[] = [];

    // Track scheduled actions that have fired
    const firedScheduled = new Set<string>(); // `${npcId}:${tick}`
    // Track recurring action next fire ticks
    const recurringNext = new Map<string, number>(); // `${npcId}:${idx}` → nextTick
    // Track one-shot reactions
    const firedReactions = new Set<string>(); // `${npcId}:${idx}`

    const module: Module = {
        id: MODULE_ID,
        type: 'actor',
        version: MODULE_VERSION,
        description: 'NPC engine — drives non-player character behavior via scheduled, recurring, and reactive actions',

        provides: [
            { name: 'npc' },
            { name: 'npc-behavior' },
        ] as readonly Capability[],
        requires: [] as readonly Capability[],

        init(context: SimulationContext): void {
            firedScheduled.clear();
            recurringNext.clear();
            firedReactions.clear();

            // Load NPCs from config
            npcs = [...(cfg.npcs ?? [])];

            // Also load NPCs from WorldSpec if present
            const worldNPCs = (context.world as { npcs?: readonly NPCDefinition[] }).npcs;
            if (worldNPCs !== undefined) {
                npcs.push(...worldNPCs);
            }

            // Set up reactive behaviors
            for (let npcIdx = 0; npcIdx < npcs.length; npcIdx++) {
                const npc = npcs[npcIdx];
                if (npc === undefined || npc.reactions === undefined) continue;

                for (let rIdx = 0; rIdx < npc.reactions.length; rIdx++) {
                    const reaction = npc.reactions[rIdx];
                    if (reaction === undefined) continue;

                    setupReaction(npc, npcIdx, rIdx, reaction, context.events);
                }
            }
        },

        onTick(tick: number, context: SimulationContext): void {
            for (let npcIdx = 0; npcIdx < npcs.length; npcIdx++) {
                const npc = npcs[npcIdx];
                if (npc === undefined) continue;

                // Process scheduled actions
                for (const scheduled of npc.schedule) {
                    if (scheduled.tick !== tick) continue;
                    const key = `${npc.id}:${tick}`;
                    if (firedScheduled.has(key)) continue;
                    firedScheduled.add(key);
                    executeNPCAction(npc, scheduled.type, context.events);
                }

                // Process recurring actions
                if (npc.recurring !== undefined) {
                    for (let rIdx = 0; rIdx < npc.recurring.length; rIdx++) {
                        const recurring = npc.recurring[rIdx];
                        if (recurring === undefined) continue;

                        const key = `${npc.id}:recurring:${rIdx}`;
                        const startTick = recurring.startTick ?? 0;
                        const stopTick = recurring.stopTick ?? Infinity;

                        if (tick < startTick || tick > stopTick) continue;

                        // Initialize next fire tick
                        if (!recurringNext.has(key)) {
                            recurringNext.set(key, startTick);
                        }

                        const next = recurringNext.get(key);
                        if (next !== undefined && tick >= next) {
                            executeNPCAction(npc, recurring.action, context.events);
                            recurringNext.set(key, next + recurring.intervalTicks);
                        }
                    }
                }
            }
        },

        destroy(): void {
            for (const unsub of unsubscribers) {
                unsub();
            }
            unsubscribers.length = 0;
            npcs = [];
            firedScheduled.clear();
            recurringNext.clear();
            firedReactions.clear();
        },
    };

    function setupReaction(
        npc: NPCDefinition,
        _npcIdx: number,
        rIdx: number,
        reaction: NPCReaction,
        events: EventBus,
    ): void {
        const key = `${npc.id}:reaction:${rIdx}`;

        const handler = () => {
            if (reaction.frequency === 'once' && firedReactions.has(key)) return;
            firedReactions.add(key);

            const delay = reaction.delay ?? 0;
            if (delay > 0) {
                setTimeout(() => executeNPCAction(npc, reaction.action, events), delay);
            } else {
                executeNPCAction(npc, reaction.action, events);
            }
        };

        // Use prefix matching for event triggers
        const triggerType = reaction.trigger;
        if (triggerType.endsWith(':') || triggerType.endsWith('*')) {
            const prefix = triggerType.replace(/\*$/, '');
            const unsub = events.onPrefix(prefix, handler);
            unsubscribers.push(unsub);
        } else {
            const prefix = triggerType.split(':')[0];
            if (prefix !== undefined) {
                const unsub = events.onPrefix(`${prefix}:`, (event) => {
                    if (event.type === triggerType) {
                        handler();
                    }
                });
                unsubscribers.push(unsub);
            }
        }
    }

    return module;
}
