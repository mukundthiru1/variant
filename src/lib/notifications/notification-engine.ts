/**
 * VARIANT — Notification Engine Implementation
 *
 * Processes events through rules to generate notifications,
 * manages notification lifecycle, and exposes query APIs.
 *
 * SWAPPABILITY: Implements NotificationEngine. Replace this file.
 */

import type {
    NotificationEngine,
    Notification,
    NotificationRule,
    NotificationTemplate,
} from './types';

let nextNotifId = 0;

export function createNotificationEngine(): NotificationEngine {
    const rules = new Map<string, NotificationRule>();
    const active = new Map<string, Notification>();
    const history: Notification[] = [];
    const notifHandlers = new Set<(n: Notification) => void>();
    const dismissHandlers = new Set<(id: string) => void>();

    function makeNotification(template: NotificationTemplate, tick: number): Notification {
        const id = `notif-${nextNotifId++}`;
        return {
            id,
            tick,
            timestamp: Date.now(),
            category: template.category,
            priority: template.priority,
            title: template.title,
            body: template.body,
            icon: template.icon,
            machine: template.machine,
            source: '',
            action: template.action,
            lifetimeTicks: template.lifetimeTicks,
            acknowledged: false,
            group: template.group,
        };
    }

    function emitNotification(notif: Notification): void {
        for (const handler of notifHandlers) {
            handler(notif);
        }
    }

    function emitDismiss(id: string): void {
        for (const handler of dismissHandlers) {
            handler(id);
        }
    }

    return {
        addRule(rule: NotificationRule): void {
            rules.set(rule.id, rule);
        },

        removeRule(ruleId: string): void {
            rules.delete(ruleId);
        },

        push(template: NotificationTemplate, tick: number): Notification {
            // Handle grouping — collapse into existing notification
            if (template.group !== null) {
                for (const [, existing] of active) {
                    if (existing.group === template.group && !existing.acknowledged) {
                        // Update existing grouped notification
                        const updated: Notification = {
                            ...existing,
                            title: template.title,
                            body: template.body,
                            tick,
                            timestamp: Date.now(),
                        };
                        active.set(existing.id, updated);
                        emitNotification(updated);
                        return updated;
                    }
                }
            }

            const notif = makeNotification(template, tick);
            active.set(notif.id, notif);
            history.push(notif);
            emitNotification(notif);
            return notif;
        },

        processEvent(event: unknown, eventType: string, tick: number): readonly Notification[] {
            const generated: Notification[] = [];

            for (const rule of rules.values()) {
                let matches = false;

                if (rule.prefixMatch) {
                    matches = rule.eventTypes.some(t => eventType.startsWith(t));
                } else {
                    matches = rule.eventTypes.includes(eventType);
                }

                if (!matches) continue;

                const template = rule.generate(event, tick);
                if (template === null) continue;

                const notif = this.push(template, tick);
                generated.push(notif);
            }

            return generated;
        },

        acknowledge(notificationId: string): boolean {
            const notif = active.get(notificationId);
            if (notif === undefined) return false;

            const updated: Notification = { ...notif, acknowledged: true };
            active.set(notificationId, updated);
            return true;
        },

        acknowledgeAll(): void {
            for (const [id, notif] of active) {
                active.set(id, { ...notif, acknowledged: true });
            }
        },

        dismiss(notificationId: string): boolean {
            if (!active.has(notificationId)) return false;
            active.delete(notificationId);
            emitDismiss(notificationId);
            return true;
        },

        getActive(): readonly Notification[] {
            return [...active.values()];
        },

        getByCategory(category: string): readonly Notification[] {
            return [...active.values()].filter(n => n.category === category);
        },

        getUnacknowledgedCount(): number {
            let count = 0;
            for (const n of active.values()) {
                if (!n.acknowledged) count++;
            }
            return count;
        },

        getHistory(): readonly Notification[] {
            return [...history];
        },

        tick(currentTick: number): readonly string[] {
            const dismissed: string[] = [];
            for (const [id, notif] of active) {
                if (notif.lifetimeTicks > 0 && (currentTick - notif.tick) >= notif.lifetimeTicks) {
                    active.delete(id);
                    dismissed.push(id);
                    emitDismiss(id);
                }
            }
            return dismissed;
        },

        onNotification(handler: (n: Notification) => void): () => void {
            notifHandlers.add(handler);
            return () => { notifHandlers.delete(handler); };
        },

        onDismiss(handler: (id: string) => void): () => void {
            dismissHandlers.add(handler);
            return () => { dismissHandlers.delete(handler); };
        },

        clear(): void {
            active.clear();
            history.length = 0;
            rules.clear();
            notifHandlers.clear();
            dismissHandlers.clear();
        },
    };
}
