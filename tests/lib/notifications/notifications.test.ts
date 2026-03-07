/**
 * VARIANT — Notification Engine tests
 */
import { describe, it, expect } from 'vitest';
import { createNotificationEngine } from '../../../src/lib/notifications/notification-engine';
import type { NotificationTemplate, Notification } from '../../../src/lib/notifications/types';

function makeTemplate(overrides?: Partial<NotificationTemplate>): NotificationTemplate {
    return {
        category: 'security',
        priority: 'medium',
        title: 'Test Notification',
        body: 'Something happened.',
        icon: 'alert',
        machine: null,
        action: null,
        lifetimeTicks: 0,
        group: null,
        ...overrides,
    };
}

describe('NotificationEngine', () => {
    it('pushes notifications and retrieves active', () => {
        const engine = createNotificationEngine();
        engine.push(makeTemplate({ title: 'Alert 1' }), 1);
        engine.push(makeTemplate({ title: 'Alert 2' }), 2);

        const active = engine.getActive();
        expect(active.length).toBe(2);
    });

    it('assigns unique IDs', () => {
        const engine = createNotificationEngine();
        const n1 = engine.push(makeTemplate(), 1);
        const n2 = engine.push(makeTemplate(), 2);
        expect(n1.id).not.toBe(n2.id);
    });

    it('acknowledges a notification', () => {
        const engine = createNotificationEngine();
        const notif = engine.push(makeTemplate(), 1);

        expect(engine.getUnacknowledgedCount()).toBe(1);
        engine.acknowledge(notif.id);
        expect(engine.getUnacknowledgedCount()).toBe(0);
    });

    it('acknowledges all notifications', () => {
        const engine = createNotificationEngine();
        engine.push(makeTemplate(), 1);
        engine.push(makeTemplate(), 2);

        expect(engine.getUnacknowledgedCount()).toBe(2);
        engine.acknowledgeAll();
        expect(engine.getUnacknowledgedCount()).toBe(0);
    });

    it('dismisses a notification', () => {
        const engine = createNotificationEngine();
        const notif = engine.push(makeTemplate(), 1);

        expect(engine.dismiss(notif.id)).toBe(true);
        expect(engine.getActive().length).toBe(0);
        // Should be in history
        expect(engine.getHistory().length).toBe(1);
    });

    it('auto-dismisses expired notifications on tick', () => {
        const engine = createNotificationEngine();
        engine.push(makeTemplate({ lifetimeTicks: 5 }), 10);

        const dismissed = engine.tick(14);
        expect(dismissed.length).toBe(0); // Only 4 ticks elapsed

        const dismissed2 = engine.tick(15);
        expect(dismissed2.length).toBe(1);
        expect(engine.getActive().length).toBe(0);
    });

    it('filters by category', () => {
        const engine = createNotificationEngine();
        engine.push(makeTemplate({ category: 'security' }), 1);
        engine.push(makeTemplate({ category: 'email' }), 2);
        engine.push(makeTemplate({ category: 'security' }), 3);

        expect(engine.getByCategory('security').length).toBe(2);
        expect(engine.getByCategory('email').length).toBe(1);
    });

    it('processes events through rules', () => {
        const engine = createNotificationEngine();
        engine.addRule({
            id: 'login-alert',
            eventTypes: ['auth:login'],
            prefixMatch: false,
            generate: (_event, _tick) => ({
                category: 'security',
                priority: 'high',
                title: 'Login Attempt',
                body: 'Someone tried to log in.',
                icon: 'lock',
                machine: null,
                action: null,
                lifetimeTicks: 30,
                group: null,
            }),
        });

        const generated = engine.processEvent({ user: 'admin' }, 'auth:login', 5);
        expect(generated.length).toBe(1);
        expect(generated[0]!.title).toBe('Login Attempt');
    });

    it('processes events with prefix matching', () => {
        const engine = createNotificationEngine();
        engine.addRule({
            id: 'auth-alert',
            eventTypes: ['auth:'],
            prefixMatch: true,
            generate: () => makeTemplate({ title: 'Auth Event' }),
        });

        const generated1 = engine.processEvent({}, 'auth:login', 1);
        expect(generated1.length).toBe(1);

        const generated2 = engine.processEvent({}, 'auth:escalate', 2);
        expect(generated2.length).toBe(1);

        const generated3 = engine.processEvent({}, 'net:connect', 3);
        expect(generated3.length).toBe(0);
    });

    it('collapses grouped notifications', () => {
        const engine = createNotificationEngine();
        engine.push(makeTemplate({ title: 'Alert 1', group: 'login-group' }), 1);
        engine.push(makeTemplate({ title: 'Alert 2', group: 'login-group' }), 2);

        // Should be collapsed into one
        expect(engine.getActive().length).toBe(1);
        expect(engine.getActive()[0]!.title).toBe('Alert 2');
    });

    it('fires notification handlers', () => {
        const engine = createNotificationEngine();
        const received: Notification[] = [];
        engine.onNotification(n => received.push(n));

        engine.push(makeTemplate({ title: 'Test' }), 1);
        expect(received.length).toBe(1);
        expect(received[0]!.title).toBe('Test');
    });

    it('fires dismiss handlers', () => {
        const engine = createNotificationEngine();
        const dismissed: string[] = [];
        engine.onDismiss(id => dismissed.push(id));

        const notif = engine.push(makeTemplate(), 1);
        engine.dismiss(notif.id);
        expect(dismissed.length).toBe(1);
    });

    it('removes rules', () => {
        const engine = createNotificationEngine();
        engine.addRule({
            id: 'rule-1',
            eventTypes: ['auth:login'],
            prefixMatch: false,
            generate: () => makeTemplate(),
        });

        engine.removeRule('rule-1');
        const generated = engine.processEvent({}, 'auth:login', 1);
        expect(generated.length).toBe(0);
    });

    it('clears all state', () => {
        const engine = createNotificationEngine();
        engine.push(makeTemplate(), 1);
        engine.push(makeTemplate(), 2);

        engine.clear();
        expect(engine.getActive().length).toBe(0);
        expect(engine.getHistory().length).toBe(0);
    });
});
