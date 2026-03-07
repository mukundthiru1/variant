/**
 * VARIANT — Notification System barrel export
 */
export type {
    Notification,
    NotificationCategory,
    NotificationPriority,
    NotificationAction,
    OpenLensAction,
    NavigateAction,
    RunCommandAction,
    CustomAction,
    NotificationRule,
    NotificationTemplate,
    NotificationEngine,
} from './types';

export { createNotificationEngine } from './notification-engine';
