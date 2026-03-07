import { useState, useCallback, useRef, useEffect } from 'react';

export type NotificationType = 'info' | 'success' | 'warning' | 'error' | 'alert';

export interface NotificationOptions {
    readonly timeout?: number;
    readonly actionLabel?: string;
    readonly onAction?: () => void;
}

export interface NotificationItem {
    readonly id: string;
    readonly type: NotificationType;
    readonly title: string;
    readonly message: string;
    readonly options?: NotificationOptions;
}

export interface NotificationContextValue {
    readonly notifications: readonly NotificationItem[];
    readonly addNotification: (type: NotificationType, title: string, message: string, options?: NotificationOptions) => string;
    readonly dismissNotification: (id: string) => void;
    readonly clearAll: () => void;
}

let nextNotifId = 0;

export function useNotifications(): NotificationContextValue {
    const [notifications, setNotifications] = useState<readonly NotificationItem[]>([]);
    const timeoutsRef = useRef<Map<string, number>>(new Map());

    const dismissNotification = useCallback((id: string) => {
        setNotifications((prev) => prev.filter((n) => n.id !== id));
        const timer = timeoutsRef.current.get(id);
        if (timer !== undefined) {
            clearTimeout(timer);
            timeoutsRef.current.delete(id);
        }
    }, []);

    const addNotification = useCallback((
        type: NotificationType,
        title: string,
        message: string,
        options?: NotificationOptions
    ): string => {
        const id = `notif-${Date.now()}-${nextNotifId++}`;

        setNotifications((prev) => {
            const base = { id, type, title, message } as const;
            const newNotif: NotificationItem = options === undefined
                ? base
                : { ...base, options };
            return [...prev, newNotif];
        });

        const timeout = options?.timeout ?? 5000;
        if (timeout > 0) {
            const timer = window.setTimeout(() => {
                dismissNotification(id);
            }, timeout);
            timeoutsRef.current.set(id, timer);
        }

        return id;
    }, [dismissNotification]);

    const clearAll = useCallback(() => {
        setNotifications([]);
        timeoutsRef.current.forEach((timer) => clearTimeout(timer));
        timeoutsRef.current.clear();
    }, []);

    useEffect(() => {
        const currentTimeouts = timeoutsRef.current;
        return () => {
            currentTimeouts.forEach((timer) => clearTimeout(timer));
        };
    }, []);

    return {
        notifications,
        addNotification,
        dismissNotification,
        clearAll,
    };
}
