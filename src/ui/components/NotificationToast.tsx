import { useEffect, useState } from 'react';
import type { CSSProperties } from 'react';
import type { NotificationItem, NotificationType } from '../hooks/useNotifications';

export interface NotificationToastProps {
    readonly notifications: readonly NotificationItem[];
    readonly onDismiss: (id: string) => void;
}

const colors: Record<NotificationType, string> = {
    info: '#00aaff',
    success: '#3DA67A',
    warning: '#ffb86c',
    error: '#ff5555',
    alert: '#bd93f9',
};

const icons: Record<NotificationType, string> = {
    info: '\u2139', // ℹ
    success: '\u2713', // ✓
    warning: '\u26A0', // ⚠
    error: '\u2715', // ✕
    alert: '\u0021', // !
};

export function NotificationToast({ notifications, onDismiss }: NotificationToastProps): JSX.Element {
    const visible = notifications.slice(-5);
    
    return (
        <div style={{
            position: 'fixed',
            bottom: '24px',
            right: '24px',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
            zIndex: 9999,
            pointerEvents: 'none',
        }}>
            {visible.map((notif) => (
                <ToastItem 
                    key={notif.id} 
                    notif={notif} 
                    onDismiss={() => { onDismiss(notif.id); }} 
                />
            ))}
        </div>
    );
}

function ToastItem({ notif, onDismiss }: { readonly notif: NotificationItem; readonly onDismiss: () => void }): JSX.Element {
    const [mounted, setMounted] = useState(false);
    
    useEffect(() => {
        const raf = requestAnimationFrame(() => { setMounted(true); });
        return () => { cancelAnimationFrame(raf); };
    }, []);

    const style: CSSProperties = {
        background: '#0a0e14',
        border: '1px solid #21262d',
        borderLeft: `4px solid ${colors[notif.type]}`,
        borderRadius: '4px',
        padding: '12px 16px',
        width: '320px',
        color: '#e0e0e0',
        fontFamily: '"JetBrains Mono", "Fira Code", monospace',
        display: 'flex',
        flexDirection: 'column',
        gap: '4px',
        pointerEvents: 'auto',
        transform: mounted ? 'translateX(0)' : 'translateX(120%)',
        opacity: mounted ? 1 : 0,
        transition: 'transform 0.3s ease-out, opacity 0.3s ease-out',
        boxShadow: '0 4px 12px rgba(0,0,0,0.5)',
    };

    return (
        <div style={style}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: colors[notif.type] }}>
                    <span style={{ fontWeight: 'bold' }}>{icons[notif.type]}</span>
                    <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#e0e0e0' }}>{notif.title}</span>
                </div>
                <button
                    onClick={onDismiss}
                    aria-label={`Dismiss ${notif.title} notification`}
                    style={{
                        background: 'transparent',
                        border: 'none',
                        color: '#666',
                        cursor: 'pointer',
                        padding: 0,
                        fontSize: '0.9rem',
                        lineHeight: 1,
                    }}
                >
                    {'\u2715'}
                </button>
            </div>
            <div style={{ fontSize: '0.75rem', color: '#999', marginTop: '4px', lineHeight: 1.4 }}>
                {notif.message}
            </div>
            {notif.options?.actionLabel !== undefined && notif.options?.onAction !== undefined && (
                <div style={{ marginTop: '8px', textAlign: 'right' }}>
                    <button
                        onClick={() => {
                            notif.options?.onAction?.();
                            onDismiss();
                        }}
                        style={{
                            background: 'transparent',
                            border: `1px solid ${colors[notif.type]}40`,
                            color: colors[notif.type],
                            padding: '4px 12px',
                            fontSize: '0.7rem',
                            cursor: 'pointer',
                            borderRadius: '2px',
                        }}
                    >
                        {notif.options.actionLabel}
                    </button>
                </div>
            )}
        </div>
    );
}
