import { useEffect, useCallback, useRef } from 'react';

export type ShortcutHandler = (e: KeyboardEvent) => void;

export interface ShortcutRegistry {
    readonly registerShortcut: (keyCombo: string, handler: ShortcutHandler) => void;
    readonly unregisterShortcut: (keyCombo: string) => void;
}

export function useKeyboardShortcuts(): ShortcutRegistry {
    const handlersRef = useRef<Map<string, ShortcutHandler>>(new Map());

    const registerShortcut = useCallback((keyCombo: string, handler: ShortcutHandler) => {
        handlersRef.current.set(keyCombo.toLowerCase(), handler);
    }, []);

    const unregisterShortcut = useCallback((keyCombo: string) => {
        handlersRef.current.delete(keyCombo.toLowerCase());
    }, []);

    useEffect(() => {
        const handleKeyDown = (e: KeyboardEvent) => {
            const keys: string[] = [];
            if (e.ctrlKey || e.metaKey) keys.push('ctrl');
            if (e.shiftKey) keys.push('shift');
            if (e.altKey) keys.push('alt');
            
            let key = e.key.toLowerCase();
            // Ignore if it's just a modifier key press
            if (key === 'control' || key === 'shift' || key === 'alt' || key === 'meta') {
                return;
            }
            if (key === ' ') key = 'space';
            keys.push(key);
            
            const combo = keys.join('+');
            const handler = handlersRef.current.get(combo);
            
            if (handler !== undefined) {
                const activeEl = document.activeElement;
                const isTyping = activeEl !== null && (
                    activeEl.tagName === 'INPUT' || 
                    activeEl.tagName === 'TEXTAREA' || 
                    (activeEl as HTMLElement).isContentEditable ||
                    activeEl.classList.contains('xterm-helper-textarea')
                );
                
                // Must not fire when terminal has focus and user is typing (check activeElement)
                // Except for our specific global navigational shortcuts that rely on modifiers or F11/Escape
                if (isTyping && !e.ctrlKey && !e.altKey && !e.metaKey && key !== 'escape' && key !== 'f11') {
                    return;
                }
                
                e.preventDefault();
                handler(e);
            }
        };

        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, []);

    return { registerShortcut, unregisterShortcut };
}
