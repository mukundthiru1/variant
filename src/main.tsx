/**
 * VARIANT — Entry Point
 *
 * Boots the application shell. The actual simulation is started
 * when a player selects a level.
 */

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './ui/App';

const rootElement = document.getElementById('root');
if (rootElement === null) {
    throw new Error('Root element not found. This is a fatal initialization error.');
}

createRoot(rootElement).render(
    <StrictMode>
        <App />
    </StrictMode>,
);
