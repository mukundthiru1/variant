import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';
export default defineConfig({
    plugins: [react()],
    resolve: {
        alias: {
            '@core': resolve(__dirname, 'src/core'),
            '@modules': resolve(__dirname, 'src/modules'),
            '@bridge': resolve(__dirname, 'src/bridge'),
            '@meta': resolve(__dirname, 'src/meta'),
            '@ui': resolve(__dirname, 'src/ui'),
        },
    },
    build: {
        target: 'es2022',
        sourcemap: true,
        rollupOptions: {
            output: {
                // v86.wasm is large — keep it as a separate chunk
                manualChunks: (id) => {
                    const normalizedId = id.replaceAll('\\', '/');
                    if (normalizedId.includes('/src/modules/'))
                        return 'modules';
                    if (normalizedId.includes('/src/levels/'))
                        return 'levels';
                    if (normalizedId.includes('/node_modules/@xterm/xterm/') || normalizedId.includes('/node_modules/@xterm/addon-fit/')) {
                        return 'xterm';
                    }
                    if (normalizedId.includes('/node_modules/react/') || normalizedId.includes('/node_modules/react-dom/')) {
                        return 'vendor';
                    }
                    return undefined;
                },
            },
        },
    },
    server: {
        port: 5174,
        headers: {
            // Required for SharedArrayBuffer (v86 performance)
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Cross-Origin-Embedder-Policy': 'require-corp',
        },
    },
});
