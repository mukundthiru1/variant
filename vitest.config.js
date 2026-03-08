import { defineConfig } from 'vitest/config';
import { resolve } from 'path';
export default defineConfig({
    resolve: {
        alias: {
            '@core': resolve(__dirname, 'src/core'),
            '@modules': resolve(__dirname, 'src/modules'),
            '@bridge': resolve(__dirname, 'src/bridge'),
            '@meta': resolve(__dirname, 'src/meta'),
            '@ui': resolve(__dirname, 'src/ui'),
        },
    },
    test: {
        globals: true,
        environment: 'node',
        include: ['tests/**/*.test.ts', 'src/**/*.test.ts'],
        coverage: {
            provider: 'v8',
            include: ['src/**/*.ts'],
            exclude: ['src/**/*.d.ts', 'src/main.tsx'],
        },
    },
});
