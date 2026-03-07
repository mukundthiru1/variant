/**
 * VARIANT — Backends barrel export.
 */
export { createBackendRouter } from './backend-router';
export { createSimulacrumBackend } from './simulacrum';
export type { BackendRouterConfig, BackendSelector } from './types';
export type {
    SimulacrumConfig,
    ProcessEntry,
    NetworkConfig,
    NetworkInterfaceConfig,
    RouteEntry,
    ListenPort,
} from './simulacrum';
