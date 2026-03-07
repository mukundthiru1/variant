/**
 * VARIANT — Telemetry System barrel export
 */
export type {
    TelemetryMetrics,
    CommandEntry,
    TimeBucket,
    StuckPeriod,
    TelemetryCollector,
    TelemetryReport,
} from './types';

export { createTelemetryCollector } from './telemetry-collector';
