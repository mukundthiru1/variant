/**
 * VARIANT — Resource Estimator
 *
 * Calculates estimated resource usage from a WorldSpec.
 * Used to warn players on low-memory devices before loading.
 *
 * DESIGN: Pure function. Takes a WorldSpec, returns a ResourceEstimation.
 * No side effects. No network. Testable in isolation.
 *
 * The estimates are deliberately conservative — better to warn
 * unnecessarily than to crash mid-level.
 */

import type { WorldSpec, ResourceEstimation, MachineSpec } from '../core/world/types';

// ── Constants ──────────────────────────────────────────────────

/**
 * Estimated per-machine overhead by backend type (MB).
 * These are conservative estimates including WASM runtime,
 * VFS, service handlers, and baseline state.
 */
const BACKEND_OVERHEAD: Readonly<Record<string, number>> = {
    'simulacrum': 3,    // VFS + ScriptedShell
    'simulacrum+': 8,    // VFS + ScriptedShell + lwIP
    'v86': 0,    // v86 overhead is in memoryMB
    'container2wasm': 15,   // WASM container runtime
};

const DEFAULT_BACKEND_OVERHEAD = 5;

/**
 * v86 has a fixed overhead for WASM, BIOS, etc.
 * This is on top of the configured memoryMB.
 */
const V86_FIXED_OVERHEAD = 12;

/**
 * Estimated boot time per machine (seconds).
 */
const BOOT_TIME: Readonly<Record<string, number>> = {
    'simulacrum': 0.05,
    'simulacrum+': 0.2,
    'v86': 3.0,
    'container2wasm': 2.0,
};

const DEFAULT_BOOT_TIME = 1.0;

/**
 * Per-service overhead (MB). Services add memory for state.
 */
const SERVICE_OVERHEAD = 0.5;

/**
 * Overhead for the lens compositor and core engine (MB).
 */
const ENGINE_OVERHEAD = 15;

// ── Estimator ──────────────────────────────────────────────────

/**
 * Infer the backend type for a machine.
 * If not specified, defaults to 'v86' for player, 'simulacrum' for others.
 */
function inferBackend(machine: MachineSpec): string {
    if (machine.backend !== undefined) return machine.backend;
    return machine.role === 'player' ? 'v86' : 'simulacrum';
}

/**
 * Estimate resource usage for a single machine.
 */
function estimateMachineRAM(machine: MachineSpec): number {
    const backend = inferBackend(machine);
    const overhead = BACKEND_OVERHEAD[backend] ?? DEFAULT_BACKEND_OVERHEAD;

    let ram = overhead;

    if (backend === 'v86') {
        ram += machine.memoryMB + V86_FIXED_OVERHEAD;
    } else if (backend === 'container2wasm') {
        ram += machine.memoryMB;
    }

    // Add service overhead
    const serviceCount = machine.services?.length ?? 0;
    ram += serviceCount * SERVICE_OVERHEAD;

    return ram;
}

/**
 * Estimate boot time for a single machine.
 */
function estimateMachineBootTime(machine: MachineSpec): number {
    const backend = inferBackend(machine);
    return BOOT_TIME[backend] ?? DEFAULT_BOOT_TIME;
}

/**
 * Estimate total resource usage for a WorldSpec.
 */
export function estimateResources(world: WorldSpec): ResourceEstimation {
    const machines = Object.values(world.machines);

    let totalRAM = ENGINE_OVERHEAD;
    let maxBootTime = 0;

    for (const machine of machines) {
        totalRAM += estimateMachineRAM(machine);
        maxBootTime = Math.max(maxBootTime, estimateMachineBootTime(machine));
    }

    // Boot happens in parallel, but add a small per-machine serialization cost
    const bootSeconds = maxBootTime + (machines.length * 0.1);

    // Determine minimum tier
    let minimumTier: 'chromebook' | 'laptop' | 'workstation';
    if (totalRAM <= 300) {
        minimumTier = 'chromebook';
    } else if (totalRAM <= 800) {
        minimumTier = 'laptop';
    } else {
        minimumTier = 'workstation';
    }

    return {
        estimatedRAMMB: Math.ceil(totalRAM),
        estimatedBootSeconds: Math.round(bootSeconds * 10) / 10,
        minimumTier,
    };
}

/**
 * Check if a WorldSpec fits within a given RAM budget.
 */
export function fitsWithinBudget(world: WorldSpec, budgetMB: number): boolean {
    const estimation = estimateResources(world);
    return estimation.estimatedRAMMB <= budgetMB;
}

/**
 * Generate a human-readable resource summary.
 */
export function resourceSummary(estimation: ResourceEstimation): string {
    const lines: string[] = [];

    lines.push(`Estimated RAM: ${estimation.estimatedRAMMB} MB`);
    lines.push(`Estimated boot: ${estimation.estimatedBootSeconds}s`);
    lines.push(`Minimum device: ${estimation.minimumTier}`);

    if (estimation.minimumTier === 'workstation') {
        lines.push('⚠ This level requires a desktop/laptop with >8GB RAM');
    } else if (estimation.minimumTier === 'laptop') {
        lines.push('ℹ This level runs best on a laptop/desktop');
    } else {
        lines.push('✓ This level runs on any device including Chromebooks');
    }

    return lines.join('\n');
}
