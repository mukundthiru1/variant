/**
 * VARIANT — Configurable Pipeline System
 *
 * A composable, type-safe pipeline for data processing.
 * Used throughout the engine for:
 *   - Input validation pipelines
 *   - Event transformation pipelines
 *   - Detection rule evaluation chains
 *   - Scoring computation chains
 *
 * DESIGN:
 *   Each stage is a pure function: Input → Output.
 *   Stages can be composed, branched, and parallelized.
 *   The pipeline is fully configurable via JSON-serializable
 *   stage descriptors (for WorldSpec integration).
 *
 * SWAPPABILITY: This is a utility module. Replace it without
 * affecting any module that uses it — they depend on the
 * Pipeline interface, not this implementation.
 */

// ── Core Types ──────────────────────────────────────────────

/**
 * A pipeline stage. Pure function from input to output.
 * Async stages are supported via PipelineStageAsync.
 */
export type PipelineStage<TIn, TOut> = (input: TIn) => TOut;

/**
 * Async pipeline stage.
 */
export type PipelineStageAsync<TIn, TOut> = (input: TIn) => Promise<TOut>;

/**
 * A named pipeline stage with metadata.
 */
export interface NamedStage<TIn, TOut> {
    readonly id: string;
    readonly description: string;
    readonly stage: PipelineStage<TIn, TOut>;
    readonly enabled?: boolean;
}

/**
 * Pipeline result with metadata.
 */
export interface PipelineResult<T> {
    readonly value: T;
    readonly stagesExecuted: number;
    readonly executionTimeMs: number;
    readonly stageResults?: readonly StageResult[];
}

export interface StageResult {
    readonly stageId: string;
    readonly durationMs: number;
    readonly skipped: boolean;
}

// ── Pipeline Builder ────────────────────────────────────────

/**
 * Build a synchronous pipeline from stages.
 *
 * Usage:
 *   const pipeline = createPipeline<string, number>()
 *     .pipe('parse', (s) => parseInt(s, 10))
 *     .pipe('double', (n) => n * 2)
 *     .build();
 *
 *   const result = pipeline.execute('21'); // { value: 42, ... }
 */
export interface PipelineBuilder<TIn, TCurrent> {
    /** Add a named stage. */
    pipe<TNext>(id: string, stage: PipelineStage<TCurrent, TNext>): PipelineBuilder<TIn, TNext>;

    /** Add a conditional stage (only runs if predicate is true). */
    pipeIf<TNext>(
        id: string,
        predicate: (input: TCurrent) => boolean,
        stage: PipelineStage<TCurrent, TNext>,
        fallback?: PipelineStage<TCurrent, TNext>,
    ): PipelineBuilder<TIn, TNext>;

    /** Add a tap (side-effect, does not transform). */
    tap(id: string, fn: (input: TCurrent) => void): PipelineBuilder<TIn, TCurrent>;

    /** Build the pipeline. */
    build(): Pipeline<TIn, TCurrent>;
}

/**
 * An executable pipeline.
 */
export interface Pipeline<TIn, TOut> {
    /** Execute the pipeline with input. */
    execute(input: TIn): PipelineResult<TOut>;

    /** Get the list of stage IDs. */
    getStageIds(): readonly string[];
}

// ── Implementation ──────────────────────────────────────────

interface StageEntry {
    readonly id: string;
    readonly fn: (input: unknown) => unknown;
    readonly conditional?: {
        readonly predicate: (input: unknown) => boolean;
        readonly fallback?: (input: unknown) => unknown;
    };
    readonly isTap: boolean;
}

export function createPipeline<TIn>(): PipelineBuilder<TIn, TIn> {
    return createPipelineBuilder<TIn, TIn>([]);
}

function createPipelineBuilder<TIn, TCurrent>(stages: StageEntry[]): PipelineBuilder<TIn, TCurrent> {
    return {
        pipe<TNext>(id: string, stage: PipelineStage<TCurrent, TNext>): PipelineBuilder<TIn, TNext> {
            return createPipelineBuilder<TIn, TNext>([
                ...stages,
                { id, fn: stage as (input: unknown) => unknown, isTap: false },
            ]);
        },

        pipeIf<TNext>(
            id: string,
            predicate: (input: TCurrent) => boolean,
            stage: PipelineStage<TCurrent, TNext>,
            fallback?: PipelineStage<TCurrent, TNext>,
        ): PipelineBuilder<TIn, TNext> {
            return createPipelineBuilder<TIn, TNext>([
                ...stages,
                {
                    id,
                    fn: stage as (input: unknown) => unknown,
                    conditional: {
                        predicate: predicate as (input: unknown) => boolean,
                        ...(fallback !== undefined ? { fallback: fallback as (input: unknown) => unknown } : {}),
                    },
                    isTap: false,
                },
            ]);
        },

        tap(id: string, fn: (input: TCurrent) => void): PipelineBuilder<TIn, TCurrent> {
            return createPipelineBuilder<TIn, TCurrent>([
                ...stages,
                {
                    id,
                    fn: (input: unknown) => { fn(input as TCurrent); return input; },
                    isTap: true,
                },
            ]);
        },

        build(): Pipeline<TIn, TCurrent> {
            const frozenStages = [...stages];

            return {
                execute(input: TIn): PipelineResult<TCurrent> {
                    const startTime = performance.now();
                    const stageResults: StageResult[] = [];
                    let current: unknown = input;
                    let stagesExecuted = 0;

                    for (const stage of frozenStages) {
                        const stageStart = performance.now();
                        let skipped = false;

                        if (stage.conditional !== undefined) {
                            if (stage.conditional.predicate(current)) {
                                current = stage.fn(current);
                            } else if (stage.conditional.fallback !== undefined) {
                                current = stage.conditional.fallback(current);
                            } else {
                                skipped = true;
                            }
                        } else {
                            current = stage.fn(current);
                        }

                        stageResults.push({
                            stageId: stage.id,
                            durationMs: performance.now() - stageStart,
                            skipped,
                        });

                        if (!skipped) stagesExecuted++;
                    }

                    return {
                        value: current as TCurrent,
                        stagesExecuted,
                        executionTimeMs: performance.now() - startTime,
                        stageResults,
                    };
                },

                getStageIds(): readonly string[] {
                    return frozenStages.map(s => s.id);
                },
            };
        },
    };
}

// ── Parallel Pipeline ───────────────────────────────────────

/**
 * Execute multiple pipelines in parallel on the same input.
 * Returns an array of results.
 */
export function parallelPipelines<TIn>(
    input: TIn,
    ...pipelines: readonly Pipeline<TIn, unknown>[]
): readonly PipelineResult<unknown>[] {
    return pipelines.map(p => p.execute(input));
}

// ── Pipeline Composition ────────────────────────────────────

/**
 * Compose two pipelines into one: A → B → C becomes A → C.
 */
export function composePipelines<A, B, C>(
    first: Pipeline<A, B>,
    second: Pipeline<B, C>,
): Pipeline<A, C> {
    return {
        execute(input: A): PipelineResult<C> {
            const firstResult = first.execute(input);
            const secondResult = second.execute(firstResult.value);

            return {
                value: secondResult.value,
                stagesExecuted: firstResult.stagesExecuted + secondResult.stagesExecuted,
                executionTimeMs: firstResult.executionTimeMs + secondResult.executionTimeMs,
                stageResults: [
                    ...(firstResult.stageResults ?? []),
                    ...(secondResult.stageResults ?? []),
                ],
            };
        },

        getStageIds(): readonly string[] {
            return [...first.getStageIds(), ...second.getStageIds()];
        },
    };
}
