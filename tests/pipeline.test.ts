import { describe, it, expect } from 'vitest';
import { createPipeline, parallelPipelines, composePipelines } from '../src/core/pipeline';

describe('Pipeline', () => {
    it('executes a simple pipeline', () => {
        const pipeline = createPipeline<string>()
            .pipe('parse', (s) => parseInt(s, 10))
            .pipe('double', (n) => n * 2)
            .build();

        const result = pipeline.execute('21');
        expect(result.value).toBe(42);
        expect(result.stagesExecuted).toBe(2);
    });

    it('supports tap stages (side effects)', () => {
        const sideEffects: string[] = [];

        const pipeline = createPipeline<number>()
            .tap('log', (n) => { sideEffects.push(`input: ${n}`); })
            .pipe('double', (n) => n * 2)
            .tap('log-after', (n) => { sideEffects.push(`output: ${n}`); })
            .build();

        const result = pipeline.execute(5);
        expect(result.value).toBe(10);
        expect(sideEffects).toEqual(['input: 5', 'output: 10']);
    });

    it('supports conditional stages', () => {
        const pipeline = createPipeline<number>()
            .pipeIf(
                'double-if-positive',
                (n) => n > 0,
                (n) => n * 2,
                (n) => n, // fallback: identity
            )
            .build();

        expect(pipeline.execute(5).value).toBe(10);
        expect(pipeline.execute(-3).value).toBe(-3);
    });

    it('skips conditional stage without fallback', () => {
        const pipeline = createPipeline<number>()
            .pipeIf(
                'only-positive',
                (n) => n > 0,
                (n) => n * 2,
            )
            .build();

        const result = pipeline.execute(-3);
        expect(result.value).toBe(-3);
        expect(result.stageResults![0]!.skipped).toBe(true);
    });

    it('reports stage IDs', () => {
        const pipeline = createPipeline<string>()
            .pipe('a', (s) => s)
            .pipe('b', (s) => s)
            .pipe('c', (s) => s)
            .build();

        expect(pipeline.getStageIds()).toEqual(['a', 'b', 'c']);
    });

    it('reports execution time', () => {
        const pipeline = createPipeline<number>()
            .pipe('identity', (n) => n)
            .build();

        const result = pipeline.execute(42);
        expect(result.executionTimeMs).toBeGreaterThanOrEqual(0);
    });

    it('handles complex transformations', () => {
        const pipeline = createPipeline<string>()
            .pipe('split', (s) => s.split(','))
            .pipe('trim', (arr) => arr.map(s => s.trim()))
            .pipe('filter-empty', (arr) => arr.filter(s => s.length > 0))
            .pipe('count', (arr) => arr.length)
            .build();

        const result = pipeline.execute(' hello , world , , foo ');
        expect(result.value).toBe(3);
    });
});

describe('Parallel Pipelines', () => {
    it('executes multiple pipelines on the same input', () => {
        const double = createPipeline<number>()
            .pipe('double', (n) => n * 2)
            .build();

        const square = createPipeline<number>()
            .pipe('square', (n) => n * n)
            .build();

        const results = parallelPipelines(5, double, square);
        expect(results.length).toBe(2);
        expect(results[0]!.value).toBe(10);
        expect(results[1]!.value).toBe(25);
    });
});

describe('Pipeline Composition', () => {
    it('composes two pipelines', () => {
        const first = createPipeline<string>()
            .pipe('parse', (s) => parseInt(s, 10))
            .build();

        const second = createPipeline<number>()
            .pipe('double', (n) => n * 2)
            .pipe('toString', (n) => `result: ${n}`)
            .build();

        const composed = composePipelines(first, second);
        const result = composed.execute('21');

        expect(result.value).toBe('result: 42');
        expect(result.stagesExecuted).toBe(3);
        expect(composed.getStageIds()).toEqual(['parse', 'double', 'toString']);
    });
});
