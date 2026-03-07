/**
 * VARIANT — Detection Engine Registry
 *
 * Composes multiple detection engines for comprehensive coverage.
 * Includes rule scoring for evaluating player-written detection rules.
 *
 * CONFIGURABILITY: Engines are registered dynamically. Third-party
 * engines can be added without modifying this file.
 *
 * SWAPPABILITY: Replace this registry. Nothing else changes.
 */

import type {
    DetectionEngine,
    DetectionEngineRegistry,
    DetectionResult,
    DetectionContext,
    DetectionCategory,
    RuleScoringResult,
    TestCorpusEntry,
} from './types';

// ── Registry Implementation ────────────────────────────────

export function createDetectionEngineRegistry(): DetectionEngineRegistry {
    const engines = new Map<string, DetectionEngine>();

    const registry: DetectionEngineRegistry = {
        register(engine: DetectionEngine): void {
            if (engines.has(engine.id)) {
                throw new Error(`Detection engine '${engine.id}' already registered`);
            }
            engines.set(engine.id, engine);
        },

        get(id: string): DetectionEngine | undefined {
            return engines.get(id);
        },

        getAll(): readonly DetectionEngine[] {
            return [...engines.values()];
        },

        getByCategory(category: DetectionCategory): readonly DetectionEngine[] {
            return [...engines.values()].filter(e => e.category === category);
        },

        analyzeAll(input: string, context?: DetectionContext): readonly DetectionResult[] {
            const results: DetectionResult[] = [];
            for (const engine of engines.values()) {
                results.push(engine.analyze(input, context));
            }
            return results;
        },

        analyzeByCategory(
            input: string,
            category: DetectionCategory,
            context?: DetectionContext,
        ): readonly DetectionResult[] {
            return this.getByCategory(category).map(e => e.analyze(input, context));
        },
    };

    return registry;
}

// ── Rule Scorer ─────────────────────────────────────────────

/**
 * Score a player-written detection rule against a test corpus.
 *
 * The player provides a detection function (string -> boolean).
 * We run it against known-good and known-bad inputs and measure
 * true positives, false positives, etc.
 *
 * CONFIGURABILITY: The test corpus is passed in — levels define
 * their own test cases for scoring.
 */
export function scoreDetectionRule(
    detectFn: (input: string) => boolean,
    corpus: readonly TestCorpusEntry[],
): RuleScoringResult {
    let tp = 0, tn = 0, fp = 0, fn = 0;

    for (const entry of corpus) {
        const detected = detectFn(entry.input);
        if (entry.malicious) {
            if (detected) tp++;
            else fn++;
        } else {
            if (detected) fp++;
            else tn++;
        }
    }

    const total = tp + tn + fp + fn;
    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    const f1 = precision + recall > 0
        ? 2 * (precision * recall) / (precision + recall)
        : 0;

    return {
        truePositiveRate: tp + fn > 0 ? tp / (tp + fn) : 0,
        trueNegativeRate: tn + fp > 0 ? tn / (tn + fp) : 0,
        falsePositiveRate: tn + fp > 0 ? fp / (tn + fp) : 0,
        falseNegativeRate: tp + fn > 0 ? fn / (tp + fn) : 0,
        f1Score: Math.round(f1 * 1000) / 1000,
        totalInputs: total,
        breakdown: {
            truePositives: tp,
            trueNegatives: tn,
            falsePositives: fp,
            falseNegatives: fn,
        },
    };
}

// ── Test Corpus Builder ─────────────────────────────────────

/**
 * Build a test corpus from detection engine patterns.
 * Generates synthetic malicious inputs from the engine's patterns
 * and pairs them with benign inputs.
 *
 * This is a utility for level builders — they can generate
 * corpus entries from the built-in engines, then customize.
 */
export function generateTestCorpus(
    engine: DetectionEngine,
    benignInputs: readonly string[],
): readonly TestCorpusEntry[] {
    const corpus: TestCorpusEntry[] = [];

    // Generate malicious entries from patterns
    for (const pattern of engine.getPatterns()) {
        if (!pattern.enabled) continue;

        // Create a synthetic input that would match this pattern
        const result = engine.analyze(pattern.pattern);
        if (result.detected) {
            corpus.push({
                input: pattern.pattern,
                malicious: true,
                category: engine.category,
                description: `Synthetic: ${pattern.name}`,
                difficulty: pattern.severity === 'critical' ? 'easy' : pattern.severity === 'high' ? 'medium' : 'hard',
            });
        }
    }

    // Add benign inputs
    for (const input of benignInputs) {
        corpus.push({
            input,
            malicious: false,
            description: 'Benign input',
        });
    }

    return corpus;
}
