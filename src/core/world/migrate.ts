/**
 * VARIANT — WorldSpec Migration System
 *
 * Migrates older WorldSpec formats to the current version.
 * Ensures backward compatibility with community levels.
 *
 * DESIGN: Pure functions. No mutation of input specs.
 * Uses BFS to find the shortest migration path across versions.
 */

export interface MigrationStep {
    readonly fromVersion: string;
    readonly toVersion: string;
    readonly migrate: (spec: unknown) => unknown;
    readonly description: string;
}

export interface MigrationRegistry {
    readonly register: (step: MigrationStep) => void;
    readonly migrate: (spec: unknown, targetVersion: string) => { readonly result: unknown; readonly steps: readonly string[] };
    readonly canMigrate: (fromVersion: string, toVersion: string) => boolean;
    readonly getPath: (fromVersion: string, toVersion: string) => readonly MigrationStep[];
}

export function createMigrationRegistry(): MigrationRegistry {
    const steps: MigrationStep[] = [];

    const registry: MigrationRegistry = {
        register(step: MigrationStep) {
            const isDuplicate = steps.some(s => s.fromVersion === step.fromVersion && s.toVersion === step.toVersion);
            if (isDuplicate) {
                throw new Error(`Migration from ${step.fromVersion} to ${step.toVersion} already registered`);
            }
            steps.push(step);
        },

        getPath(fromVersion: string, toVersion: string): readonly MigrationStep[] {
            if (fromVersion === toVersion) {
                return [];
            }

            interface QueueItem {
                currentVersion: string;
                path: MigrationStep[];
            }

            const queue: QueueItem[] = [{ currentVersion: fromVersion, path: [] }];
            const visited = new Set<string>([fromVersion]);

            while (queue.length > 0) {
                const { currentVersion, path } = queue.shift()!;

                if (currentVersion === toVersion) {
                    return path;
                }

                for (const step of steps) {
                    if (step.fromVersion === currentVersion && !visited.has(step.toVersion)) {
                        visited.add(step.toVersion);
                        queue.push({
                            currentVersion: step.toVersion,
                            path: [...path, step]
                        });
                    }
                }
            }

            throw new Error(`No migration path found from ${fromVersion} to ${toVersion}`);
        },

        canMigrate(fromVersion: string, toVersion: string): boolean {
            try {
                this.getPath(fromVersion, toVersion);
                return true;
            } catch {
                return false;
            }
        },

        migrate(spec: unknown, targetVersion: string) {
            if (!spec || typeof spec !== 'object') {
                throw new Error('Invalid spec: must be an object');
            }

            const recordSpec = spec as Record<string, unknown>;
            const currentVersion = recordSpec['version'];
            
            if (typeof currentVersion !== 'string') {
                throw new Error('Invalid spec: missing or invalid version field');
            }

            const path = this.getPath(currentVersion, targetVersion);
            
            let currentSpec: unknown = spec;
            const appliedSteps: string[] = [];

            for (const step of path) {
                // Deep clone before passing to step to ensure purity and no mutation of original
                currentSpec = step.migrate(JSON.parse(JSON.stringify(currentSpec)));
                appliedSteps.push(step.description);
            }

            return {
                result: currentSpec,
                steps: appliedSteps
            };
        }
    };

    // Register built-in migrations
    registry.register({
        fromVersion: '1.0.0',
        toVersion: '2.0',
        description: 'Upgrade to 2.0: rename description->scenario, set trust, upgrade credentials, add default scoring',
        migrate: (spec: unknown) => {
            const oldSpec = spec as Record<string, any>;
            const newSpec = { ...oldSpec }; // Shallow clone of the root object
            
            // 1. Rename 'description' to 'scenario' in meta
            if (newSpec['meta'] && typeof newSpec['meta'] === 'object') {
                newSpec['meta'] = { ...newSpec['meta'] };
                if ('description' in newSpec['meta']) {
                    newSpec['meta']['scenario'] = newSpec['meta']['description'];
                    delete newSpec['meta']['description'];
                } else if (!('scenario' in newSpec['meta'])) {
                    newSpec['meta']['scenario'] = '';
                }
            }

            // 2. Add default 'trust: community'
            if (!('trust' in newSpec)) {
                newSpec['trust'] = 'community';
            }

            // 3. Convert flat credentials to CredentialEntry format
            if (Array.isArray(newSpec['credentials'])) {
                newSpec['credentials'] = newSpec['credentials'].map((oldCred: any) => {
                    // Check if already in 2.0 format
                    if (oldCred && oldCred.foundAt && oldCred.validAt) {
                        return oldCred;
                    }
                    
                    return {
                        id: oldCred.id ?? 'unknown-cred',
                        type: oldCred.type ?? 'password',
                        value: oldCred.value ?? '',
                        foundAt: {
                            machine: oldCred.machine ?? 'unknown',
                            path: oldCred.path,
                        },
                        validAt: {
                            machine: oldCred.machine ?? 'unknown',
                            service: oldCred.service ?? 'unknown',
                            user: oldCred.user ?? 'root',
                        }
                    };
                });
            }

            // 4. Add default scoring if missing
            if (!('scoring' in newSpec)) {
                newSpec['scoring'] = {
                    maxScore: 1000,
                    timeBonus: true,
                    stealthBonus: true,
                    hintPenalty: 50,
                    tiers: [
                        { name: 'MASTERY', minScore: 900, color: 'gold' },
                        { name: 'PROFICIENT', minScore: 700, color: 'silver' },
                        { name: 'NOVICE', minScore: 0, color: 'bronze' }
                    ]
                };
            }

            // Update version
            newSpec['version'] = '2.0';

            return newSpec;
        }
    });

    return registry;
}
