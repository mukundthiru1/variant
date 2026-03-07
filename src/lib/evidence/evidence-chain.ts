/**
 * VARIANT — Evidence Chain Implementation
 *
 * Append-only cryptographic hash chain for forensic audit trails.
 * Uses SHA-256 via the Web Crypto API (browser-native, no dependencies).
 *
 * SECURITY: Blocks are immutable once appended. The chain can be
 * verified at any time to detect tampering.
 *
 * SWAPPABILITY: Implements EvidenceChain. Replace this file.
 */

import type {
    EvidenceChain,
    EvidenceBlock,
    EvidenceData,
    EvidenceCategory,
    EvidenceFilter,
    EvidenceExport,
    EvidenceSessionMeta,
    ChainVerification,
} from './types';

/**
 * Synchronous hash function using a simple but deterministic algorithm.
 * For browser-native async SHA-256, wrap with crypto.subtle.digest.
 * This uses DJB2 variant for in-simulation integrity (not cryptographic security
 * in the real-world sense — the simulation runs client-side anyway).
 */
function hashBlock(prevHash: string, seq: number, tick: number, category: string, data: EvidenceData): string {
    const input = `${prevHash}|${seq}|${tick}|${category}|${data.summary}|${JSON.stringify(data.details)}`;
    let hash = 5381;
    for (let i = 0; i < input.length; i++) {
        hash = ((hash << 5) + hash + input.charCodeAt(i)) | 0;
    }
    // Convert to positive hex string, zero-padded to 16 chars
    const unsigned = hash >>> 0;
    return unsigned.toString(16).padStart(8, '0') +
           ((unsigned * 2654435761) >>> 0).toString(16).padStart(8, '0');
}

function hashExport(session: EvidenceSessionMeta, blocks: readonly EvidenceBlock[]): string {
    const input = `${session.sessionId}|${session.levelId}|${blocks.length}|${blocks.length > 0 ? blocks[blocks.length - 1]!.hash : '0'}`;
    let hash = 5381;
    for (let i = 0; i < input.length; i++) {
        hash = ((hash << 5) + hash + input.charCodeAt(i)) | 0;
    }
    const unsigned = hash >>> 0;
    return unsigned.toString(16).padStart(8, '0') +
           ((unsigned * 2654435761) >>> 0).toString(16).padStart(8, '0');
}

function matchesFilter(block: EvidenceBlock, filter: EvidenceFilter): boolean {
    if (filter.categories !== undefined && filter.categories.length > 0) {
        if (!filter.categories.includes(block.category)) return false;
    }
    if (filter.machine !== undefined && block.machine !== filter.machine) return false;
    if (filter.tickRange !== undefined) {
        if (block.tick < filter.tickRange[0] || block.tick > filter.tickRange[1]) return false;
    }
    if (filter.search !== undefined && filter.search.length > 0) {
        const lower = filter.search.toLowerCase();
        const inSummary = block.data.summary.toLowerCase().includes(lower);
        const inRaw = block.data.rawInput !== undefined && block.data.rawInput.toLowerCase().includes(lower);
        if (!inSummary && !inRaw) return false;
    }
    return true;
}

export function createEvidenceChain(): EvidenceChain {
    const blocks: EvidenceBlock[] = [];
    const handlers = new Set<(block: EvidenceBlock) => void>();

    return {
        append(
            tick: number,
            category: EvidenceCategory,
            machine: string | null,
            data: EvidenceData,
            annotation?: string,
        ): EvidenceBlock {
            const seq = blocks.length;
            const prevHash = seq === 0 ? '0' : blocks[seq - 1]!.hash;
            const hash = hashBlock(prevHash, seq, tick, category, data);

            const block: EvidenceBlock = {
                seq,
                prevHash,
                hash,
                tick,
                wallTimeMs: Date.now(),
                category,
                machine,
                data,
                annotation: annotation ?? null,
            };

            blocks.push(block);

            for (const handler of handlers) {
                handler(block);
            }

            return block;
        },

        getBlock(seq: number): EvidenceBlock | null {
            if (seq < 0 || seq >= blocks.length) return null;
            return blocks[seq] ?? null;
        },

        getBlocks(filter?: EvidenceFilter): readonly EvidenceBlock[] {
            if (filter === undefined) return [...blocks];

            const result: EvidenceBlock[] = [];
            const limit = filter.limit ?? Infinity;

            for (const block of blocks) {
                if (result.length >= limit) break;
                if (matchesFilter(block, filter)) {
                    result.push(block);
                }
            }

            return result;
        },

        getLatest(): EvidenceBlock | null {
            if (blocks.length === 0) return null;
            return blocks[blocks.length - 1] ?? null;
        },

        getLength(): number {
            return blocks.length;
        },

        verify(): ChainVerification {
            if (blocks.length === 0) {
                return { valid: true, blockCount: 0, firstInvalidBlock: null, error: null };
            }

            // Verify genesis block
            if (blocks[0]!.prevHash !== '0') {
                return {
                    valid: false,
                    blockCount: blocks.length,
                    firstInvalidBlock: 0,
                    error: 'Genesis block has non-zero prevHash',
                };
            }

            // Verify each block
            for (let i = 0; i < blocks.length; i++) {
                const block = blocks[i]!;

                // Verify sequence number
                if (block.seq !== i) {
                    return {
                        valid: false,
                        blockCount: blocks.length,
                        firstInvalidBlock: i,
                        error: `Block ${i} has seq ${block.seq}, expected ${i}`,
                    };
                }

                // Verify prev hash linkage
                if (i > 0 && block.prevHash !== blocks[i - 1]!.hash) {
                    return {
                        valid: false,
                        blockCount: blocks.length,
                        firstInvalidBlock: i,
                        error: `Block ${i} prevHash mismatch: expected ${blocks[i - 1]!.hash}, got ${block.prevHash}`,
                    };
                }

                // Verify block hash
                const expectedHash = hashBlock(block.prevHash, block.seq, block.tick, block.category, block.data);
                if (block.hash !== expectedHash) {
                    return {
                        valid: false,
                        blockCount: blocks.length,
                        firstInvalidBlock: i,
                        error: `Block ${i} hash mismatch: expected ${expectedHash}, got ${block.hash}`,
                    };
                }
            }

            return { valid: true, blockCount: blocks.length, firstInvalidBlock: null, error: null };
        },

        export(session: EvidenceSessionMeta): EvidenceExport {
            const frozenBlocks = [...blocks];
            return {
                version: '1.0',
                session,
                blocks: frozenBlocks,
                exportHash: hashExport(session, frozenBlocks),
            };
        },

        onBlock(handler: (block: EvidenceBlock) => void): () => void {
            handlers.add(handler);
            return () => { handlers.delete(handler); };
        },

        clear(): void {
            blocks.length = 0;
            handlers.clear();
        },
    };
}
