import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ChangeEvent, CSSProperties, JSX } from 'react';
import type {
    LevelDifficulty,
    LevelPackage,
    LevelSearchQuery,
    LevelStats,
    MarketplaceStore,
} from '../../lib/marketplace/types';

const PAGE_SIZE = 9;
const DIFFICULTIES: readonly LevelDifficulty[] = ['beginner', 'easy', 'medium', 'hard', 'expert', 'insane'];

interface MarketplacePageProps {
    readonly store: MarketplaceStore;
    readonly onPlayLevel: (pkg: LevelPackage) => void;
}

export function MarketplacePage({ store, onPlayLevel }: MarketplacePageProps): JSX.Element {
    const fileInputRef = useRef<HTMLInputElement | null>(null);

    const [queryText, setQueryText] = useState('');
    const [selectedDifficulties, setSelectedDifficulties] = useState<readonly LevelDifficulty[]>([]);
    const [selectedTags, setSelectedTags] = useState<readonly string[]>([]);
    const [sortBy, setSortBy] = useState<NonNullable<LevelSearchQuery['sortBy']>>('newest');
    const [page, setPage] = useState(1);

    const [searchResult, setSearchResult] = useState<{
        readonly levels: readonly LevelPackage[];
        readonly total: number;
    }>({ levels: [], total: 0 });
    const [availableTags, setAvailableTags] = useState<readonly string[]>([]);
    const [expandedLevelIds, setExpandedLevelIds] = useState<readonly string[]>([]);
    const [statsByLevelId, setStatsByLevelId] = useState<Readonly<Record<string, LevelStats>>>({});

    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const [importJsonText, setImportJsonText] = useState('');
    const [importStatus, setImportStatus] = useState<string | null>(null);
    const [importBusy, setImportBusy] = useState(false);

    const [refreshKey, setRefreshKey] = useState(0);

    const totalPages = Math.max(1, Math.ceil(searchResult.total / PAGE_SIZE));

    useEffect(() => {
        setPage(1);
    }, [queryText, selectedDifficulties, selectedTags, sortBy]);

    const loadTags = useCallback(async () => {
        try {
            const tags = await store.getAllTags();
            setAvailableTags(tags);
        } catch (err: unknown) {
            setError(err instanceof Error ? err.message : 'Failed to load tags');
        }
    }, [store]);

    const loadSearch = useCallback(async () => {
        setLoading(true);
        setError(null);

        const offset = (page - 1) * PAGE_SIZE;
        const trimmedText = queryText.trim();

        const query: LevelSearchQuery = {
            sortBy,
            offset,
            limit: PAGE_SIZE,
            ...(trimmedText.length > 0 ? { text: trimmedText } : {}),
            ...(selectedDifficulties.length > 0 ? { difficulty: selectedDifficulties } : {}),
            ...(selectedTags.length > 0 ? { tags: selectedTags } : {}),
        };

        try {
            const result = await store.search(query);
            setSearchResult({ levels: result.levels, total: result.total });
        } catch (err: unknown) {
            setError(err instanceof Error ? err.message : 'Search failed');
            setSearchResult({ levels: [], total: 0 });
        } finally {
            setLoading(false);
        }
    }, [page, queryText, selectedDifficulties, selectedTags, sortBy, store]);

    useEffect(() => {
        void loadTags();
    }, [loadTags, refreshKey]);

    useEffect(() => {
        void loadSearch();
    }, [loadSearch, refreshKey]);

    useEffect(() => {
        let cancelled = false;

        async function loadStats(): Promise<void> {
            const levels = searchResult.levels;
            if (levels.length === 0) {
                setStatsByLevelId({});
                return;
            }

            const entries = await Promise.all(
                levels.map(async (level) => [level.id, await store.getStats(level.id)] as const),
            );

            if (cancelled) return;

            const next: Record<string, LevelStats> = {};
            for (const [id, stats] of entries) {
                next[id] = stats;
            }
            setStatsByLevelId(next);
        }

        loadStats().catch((err: unknown) => {
            if (!cancelled) {
                setError(err instanceof Error ? err.message : 'Failed to load stats');
            }
        });

        return () => {
            cancelled = true;
        };
    }, [searchResult.levels, store]);

    const toggleDifficulty = useCallback((difficulty: LevelDifficulty) => {
        setSelectedDifficulties((prev) =>
            prev.includes(difficulty)
                ? prev.filter((entry) => entry !== difficulty)
                : [...prev, difficulty],
        );
    }, []);

    const toggleTag = useCallback((tag: string) => {
        setSelectedTags((prev) =>
            prev.includes(tag)
                ? prev.filter((entry) => entry !== tag)
                : [...prev, tag],
        );
    }, []);

    const toggleExpanded = useCallback((levelId: string) => {
        setExpandedLevelIds((prev) =>
            prev.includes(levelId)
                ? prev.filter((entry) => entry !== levelId)
                : [...prev, levelId],
        );
    }, []);

    const handleImportText = useCallback(async () => {
        if (importJsonText.trim().length === 0) {
            setImportStatus('Paste level JSON first.');
            return;
        }

        setImportBusy(true);
        setImportStatus(null);

        try {
            const result = await store.importFromJson(importJsonText);
            if (result.success) {
                setImportStatus(`Imported level ${result.levelId ?? ''}`.trim());
                setImportJsonText('');
                setRefreshKey((prev) => prev + 1);
            } else {
                setImportStatus(result.errors?.join('; ') ?? 'Import failed');
            }
        } catch (err: unknown) {
            setImportStatus(err instanceof Error ? err.message : 'Import failed');
        } finally {
            setImportBusy(false);
        }
    }, [importJsonText, store]);

    const handleChooseFile = useCallback(() => {
        fileInputRef.current?.click();
    }, []);

    const handleFileUpload = useCallback(
        async (event: ChangeEvent<HTMLInputElement>) => {
            const file = event.target.files?.[0];
            if (file === undefined) return;

            setImportBusy(true);
            setImportStatus(null);

            try {
                const contents = await file.text();
                const result = await store.importFromJson(contents);
                if (result.success) {
                    setImportStatus(`Imported ${file.name}`);
                    setRefreshKey((prev) => prev + 1);
                } else {
                    setImportStatus(result.errors?.join('; ') ?? 'Import failed');
                }
            } catch (err: unknown) {
                setImportStatus(err instanceof Error ? err.message : 'File import failed');
            } finally {
                setImportBusy(false);
                event.target.value = '';
            }
        },
        [store],
    );

    const handleExport = useCallback(
        async (level: LevelPackage) => {
            const json = await store.exportLevel(level.id);
            if (json === null) {
                setError(`Failed to export ${level.metadata.title}`);
                return;
            }

            const blob = new Blob([json], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const anchor = document.createElement('a');
            anchor.href = url;
            anchor.download = `${sanitizeFilename(level.metadata.title)}.json`;
            document.body.appendChild(anchor);
            anchor.click();
            document.body.removeChild(anchor);
            URL.revokeObjectURL(url);
        },
        [store],
    );

    const visibleTags = useMemo(() => availableTags.slice(0, 36), [availableTags]);

    return (
        <div style={rootStyle}>
            <div style={headerStyle}>
                <h1 style={titleStyle}>MARKETPLACE</h1>
                <div style={subtleStyle}>{searchResult.total} levels available</div>
            </div>

            <div style={controlsPanelStyle}>
                <div style={controlsRowStyle}>
                    <input
                        value={queryText}
                        onChange={(event) => {
                            setQueryText(event.target.value);
                        }}
                        placeholder="Search title, author, tags, skills..."
                        style={searchInputStyle}
                    />
                    <select
                        value={sortBy}
                        onChange={(event) => {
                            setSortBy(event.target.value as NonNullable<LevelSearchQuery['sortBy']>);
                        }}
                        style={selectStyle}
                    >
                        <option value="newest">Newest</option>
                        <option value="popular">Popular</option>
                        <option value="rating">Rating</option>
                        <option value="difficulty">Difficulty</option>
                    </select>
                </div>

                <div style={controlsRowStyle}>
                    <span style={labelStyle}>Difficulty:</span>
                    {DIFFICULTIES.map((difficulty) => {
                        const active = selectedDifficulties.includes(difficulty);
                        return (
                            <button
                                key={difficulty}
                                type="button"
                                onClick={() => {
                                    toggleDifficulty(difficulty);
                                }}
                                style={chipStyle(active)}
                            >
                                {difficulty.toUpperCase()}
                            </button>
                        );
                    })}
                </div>

                <div style={controlsRowStyle}>
                    <span style={labelStyle}>Tags:</span>
                    {visibleTags.length === 0 && <span style={subtleStyle}>No tags yet</span>}
                    {visibleTags.map((tag) => {
                        const active = selectedTags.includes(tag);
                        return (
                            <button
                                key={tag}
                                type="button"
                                onClick={() => {
                                    toggleTag(tag);
                                }}
                                style={chipStyle(active)}
                            >
                                #{tag}
                            </button>
                        );
                    })}
                </div>
            </div>

            <div style={importPanelStyle}>
                <div style={panelTitleStyle}>Import Level</div>
                <textarea
                    value={importJsonText}
                    onChange={(event) => {
                        setImportJsonText(event.target.value);
                    }}
                    placeholder="Paste LevelPackage JSON here"
                    style={textAreaStyle}
                />
                <div style={controlsRowStyle}>
                    <button type="button" onClick={() => { void handleImportText(); }} style={actionButtonStyle} disabled={importBusy}>
                        {importBusy ? 'Importing...' : 'Import JSON'}
                    </button>
                    <button type="button" onClick={handleChooseFile} style={secondaryButtonStyle} disabled={importBusy}>
                        Upload JSON File
                    </button>
                    <input
                        ref={fileInputRef}
                        type="file"
                        accept="application/json,.json"
                        style={{ display: 'none' }}
                        onChange={(event) => {
                            void handleFileUpload(event);
                        }}
                    />
                    {importStatus !== null && <span style={subtleStyle}>{importStatus}</span>}
                </div>
            </div>

            {error !== null && <div style={errorStyle}>{error}</div>}

            <div style={cardsGridStyle}>
                {loading && <div style={subtleStyle}>Loading levels...</div>}
                {!loading && searchResult.levels.length === 0 && <div style={subtleStyle}>No levels match current filters.</div>}
                {!loading && searchResult.levels.map((level) => {
                    const expanded = expandedLevelIds.includes(level.id);
                    const stats = statsByLevelId[level.id];
                    return (
                        <article
                            key={level.id}
                            style={cardStyle(expanded)}
                            onClick={() => {
                                toggleExpanded(level.id);
                            }}
                        >
                            <div style={cardTopStyle}>
                                <div>
                                    <div style={cardTitleStyle}>{level.metadata.title}</div>
                                    <div style={subtleStyle}>by {level.author.name}</div>
                                </div>
                                <span style={difficultyBadgeStyle(level.metadata.difficulty)}>{level.metadata.difficulty}</span>
                            </div>

                            <div style={tagRowStyle}>
                                {level.metadata.tags.slice(0, 5).map((tag) => (
                                    <span key={`${level.id}-${tag}`} style={tagStyle}>#{tag}</span>
                                ))}
                            </div>

                            <div style={metaRowStyle}>
                                <span>~{level.metadata.estimatedMinutes}m</span>
                                <span>{level.metadata.machineCount} machines</span>
                                <span>{renderStars(stats?.averageRating ?? 0)} ({stats?.ratingCount ?? 0})</span>
                            </div>

                            {expanded && (
                                <div style={expandedStyle}>
                                    <p style={descStyle}>{level.metadata.description}</p>
                                    <div style={listBlockStyle}>
                                        <span style={labelStyle}>MITRE:</span> {level.metadata.mitreTechniques.join(', ') || 'None'}
                                    </div>
                                    <div style={listBlockStyle}>
                                        <span style={labelStyle}>Skills:</span> {level.metadata.skills.join(', ') || 'None'}
                                    </div>
                                    {level.metadata.screenshots !== undefined && level.metadata.screenshots.length > 0 && (
                                        <div style={screenshotsRowStyle}>
                                            {level.metadata.screenshots.slice(0, 3).map((src, index) => (
                                                <img
                                                    key={`${level.id}-shot-${index}`}
                                                    src={src}
                                                    alt={`${level.metadata.title} screenshot ${index + 1}`}
                                                    style={screenshotStyle}
                                                />
                                            ))}
                                        </div>
                                    )}
                                </div>
                            )}

                            <div style={cardActionRowStyle} onClick={(event) => { event.stopPropagation(); }}>
                                <button
                                    type="button"
                                    onClick={() => {
                                        onPlayLevel(level);
                                    }}
                                    style={actionButtonStyle}
                                >
                                    Play
                                </button>
                                <button
                                    type="button"
                                    onClick={() => {
                                        void handleExport(level);
                                    }}
                                    style={secondaryButtonStyle}
                                >
                                    Export
                                </button>
                            </div>
                        </article>
                    );
                })}
            </div>

            <div style={paginationStyle}>
                <button
                    type="button"
                    style={secondaryButtonStyle}
                    disabled={page <= 1}
                    onClick={() => {
                        setPage((prev) => Math.max(1, prev - 1));
                    }}
                >
                    Prev
                </button>
                <span style={subtleStyle}>Page {page} / {totalPages}</span>
                <button
                    type="button"
                    style={secondaryButtonStyle}
                    disabled={page >= totalPages}
                    onClick={() => {
                        setPage((prev) => Math.min(totalPages, prev + 1));
                    }}
                >
                    Next
                </button>
            </div>
        </div>
    );
}

function sanitizeFilename(input: string): string {
    const trimmed = input.trim();
    return (trimmed.length > 0 ? trimmed : 'level')
        .toLowerCase()
        .replace(/[^a-z0-9-_]+/g, '-')
        .replace(/^-+|-+$/g, '');
}

function renderStars(rating: number): string {
    const rounded = Math.max(0, Math.min(5, Math.round(rating)));
    return `${'★'.repeat(rounded)}${'☆'.repeat(5 - rounded)}`;
}

function chipStyle(active: boolean): CSSProperties {
    return {
        padding: '4px 10px',
        borderRadius: '999px',
        border: `1px solid ${active ? '#D4A03A' : '#21262d'}`,
        background: active ? 'rgba(212, 160, 58, 0.15)' : '#111111',
        color: active ? '#D4A03A' : '#e6edf3',
        cursor: 'pointer',
        fontFamily: 'var(--font-mono)',
        fontSize: '0.72rem',
    };
}

function difficultyBadgeStyle(difficulty: LevelDifficulty): CSSProperties {
    const colors: Record<LevelDifficulty, string> = {
        beginner: '#3DA67A',
        easy: '#66B08A',
        medium: '#D4A03A',
        hard: '#C75450',
        expert: '#ff4444',
        insane: '#ff2255',
    };

    return {
        padding: '3px 8px',
        borderRadius: '4px',
        border: `1px solid ${colors[difficulty]}`,
        color: colors[difficulty],
        fontSize: '0.72rem',
        textTransform: 'uppercase',
    };
}

const rootStyle: CSSProperties = {
    minHeight: '100vh',
    background: '#0A0A0A',
    color: '#e6edf3',
    fontFamily: 'var(--font-mono)',
    padding: '20px',
    display: 'flex',
    flexDirection: 'column',
    gap: '16px',
};

const headerStyle: CSSProperties = {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
};

const titleStyle: CSSProperties = {
    margin: 0,
    color: '#D4A03A',
    fontSize: '1.25rem',
    letterSpacing: '0.08em',
};

const controlsPanelStyle: CSSProperties = {
    border: '1px solid #21262d',
    borderRadius: '8px',
    padding: '12px',
    background: '#111111',
    display: 'flex',
    flexDirection: 'column',
    gap: '10px',
};

const controlsRowStyle: CSSProperties = {
    display: 'flex',
    flexWrap: 'wrap',
    gap: '8px',
    alignItems: 'center',
};

const labelStyle: CSSProperties = {
    color: '#8b949e',
    fontSize: '0.78rem',
};

const subtleStyle: CSSProperties = {
    color: '#8b949e',
    fontSize: '0.78rem',
};

const searchInputStyle: CSSProperties = {
    flex: 1,
    minWidth: '220px',
    border: '1px solid #21262d',
    background: '#0A0A0A',
    color: '#e6edf3',
    borderRadius: '6px',
    padding: '8px 10px',
    fontFamily: 'var(--font-mono)',
};

const selectStyle: CSSProperties = {
    border: '1px solid #21262d',
    background: '#0A0A0A',
    color: '#e6edf3',
    borderRadius: '6px',
    padding: '8px 10px',
    fontFamily: 'var(--font-mono)',
};

const importPanelStyle: CSSProperties = {
    border: '1px solid #21262d',
    borderRadius: '8px',
    padding: '12px',
    background: '#111111',
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
};

const panelTitleStyle: CSSProperties = {
    color: '#D4A03A',
    fontSize: '0.9rem',
};

const textAreaStyle: CSSProperties = {
    minHeight: '90px',
    border: '1px solid #21262d',
    borderRadius: '6px',
    background: '#0A0A0A',
    color: '#e6edf3',
    padding: '10px',
    fontFamily: 'var(--font-mono)',
};

const actionButtonStyle: CSSProperties = {
    border: '1px solid #D4A03A',
    background: 'rgba(212, 160, 58, 0.12)',
    color: '#D4A03A',
    borderRadius: '6px',
    padding: '7px 12px',
    cursor: 'pointer',
    fontFamily: 'var(--font-mono)',
};

const secondaryButtonStyle: CSSProperties = {
    border: '1px solid #21262d',
    background: '#0A0A0A',
    color: '#e6edf3',
    borderRadius: '6px',
    padding: '7px 12px',
    cursor: 'pointer',
    fontFamily: 'var(--font-mono)',
};

const cardsGridStyle: CSSProperties = {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
    gap: '12px',
    alignItems: 'start',
};

function cardStyle(expanded: boolean): CSSProperties {
    return {
        border: `1px solid ${expanded ? '#D4A03A' : '#21262d'}`,
        borderRadius: '8px',
        background: '#111111',
        padding: '12px',
        cursor: 'pointer',
        display: 'flex',
        flexDirection: 'column',
        gap: '10px',
    };
}

const cardTopStyle: CSSProperties = {
    display: 'flex',
    justifyContent: 'space-between',
    gap: '8px',
};

const cardTitleStyle: CSSProperties = {
    fontSize: '0.96rem',
    color: '#e6edf3',
    fontWeight: 700,
};

const tagRowStyle: CSSProperties = {
    display: 'flex',
    gap: '6px',
    flexWrap: 'wrap',
};

const tagStyle: CSSProperties = {
    border: '1px solid #21262d',
    borderRadius: '999px',
    padding: '2px 8px',
    color: '#8b949e',
    fontSize: '0.72rem',
};

const metaRowStyle: CSSProperties = {
    display: 'flex',
    gap: '10px',
    flexWrap: 'wrap',
    color: '#8b949e',
    fontSize: '0.75rem',
};

const expandedStyle: CSSProperties = {
    borderTop: '1px solid #21262d',
    paddingTop: '8px',
    display: 'flex',
    flexDirection: 'column',
    gap: '6px',
};

const descStyle: CSSProperties = {
    margin: 0,
    color: '#c9d1d9',
    fontSize: '0.78rem',
    lineHeight: 1.5,
};

const listBlockStyle: CSSProperties = {
    fontSize: '0.76rem',
    color: '#c9d1d9',
};

const screenshotsRowStyle: CSSProperties = {
    display: 'grid',
    gridTemplateColumns: 'repeat(3, minmax(0, 1fr))',
    gap: '6px',
};

const screenshotStyle: CSSProperties = {
    width: '100%',
    height: '72px',
    objectFit: 'cover',
    borderRadius: '4px',
    border: '1px solid #21262d',
    background: '#0A0A0A',
};

const cardActionRowStyle: CSSProperties = {
    display: 'flex',
    gap: '8px',
};

const paginationStyle: CSSProperties = {
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    gap: '10px',
    paddingBottom: '12px',
};

const errorStyle: CSSProperties = {
    border: '1px solid #ff6b6b',
    color: '#ff6b6b',
    background: 'rgba(255, 107, 107, 0.08)',
    borderRadius: '6px',
    padding: '8px 10px',
    fontSize: '0.78rem',
};
