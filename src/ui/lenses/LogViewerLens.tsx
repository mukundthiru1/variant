import { useMemo, useState, useRef, useEffect, useCallback } from 'react';
import type { CSSProperties } from 'react';

const SEVERITY_COLORS: Readonly<Record<LogEntry['severity'], string>> = {
    debug: '#666',
    info: '#8be9fd',
    warn: '#f1fa8c',
    error: '#ff5555',
    crit: '#ff79c6',
};

const SOURCE_TABS = ['all', 'auth.log', 'syslog', 'access.log', 'error.log', 'kern.log'] as const;
type SourceTab = typeof SOURCE_TABS[number];

const ROW_HEIGHT = 28;
const OVERSCAN = 10;

export interface LogViewerLensProps {
    readonly logs: readonly LogEntry[];
    readonly onRefresh?: () => void;
    readonly focused: boolean;
}

export interface LogEntry {
    readonly id: string;
    readonly timestamp: string;
    readonly source: string;
    readonly severity: 'debug' | 'info' | 'warn' | 'error' | 'crit';
    readonly message: string;
    readonly raw: string;
    readonly structured?: Readonly<Record<string, unknown>>;
}

interface ParsedRegex {
    readonly filter: RegExp | null;
    readonly highlight: RegExp | null;
    readonly error: string | null;
}

export function LogViewerLens({ logs, onRefresh, focused }: LogViewerLensProps): JSX.Element {
    const [selectedSource, setSelectedSource] = useState<SourceTab>('all');
    const [searchValue, setSearchValue] = useState('');
    const [paused, setPaused] = useState(false);
    const [expandedLogId, setExpandedLogId] = useState<string | null>(null);
    const [selectedLines, setSelectedLines] = useState<Set<string>>(new Set());
    const [selectionAnchor, setSelectionAnchor] = useState<number | null>(null);
    const [scrollTop, setScrollTop] = useState(0);
    const [viewportHeight, setViewportHeight] = useState(0);

    const listRef = useRef<HTMLDivElement | null>(null);
    const searchRef = useRef<HTMLInputElement | null>(null);

    useEffect(() => {
        if (focused) {
            searchRef.current?.focus();
        }
    }, [focused]);

    const regex = useMemo(() => parseRegex(searchValue), [searchValue]);

    const filteredLogs = useMemo(() => {
        const bySource = selectedSource === 'all'
            ? logs
            : logs.filter((entry) => normalizeSource(entry.source) === selectedSource);

        if (regex.filter === null) {
            return bySource;
        }

        return bySource.filter((entry) => {
            const line = `${entry.timestamp} ${entry.source} ${entry.message} ${entry.raw}`;
            return regex.filter?.test(line) ?? false;
        });
    }, [logs, selectedSource, regex.filter]);

    useEffect(() => {
        if (paused) return;
        const el = listRef.current;
        if (el === null) return;
        el.scrollTop = Math.max(0, (filteredLogs.length * ROW_HEIGHT) - el.clientHeight);
    }, [filteredLogs.length, paused]);

    useEffect(() => {
        const el = listRef.current;
        if (el === null) return;
        setViewportHeight(el.clientHeight);
    }, []);

    const totalRows = filteredLogs.length;
    const visibleRows = viewportHeight > 0 ? Math.ceil(viewportHeight / ROW_HEIGHT) : 0;
    const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
    const endIndex = Math.min(totalRows, startIndex + visibleRows + (OVERSCAN * 2));
    const topSpacerHeight = startIndex * ROW_HEIGHT;
    const bottomSpacerHeight = Math.max(0, (totalRows - endIndex) * ROW_HEIGHT);
    const visibleEntries = filteredLogs.slice(startIndex, endIndex);

    const expandedEntry = useMemo(
        () => logs.find((entry) => entry.id === expandedLogId) ?? null,
        [logs, expandedLogId],
    );

    const selectedCount = selectedLines.size;
    const firstVisibleLine = totalRows === 0 ? 0 : Math.min(totalRows, Math.floor(scrollTop / ROW_HEIGHT) + 1);
    const lastVisibleLine = totalRows === 0
        ? 0
        : Math.min(totalRows, Math.floor((scrollTop + viewportHeight) / ROW_HEIGHT));
    const scrollPercent = totalRows === 0 || viewportHeight === 0
        ? 0
        : Math.min(100, ((scrollTop + viewportHeight) / (totalRows * ROW_HEIGHT)) * 100);

    const handleScroll = useCallback((event: React.UIEvent<HTMLDivElement>) => {
        const target = event.currentTarget;
        setScrollTop(target.scrollTop);
        setViewportHeight(target.clientHeight);
    }, []);

    const handleToggleLine = useCallback((index: number, lineId: string, event: React.MouseEvent<HTMLButtonElement>) => {
        event.stopPropagation();

        setSelectedLines((prev) => {
            const next = new Set(prev);

            if (event.shiftKey && selectionAnchor !== null) {
                const from = Math.min(selectionAnchor, index);
                const to = Math.max(selectionAnchor, index);
                for (let i = from; i <= to; i += 1) {
                    const entry = filteredLogs[i];
                    if (entry !== undefined) next.add(entry.id);
                }
                return next;
            }

            if (next.has(lineId)) {
                next.delete(lineId);
            } else {
                next.add(lineId);
            }
            return next;
        });

        setSelectionAnchor(index);
    }, [filteredLogs, selectionAnchor]);

    const handleCopySelected = useCallback(async () => {
        if (selectedLines.size === 0) return;

        const selectedText = logs
            .filter((entry) => selectedLines.has(entry.id))
            .map(formatLogLine)
            .join('\n');

        await copyToClipboard(selectedText);
    }, [logs, selectedLines]);

    const handleExportVisible = useCallback(async () => {
        const text = filteredLogs.map(formatLogLine).join('\n');
        await copyToClipboard(text);
    }, [filteredLogs]);

    return (
        <div style={styles.root}>
            <div style={styles.toolbar}>
                <div style={styles.tabsRow}>
                    {SOURCE_TABS.map((tab) => (
                        <button
                            key={tab}
                            onClick={() => { setSelectedSource(tab); }}
                            style={{
                                ...styles.tab,
                                ...(selectedSource === tab ? styles.tabActive : null),
                            }}
                        >
                            {tab}
                        </button>
                    ))}
                </div>

                <div style={styles.controlsRow}>
                    <input
                        ref={searchRef}
                        value={searchValue}
                        onChange={(event) => { setSearchValue(event.target.value); }}
                        placeholder="Regex filter (e.g. failed|sudo|5\\d\\d)"
                        style={{
                            ...styles.search,
                            borderColor: regex.error === null ? '#21262d' : '#ff5555',
                        }}
                    />

                    <button onClick={() => { setPaused((prev) => !prev); }} style={styles.button}>
                        {paused ? 'Resume' : 'Pause'}
                    </button>

                    {onRefresh !== undefined && (
                        <button onClick={onRefresh} style={styles.button}>Refresh</button>
                    )}

                    <button
                        onClick={() => { void handleCopySelected(); }}
                        style={styles.button}
                        disabled={selectedCount === 0}
                    >
                        Copy selected ({selectedCount})
                    </button>

                    <button onClick={() => { void handleExportVisible(); }} style={styles.button}>
                        Export visible
                    </button>
                </div>

                <div style={styles.metaRow}>
                    <span>
                        Lines: {totalRows.toLocaleString()} visible / {logs.length.toLocaleString()} total
                    </span>
                    <span>
                        View: {firstVisibleLine.toLocaleString()}-{lastVisibleLine.toLocaleString()} ({scrollPercent.toFixed(1)}%)
                    </span>
                    {regex.error !== null && <span style={styles.errorText}>Invalid regex: {regex.error}</span>}
                </div>
            </div>

            <div style={styles.header}>
                <div>Timestamp</div>
                <div>Source</div>
                <div>Message</div>
                <div style={{ textAlign: 'center' }}>Sel</div>
            </div>

            <div ref={listRef} style={styles.list} onScroll={handleScroll}>
                <div style={{ height: `${topSpacerHeight}px` }} />

                {visibleEntries.map((entry, localIndex) => {
                    const absoluteIndex = startIndex + localIndex;
                    const isSelected = selectedLines.has(entry.id);
                    return (
                        <div
                            key={entry.id}
                            onClick={() => { setExpandedLogId(entry.id); }}
                            style={{
                                ...styles.row,
                                ...(expandedLogId === entry.id ? styles.rowExpanded : null),
                            }}
                        >
                            <div style={styles.timestampCell}>{entry.timestamp}</div>
                            <div style={styles.sourceCell}>{normalizeSource(entry.source)}</div>
                            <div
                                style={{
                                    ...styles.messageCell,
                                    color: SEVERITY_COLORS[entry.severity],
                                }}
                            >
                                <span style={styles.severityLabel}>[{entry.severity.toUpperCase()}]</span>{' '}
                                {renderHighlightedText(entry.message, regex.highlight)}
                            </div>
                            <div style={styles.selectCell}>
                                <button
                                    onClick={(event) => { handleToggleLine(absoluteIndex, entry.id, event); }}
                                    style={{
                                        ...styles.checkbox,
                                        borderColor: isSelected ? '#00ff41' : '#444',
                                        color: isSelected ? '#00ff41' : '#333',
                                    }}
                                    title="Toggle line selection (Shift-click for range)"
                                >
                                    {isSelected ? 'x' : ''}
                                </button>
                            </div>
                        </div>
                    );
                })}

                <div style={{ height: `${bottomSpacerHeight}px` }} />
            </div>

            <div style={styles.detailsPane}>
                {expandedEntry === null ? (
                    <div style={styles.placeholder}>Click a log line to inspect full details</div>
                ) : (
                    <>
                        <div style={styles.detailsHeader}>
                            <span style={{ color: SEVERITY_COLORS[expandedEntry.severity], fontWeight: 700 }}>
                                {expandedEntry.severity.toUpperCase()}
                            </span>
                            <span>{expandedEntry.timestamp}</span>
                            <span>{normalizeSource(expandedEntry.source)}</span>
                        </div>
                        <pre style={styles.rawBlock}>{expandedEntry.raw}</pre>
                        {expandedEntry.structured !== undefined && (
                            <pre style={styles.jsonBlock}>{JSON.stringify(expandedEntry.structured, null, 2)}</pre>
                        )}
                    </>
                )}
            </div>
        </div>
    );
}

function parseRegex(input: string): ParsedRegex {
    const value = input.trim();
    if (value.length === 0) {
        return { filter: null, highlight: null, error: null };
    }

    let source = value;
    let flags = 'i';

    const slashPattern = /^\/(.*)\/([a-z]*)$/i.exec(value);
    if (slashPattern !== null) {
        source = slashPattern[1] ?? '';
        flags = slashPattern[2] ?? '';
    }

    try {
        const dedupedFlags = [...new Set(flags.split(''))].join('');
        const filterFlags = dedupedFlags.replace(/g/g, '');
        const highlightFlags = filterFlags.includes('g') ? filterFlags : `${filterFlags}g`;

        return {
            filter: new RegExp(source, filterFlags),
            highlight: new RegExp(source, highlightFlags),
            error: null,
        };
    } catch (error) {
        return {
            filter: null,
            highlight: null,
            error: error instanceof Error ? error.message : 'Invalid pattern',
        };
    }
}

function normalizeSource(source: string): SourceTab {
    const lower = source.toLowerCase();
    if (lower.includes('auth')) return 'auth.log';
    if (lower.includes('syslog')) return 'syslog';
    if (lower.includes('access')) return 'access.log';
    if (lower.includes('error')) return 'error.log';
    if (lower.includes('kern')) return 'kern.log';
    return 'syslog';
}

function renderHighlightedText(text: string, regex: RegExp | null): React.ReactNode {
    if (regex === null || text.length === 0) {
        return text;
    }

    regex.lastIndex = 0;
    const parts: React.ReactNode[] = [];
    let last = 0;
    let match = regex.exec(text);

    while (match !== null) {
        const fullMatch = match[0] ?? '';
        const index = match.index;

        if (index > last) {
            parts.push(text.slice(last, index));
        }

        if (fullMatch.length > 0) {
            parts.push(
                <mark key={`${index}-${fullMatch}`} style={styles.highlight}>
                    {fullMatch}
                </mark>,
            );
            last = index + fullMatch.length;
        } else {
            // Prevent infinite loops on zero-length matches.
            regex.lastIndex += 1;
            last = index;
        }

        match = regex.exec(text);
    }

    if (last < text.length) {
        parts.push(text.slice(last));
    }

    return parts.length > 0 ? parts : text;
}

function formatLogLine(entry: LogEntry): string {
    if (entry.raw.trim().length > 0) return entry.raw;
    return `${entry.timestamp} ${entry.source} [${entry.severity.toUpperCase()}] ${entry.message}`;
}

async function copyToClipboard(value: string): Promise<void> {
    if (value.length === 0) return;

    try {
        await navigator.clipboard.writeText(value);
        return;
    } catch {
        // Fallback for restricted clipboard environments.
    }

    const textarea = document.createElement('textarea');
    textarea.value = value;
    textarea.setAttribute('readonly', 'true');
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    document.body.append(textarea);
    textarea.select();
    document.execCommand('copy');
    textarea.remove();
}

interface LogViewerStyles {
    readonly root: CSSProperties;
    readonly toolbar: CSSProperties;
    readonly tabsRow: CSSProperties;
    readonly tab: CSSProperties;
    readonly tabActive: CSSProperties;
    readonly controlsRow: CSSProperties;
    readonly search: CSSProperties;
    readonly button: CSSProperties;
    readonly metaRow: CSSProperties;
    readonly errorText: CSSProperties;
    readonly header: CSSProperties;
    readonly list: CSSProperties;
    readonly row: CSSProperties;
    readonly rowExpanded: CSSProperties;
    readonly timestampCell: CSSProperties;
    readonly sourceCell: CSSProperties;
    readonly messageCell: CSSProperties;
    readonly severityLabel: CSSProperties;
    readonly selectCell: CSSProperties;
    readonly checkbox: CSSProperties;
    readonly highlight: CSSProperties;
    readonly detailsPane: CSSProperties;
    readonly detailsHeader: CSSProperties;
    readonly rawBlock: CSSProperties;
    readonly jsonBlock: CSSProperties;
    readonly placeholder: CSSProperties;
}

const styles: LogViewerStyles = {
    root: {
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        background: '#0a0e14',
        color: '#e6edf3',
        fontFamily: 'var(--font-mono)',
        fontSize: '0.74rem',
    },
    toolbar: {
        display: 'flex',
        flexDirection: 'column',
        gap: '6px',
        padding: '8px',
        borderBottom: '1px solid #21262d',
        background: '#0d1117',
    },
    tabsRow: {
        display: 'flex',
        flexWrap: 'wrap',
        gap: '4px',
    },
    tab: {
        padding: '3px 8px',
        border: '1px solid #21262d',
        borderRadius: '3px',
        background: '#111827',
        color: '#8b949e',
        cursor: 'pointer',
        fontFamily: 'inherit',
        fontSize: '0.72rem',
    },
    tabActive: {
        border: '1px solid #00ff41',
        color: '#e6edf3',
        background: '#122018',
    },
    controlsRow: {
        display: 'flex',
        flexWrap: 'wrap',
        gap: '6px',
        alignItems: 'center',
    },
    search: {
        flex: '1 1 280px',
        minWidth: '180px',
        borderRadius: '3px',
        borderWidth: '1px',
        borderStyle: 'solid',
        background: '#10151e',
        color: '#e6edf3',
        padding: '5px 8px',
        fontFamily: 'inherit',
        fontSize: '0.75rem',
        outline: 'none',
    },
    button: {
        padding: '4px 8px',
        border: '1px solid #21262d',
        borderRadius: '3px',
        background: '#111827',
        color: '#d0d7de',
        cursor: 'pointer',
        fontFamily: 'inherit',
        fontSize: '0.72rem',
    },
    metaRow: {
        display: 'flex',
        flexWrap: 'wrap',
        gap: '12px',
        color: '#7d8590',
        fontSize: '0.68rem',
    },
    errorText: {
        color: '#ff5555',
    },
    header: {
        display: 'grid',
        gridTemplateColumns: '170px 96px minmax(240px, 1fr) 40px',
        gap: '8px',
        padding: '6px 10px',
        borderBottom: '1px solid #21262d',
        background: '#0f1520',
        color: '#8b949e',
        fontSize: '0.68rem',
        textTransform: 'uppercase',
        letterSpacing: '0.04em',
    },
    list: {
        flex: 1,
        overflowY: 'auto',
        overflowX: 'hidden',
    },
    row: {
        display: 'grid',
        gridTemplateColumns: '170px 96px minmax(240px, 1fr) 40px',
        gap: '8px',
        alignItems: 'center',
        height: `${ROW_HEIGHT}px`,
        padding: '0 10px',
        borderBottom: '1px solid #171b22',
        cursor: 'pointer',
    },
    rowExpanded: {
        background: 'rgba(98, 114, 164, 0.12)',
    },
    timestampCell: {
        color: '#9db1c2',
        whiteSpace: 'nowrap',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
    },
    sourceCell: {
        color: '#a5b4c3',
        whiteSpace: 'nowrap',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
    },
    messageCell: {
        whiteSpace: 'nowrap',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
    },
    severityLabel: {
        color: '#6e7681',
        fontWeight: 700,
        fontSize: '0.65rem',
    },
    selectCell: {
        display: 'flex',
        justifyContent: 'center',
    },
    checkbox: {
        width: '16px',
        height: '16px',
        borderWidth: '1px',
        borderStyle: 'solid',
        borderRadius: '2px',
        background: '#0a0e14',
        fontFamily: 'inherit',
        fontSize: '0.7rem',
        lineHeight: '14px',
        cursor: 'pointer',
        padding: 0,
    },
    highlight: {
        background: '#f1fa8c',
        color: '#0a0e14',
        padding: 0,
    },
    detailsPane: {
        minHeight: '120px',
        maxHeight: '35%',
        overflow: 'auto',
        borderTop: '1px solid #21262d',
        background: '#0a111a',
        padding: '8px 10px',
    },
    detailsHeader: {
        display: 'flex',
        gap: '12px',
        alignItems: 'center',
        color: '#9db1c2',
        marginBottom: '6px',
        fontSize: '0.68rem',
    },
    rawBlock: {
        margin: 0,
        color: '#dce3eb',
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-word',
        fontFamily: 'inherit',
        fontSize: '0.72rem',
    },
    jsonBlock: {
        margin: '8px 0 0 0',
        color: '#8be9fd',
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-word',
        fontFamily: 'inherit',
        fontSize: '0.7rem',
        background: '#10151e',
        border: '1px solid #1f2630',
        padding: '8px',
        borderRadius: '4px',
    },
    placeholder: {
        color: '#6e7681',
        fontSize: '0.72rem',
    },
};
