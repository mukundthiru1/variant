/**
 * VARIANT — Browser Lens
 *
 * Renders HTTP responses from simulated services. The player types
 * a URL in the address bar, the lens routes it through the VARIANT
 * Internet module (or directly to a machine's web service), and
 * renders the HTML response.
 *
 * Browser chrome: back/forward/refresh, address bar, view-source.
 * Content is rendered in a sandboxed container; link clicks and
 * form submissions are intercepted and routed through the simulation.
 *
 * SECURITY: All content comes from the simulation's fabricated
 * HTTP services. Links and forms are re-routed through the
 * simulation's network fabric. No real internet access.
 */

import { useState, useCallback, useRef, useEffect, type ReactNode } from 'react';

export interface BrowserLensProps {
    /** Initial URL to load. */
    readonly initialUrl?: string;
    /** Handler to fetch a URL from the simulated internet. Returns HTML body. */
    readonly onNavigate: (url: string, method?: string, body?: string) => BrowserResponse;
    readonly focused: boolean;
}

export interface BrowserResponse {
    readonly status: number;
    readonly statusText: string;
    readonly headers: ReadonlyMap<string, string>;
    readonly body: string;
    readonly contentType: string;
}

interface HistoryEntry {
    readonly url: string;
    readonly title: string;
}

const CHROME_BG = '#111111';
const CHROME_ACTIVE = '#D4A03A';
const STATUS_BAR_BG = '#0A0A0A';
const STATUS_BAR_TEXT = '#707070';
const CONTENT_BG = '#ffffff';

export function BrowserLens({ initialUrl, onNavigate, focused }: BrowserLensProps): JSX.Element {
    const [url, setUrl] = useState(initialUrl ?? 'about:blank');
    const [addressBar, setAddressBar] = useState(initialUrl ?? '');
    const [response, setResponse] = useState<BrowserResponse | null>(null);
    const [viewSource, setViewSource] = useState(false);
    const [loading, setLoading] = useState(false);
    const [responseTimeMs, setResponseTimeMs] = useState<number | null>(null);
    const [history, setHistory] = useState<HistoryEntry[]>([]);
    const [historyIdx, setHistoryIdx] = useState(-1);
    const [addressFocused, setAddressFocused] = useState(false);
    const addressRef = useRef<HTMLInputElement | null>(null);
    const contentRef = useRef<HTMLDivElement | null>(null);

    const navigate = useCallback((targetUrl: string, method?: string, body?: string) => {
        setLoading(true);
        setViewSource(false);

        let normalized = targetUrl.trim();
        if (!normalized.startsWith('http://') && !normalized.startsWith('https://') && normalized !== 'about:blank') {
            normalized = `http://${normalized}`;
        }

        setUrl(normalized);
        setAddressBar(normalized);

        if (normalized === 'about:blank') {
            setResponse({ status: 200, statusText: 'OK', headers: new Map(), body: '', contentType: 'text/html' });
            setLoading(false);
            setResponseTimeMs(null);
            return;
        }

        const start = performance.now();
        const resp = onNavigate(normalized, method, body);
        setResponseTimeMs(Math.round(performance.now() - start));
        setResponse(resp);
        setLoading(false);

        const title = extractTitle(resp.body) || normalized;
        setHistory(prev => {
            const trimmed = prev.slice(0, historyIdx + 1);
            return [...trimmed, { url: normalized, title }];
        });
        setHistoryIdx(prev => prev + 1);
    }, [onNavigate, historyIdx]);

    useEffect(() => {
        if (initialUrl !== undefined && initialUrl !== 'about:blank') {
            navigate(initialUrl);
        }
    }, []); // eslint-disable-line react-hooks/exhaustive-deps

    const handleAddressSubmit = useCallback((e: React.FormEvent) => {
        e.preventDefault();
        navigate(addressBar);
    }, [addressBar, navigate]);

    const handleBack = useCallback(() => {
        if (historyIdx > 0) {
            const newIdx = historyIdx - 1;
            const entry = history[newIdx];
            if (entry !== undefined) {
                setHistoryIdx(newIdx);
                setUrl(entry.url);
                setAddressBar(entry.url);
                const resp = onNavigate(entry.url);
                setResponse(resp);
            }
        }
    }, [historyIdx, history, onNavigate]);

    const handleForward = useCallback(() => {
        if (historyIdx < history.length - 1) {
            const newIdx = historyIdx + 1;
            const entry = history[newIdx];
            if (entry !== undefined) {
                setHistoryIdx(newIdx);
                setUrl(entry.url);
                setAddressBar(entry.url);
                const resp = onNavigate(entry.url);
                setResponse(resp);
            }
        }
    }, [historyIdx, history, onNavigate]);

    const handleContentClick = useCallback((e: React.MouseEvent<HTMLDivElement>) => {
        const target = (e.target as Element).closest('a');
        if (target === null) return;
        const href = (target as HTMLAnchorElement).getAttribute('href');
        if (href === null || href.startsWith('javascript:')) return;
        e.preventDefault();
        let resolved: string;
        try {
            resolved = new URL(href, url).href;
        } catch {
            resolved = href;
        }
        navigate(resolved);
    }, [url, navigate]);

    const handleContentSubmit = useCallback((e: React.FormEvent<HTMLDivElement>) => {
        const form = (e.target as Element).closest('form') as HTMLFormElement | null;
        if (form === null) return;
        e.preventDefault();
        const formData = new FormData(form);
        const method = (form.method || 'GET').toUpperCase();
        const action = form.getAttribute('action') || url;
        let resolved: string;
        try {
            resolved = new URL(action, url).href;
        } catch {
            resolved = action;
        }
        if (method === 'GET') {
            const params = new URLSearchParams(Array.from(formData.entries()) as unknown as [string, string][]);
            const sep = resolved.includes('?') ? '&' : '?';
            navigate(params.toString() ? `${resolved}${sep}${params.toString()}` : resolved);
        } else {
            const params = new URLSearchParams(Array.from(formData.entries()) as unknown as [string, string][]);
            navigate(resolved, 'POST', params.toString());
        }
    }, [url, navigate]);

    const statusColor = response === null ? STATUS_BAR_TEXT
        : response.status < 300 ? '#3DA67A'
            : response.status < 400 ? '#f1fa8c'
                : response.status < 500 ? '#ffaa00'
                    : '#ff5555';

    return (
        <>
            <style>{`
                @keyframes browser-lens-spin { to { transform: rotate(360deg); } }
                @keyframes browser-lens-loading-bar {
                    0% { transform: translateX(-100%); }
                    50% { transform: translateX(0%); }
                    100% { transform: translateX(100%); }
                }
            `}</style>
            {loading && (
                <div
                    style={{
                        position: 'absolute',
                        top: 0,
                        left: 0,
                        right: 0,
                        height: '3px',
                        background: '#D4A03A',
                        animation: 'browser-lens-loading-bar 1.2s ease-in-out infinite',
                        zIndex: 10,
                    }}
                    aria-hidden
                />
            )}
            <div style={{
            position: 'relative',
            display: 'flex',
            flexDirection: 'column',
            height: '100%',
            background: CHROME_BG,
            color: 'var(--text-primary, #e6edf3)',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.75rem',
        }}>
            {/* Browser chrome */}
            <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '6px 10px',
                background: CHROME_BG,
                borderBottom: '1px solid rgba(255,255,255,0.08)',
                minHeight: '36px',
            }}>
                <button
                    type="button"
                    onClick={handleBack}
                    disabled={historyIdx <= 0}
                    style={navBtnStyle(historyIdx <= 0)}
                    aria-label="Back"
                >
                    ←
                </button>
                <button
                    type="button"
                    onClick={handleForward}
                    disabled={historyIdx >= Math.max(0, history.length - 1)}
                    style={navBtnStyle(historyIdx >= Math.max(0, history.length - 1))}
                    aria-label="Forward"
                >
                    →
                </button>
                <button
                    type="button"
                    onClick={() => { navigate(url); }}
                    disabled={loading}
                    style={navBtnStyle(false)}
                    aria-label="Refresh"
                >
                    {loading ? (
                        <span style={{
                            display: 'inline-block',
                            width: 10,
                            height: 10,
                            border: '2px solid rgba(255,255,255,0.2)',
                            borderTopColor: CHROME_ACTIVE,
                            borderRadius: '50%',
                            animation: 'browser-lens-spin 0.6s linear infinite',
                        }} />
                    ) : (
                        '⟳'
                    )}
                </button>

                <form onSubmit={handleAddressSubmit} style={{ flex: 1, display: 'flex', minWidth: 0, alignItems: 'center', gap: '6px' }}>
                    <span
                        style={{
                            flexShrink: 0,
                            fontSize: '0.9rem',
                            color: url.startsWith('https://') ? '#3DA67A' : url.startsWith('http://') ? '#f1fa8c' : 'var(--text-muted, #707070)',
                        }}
                        aria-hidden
                    >
                        {url.startsWith('https://') ? '\u{1F512}' : url.startsWith('http://') ? '\u26A0' : ''}
                    </span>
                    <input
                        ref={addressRef}
                        type="text"
                        value={addressBar}
                        onChange={(e) => { setAddressBar(e.target.value); }}
                        onFocus={() => { setAddressFocused(true); }}
                        onBlur={() => { setAddressFocused(false); }}
                        placeholder="Enter URL and press Enter..."
                        style={{
                            flex: 1,
                            width: '100%',
                            background: addressFocused ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.3)',
                            border: `1px solid ${addressFocused ? CHROME_ACTIVE : 'rgba(255,255,255,0.12)'}`,
                            borderRadius: '4px',
                            color: 'var(--text-primary, #e6edf3)',
                            fontFamily: 'var(--font-mono)',
                            fontSize: '0.8rem',
                            padding: '6px 10px',
                            outline: 'none',
                            boxShadow: addressFocused ? `0 0 0 1px ${CHROME_ACTIVE}` : 'none',
                        }}
                        autoFocus={focused}
                    />
                </form>

                <button
                    type="button"
                    onClick={() => { setViewSource(!viewSource); }}
                    style={{
                        ...navBtnStyle(false),
                        color: viewSource ? CHROME_ACTIVE : 'var(--text-muted, #707070)',
                        fontSize: '0.7rem',
                    }}
                    aria-label={viewSource ? 'View page' : 'View source'}
                >
                    {'</>'}
                </button>
            </div>

            {/* Content area */}
            <div style={{ flex: 1, overflow: 'auto', position: 'relative', minHeight: 0 }}>
                {viewSource ? (
                    <pre style={{
                        padding: '12px',
                        margin: 0,
                        fontSize: '0.75rem',
                        lineHeight: 1.5,
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                        background: '#0d1117',
                        fontFamily: 'var(--font-mono), ui-monospace, monospace',
                    }}>
                        {highlightHtml(response?.body ?? '')}
                    </pre>
                ) : (
                    <div
                        ref={contentRef}
                        onClick={handleContentClick}
                        onSubmit={handleContentSubmit}
                        style={{
                            width: '100%',
                            minHeight: '100%',
                            background: CONTENT_BG,
                            color: '#1D1D1F',
                        }}
                        className="browser-content-sandbox"
                    >
                        {response?.body != null && response.body !== '' ? (
                            <div
                                dangerouslySetInnerHTML={{ __html: response.body }}
                                style={{ padding: 0, margin: 0 }}
                            />
                        ) : (
                            <div style={{ padding: 16, color: '#707070' }}>No content</div>
                        )}
                    </div>
                )}
            </div>

            {/* Status bar (bottom) */}
            <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                padding: '4px 10px',
                background: STATUS_BAR_BG,
                borderTop: '1px solid rgba(255,255,255,0.06)',
                fontSize: '0.65rem',
                color: STATUS_BAR_TEXT,
                minHeight: '22px',
            }}>
                {response !== null && (
                    <>
                        <span style={{ color: statusColor }}>
                            {response.status} {response.statusText}
                        </span>
                        <span>{response.contentType}</span>
                        {responseTimeMs !== null && <span>{responseTimeMs} ms</span>}
                    </>
                )}
            </div>
        </div>
        </>
    );
}

// ── Helpers ──────────────────────────────────────────────────────

const SOURCE_COLORS = {
    tag: '#569cd6',
    attrName: '#9cdcfe',
    attrValue: '#ce9178',
    comment: '#6a9955',
    doctype: '#808080',
    punctuation: '#d4d4d4',
    text: '#d4d4d4',
} as const;

function highlightHtml(html: string): ReactNode {
    if (html === '') return '';
    const out: ReactNode[] = [];
    let i = 0;
    const len = html.length;
    while (i < len) {
        if (html.slice(i).startsWith('<!--')) {
            const end = html.indexOf('-->', i);
            const comment = end === -1 ? html.slice(i) : html.slice(i, end + 3);
            out.push(<span key={i} style={{ color: SOURCE_COLORS.comment }}>{comment}</span>);
            i += comment.length;
            continue;
        }
        if (html.slice(i).startsWith('<!') && !html.slice(i).startsWith('<!--')) {
            const close = html.indexOf('>', i);
            const doctype = close === -1 ? html.slice(i) : html.slice(i, close + 1);
            out.push(<span key={i} style={{ color: SOURCE_COLORS.doctype }}>{doctype}</span>);
            i += doctype.length;
            continue;
        }
        if (html[i] === '<') {
            const tagEnd = html.indexOf('>', i);
            const raw = tagEnd === -1 ? html.slice(i) : html.slice(i, tagEnd + 1);
            out.push(<span key={i}>{highlightTag(raw)}</span>);
            i += raw.length;
            continue;
        }
        const nextLt = html.indexOf('<', i);
        const textEnd = nextLt === -1 ? len : nextLt;
        const text = html.slice(i, textEnd);
        if (text.length > 0) {
            out.push(<span key={i} style={{ color: SOURCE_COLORS.text }}>{text}</span>);
        }
        i = textEnd;
    }
    return <>{out}</>;
}

function highlightTag(tag: string): ReactNode {
    const parts: ReactNode[] = [];
    let i = 0;
    if (tag[i] === '<') {
        parts.push(<span key="open" style={{ color: SOURCE_COLORS.punctuation }}>{'<'}</span>);
        i++;
    }
    if (tag[i] === '/') {
        parts.push(<span key="slash" style={{ color: SOURCE_COLORS.punctuation }}>/</span>);
        i++;
    }
    const nameMatch = /^[\w-]+/.exec(tag.slice(i));
    if (nameMatch) {
        parts.push(<span key="name" style={{ color: SOURCE_COLORS.tag }}>{nameMatch[0]}</span>);
        i += nameMatch[0].length;
    }
    const rest = tag.slice(i);
    const attrRegex = /(\s+)([\w-]+)(\s*=\s*)(["'][^"']*["']|[^\s>]+)/g;
    let lastIdx = 0;
    let m: RegExpExecArray | null;
    while ((m = attrRegex.exec(rest)) !== null) {
        parts.push(<span key={`ws-${m.index}`} style={{ color: SOURCE_COLORS.punctuation }}>{m[1]}</span>);
        parts.push(<span key={`an-${m.index}`} style={{ color: SOURCE_COLORS.attrName }}>{m[2]}</span>);
        parts.push(<span key={`eq-${m.index}`} style={{ color: SOURCE_COLORS.punctuation }}>{m[3]}</span>);
        parts.push(<span key={`av-${m.index}`} style={{ color: SOURCE_COLORS.attrValue }}>{m[4]}</span>);
        lastIdx = m.index + m[0].length;
    }
    if (lastIdx < rest.length) {
        parts.push(<span key="tail" style={{ color: SOURCE_COLORS.punctuation }}>{rest.slice(lastIdx)}</span>);
    }
    return <>{parts}</>;
}

function extractTitle(html: string): string {
    const match = /<title[^>]*>(.*?)<\/title>/is.exec(html);
    return match !== null ? match[1]!.trim() : '';
}

function navBtnStyle(disabled: boolean): React.CSSProperties {
    return {
        background: 'transparent',
        border: '1px solid rgba(255,255,255,0.12)',
        borderRadius: '4px',
        color: disabled ? 'rgba(255,255,255,0.3)' : 'var(--text-secondary, #8b949e)',
        opacity: disabled ? 0.5 : 1,
        fontFamily: 'inherit',
        fontSize: '0.85rem',
        padding: '4px 8px',
        cursor: disabled ? 'default' : 'pointer',
        minWidth: '28px',
        textAlign: 'center',
    };
}
