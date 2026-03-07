/**
 * VARIANT — Browser Lens
 *
 * Renders HTTP responses from simulated services. The player types
 * a URL in the address bar, the lens routes it through the VARIANT
 * Internet module (or directly to a machine's web service), and
 * renders the HTML response.
 *
 * This is NOT an iframe. It's a sandboxed HTML renderer that:
 *   - Renders HTML/CSS from simulated servers
 *   - Intercepts link clicks to stay within the simulation
 *   - Supports form submission (POST to simulated endpoints)
 *   - Shows raw source via "View Source"
 *   - Cannot access the real internet (air-gapped)
 *
 * SECURITY: All content comes from the simulation's fabricated
 * HTTP services. The srcdoc iframe is sandboxed with no script
 * execution. Links are intercepted and re-routed through the
 * simulation's network fabric.
 */

import { useState, useCallback, useRef, useEffect } from 'react';

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

export function BrowserLens({ initialUrl, onNavigate, focused }: BrowserLensProps): JSX.Element {
    const [url, setUrl] = useState(initialUrl ?? 'about:blank');
    const [addressBar, setAddressBar] = useState(initialUrl ?? '');
    const [response, setResponse] = useState<BrowserResponse | null>(null);
    const [viewSource, setViewSource] = useState(false);
    const [loading, setLoading] = useState(false);
    const [history, setHistory] = useState<HistoryEntry[]>([]);
    const [historyIdx, setHistoryIdx] = useState(-1);
    const addressRef = useRef<HTMLInputElement | null>(null);
    const iframeRef = useRef<HTMLIFrameElement | null>(null);

    const navigate = useCallback((targetUrl: string, method?: string, body?: string) => {
        setLoading(true);
        setViewSource(false);

        // Normalize URL
        let normalized = targetUrl.trim();
        if (!normalized.startsWith('http://') && !normalized.startsWith('https://') && normalized !== 'about:blank') {
            normalized = `http://${normalized}`;
        }

        setUrl(normalized);
        setAddressBar(normalized);

        if (normalized === 'about:blank') {
            setResponse({ status: 200, statusText: 'OK', headers: new Map(), body: '', contentType: 'text/html' });
            setLoading(false);
            return;
        }

        const resp = onNavigate(normalized, method, body);
        setResponse(resp);
        setLoading(false);

        // Push to history
        const title = extractTitle(resp.body) || normalized;
        setHistory(prev => {
            const trimmed = prev.slice(0, historyIdx + 1);
            return [...trimmed, { url: normalized, title }];
        });
        setHistoryIdx(prev => prev + 1);
    }, [onNavigate, historyIdx]);

    // Load initial URL
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

    // Intercept link clicks inside the iframe
    useEffect(() => {
        const iframe = iframeRef.current;
        if (iframe === null || response === null) return;

        const handleLoad = (): void => {
            try {
                const doc = iframe.contentDocument;
                if (doc === null) return;

                // Intercept all link clicks
                doc.addEventListener('click', (e: MouseEvent) => {
                    const target = (e.target as Element).closest('a');
                    if (target === null) return;

                    const href = target.getAttribute('href');
                    if (href === null || href.startsWith('javascript:')) return;

                    e.preventDefault();

                    // Resolve relative URLs
                    let resolved: string;
                    try {
                        resolved = new URL(href, url).href;
                    } catch {
                        resolved = href;
                    }
                    navigate(resolved);
                });

                // Intercept form submissions
                doc.addEventListener('submit', (e: SubmitEvent) => {
                    e.preventDefault();
                    const form = e.target as HTMLFormElement;
                    const formData = new FormData(form);
                    const method = (form.method || 'GET').toUpperCase();
                    const action = form.action || url;

                    let resolved: string;
                    try {
                        resolved = new URL(action, url).href;
                    } catch {
                        resolved = action;
                    }

                    if (method === 'GET') {
                        const params = new URLSearchParams(formData as unknown as Record<string, string>);
                        navigate(`${resolved}?${params.toString()}`);
                    } else {
                        const params = new URLSearchParams(formData as unknown as Record<string, string>);
                        navigate(resolved, 'POST', params.toString());
                    }
                });
            } catch {
                // Cross-origin restrictions — expected for sandboxed iframes
            }
        };

        iframe.addEventListener('load', handleLoad);
        return () => { iframe.removeEventListener('load', handleLoad); };
    }, [response, url, navigate]);

    const statusColor = response === null ? '#666'
        : response.status < 300 ? '#00ff41'
            : response.status < 400 ? '#f1fa8c'
                : response.status < 500 ? '#ffaa00'
                    : '#ff5555';

    return (
        <div style={{
            display: 'flex',
            flexDirection: 'column',
            height: '100%',
            background: 'var(--bg-primary, #0a0e14)',
            color: 'var(--text-primary, #e6edf3)',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.75rem',
        }}>
            {/* Toolbar */}
            <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
                padding: '4px 8px',
                background: 'var(--bg-secondary, #0d1117)',
                borderBottom: '1px solid var(--border-default, #21262d)',
                minHeight: '32px',
            }}>
                {/* Nav buttons */}
                <button onClick={handleBack} disabled={historyIdx <= 0} style={navBtnStyle}>
                    {'<'}
                </button>
                <button onClick={handleForward} disabled={historyIdx >= history.length - 1} style={navBtnStyle}>
                    {'>'}
                </button>
                <button onClick={() => { navigate(url); }} style={navBtnStyle}>
                    {loading ? '...' : 'R'}
                </button>

                {/* Address bar */}
                <form onSubmit={handleAddressSubmit} style={{ flex: 1, display: 'flex' }}>
                    <input
                        ref={addressRef}
                        type="text"
                        value={addressBar}
                        onChange={(e) => { setAddressBar(e.target.value); }}
                        placeholder="Enter URL..."
                        style={{
                            flex: 1,
                            background: 'var(--bg-elevated, #1c2128)',
                            border: '1px solid var(--border-default, #21262d)',
                            borderRadius: '3px',
                            color: 'var(--text-primary, #e6edf3)',
                            fontFamily: 'inherit',
                            fontSize: '0.75rem',
                            padding: '4px 8px',
                            outline: 'none',
                        }}
                        autoFocus={focused}
                    />
                </form>

                {/* View source toggle */}
                <button
                    onClick={() => { setViewSource(!viewSource); }}
                    style={{
                        ...navBtnStyle,
                        color: viewSource ? '#00ff41' : '#666',
                        fontSize: '0.65rem',
                    }}
                >
                    {'</>'}
                </button>
            </div>

            {/* Status bar */}
            {response !== null && (
                <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '12px',
                    padding: '2px 8px',
                    background: 'var(--bg-secondary, #0d1117)',
                    borderBottom: '1px solid var(--border-default, #21262d)',
                    fontSize: '0.65rem',
                    color: '#666',
                }}>
                    <span style={{ color: statusColor }}>
                        {response.status} {response.statusText}
                    </span>
                    <span>{response.contentType}</span>
                    <span>{response.body.length} bytes</span>
                </div>
            )}

            {/* Content area */}
            <div style={{ flex: 1, overflow: 'auto', position: 'relative' }}>
                {viewSource ? (
                    <pre style={{
                        padding: '8px',
                        margin: 0,
                        fontSize: '0.75rem',
                        lineHeight: 1.5,
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                        color: '#8be9fd',
                    }}>
                        {response?.body ?? ''}
                    </pre>
                ) : (
                    <iframe
                        ref={iframeRef}
                        srcDoc={response?.body ?? ''}
                        sandbox="allow-same-origin allow-forms"
                        style={{
                            width: '100%',
                            height: '100%',
                            border: 'none',
                            background: '#fff',
                        }}
                        title="VARIANT Browser"
                    />
                )}
            </div>
        </div>
    );
}

// ── Helpers ──────────────────────────────────────────────────────

function extractTitle(html: string): string {
    const match = /<title[^>]*>(.*?)<\/title>/is.exec(html);
    return match !== null ? match[1]!.trim() : '';
}

const navBtnStyle: React.CSSProperties = {
    background: 'transparent',
    border: '1px solid var(--border-default, #21262d)',
    borderRadius: '3px',
    color: '#666',
    fontFamily: 'inherit',
    fontSize: '0.75rem',
    padding: '2px 8px',
    cursor: 'pointer',
    minWidth: '28px',
    textAlign: 'center',
};
