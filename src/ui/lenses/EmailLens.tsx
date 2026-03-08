import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

export interface EmailLensProps {
    readonly account: string;
    readonly emails: readonly EmailMessage[];
    readonly onSend: (to: string, subject: string, body: string) => void;
    readonly onMarkRead: (emailId: string) => void;
    readonly focused: boolean;
}

export interface EmailMessage {
    readonly id: string;
    readonly from: string;
    readonly to: string;
    readonly subject: string;
    readonly body: string;
    readonly date: string;
    readonly read: boolean;
    readonly folder: 'inbox' | 'sent' | 'drafts' | 'spam';
    readonly attachments?: readonly { name: string; size: number }[];
    readonly headers?: Readonly<Record<string, string>>;
}

type MailFolder = EmailMessage['folder'];

type ComposePrefill = {
    to: string;
    subject: string;
    body: string;
};

const FOLDERS: readonly MailFolder[] = ['inbox', 'sent', 'drafts', 'spam'];

function normalizeSubjectForThread(subject: string): string {
    const trimmed = subject.trim();
    const lower = trimmed.toLowerCase();
    if (lower.startsWith('re:')) return normalizeSubjectForThread(trimmed.slice(3).trim());
    if (lower.startsWith('fwd:')) return normalizeSubjectForThread(trimmed.slice(4).trim());
    if (lower.startsWith('fw:')) return normalizeSubjectForThread(trimmed.slice(3).trim());
    return trimmed.length > 0 ? trimmed : subject;
}

export function EmailLens({ account, emails, onSend, onMarkRead, focused }: EmailLensProps): JSX.Element {
    const [activeFolder, setActiveFolder] = useState<MailFolder>('inbox');
    const [selectedEmailId, setSelectedEmailId] = useState<string | null>(null);
    const [searchQuery, setSearchQuery] = useState('');
    const [showCompose, setShowCompose] = useState(false);
    const [composeTo, setComposeTo] = useState('');
    const [composeSubject, setComposeSubject] = useState('');
    const [composeBody, setComposeBody] = useState('');
    const [composeOrigin, setComposeOrigin] = useState<'new' | 'reply' | 'forward'>('new');
    const composeToRef = useRef<HTMLInputElement | null>(null);

    const folderCounts = useMemo(() => {
        const counts: Record<MailFolder, number> = {
            inbox: 0,
            sent: 0,
            drafts: 0,
            spam: 0,
        };
        for (const email of emails) {
            counts[email.folder] += 1;
        }
        return counts;
    }, [emails]);

    const folderEmails = useMemo(() => {
        const filtered = emails.filter(email => email.folder === activeFolder);
        return [...filtered].sort((a, b) => Date.parse(b.date) - Date.parse(a.date));
    }, [emails, activeFolder]);

    const folderEmailsFiltered = useMemo(() => {
        const q = searchQuery.trim().toLowerCase();
        if (q === '') return folderEmails;
        return folderEmails.filter(email => {
            const from = email.from.toLowerCase();
            const to = email.to.toLowerCase();
            const subj = email.subject.toLowerCase();
            const bodyPlain = toPlainText(email.body).toLowerCase();
            return from.includes(q) || to.includes(q) || subj.includes(q) || bodyPlain.includes(q);
        });
    }, [folderEmails, searchQuery]);

    type EmailThread = { normalizedSubject: string; displaySubject: string; emails: EmailMessage[] };
    const threads = useMemo((): EmailThread[] => {
        const bySubject = new Map<string, EmailMessage[]>();
        for (const email of folderEmailsFiltered) {
            const key = normalizeSubjectForThread(email.subject);
            const list = bySubject.get(key) ?? [];
            list.push(email);
            bySubject.set(key, list);
        }
        const result: EmailThread[] = [];
        bySubject.forEach((list, normalizedSubject) => {
            const sorted = [...list].sort((a, b) => Date.parse(b.date) - Date.parse(a.date));
            const displaySubject = sorted[0]!.subject;
            result.push({ normalizedSubject, displaySubject, emails: sorted });
        });
        result.sort((a, b) => {
            const dateA = a.emails[0] ? Date.parse(a.emails[0].date) : 0;
            const dateB = b.emails[0] ? Date.parse(b.emails[0].date) : 0;
            return dateB - dateA;
        });
        return result;
    }, [folderEmailsFiltered]);

    const selectedEmail = useMemo(() => {
        if (selectedEmailId === null) return null;
        return folderEmails.find(email => email.id === selectedEmailId) ?? null;
    }, [folderEmails, selectedEmailId]);

    const selectedThread = useMemo((): EmailThread | null => {
        if (selectedEmail === null) return null;
        const key = normalizeSubjectForThread(selectedEmail.subject);
        for (const thread of threads) {
            if (thread.normalizedSubject === key && thread.emails.some(e => e.id === selectedEmail.id))
                return thread;
        }
        return null;
    }, [selectedEmail, threads]);

    useEffect(() => {
        if (folderEmailsFiltered.length === 0) {
            setSelectedEmailId(null);
            return;
        }
        const idsInFiltered = new Set(folderEmailsFiltered.map(e => e.id));
        const hasSelection = selectedEmailId !== null && idsInFiltered.has(selectedEmailId);
        if (!hasSelection) {
            const firstThreadLatest = threads[0]?.emails[0];
            setSelectedEmailId(firstThreadLatest ? firstThreadLatest.id : null);
        }
    }, [folderEmailsFiltered, threads, selectedEmailId]);

    useEffect(() => {
        if (selectedEmail !== null && !selectedEmail.read) {
            onMarkRead(selectedEmail.id);
        }
    }, [selectedEmail, onMarkRead]);

    useEffect(() => {
        if (focused && showCompose) {
            composeToRef.current?.focus();
        }
    }, [focused, showCompose]);

    const setComposeFromPrefill = useCallback((prefill: ComposePrefill, origin: 'new' | 'reply' | 'forward') => {
        setComposeTo(prefill.to);
        setComposeSubject(prefill.subject);
        setComposeBody(prefill.body);
        setComposeOrigin(origin);
        setShowCompose(true);
    }, []);

    const handleStartCompose = useCallback(() => {
        setComposeFromPrefill({ to: '', subject: '', body: '' }, 'new');
    }, [setComposeFromPrefill]);

    const handleReply = useCallback(() => {
        if (selectedEmail === null) return;
        const nextSubject = selectedEmail.subject.toLowerCase().startsWith('re:')
            ? selectedEmail.subject
            : `Re: ${selectedEmail.subject}`;
        setComposeFromPrefill({
            to: selectedEmail.from,
            subject: nextSubject,
            body: `\n\nOn ${formatDate(selectedEmail.date)}, ${selectedEmail.from} wrote:\n${toPlainText(selectedEmail.body)}`,
        }, 'reply');
    }, [selectedEmail, setComposeFromPrefill]);

    const handleForward = useCallback(() => {
        if (selectedEmail === null) return;
        const nextSubject = selectedEmail.subject.toLowerCase().startsWith('fwd:')
            ? selectedEmail.subject
            : `Fwd: ${selectedEmail.subject}`;
        const attachmentLines = selectedEmail.attachments?.length
            ? `\nAttachments: ${selectedEmail.attachments.map(att => att.name).join(', ')}`
            : '';
        setComposeFromPrefill({
            to: '',
            subject: nextSubject,
            body: `\n\n---------- Forwarded message ----------\nFrom: ${selectedEmail.from}\nDate: ${formatDate(selectedEmail.date)}\nSubject: ${selectedEmail.subject}\nTo: ${selectedEmail.to}${attachmentLines}\n\n${toPlainText(selectedEmail.body)}`,
        }, 'forward');
    }, [selectedEmail, setComposeFromPrefill]);

    const handleSend = useCallback((event: React.FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        const to = composeTo.trim();
        if (to.length === 0) return;
        onSend(to, composeSubject.trim(), composeBody);
        setComposeTo('');
        setComposeSubject('');
        setComposeBody('');
        setComposeOrigin('new');
        setShowCompose(false);
        setActiveFolder('sent');
    }, [composeTo, composeSubject, composeBody, onSend]);

    const renderedEmailBody = useMemo(() => {
        if (selectedEmail === null) return '';
        return prepareEmailBodyForSandbox(selectedEmail.body);
    }, [selectedEmail]);

    return (
        <div style={rootStyle}>
            <aside style={sidebarStyle}>
                <div style={accountStyle}>
                    <div style={{ color: '#D4A03A', fontWeight: 600 }}>MAIL</div>
                    <div style={{ color: '#9ca3af' }}>{account}</div>
                </div>
                <button onClick={handleStartCompose} style={composeButtonStyle}>Compose</button>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    {FOLDERS.map(folder => (
                        <button
                            key={folder}
                            onClick={() => {
                                setActiveFolder(folder);
                                setShowCompose(false);
                            }}
                            style={{
                                ...folderButtonStyle,
                                background: activeFolder === folder ? 'rgba(212, 160, 58, 0.12)' : 'transparent',
                                color: activeFolder === folder ? '#D4A03A' : '#e0e0e0',
                                borderColor: activeFolder === folder ? 'rgba(212, 160, 58, 0.45)' : 'transparent',
                            }}
                        >
                            <span>{folderName(folder)}</span>
                            <span style={{ color: '#9ca3af', fontSize: '0.7rem' }}>{folderCounts[folder]}</span>
                        </button>
                    ))}
                </div>
            </aside>

            <section style={listPanelStyle}>
                <div style={searchBarWrapStyle}>
                    <input
                        type="text"
                        placeholder="Search mail…"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        style={searchInputStyle}
                        aria-label="Search emails"
                    />
                </div>
                <div style={panelHeaderStyle}>
                    <span>{folderName(activeFolder)}</span>
                    <span style={{ color: 'var(--text-secondary, #e0e0e0)' }}>{folderEmailsFiltered.length} messages</span>
                </div>
                <div style={listBodyStyle}>
                    {folderEmails.length === 0 && (
                        <div style={emptyStateStyle}>No messages in {folderName(activeFolder).toLowerCase()}.</div>
                    )}
                    {folderEmails.length > 0 && threads.length === 0 && (
                        <div style={emptyStateStyle}>No messages match your search.</div>
                    )}
                    {threads.map(thread => {
                        const latest = thread.emails[0]!;
                        const hasUnread = thread.emails.some(e => !e.read);
                        const isSelected = selectedEmailId === latest.id || thread.emails.some(e => e.id === selectedEmailId);
                        return (
                            <button
                                key={thread.normalizedSubject + latest.id}
                                onClick={() => {
                                    setSelectedEmailId(latest.id);
                                    setShowCompose(false);
                                }}
                                style={{
                                    ...emailRowStyle,
                                    background: isSelected ? 'rgba(212, 160, 58, 0.12)' : 'transparent',
                                    borderLeft: isSelected
                                        ? '3px solid #D4A03A'
                                        : '3px solid transparent',
                                    fontWeight: hasUnread ? 700 : 400,
                                }}
                            >
                                <div style={emailRowTopStyle}>
                                    <span style={{ display: 'flex', alignItems: 'center', gap: '6px', minWidth: 0 }}>
                                        {hasUnread && <span style={unreadDotStyle} aria-hidden />}
                                        <span style={{ color: hasUnread ? '#e0e0e0' : 'var(--text-secondary, #9ca3af)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                            {activeFolder === 'sent' ? `To: ${latest.to}` : latest.from}
                                        </span>
                                    </span>
                                    <span style={{ color: 'var(--text-secondary, #9ca3af)', fontSize: '0.67rem', flexShrink: 0 }}>{formatDate(latest.date)}</span>
                                </div>
                                <div style={emailRowBottomStyle}>
                                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: hasUnread ? '#e0e0e0' : 'var(--text-secondary, #9ca3af)' }}>{thread.displaySubject}</span>
                                    {thread.emails.length > 1 ? (
                                        <span style={{ color: '#D4A03A', fontSize: '0.68rem', flexShrink: 0 }}>{thread.emails.length}</span>
                                    ) : latest.attachments !== undefined && latest.attachments.length > 0 ? (
                                        <span title={`${latest.attachments.length} attachment(s)`} style={{ color: '#9ca3af', fontSize: '0.8rem' }}>📎</span>
                                    ) : null}
                                </div>
                            </button>
                        );
                    })}
                </div>
            </section>

            <section style={readerPanelStyle}>
                <div style={panelHeaderStyle}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span>{showCompose ? 'Compose' : 'Message'}</span>
                        {composeOrigin !== 'new' && showCompose && (
                            <span style={{ color: '#9ca3af', fontSize: '0.67rem' }}>
                                {composeOrigin === 'reply' ? 'Reply' : 'Forward'}
                            </span>
                        )}
                    </div>
                    {!showCompose && (
                        <div style={{ display: 'flex', gap: '6px' }}>
                            <button onClick={handleReply} disabled={selectedEmail === null} style={toolbarButtonStyle}>Reply</button>
                            <button onClick={handleForward} disabled={selectedEmail === null} style={toolbarButtonStyle}>Forward</button>
                        </div>
                    )}
                </div>

                {showCompose ? (
                    <form onSubmit={handleSend} style={composeFormStyle}>
                        <label style={fieldLabelStyle}>
                            To
                            <input
                                ref={composeToRef}
                                type="text"
                                value={composeTo}
                                onChange={(event) => { setComposeTo(event.target.value); }}
                                placeholder="recipient@example.com"
                                style={inputStyle}
                            />
                        </label>
                        <label style={fieldLabelStyle}>
                            Subject
                            <input
                                type="text"
                                value={composeSubject}
                                onChange={(event) => { setComposeSubject(event.target.value); }}
                                placeholder="Subject"
                                style={inputStyle}
                            />
                        </label>
                        <label style={{ ...fieldLabelStyle, flex: 1, minHeight: 0 }}>
                            Body
                            <textarea
                                value={composeBody}
                                onChange={(event) => { setComposeBody(event.target.value); }}
                                style={textAreaStyle}
                            />
                        </label>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <button type="button" onClick={() => { setShowCompose(false); }} style={secondaryButtonStyle}>Cancel</button>
                            <button type="submit" style={sendButtonStyle} disabled={composeTo.trim().length === 0}>Send</button>
                        </div>
                    </form>
                ) : selectedEmail !== null ? (
                    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>
                        {selectedThread !== null && selectedThread.emails.length > 1 && (
                            <div style={threadSiblingsStyle}>
                                <span style={{ color: '#D4A03A', fontSize: '0.7rem', fontWeight: 600 }}>Thread ({selectedThread.emails.length})</span>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                                    {selectedThread.emails.map(em => (
                                        <button
                                            key={em.id}
                                            type="button"
                                            onClick={() => setSelectedEmailId(em.id)}
                                            style={{
                                                ...threadSiblingButtonStyle,
                                                background: selectedEmailId === em.id ? 'rgba(212, 160, 58, 0.2)' : 'rgba(255,255,255,0.06)',
                                                borderColor: selectedEmailId === em.id ? '#D4A03A' : 'transparent',
                                            }}
                                        >
                                            {formatDate(em.date)} — {em.from}
                                            {!em.read && <span style={unreadDotStyle} aria-hidden />}
                                        </button>
                                    ))}
                                </div>
                            </div>
                        )}
                        <div style={messageMetaStyle}>
                            <div style={{ fontSize: '0.95rem', fontWeight: 600, color: '#e0e0e0' }}>{selectedEmail.subject}</div>
                            <div style={{ color: '#9ca3af' }}>From: {selectedEmail.from}</div>
                            <div style={{ color: '#9ca3af' }}>To: {selectedEmail.to}</div>
                            <div style={{ color: '#9ca3af' }}>{formatDate(selectedEmail.date)}</div>
                            {selectedEmail.attachments !== undefined && selectedEmail.attachments.length > 0 && (
                                <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '4px' }}>
                                    {selectedEmail.attachments.map(att => (
                                        <span key={`${selectedEmail.id}-${att.name}`} style={attachmentChipStyle}>
                                            📎 {att.name} ({formatSize(att.size)})
                                        </span>
                                    ))}
                                </div>
                            )}
                        </div>
                        <iframe
                            title={`Email ${selectedEmail.id}`}
                            srcDoc={renderedEmailBody}
                            sandbox=""
                            style={messageBodyFrameStyle}
                        />
                    </div>
                ) : (
                    <div style={emptyStateStyle}>Select a message to read it.</div>
                )}
            </section>
        </div>
    );
}

function prepareEmailBodyForSandbox(rawBody: string): string {
    const parser = new DOMParser();
    const parsed = parser.parseFromString(rawBody, 'text/html');

    parsed.querySelectorAll('script, iframe, object, embed, form').forEach(node => {
        node.remove();
    });

    parsed.querySelectorAll<HTMLElement>('*').forEach(node => {
        for (const attr of [...node.attributes]) {
            if (attr.name.toLowerCase().startsWith('on')) {
                node.removeAttribute(attr.name);
            }
        }
    });

    parsed.querySelectorAll<HTMLAnchorElement>('a[href]').forEach(link => {
        const href = link.getAttribute('href');
        if (href === null || href.trim() === '') return;
        const suspicious = isSuspiciousLink(link.textContent ?? '', href);
        if (!suspicious) return;

        const existing = link.getAttribute('style');
        const warnStyle = 'background: rgba(255, 221, 87, 0.38); color: #171717; border-bottom: 1px dashed #ffd447;';
        link.setAttribute('style', existing !== null ? `${existing};${warnStyle}` : warnStyle);
        link.title = `Suspicious link detected. Real URL: ${href}`;
    });

    const body = parsed.body.innerHTML.trim().length > 0
        ? parsed.body.innerHTML
        : `<pre style="white-space: pre-wrap; font-family: monospace;">${escapeHtml(rawBody)}</pre>`;

    return `<!doctype html><html><head><meta charset="utf-8"><style>
        body {
            margin: 0;
            padding: 14px;
            background: #0a0a0a;
            color: #e0e0e0;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, monospace;
            line-height: 1.45;
            font-size: 13px;
        }
        a { color: #D4A03A; }
        blockquote { border-left: 2px solid rgba(212, 160, 58, 0.4); margin-left: 0; padding-left: 8px; color: #9ca3af; }
        pre { background: #111; border: 1px solid rgba(224, 224, 224, 0.12); padding: 8px; overflow: auto; }
        table { border-collapse: collapse; }
        td, th { border: 1px solid rgba(224, 224, 224, 0.15); padding: 4px 6px; }
    </style></head><body>${body}</body></html>`;
}

function isSuspiciousLink(anchorText: string, href: string): boolean {
    const trimmedHref = href.trim();
    if (trimmedHref.startsWith('#') || trimmedHref.startsWith('mailto:')) return false;

    let parsedHref: URL;
    try {
        parsedHref = new URL(trimmedHref, 'https://mail.variant.local');
    } catch {
        return true;
    }

    const host = parsedHref.hostname.toLowerCase();
    const decodedText = anchorText.trim().toLowerCase();
    const hasIpHost = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
    const suspiciousWords = /(verify|urgent|security|password|invoice|login|gift|wire)/i.test(trimmedHref);
    const hasPunycode = host.includes('xn--');

    let textHost: string | null = null;
    const textUrlMatch = decodedText.match(/https?:\/\/[^\s]+/i);
    if (textUrlMatch !== null) {
        try {
            textHost = new URL(textUrlMatch[0]).hostname.toLowerCase();
        } catch {
            textHost = null;
        }
    }

    const mismatchedDisplayedUrl = textHost !== null && textHost !== host;
    const disguisedDomain = decodedText.includes('@') && decodedText.includes('.') && !decodedText.includes(host);

    return hasIpHost || hasPunycode || mismatchedDisplayedUrl || disguisedDomain || suspiciousWords;
}

function toPlainText(html: string): string {
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');
    const text = doc.body.textContent ?? '';
    return text.trim().length > 0 ? text.trim() : html;
}

function escapeHtml(input: string): string {
    return input
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;');
}

function formatDate(value: string): string {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
    });
}

function formatSize(bytes: number): string {
    if (bytes < 1024) return `${bytes}B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
}

function folderName(folder: MailFolder): string {
    switch (folder) {
        case 'inbox': return 'Inbox';
        case 'sent': return 'Sent';
        case 'drafts': return 'Drafts';
        case 'spam': return 'Spam';
    }
}

const rootStyle: React.CSSProperties = {
    display: 'grid',
    gridTemplateColumns: '220px 340px 1fr',
    height: '100%',
    width: '100%',
    background: '#0a0a0a',
    color: '#e0e0e0',
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, monospace',
    fontSize: '0.75rem',
};

const sidebarStyle: React.CSSProperties = {
    borderRight: '1px solid rgba(224, 224, 224, 0.12)',
    background: 'linear-gradient(180deg, #0a0a0a 0%, #111 100%)',
    padding: '10px 8px',
    display: 'flex',
    flexDirection: 'column',
    gap: '10px',
};

const accountStyle: React.CSSProperties = {
    border: '1px solid rgba(224, 224, 224, 0.12)',
    background: '#111',
    padding: '8px',
    borderRadius: '6px',
    display: 'flex',
    flexDirection: 'column',
    gap: '4px',
};

const composeButtonStyle: React.CSSProperties = {
    background: 'rgba(212, 160, 58, 0.16)',
    border: '1px solid rgba(212, 160, 58, 0.45)',
    color: '#D4A03A',
    borderRadius: '6px',
    padding: '8px 10px',
    textAlign: 'left',
    cursor: 'pointer',
    fontFamily: 'inherit',
    fontSize: '0.78rem',
    fontWeight: 600,
};

const folderButtonStyle: React.CSSProperties = {
    border: '1px solid transparent',
    borderRadius: '5px',
    padding: '6px 8px',
    background: 'transparent',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    cursor: 'pointer',
    fontFamily: 'inherit',
    fontSize: '0.74rem',
};

const searchBarWrapStyle: React.CSSProperties = {
    padding: '8px 10px',
    borderBottom: '1px solid rgba(224, 224, 224, 0.08)',
    background: '#0a0a0a',
};

const searchInputStyle: React.CSSProperties = {
    width: '100%',
    background: '#111',
    border: '1px solid rgba(224, 224, 224, 0.12)',
    color: '#e0e0e0',
    borderRadius: '6px',
    padding: '8px 10px',
    outline: 'none',
    fontFamily: 'inherit',
    fontSize: '0.75rem',
};

const unreadDotStyle: React.CSSProperties = {
    width: '8px',
    height: '8px',
    borderRadius: '50%',
    background: '#D4A03A',
    flexShrink: 0,
};

const listPanelStyle: React.CSSProperties = {
    borderRight: '1px solid rgba(224, 224, 224, 0.12)',
    display: 'flex',
    flexDirection: 'column',
    minWidth: 0,
    background: '#111',
};

const panelHeaderStyle: React.CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    minHeight: '36px',
    padding: '0 10px',
    borderBottom: '1px solid rgba(224, 224, 224, 0.12)',
    background: 'rgba(0, 0, 0, 0.2)',
    fontSize: '0.72rem',
    letterSpacing: '0.02em',
};

const listBodyStyle: React.CSSProperties = {
    overflow: 'auto',
    flex: 1,
};

const threadSiblingsStyle: React.CSSProperties = {
    padding: '8px 12px',
    borderBottom: '1px solid rgba(224, 224, 224, 0.08)',
    background: '#0a0a0a',
    display: 'flex',
    flexDirection: 'column',
    gap: '6px',
};

const threadSiblingButtonStyle: React.CSSProperties = {
    border: '1px solid transparent',
    borderRadius: '4px',
    padding: '4px 8px',
    cursor: 'pointer',
    fontFamily: 'inherit',
    fontSize: '0.68rem',
    color: '#e0e0e0',
    display: 'inline-flex',
    alignItems: 'center',
    gap: '6px',
};

const emailRowStyle: React.CSSProperties = {
    width: '100%',
    borderTop: 'none',
    borderRight: 'none',
    borderBottom: '1px solid rgba(224, 224, 224, 0.06)',
    textAlign: 'left',
    cursor: 'pointer',
    padding: '8px 10px',
    color: '#e0e0e0',
    fontFamily: 'inherit',
    fontSize: '0.73rem',
};

const emailRowTopStyle: React.CSSProperties = {
    display: 'flex',
    justifyContent: 'space-between',
    gap: '8px',
    marginBottom: '4px',
};

const emailRowBottomStyle: React.CSSProperties = {
    display: 'flex',
    justifyContent: 'space-between',
    gap: '8px',
    alignItems: 'center',
};

const readerPanelStyle: React.CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    minWidth: 0,
    background: '#0a0a0a',
};

const toolbarButtonStyle: React.CSSProperties = {
    background: '#111',
    border: '1px solid rgba(224, 224, 224, 0.12)',
    color: '#e0e0e0',
    borderRadius: '4px',
    padding: '2px 8px',
    cursor: 'pointer',
    fontFamily: 'inherit',
    fontSize: '0.68rem',
};

const composeFormStyle: React.CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
    flex: 1,
    minHeight: 0,
    padding: '10px',
};

const fieldLabelStyle: React.CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    gap: '4px',
    color: '#9ca3af',
};

const inputStyle: React.CSSProperties = {
    background: '#111',
    border: '1px solid rgba(224, 224, 224, 0.12)',
    color: '#e0e0e0',
    borderRadius: '5px',
    padding: '7px 8px',
    outline: 'none',
    fontFamily: 'inherit',
    fontSize: '0.75rem',
};

const textAreaStyle: React.CSSProperties = {
    ...inputStyle,
    resize: 'none',
    flex: 1,
    minHeight: '220px',
};

const secondaryButtonStyle: React.CSSProperties = {
    background: 'transparent',
    border: '1px solid rgba(224, 224, 224, 0.12)',
    color: '#9ca3af',
    borderRadius: '5px',
    padding: '6px 10px',
    cursor: 'pointer',
    fontFamily: 'inherit',
    fontSize: '0.74rem',
};

const sendButtonStyle: React.CSSProperties = {
    background: '#D4A03A',
    border: '1px solid rgba(212, 160, 58, 0.85)',
    color: '#0a0a0a',
    borderRadius: '5px',
    padding: '6px 12px',
    cursor: 'pointer',
    fontFamily: 'inherit',
    fontSize: '0.76rem',
    fontWeight: 700,
};

const messageMetaStyle: React.CSSProperties = {
    padding: '12px 12px 8px',
    borderBottom: '1px solid rgba(224, 224, 224, 0.12)',
    display: 'flex',
    flexDirection: 'column',
    gap: '4px',
    background: '#111',
};

const attachmentChipStyle: React.CSSProperties = {
    background: 'rgba(255, 255, 255, 0.06)',
    border: '1px solid rgba(224, 224, 224, 0.1)',
    borderRadius: '4px',
    padding: '2px 6px',
    fontSize: '0.67rem',
    color: '#9ca3af',
};

const messageBodyFrameStyle: React.CSSProperties = {
    border: 'none',
    width: '100%',
    flex: 1,
    minHeight: 0,
    background: '#0a0a0a',
};

const emptyStateStyle: React.CSSProperties = {
    color: '#9ca3af',
    fontSize: '0.74rem',
    padding: '16px',
};
