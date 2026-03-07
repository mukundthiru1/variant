/**
 * VARIANT — File Manager Lens
 *
 * Tree view of a machine's virtual filesystem. Players can browse
 * directories, read file contents, and inspect permissions — just
 * like a graphical file manager on the target machine.
 *
 * SECURITY: Read-only view of the VFS. Cannot modify files.
 * Write operations go through the terminal (the shell enforces
 * permission checks).
 */

import { useState, useCallback, useMemo } from 'react';

export interface FileManagerLensProps {
    /** List files in a directory. Returns entries. */
    readonly onListDir: (path: string) => readonly FileEntry[];
    /** Read file contents. */
    readonly onReadFile: (path: string) => string | null;
    readonly focused: boolean;
}

export interface FileEntry {
    readonly name: string;
    readonly path: string;
    readonly isDirectory: boolean;
    readonly size: number;
    readonly owner: string;
    readonly mode: number;
}

export function FileManagerLens({ onListDir, onReadFile, focused: _focused }: FileManagerLensProps): JSX.Element {
    const [currentPath, setCurrentPath] = useState('/');
    const [selectedFile, setSelectedFile] = useState<string | null>(null);
    const [fileContent, setFileContent] = useState<string | null>(null);
    const [, setExpandedDirs] = useState<Set<string>>(new Set(['/']));

    const entries = useMemo(() => onListDir(currentPath), [currentPath, onListDir]);

    const handleNavigate = useCallback((path: string) => {
        setCurrentPath(path);
        setSelectedFile(null);
        setFileContent(null);
        setExpandedDirs(prev => {
            const next = new Set(prev);
            next.add(path);
            return next;
        });
    }, []);

    const handleSelectFile = useCallback((path: string) => {
        setSelectedFile(path);
        const content = onReadFile(path);
        setFileContent(content);
    }, [onReadFile]);

    const handleGoUp = useCallback(() => {
        if (currentPath === '/') return;
        const parent = currentPath.replace(/\/[^/]+\/?$/, '') || '/';
        handleNavigate(parent);
    }, [currentPath, handleNavigate]);

    const breadcrumbs = currentPath === '/' ? ['/'] : currentPath.split('/').filter(Boolean);

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
            {/* Path bar */}
            <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
                padding: '4px 8px',
                background: 'var(--bg-secondary, #0d1117)',
                borderBottom: '1px solid var(--border-default, #21262d)',
                minHeight: '28px',
            }}>
                <button onClick={handleGoUp} disabled={currentPath === '/'} style={navBtnStyle}>
                    ..
                </button>
                <div style={{ display: 'flex', gap: '2px', alignItems: 'center', overflow: 'hidden' }}>
                    <span
                        style={{ cursor: 'pointer', color: '#00ff41' }}
                        onClick={() => { handleNavigate('/'); }}
                    >
                        /
                    </span>
                    {breadcrumbs.map((segment, i) => {
                        const fullPath = '/' + breadcrumbs.slice(0, i + 1).join('/');
                        return (
                            <span key={fullPath}>
                                <span style={{ color: '#444' }}>/</span>
                                <span
                                    style={{ cursor: 'pointer', color: i === breadcrumbs.length - 1 ? '#e6edf3' : '#8b949e' }}
                                    onClick={() => { handleNavigate(fullPath); }}
                                >
                                    {segment}
                                </span>
                            </span>
                        );
                    })}
                </div>
            </div>

            {/* Content */}
            <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
                {/* File list */}
                <div style={{
                    width: selectedFile !== null ? '40%' : '100%',
                    overflow: 'auto',
                    borderRight: selectedFile !== null ? '1px solid var(--border-default, #21262d)' : 'none',
                }}>
                    {entries.length === 0 ? (
                        <div style={{ padding: '16px', color: '#666', textAlign: 'center' }}>
                            Empty directory
                        </div>
                    ) : (
                        entries.map(entry => (
                            <div
                                key={entry.path}
                                onClick={() => {
                                    if (entry.isDirectory) {
                                        handleNavigate(entry.path);
                                    } else {
                                        handleSelectFile(entry.path);
                                    }
                                }}
                                style={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '8px',
                                    padding: '3px 8px',
                                    cursor: 'pointer',
                                    background: selectedFile === entry.path
                                        ? 'rgba(0, 255, 65, 0.08)'
                                        : 'transparent',
                                    borderLeft: selectedFile === entry.path
                                        ? '2px solid #00ff41'
                                        : '2px solid transparent',
                                }}
                                onMouseEnter={(e) => {
                                    if (selectedFile !== entry.path) {
                                        e.currentTarget.style.background = 'rgba(255,255,255,0.02)';
                                    }
                                }}
                                onMouseLeave={(e) => {
                                    if (selectedFile !== entry.path) {
                                        e.currentTarget.style.background = 'transparent';
                                    }
                                }}
                            >
                                <span style={{
                                    color: entry.isDirectory ? '#f1fa8c' : '#8b949e',
                                    width: '16px',
                                    textAlign: 'center',
                                }}>
                                    {entry.isDirectory ? 'd' : '-'}
                                </span>
                                <span style={{ color: '#666', fontSize: '0.65rem', width: '60px' }}>
                                    {formatMode(entry.mode)}
                                </span>
                                <span style={{ color: '#6272a4', fontSize: '0.65rem', width: '56px' }}>
                                    {entry.owner}
                                </span>
                                <span style={{
                                    color: entry.isDirectory ? '#f1fa8c' : '#e6edf3',
                                    flex: 1,
                                }}>
                                    {entry.name}{entry.isDirectory ? '/' : ''}
                                </span>
                                {!entry.isDirectory && (
                                    <span style={{ color: '#666', fontSize: '0.65rem' }}>
                                        {formatSize(entry.size)}
                                    </span>
                                )}
                            </div>
                        ))
                    )}
                </div>

                {/* File content viewer */}
                {selectedFile !== null && (
                    <div style={{ flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column' }}>
                        <div style={{
                            padding: '4px 8px',
                            background: 'var(--bg-secondary, #0d1117)',
                            borderBottom: '1px solid var(--border-default, #21262d)',
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                        }}>
                            <span style={{ color: '#8b949e' }}>{selectedFile}</span>
                            <button
                                onClick={() => { setSelectedFile(null); setFileContent(null); }}
                                style={{ ...navBtnStyle, fontSize: '0.65rem' }}
                            >
                                X
                            </button>
                        </div>
                        <pre style={{
                            flex: 1,
                            margin: 0,
                            padding: '8px',
                            fontSize: '0.7rem',
                            lineHeight: 1.5,
                            whiteSpace: 'pre-wrap',
                            wordBreak: 'break-all',
                            overflow: 'auto',
                            color: fileContent !== null ? '#e6edf3' : '#ff5555',
                        }}>
                            {fileContent ?? 'Permission denied'}
                        </pre>
                    </div>
                )}
            </div>
        </div>
    );
}

// ── Helpers ──────────────────────────────────────────────────────

function formatMode(mode: number): string {
    const m = mode & 0o777;
    const parts = [
        (m & 0o400) ? 'r' : '-', (m & 0o200) ? 'w' : '-', (m & 0o100) ? 'x' : '-',
        (m & 0o040) ? 'r' : '-', (m & 0o020) ? 'w' : '-', (m & 0o010) ? 'x' : '-',
        (m & 0o004) ? 'r' : '-', (m & 0o002) ? 'w' : '-', (m & 0o001) ? 'x' : '-',
    ];
    return parts.join('');
}

function formatSize(bytes: number): string {
    if (bytes < 1024) return `${bytes}B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}K`;
    return `${(bytes / (1024 * 1024)).toFixed(1)}M`;
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
};
