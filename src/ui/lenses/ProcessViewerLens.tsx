/**
 * VARIANT — Process Viewer Lens
 *
 * Displays running processes on a target machine, similar to
 * `ps aux` or `top`. Shows PID, user, CPU, memory, command line.
 * Players can inspect process details to understand what's running
 * on a compromised/defended machine.
 *
 * SECURITY: Read-only view. Process kill goes through the terminal.
 */

import { useMemo, useState, useCallback } from 'react';

export interface ProcessViewerLensProps {
    readonly processes: readonly ProcessInfo[];
    readonly machineName: string;
    readonly onRefresh?: () => void;
    readonly focused: boolean;
}

export interface ProcessInfo {
    readonly pid: number;
    readonly ppid: number;
    readonly user: string;
    readonly cpu: number;
    readonly mem: number;
    readonly vsz: number;
    readonly rss: number;
    readonly tty: string;
    readonly stat: string;
    readonly start: string;
    readonly time: string;
    readonly command: string;
}

type SortField = 'pid' | 'user' | 'cpu' | 'mem' | 'command';
type SortDir = 'asc' | 'desc';

export function ProcessViewerLens({ processes, machineName, onRefresh, focused: _focused }: ProcessViewerLensProps): JSX.Element {
    const [filter, setFilter] = useState('');
    const [sortField, setSortField] = useState<SortField>('pid');
    const [sortDir, setSortDir] = useState<SortDir>('asc');
    const [selectedPid, setSelectedPid] = useState<number | null>(null);

    const handleSort = useCallback((field: SortField) => {
        if (sortField === field) {
            setSortDir(prev => prev === 'asc' ? 'desc' : 'asc');
        } else {
            setSortField(field);
            setSortDir(field === 'cpu' || field === 'mem' ? 'desc' : 'asc');
        }
    }, [sortField]);

    const filtered = useMemo(() => {
        const term = filter.toLowerCase().trim();
        if (term.length === 0) return processes;
        return processes.filter(p =>
            p.command.toLowerCase().includes(term) ||
            p.user.toLowerCase().includes(term) ||
            String(p.pid).includes(term),
        );
    }, [processes, filter]);

    const sorted = useMemo(() => {
        const result = [...filtered];
        const dir = sortDir === 'asc' ? 1 : -1;

        result.sort((a, b) => {
            switch (sortField) {
                case 'pid': return (a.pid - b.pid) * dir;
                case 'user': return a.user.localeCompare(b.user) * dir;
                case 'cpu': return (a.cpu - b.cpu) * dir;
                case 'mem': return (a.mem - b.mem) * dir;
                case 'command': return a.command.localeCompare(b.command) * dir;
            }
        });
        return result;
    }, [filtered, sortField, sortDir]);

    const selectedProcess = selectedPid !== null
        ? processes.find(p => p.pid === selectedPid) ?? null
        : null;

    const totalCpu = useMemo(() => processes.reduce((sum, p) => sum + p.cpu, 0), [processes]);
    const totalMem = useMemo(() => processes.reduce((sum, p) => sum + p.mem, 0), [processes]);

    const sortIndicator = (field: SortField): string => {
        if (sortField !== field) return '';
        return sortDir === 'asc' ? ' \u25B2' : ' \u25BC';
    };

    return (
        <div style={rootStyle}>
            <div style={toolbarStyle}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ color: '#D4A03A', fontWeight: 600 }}>PROCESSES</span>
                    <span style={{ color: '#8b949e' }}>{machineName}</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <input
                        value={filter}
                        onChange={(e) => { setFilter(e.target.value); }}
                        placeholder="Filter (pid, user, cmd)"
                        style={searchStyle}
                    />
                    {onRefresh !== undefined && (
                        <button onClick={onRefresh} style={btnStyle}>Refresh</button>
                    )}
                </div>
            </div>

            <div style={summaryStyle}>
                <span>Processes: {processes.length}</span>
                <span>Total CPU: {totalCpu.toFixed(1)}%</span>
                <span>Total MEM: {totalMem.toFixed(1)}%</span>
                {filter.length > 0 && <span>Showing: {filtered.length}</span>}
            </div>

            <div style={headerStyle}>
                <div style={headerCellStyle} onClick={() => { handleSort('pid'); }}>
                    PID{sortIndicator('pid')}
                </div>
                <div style={headerCellStyle} onClick={() => { handleSort('user'); }}>
                    USER{sortIndicator('user')}
                </div>
                <div style={{ ...headerCellStyle, textAlign: 'right' }} onClick={() => { handleSort('cpu'); }}>
                    %CPU{sortIndicator('cpu')}
                </div>
                <div style={{ ...headerCellStyle, textAlign: 'right' }} onClick={() => { handleSort('mem'); }}>
                    %MEM{sortIndicator('mem')}
                </div>
                <div style={headerCellStyle}>STAT</div>
                <div style={headerCellStyle} onClick={() => { handleSort('command'); }}>
                    COMMAND{sortIndicator('command')}
                </div>
            </div>

            <div style={listStyle}>
                {sorted.map((proc) => (
                    <div
                        key={proc.pid}
                        onClick={() => { setSelectedPid(proc.pid); }}
                        style={{
                            ...rowStyle,
                            background: selectedPid === proc.pid ? 'rgba(212, 160, 58, 0.06)' : 'transparent',
                        }}
                    >
                        <div style={{ color: '#8be9fd' }}>{proc.pid}</div>
                        <div style={{ color: proc.user === 'root' ? '#ff79c6' : '#e6edf3' }}>{proc.user}</div>
                        <div style={{
                            textAlign: 'right',
                            color: proc.cpu > 50 ? '#ff5555' : proc.cpu > 20 ? '#f1fa8c' : '#e6edf3',
                        }}>
                            {proc.cpu.toFixed(1)}
                        </div>
                        <div style={{
                            textAlign: 'right',
                            color: proc.mem > 50 ? '#ff5555' : proc.mem > 20 ? '#f1fa8c' : '#e6edf3',
                        }}>
                            {proc.mem.toFixed(1)}
                        </div>
                        <div style={{ color: '#8b949e' }}>{proc.stat}</div>
                        <div style={{
                            whiteSpace: 'nowrap',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            color: '#e6edf3',
                        }}>
                            {proc.command}
                        </div>
                    </div>
                ))}
            </div>

            {selectedProcess !== null && (
                <div style={detailsStyle}>
                    <div style={{ color: '#D4A03A', fontWeight: 600, marginBottom: '6px' }}>
                        Process {selectedProcess.pid} Details
                    </div>
                    <div style={detailRowStyle}><span>PID:</span><span>{selectedProcess.pid}</span></div>
                    <div style={detailRowStyle}><span>PPID:</span><span>{selectedProcess.ppid}</span></div>
                    <div style={detailRowStyle}><span>User:</span><span>{selectedProcess.user}</span></div>
                    <div style={detailRowStyle}><span>CPU:</span><span>{selectedProcess.cpu.toFixed(1)}%</span></div>
                    <div style={detailRowStyle}><span>MEM:</span><span>{selectedProcess.mem.toFixed(1)}%</span></div>
                    <div style={detailRowStyle}><span>VSZ:</span><span>{formatBytes(selectedProcess.vsz * 1024)}</span></div>
                    <div style={detailRowStyle}><span>RSS:</span><span>{formatBytes(selectedProcess.rss * 1024)}</span></div>
                    <div style={detailRowStyle}><span>TTY:</span><span>{selectedProcess.tty}</span></div>
                    <div style={detailRowStyle}><span>STAT:</span><span>{selectedProcess.stat}</span></div>
                    <div style={detailRowStyle}><span>START:</span><span>{selectedProcess.start}</span></div>
                    <div style={detailRowStyle}><span>TIME:</span><span>{selectedProcess.time}</span></div>
                    <div style={{ marginTop: '6px' }}>
                        <div style={{ color: '#8b949e', marginBottom: '2px' }}>Command:</div>
                        <pre style={cmdStyle}>{selectedProcess.command}</pre>
                    </div>
                </div>
            )}
        </div>
    );
}

function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes}B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}K`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)}M`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)}G`;
}

const rootStyle: React.CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    height: '100%',
    background: '#0a0e14',
    color: '#e6edf3',
    fontFamily: 'var(--font-mono, "JetBrains Mono", monospace)',
    fontSize: '0.74rem',
};

const toolbarStyle: React.CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '6px 10px',
    borderBottom: '1px solid #21262d',
    background: '#0d1117',
    gap: '8px',
};

const searchStyle: React.CSSProperties = {
    background: '#10151e',
    border: '1px solid #21262d',
    color: '#e6edf3',
    padding: '4px 8px',
    borderRadius: '3px',
    fontFamily: 'inherit',
    fontSize: '0.72rem',
    outline: 'none',
    width: '180px',
};

const btnStyle: React.CSSProperties = {
    padding: '4px 8px',
    border: '1px solid #21262d',
    borderRadius: '3px',
    background: '#111827',
    color: '#d0d7de',
    cursor: 'pointer',
    fontFamily: 'inherit',
    fontSize: '0.72rem',
};

const summaryStyle: React.CSSProperties = {
    display: 'flex',
    gap: '16px',
    padding: '4px 10px',
    borderBottom: '1px solid #171b22',
    color: '#8b949e',
    fontSize: '0.68rem',
};

const headerStyle: React.CSSProperties = {
    display: 'grid',
    gridTemplateColumns: '60px 80px 60px 60px 50px 1fr',
    gap: '8px',
    padding: '5px 10px',
    borderBottom: '1px solid #21262d',
    background: '#0f1520',
    color: '#8b949e',
    fontSize: '0.68rem',
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
};

const headerCellStyle: React.CSSProperties = {
    cursor: 'pointer',
    userSelect: 'none',
};

const listStyle: React.CSSProperties = {
    flex: 1,
    overflowY: 'auto',
    overflowX: 'hidden',
};

const rowStyle: React.CSSProperties = {
    display: 'grid',
    gridTemplateColumns: '60px 80px 60px 60px 50px 1fr',
    gap: '8px',
    padding: '3px 10px',
    borderBottom: '1px solid #171b22',
    cursor: 'pointer',
    alignItems: 'center',
};

const detailsStyle: React.CSSProperties = {
    padding: '10px 12px',
    borderTop: '1px solid #21262d',
    background: '#0a111a',
    maxHeight: '35%',
    overflow: 'auto',
};

const detailRowStyle: React.CSSProperties = {
    display: 'flex',
    justifyContent: 'space-between',
    gap: '12px',
    padding: '1px 0',
    color: '#e6edf3',
    fontSize: '0.72rem',
};

const cmdStyle: React.CSSProperties = {
    margin: 0,
    padding: '6px',
    background: '#10151e',
    border: '1px solid #1f2630',
    borderRadius: '3px',
    color: '#8be9fd',
    fontSize: '0.72rem',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
    fontFamily: 'inherit',
};
