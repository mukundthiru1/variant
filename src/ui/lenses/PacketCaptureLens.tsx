/**
 * VARIANT — Packet Capture Lens
 *
 * Wireshark-like view of network traffic. Shows packets flowing
 * through the simulation's fabric. Players can filter by protocol,
 * source, destination, and inspect packet contents.
 *
 * SECURITY: Read-only view. Uses the fabric's tap() API.
 */

import { useCallback, useMemo, useRef, useState, useEffect } from 'react';

export interface PacketCaptureLensProps {
    readonly packets: readonly CapturedPacket[];
    readonly capturing: boolean;
    readonly onToggleCapture?: () => void;
    readonly onClear?: () => void;
    readonly focused: boolean;
}

export interface CapturedPacket {
    readonly id: string;
    readonly timestamp: number;
    readonly source: string;
    readonly destination: string;
    readonly protocol: string;
    readonly length: number;
    readonly info: string;
    readonly rawHex?: string;
    readonly decoded?: Readonly<Record<string, unknown>>;
}

const ROW_HEIGHT = 24;
const PROTOCOL_COLORS: Readonly<Record<string, string>> = {
    TCP: '#8be9fd',
    UDP: '#f1fa8c',
    HTTP: '#50fa7b',
    HTTPS: '#00ff41',
    DNS: '#bd93f9',
    ICMP: '#ffb86c',
    ARP: '#ff79c6',
    SSH: '#6272a4',
};

export function PacketCaptureLens({ packets, capturing, onToggleCapture, onClear, focused }: PacketCaptureLensProps): JSX.Element {
    const [filter, setFilter] = useState('');
    const [selectedPacketId, setSelectedPacketId] = useState<string | null>(null);
    const [autoScroll, setAutoScroll] = useState(true);
    const [scrollTop, setScrollTop] = useState(0);
    const [viewportHeight, setViewportHeight] = useState(0);

    const listRef = useRef<HTMLDivElement | null>(null);
    const filterRef = useRef<HTMLInputElement | null>(null);

    useEffect(() => {
        if (focused) {
            filterRef.current?.focus();
        }
    }, [focused]);

    const filtered = useMemo(() => {
        const term = filter.toLowerCase().trim();
        if (term.length === 0) return packets;

        return packets.filter(p =>
            p.source.toLowerCase().includes(term) ||
            p.destination.toLowerCase().includes(term) ||
            p.protocol.toLowerCase().includes(term) ||
            p.info.toLowerCase().includes(term),
        );
    }, [packets, filter]);

    // Auto-scroll to bottom
    useEffect(() => {
        if (!autoScroll) return;
        const el = listRef.current;
        if (el === null) return;
        el.scrollTop = Math.max(0, (filtered.length * ROW_HEIGHT) - el.clientHeight);
    }, [filtered.length, autoScroll]);

    const totalRows = filtered.length;
    const visibleRows = viewportHeight > 0 ? Math.ceil(viewportHeight / ROW_HEIGHT) : 0;
    const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - 5);
    const endIndex = Math.min(totalRows, startIndex + visibleRows + 10);
    const topSpacer = startIndex * ROW_HEIGHT;
    const bottomSpacer = Math.max(0, (totalRows - endIndex) * ROW_HEIGHT);
    const visible = filtered.slice(startIndex, endIndex);

    const selectedPacket = selectedPacketId !== null
        ? packets.find(p => p.id === selectedPacketId) ?? null
        : null;

    const handleScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
        const target = e.currentTarget;
        setScrollTop(target.scrollTop);
        setViewportHeight(target.clientHeight);

        // Disable auto-scroll if user scrolls up
        const atBottom = target.scrollTop + target.clientHeight >= target.scrollHeight - 10;
        setAutoScroll(atBottom);
    }, []);

    const formatTimestamp = useCallback((ts: number): string => {
        const d = new Date(ts);
        return d.toLocaleTimeString(undefined, { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0');
    }, []);

    const protocolColor = useCallback((proto: string): string => {
        return PROTOCOL_COLORS[proto.toUpperCase()] ?? '#e6edf3';
    }, []);

    return (
        <div style={rootStyle}>
            <div style={toolbarStyle}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ color: capturing ? '#ff5555' : '#00ff41', fontWeight: 600 }}>
                        {capturing ? '\u25CF CAPTURING' : '\u25CB STOPPED'}
                    </span>
                    <span style={{ color: '#8b949e' }}>{packets.length} packets</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <input
                        ref={filterRef}
                        value={filter}
                        onChange={(e) => { setFilter(e.target.value); }}
                        placeholder="Filter (ip, protocol, info)"
                        style={searchStyle}
                    />
                    {onToggleCapture !== undefined && (
                        <button onClick={onToggleCapture} style={{
                            ...btnStyle,
                            color: capturing ? '#ff5555' : '#00ff41',
                            borderColor: capturing ? '#ff555540' : '#00ff4140',
                        }}>
                            {capturing ? 'Stop' : 'Start'}
                        </button>
                    )}
                    {onClear !== undefined && (
                        <button onClick={onClear} style={btnStyle}>Clear</button>
                    )}
                </div>
            </div>

            <div style={headerStyle}>
                <div>No.</div>
                <div>Time</div>
                <div>Source</div>
                <div>Destination</div>
                <div>Protocol</div>
                <div>Length</div>
                <div>Info</div>
            </div>

            <div ref={listRef} style={listStyle} onScroll={handleScroll}>
                <div style={{ height: `${topSpacer}px` }} />

                {visible.map((pkt, localIdx) => {
                    const absIdx = startIndex + localIdx;
                    return (
                        <div
                            key={pkt.id}
                            onClick={() => { setSelectedPacketId(pkt.id); }}
                            style={{
                                ...rowStyle,
                                background: selectedPacketId === pkt.id
                                    ? 'rgba(0, 255, 65, 0.08)'
                                    : absIdx % 2 === 0 ? 'transparent' : 'rgba(255, 255, 255, 0.015)',
                            }}
                        >
                            <div style={{ color: '#555' }}>{absIdx + 1}</div>
                            <div style={{ color: '#9db1c2' }}>{formatTimestamp(pkt.timestamp)}</div>
                            <div style={{ color: '#e6edf3' }}>{pkt.source}</div>
                            <div style={{ color: '#e6edf3' }}>{pkt.destination}</div>
                            <div style={{ color: protocolColor(pkt.protocol), fontWeight: 600 }}>{pkt.protocol}</div>
                            <div style={{ color: '#8b949e', textAlign: 'right' }}>{pkt.length}</div>
                            <div style={{
                                color: '#c0c8d4',
                                whiteSpace: 'nowrap',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                            }}>
                                {pkt.info}
                            </div>
                        </div>
                    );
                })}

                <div style={{ height: `${bottomSpacer}px` }} />
            </div>

            {selectedPacket !== null && (
                <div style={detailsStyle}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                        <span style={{ color: '#00ff41', fontWeight: 600 }}>
                            Packet #{packets.indexOf(selectedPacket) + 1}
                        </span>
                        <span style={{ color: protocolColor(selectedPacket.protocol) }}>
                            {selectedPacket.protocol}
                        </span>
                    </div>

                    <div style={metaGridStyle}>
                        <span style={{ color: '#8b949e' }}>Source:</span>
                        <span>{selectedPacket.source}</span>
                        <span style={{ color: '#8b949e' }}>Dest:</span>
                        <span>{selectedPacket.destination}</span>
                        <span style={{ color: '#8b949e' }}>Length:</span>
                        <span>{selectedPacket.length} bytes</span>
                        <span style={{ color: '#8b949e' }}>Time:</span>
                        <span>{formatTimestamp(selectedPacket.timestamp)}</span>
                    </div>

                    <div style={{ marginTop: '6px', color: '#c0c8d4' }}>{selectedPacket.info}</div>

                    {selectedPacket.decoded !== undefined && (
                        <pre style={decodedStyle}>
                            {JSON.stringify(selectedPacket.decoded, null, 2)}
                        </pre>
                    )}

                    {selectedPacket.rawHex !== undefined && (
                        <pre style={hexStyle}>{selectedPacket.rawHex}</pre>
                    )}
                </div>
            )}
        </div>
    );
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
    flexWrap: 'wrap',
    gap: '6px',
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
    width: '200px',
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

const headerStyle: React.CSSProperties = {
    display: 'grid',
    gridTemplateColumns: '44px 100px 130px 130px 64px 56px 1fr',
    gap: '6px',
    padding: '5px 10px',
    borderBottom: '1px solid #21262d',
    background: '#0f1520',
    color: '#8b949e',
    fontSize: '0.68rem',
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
};

const listStyle: React.CSSProperties = {
    flex: 1,
    overflowY: 'auto',
    overflowX: 'hidden',
};

const rowStyle: React.CSSProperties = {
    display: 'grid',
    gridTemplateColumns: '44px 100px 130px 130px 64px 56px 1fr',
    gap: '6px',
    padding: '2px 10px',
    height: `${ROW_HEIGHT}px`,
    alignItems: 'center',
    cursor: 'pointer',
    borderBottom: '1px solid #171b22',
};

const detailsStyle: React.CSSProperties = {
    padding: '10px 12px',
    borderTop: '1px solid #21262d',
    background: '#0a111a',
    maxHeight: '35%',
    overflow: 'auto',
};

const metaGridStyle: React.CSSProperties = {
    display: 'grid',
    gridTemplateColumns: '60px 1fr 60px 1fr',
    gap: '2px 12px',
    fontSize: '0.72rem',
};

const decodedStyle: React.CSSProperties = {
    margin: '8px 0 0 0',
    padding: '6px',
    background: '#10151e',
    border: '1px solid #1f2630',
    borderRadius: '3px',
    color: '#8be9fd',
    fontSize: '0.7rem',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-word',
    fontFamily: 'inherit',
};

const hexStyle: React.CSSProperties = {
    margin: '8px 0 0 0',
    padding: '6px',
    background: '#10151e',
    border: '1px solid #1f2630',
    borderRadius: '3px',
    color: '#6e7681',
    fontSize: '0.68rem',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
    fontFamily: 'inherit',
};
