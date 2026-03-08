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
/** Protocol colors: TCP blue, UDP green, HTTP amber, DNS cyan (Wireshark-like). */
const PROTOCOL_COLORS: Readonly<Record<string, string>> = {
    TCP: '#2563eb',
    UDP: '#16a34a',
    HTTP: '#d97706',
    HTTPS: '#b45309',
    DNS: '#0891b2',
    ICMP: '#ffb86c',
    ARP: '#ff79c6',
    SSH: '#6272a4',
};

const FILTER_SUGGESTIONS = ['tcp', 'udp', 'http', 'dns', 'https', 'icmp', 'ip'];

/** Format raw hex string into Wireshark-style offset + hex + ASCII (16 bytes per line). */
function formatHexDump(rawHex: string | undefined): string {
    if (rawHex === undefined || rawHex.length === 0) return '';
    const hex = rawHex.replace(/\s+/g, '');
    if (hex.length === 0) return '';
    const bytes: number[] = [];
    for (let i = 0; i < hex.length; i += 2) {
        const pair = hex.slice(i, i + 2);
        if (pair.length === 2) bytes.push(parseInt(pair, 16));
        else if (pair.length === 1) bytes.push(parseInt(pair + '0', 16));
    }
    const lines: string[] = [];
    const BYTES_PER_LINE = 16;
    for (let off = 0; off < bytes.length; off += BYTES_PER_LINE) {
        const chunk = bytes.slice(off, off + BYTES_PER_LINE);
        const offsetStr = off.toString(16).toUpperCase().padStart(4, '0');
        const hexPart = chunk.map(b => b.toString(16).toUpperCase().padStart(2, '0')).join(' ');
        const paddedHex = hexPart.padEnd(BYTES_PER_LINE * 3 - 1);
        const asciiPart = chunk.map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join('');
        lines.push(`${offsetStr}  ${paddedHex}  ${asciiPart}`);
    }
    return lines.join('\n');
}

function formatBytes(n: number): string {
    if (n >= 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + ' MB';
    if (n >= 1024) return (n / 1024).toFixed(1) + ' KB';
    return String(Math.round(n)) + ' B';
}

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

    const stats = useMemo(() => {
        const totalPackets = packets.length;
        const totalBytes = packets.reduce((sum, p) => sum + p.length, 0);
        const firstTs = packets[0]?.timestamp;
        const lastTs = packets[packets.length - 1]?.timestamp;
        const spanSec = firstTs != null && lastTs != null && lastTs > firstTs ? (lastTs - firstTs) / 1000 : 0;
        const packetsPerSec = spanSec > 0 ? totalPackets / spanSec : 0;
        const bytesPerSec = spanSec > 0 ? totalBytes / spanSec : 0;
        return { totalPackets, totalBytes, packetsPerSec, bytesPerSec };
    }, [packets]);

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
        return PROTOCOL_COLORS[proto.toUpperCase()] ?? '#e0e0e0';
    }, []);

    return (
        <div style={rootStyle}>
            <div style={toolbarStyle}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
                    <span style={{ color: capturing ? '#ef4444' : '#D4A03A', fontWeight: 600 }}>
                        {capturing ? '\u25CF CAPTURING' : '\u25CB STOPPED'}
                    </span>
                    <span style={statsStyle}>{stats.totalPackets} packets</span>
                    <span style={statsStyle}>{formatBytes(stats.totalBytes)}</span>
                    <span style={statsStyle}>{stats.packetsPerSec.toFixed(1)} pkt/s</span>
                    <span style={statsStyle}>{formatBytes(stats.bytesPerSec)}/s</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <input
                        ref={filterRef}
                        value={filter}
                        onChange={(e) => { setFilter(e.target.value); }}
                        placeholder="Filter (tcp, udp, http, dns...)"
                        list="packet-filter-suggestions"
                        style={searchStyle}
                    />
                    <datalist id="packet-filter-suggestions">
                        {FILTER_SUGGESTIONS.map(s => <option key={s} value={s} />)}
                    </datalist>
                    {onToggleCapture !== undefined && (
                        <button onClick={onToggleCapture} style={{
                            ...btnStyle,
                            color: capturing ? '#ef4444' : '#D4A03A',
                            borderColor: capturing ? 'rgba(239, 68, 68, 0.4)' : 'rgba(212, 160, 58, 0.4)',
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
                                    ? 'rgba(212, 160, 58, 0.12)'
                                    : absIdx % 2 === 0 ? 'transparent' : 'rgba(255, 255, 255, 0.03)',
                            }}
                        >
                            <div style={{ color: '#888' }}>{absIdx + 1}</div>
                            <div style={{ color: '#b0b0b0' }}>{formatTimestamp(pkt.timestamp)}</div>
                            <div style={{ color: '#e0e0e0' }}>{pkt.source}</div>
                            <div style={{ color: '#e0e0e0' }}>{pkt.destination}</div>
                            <div style={{ color: protocolColor(pkt.protocol), fontWeight: 600 }}>{pkt.protocol}</div>
                            <div style={{ color: '#b0b0b0', textAlign: 'right' }}>{pkt.length}</div>
                            <div style={{
                                color: '#e0e0e0',
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
                        <span style={{ color: '#D4A03A', fontWeight: 600 }}>
                            Packet #{packets.indexOf(selectedPacket) + 1}
                        </span>
                        <span style={{ color: protocolColor(selectedPacket.protocol) }}>
                            {selectedPacket.protocol}
                        </span>
                    </div>

                    <div style={metaGridStyle}>
                        <span style={{ color: '#b0b0b0' }}>Source:</span>
                        <span style={{ color: '#e0e0e0' }}>{selectedPacket.source}</span>
                        <span style={{ color: '#b0b0b0' }}>Dest:</span>
                        <span style={{ color: '#e0e0e0' }}>{selectedPacket.destination}</span>
                        <span style={{ color: '#b0b0b0' }}>Length:</span>
                        <span style={{ color: '#e0e0e0' }}>{selectedPacket.length} bytes</span>
                        <span style={{ color: '#b0b0b0' }}>Time:</span>
                        <span style={{ color: '#e0e0e0' }}>{formatTimestamp(selectedPacket.timestamp)}</span>
                    </div>

                    <div style={{ marginTop: '6px', color: '#e0e0e0' }}>{selectedPacket.info}</div>

                    {selectedPacket.decoded !== undefined && (
                        <pre style={decodedStyle}>
                            {JSON.stringify(selectedPacket.decoded, null, 2)}
                        </pre>
                    )}

                    <div style={{ marginTop: '10px' }}>
                        <div style={{ color: '#D4A03A', fontWeight: 600, marginBottom: '4px', fontSize: '0.7rem' }}>Hex Dump</div>
                        <pre style={hexStyle}>
                            {formatHexDump(selectedPacket.rawHex) || 'No raw data available for this packet.'}
                        </pre>
                    </div>
                </div>
            )}
        </div>
    );
}

const rootStyle: React.CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    height: '100%',
    background: '#0a0a0a',
    color: '#e0e0e0',
    fontFamily: 'var(--font-mono, "JetBrains Mono", monospace)',
    fontSize: '0.74rem',
};

const toolbarStyle: React.CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '6px 10px',
    borderBottom: '1px solid #333',
    background: '#0a0a0a',
    flexWrap: 'wrap',
    gap: '6px',
};

const statsStyle: React.CSSProperties = {
    color: '#e0e0e0',
    fontSize: '0.72rem',
};

const searchStyle: React.CSSProperties = {
    background: '#111',
    border: '1px solid #333',
    color: '#e0e0e0',
    padding: '4px 8px',
    borderRadius: '3px',
    fontFamily: 'inherit',
    fontSize: '0.72rem',
    outline: 'none',
    width: '200px',
};

const btnStyle: React.CSSProperties = {
    padding: '4px 8px',
    border: '1px solid #333',
    borderRadius: '3px',
    background: '#111',
    color: '#e0e0e0',
    cursor: 'pointer',
    fontFamily: 'inherit',
    fontSize: '0.72rem',
};

const headerStyle: React.CSSProperties = {
    display: 'grid',
    gridTemplateColumns: '44px 100px 130px 130px 64px 56px 1fr',
    gap: '6px',
    padding: '5px 10px',
    borderBottom: '1px solid #333',
    background: '#0a0a0a',
    color: '#e0e0e0',
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
    borderBottom: '1px solid #222',
};

const detailsStyle: React.CSSProperties = {
    padding: '10px 12px',
    borderTop: '1px solid #333',
    background: '#0a0a0a',
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
    background: '#111',
    border: '1px solid #333',
    borderRadius: '3px',
    color: '#0891b2',
    fontSize: '0.7rem',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-word',
    fontFamily: 'inherit',
};

const hexStyle: React.CSSProperties = {
    margin: '0',
    padding: '8px',
    background: '#111',
    border: '1px solid #333',
    borderRadius: '3px',
    color: '#e0e0e0',
    fontSize: '0.68rem',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
    fontFamily: 'inherit',
};
