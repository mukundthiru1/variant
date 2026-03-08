/**
 * VARIANT — Network Map Lens
 *
 * Visualizes the simulation's network topology. Nodes represent
 * machines (VMs), edges represent connections. Traffic flows
 * animate along edges. Players see the same topology that the
 * fabric uses internally.
 *
 * SECURITY: Read-only visualization. Cannot modify topology.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

export interface NetworkMapLensProps {
    /** Machines in the network. */
    readonly nodes: readonly NetworkNode[];
    /** Connections between machines. */
    readonly edges: readonly NetworkEdge[];
    /** Active traffic flows (animated). */
    readonly traffic: readonly TrafficFlow[];
    readonly focused: boolean;
}

export interface NetworkNode {
    readonly id: string;
    readonly label: string;
    readonly ip: string;
    readonly type: 'workstation' | 'server' | 'router' | 'firewall' | 'cloud' | 'attacker';
    readonly status: 'up' | 'down' | 'compromised' | 'unknown';
    readonly x: number;
    readonly y: number;
}

export interface NetworkEdge {
    readonly from: string;
    readonly to: string;
    readonly label?: string;
    readonly bandwidth?: number;
}

export interface TrafficFlow {
    readonly id: string;
    readonly from: string;
    readonly to: string;
    readonly protocol: string;
    readonly size: number;
    readonly timestamp: number;
}

const NODE_WIDTH = 72;
const NODE_HEIGHT = 44;
const NODE_RX = 6;

/** Player (attacker) nodes — amber. Target nodes — gray. Compromised — red. */
const BORDER_PLAYER = '#D4A03A';
const BORDER_TARGET = '#505050';
const BORDER_COMPROMISED = '#C75450';

const BG_MAP = '#0A0A0A';
const TEXT_PRIMARY = '#E0E0E0';
const TEXT_SECONDARY = '#8b949e';

const TYPE_ICONS: Record<NetworkNode['type'], string> = {
    workstation: '\u{1F5A5}',
    server: '\u{1F5A7}',
    router: '\u{1F310}',
    firewall: '\u{1F6E1}',
    cloud: '\u{2601}',
    attacker: '\u{1F480}',
};

/** Derive subnet id from IP for segment grouping (e.g. 10.0.1.5 -> 10.0.1.0). */
function subnetFromIp(ip: string): string {
    const parts = ip.trim().split(/\./);
    if (parts.length >= 3) {
        parts[3] = '0';
        return parts.join('.');
    }
    return ip;
}

/** Simple grid layout when all positions are zero or collapsed. */
function gridLayout(nodes: readonly NetworkNode[], width: number, height: number): Map<string, { x: number; y: number }> {
    const n = nodes.length;
    const cols = Math.max(1, Math.ceil(Math.sqrt(n)));
    const rows = Math.max(1, Math.ceil(n / cols));
    const pad = 80;
    const cellW = (width - 2 * pad) / cols;
    const cellH = (height - 2 * pad) / rows;
    const out = new Map<string, { x: number; y: number }>();
    nodes.forEach((node, i) => {
        const c = i % cols;
        const r = Math.floor(i / cols);
        out.set(node.id, {
            x: pad + (c + 0.5) * cellW,
            y: pad + (r + 0.5) * cellH,
        });
    });
    return out;
}

export function NetworkMapLens({ nodes, edges, traffic, focused }: NetworkMapLensProps): JSX.Element {
    const containerRef = useRef<HTMLDivElement | null>(null);
    const [dimensions, setDimensions] = useState({ width: 800, height: 600 });
    const [hoveredNode, setHoveredNode] = useState<string | null>(null);
    const [selectedNode, setSelectedNode] = useState<string | null>(null);

    useEffect(() => {
        const container = containerRef.current;
        if (container === null) return;
        const observer = new ResizeObserver((entries) => {
            const entry = entries[0];
            if (entry !== undefined) {
                setDimensions({
                    width: entry.contentRect.width,
                    height: entry.contentRect.height,
                });
            }
        });
        observer.observe(container);
        return () => { observer.disconnect(); };
    }, []);

    const nodeMap = useMemo(() => {
        const map = new Map<string, NetworkNode>();
        for (const node of nodes) {
            map.set(node.id, node);
        }
        return map;
    }, [nodes]);

    const hasRealPositions = useMemo(() => {
        if (nodes.length === 0) return false;
        const first = nodes[0]!;
        const same = nodes.every((n) => n.x === first.x && n.y === first.y);
        const allZero = nodes.every((n) => n.x === 0 && n.y === 0);
        return !allZero && !same;
    }, [nodes]);

    const positions = useMemo(() => {
        if (hasRealPositions) {
            const map = new Map<string, { x: number; y: number }>();
            for (const node of nodes) {
                map.set(node.id, { x: node.x, y: node.y });
            }
            return map;
        }
        return gridLayout(nodes, dimensions.width, dimensions.height);
    }, [nodes, hasRealPositions, dimensions.width, dimensions.height]);

    const bounds = useMemo(() => {
        if (positions.size === 0) {
            return { minX: 0, minY: 0, maxX: dimensions.width, maxY: dimensions.height };
        }
        let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
        positions.forEach(({ x, y }) => {
            minX = Math.min(minX, x);
            minY = Math.min(minY, y);
            maxX = Math.max(maxX, x);
            maxY = Math.max(maxY, y);
        });
        const pad = 100;
        return {
            minX: minX - pad,
            minY: minY - pad,
            maxX: maxX + pad,
            maxY: maxY + pad,
        };
    }, [positions, dimensions]);

    const viewBox = useMemo(() => {
        const { minX, minY, maxX, maxY } = bounds;
        const w = Math.max(100, maxX - minX);
        const h = Math.max(100, maxY - minY);
        return `${minX} ${minY} ${w} ${h}`;
    }, [bounds]);

    const segments = useMemo(() => {
        const bySubnet = new Map<string, string[]>();
        for (const node of nodes) {
            const seg = subnetFromIp(node.ip);
            const list = bySubnet.get(seg) ?? [];
            list.push(node.id);
            bySubnet.set(seg, list);
        }
        return Array.from(bySubnet.entries()).map(([subnet, nodeIds]) => ({ name: subnet, nodeIds }));
    }, [nodes]);

    const segmentRects = useMemo(() => {
        return segments.map((seg) => {
            const pts = seg.nodeIds
                .map((id) => positions.get(id))
                .filter((p): p is { x: number; y: number } => p !== undefined);
            if (pts.length === 0) return null;
            const minX = Math.min(...pts.map((p) => p.x)) - NODE_WIDTH / 2 - 16;
            const maxX = Math.max(...pts.map((p) => p.x)) + NODE_WIDTH / 2 + 16;
            const minY = Math.min(...pts.map((p) => p.y)) - NODE_HEIGHT / 2 - 16;
            const maxY = Math.max(...pts.map((p) => p.y)) + NODE_HEIGHT / 2 + 16;
            return { name: seg.name, x: minX, y: minY, width: maxX - minX, height: maxY - minY };
        }).filter((r): r is NonNullable<typeof r> => r !== null);
    }, [segments, positions]);

    const getNodeBorder = useCallback((node: NetworkNode): string => {
        if (node.status === 'compromised') return BORDER_COMPROMISED;
        if (node.type === 'attacker') return BORDER_PLAYER;
        return BORDER_TARGET;
    }, []);

    const selectedInfo = selectedNode !== null ? nodeMap.get(selectedNode) ?? null : null;

    return (
        <div style={rootStyle}>
            <div style={toolbarStyle}>
                <span style={{ color: BORDER_PLAYER, fontWeight: 600 }}>NETWORK MAP</span>
                <span style={{ color: TEXT_SECONDARY }}>
                    {nodes.length} nodes | {edges.length} links | {traffic.length} flows
                </span>
            </div>

            <div ref={containerRef} style={canvasContainerStyle}>
                <svg
                    width="100%"
                    height="100%"
                    viewBox={viewBox}
                    preserveAspectRatio="xMidYMid meet"
                    style={{ display: 'block', background: BG_MAP }}
                    data-focused={focused}
                >
                    <defs>
                        <filter id="node-glow-compromised" x="-50%" y="-50%" width="200%" height="200%">
                            <feGaussianBlur in="SourceGraphic" stdDeviation="4" result="blur" />
                            <feMerge>
                                <feMergeNode in="blur" />
                                <feMergeNode in="SourceGraphic" />
                            </feMerge>
                        </filter>
                        <linearGradient id="edge-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
                            <stop offset="0%" stopColor="#383838" />
                            <stop offset="100%" stopColor="#505050" />
                        </linearGradient>
                    </defs>

                    {/* Segment background groups */}
                    <g aria-hidden>
                        {segmentRects.map((r, _i) => (
                            <g key={r.name}>
                                <rect
                                    x={r.x}
                                    y={r.y}
                                    width={r.width}
                                    height={r.height}
                                    fill="rgba(255,255,255,0.02)"
                                    stroke="rgba(255,255,255,0.06)"
                                    strokeWidth="1"
                                    rx="8"
                                />
                                <text
                                    x={r.x + 8}
                                    y={r.y + 14}
                                    fill={TEXT_SECONDARY}
                                    fontSize="10"
                                    fontFamily="var(--font-mono, monospace)"
                                >
                                    {r.name}/24
                                </text>
                            </g>
                        ))}
                    </g>

                    {/* Edges */}
                    <g stroke="#383838" strokeWidth="1.5" fill="none">
                        {edges.map((edge, i) => {
                            const from = positions.get(edge.from);
                            const to = positions.get(edge.to);
                            if (from === undefined || to === undefined) return null;
                            const midX = (from.x + to.x) / 2;
                            const midY = (from.y + to.y) / 2;
                            return (
                                <g key={`edge-${edge.from}-${edge.to}-${i}`}>
                                    <line x1={from.x} y1={from.y} x2={to.x} y2={to.y} />
                                    {edge.label !== undefined && (
                                        <text
                                            x={midX}
                                            y={midY - 4}
                                            fill={TEXT_SECONDARY}
                                            fontSize="9"
                                            textAnchor="middle"
                                            fontFamily="var(--font-mono, monospace)"
                                        >
                                            {edge.label}
                                        </text>
                                    )}
                                </g>
                            );
                        })}
                    </g>

                    {/* Traffic flow dots (animated along edges) */}
                    <g fill="none" strokeWidth="0">
                        {traffic.map((flow) => {
                            const from = positions.get(flow.from);
                            const to = positions.get(flow.to);
                            if (from === undefined || to === undefined) return null;
                            const dur = 1.2 + (flow.size % 800) / 1000;
                            const color = flow.protocol === 'tcp' ? '#4A9EFF' : flow.protocol === 'udp' ? '#f1fa8c' : '#bd93f9';
                            return (
                                <g key={flow.id}>
                                    <circle r={3 + Math.min(2, flow.size / 500)} fill={color} opacity={0.9}>
                                        <animateMotion
                                            dur={`${dur}s`}
                                            repeatCount="indefinite"
                                            path={`M ${from.x} ${from.y} L ${to.x} ${to.y}`}
                                        />
                                    </circle>
                                </g>
                            );
                        })}
                    </g>

                    {/* Nodes */}
                    {nodes.map((node) => {
                        const pos = positions.get(node.id);
                        if (pos === undefined) return null;
                        const isHovered = hoveredNode === node.id;
                        const isSelected = selectedNode === node.id;
                        const border = getNodeBorder(node);
                        const glow = node.status === 'compromised';
                        const w = NODE_WIDTH;
                        const h = NODE_HEIGHT;
                        return (
                            <g
                                key={node.id}
                                transform={`translate(${pos.x}, ${pos.y})`}
                                style={{ cursor: 'pointer' }}
                                onMouseEnter={() => setHoveredNode(node.id)}
                                onMouseLeave={() => setHoveredNode(null)}
                                onClick={() => setSelectedNode((prev) => (prev === node.id ? null : node.id))}
                            >
                                {glow && (
                                    <rect
                                        x={-w / 2 - 6}
                                        y={-h / 2 - 6}
                                        width={w + 12}
                                        height={h + 12}
                                        rx={NODE_RX + 4}
                                        fill="rgba(199, 84, 80, 0.12)"
                                        filter="url(#node-glow-compromised)"
                                    />
                                )}
                                <rect
                                    x={-w / 2}
                                    y={-h / 2}
                                    width={w}
                                    height={h}
                                    rx={NODE_RX}
                                    fill={isSelected ? '#161b22' : '#0d1117'}
                                    stroke={border}
                                    strokeWidth={isHovered || isSelected ? 2.5 : 1.5}
                                />
                                <text
                                    textAnchor="middle"
                                    dominantBaseline="central"
                                    fill={border}
                                    fontSize="14"
                                    fontFamily="sans-serif"
                                >
                                    {TYPE_ICONS[node.type]}
                                </text>
                                <text
                                    y={h / 2 + 12}
                                    textAnchor="middle"
                                    fill={isHovered ? TEXT_PRIMARY : TEXT_SECONDARY}
                                    fontSize="10"
                                    fontFamily="var(--font-mono, monospace)"
                                >
                                    {node.label}
                                </text>
                                <text
                                    y={h / 2 + 24}
                                    textAnchor="middle"
                                    fill={TEXT_SECONDARY}
                                    fontSize="9"
                                    fontFamily="var(--font-mono, monospace)"
                                >
                                    {node.ip}
                                </text>
                            </g>
                        );
                    })}
                </svg>
            </div>

            {/* Legend */}
            <div style={legendStyle}>
                <span style={legendTitleStyle}>Node types</span>
                <span style={{ borderColor: BORDER_PLAYER, ...legendItemStyle }}>Player</span>
                <span style={{ borderColor: BORDER_TARGET, ...legendItemStyle }}>Target</span>
                <span style={{ borderColor: BORDER_COMPROMISED, ...legendItemStyle }}>Compromised</span>
            </div>

            {selectedInfo !== null && (
                <div style={detailsPanelStyle}>
                    <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                        <span style={{ fontSize: '1.2rem' }}>{TYPE_ICONS[selectedInfo.type]}</span>
                        <div>
                            <div style={{ fontWeight: 600, color: TEXT_PRIMARY }}>{selectedInfo.label}</div>
                            <div style={{ color: TEXT_SECONDARY }}>{selectedInfo.ip}</div>
                        </div>
                        <span
                            style={{
                                marginLeft: 'auto',
                                padding: '2px 8px',
                                border: `1px solid ${getNodeBorder(selectedInfo)}40`,
                                color: getNodeBorder(selectedInfo),
                                fontSize: '0.7rem',
                                borderRadius: '3px',
                            }}
                        >
                            {selectedInfo.status.toUpperCase()}
                        </span>
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
    background: BG_MAP,
    color: TEXT_PRIMARY,
    fontFamily: 'var(--font-mono, "JetBrains Mono", monospace)',
    fontSize: '0.75rem',
};

const toolbarStyle: React.CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '6px 10px',
    borderBottom: '1px solid #21262d',
    background: '#0d1117',
    fontSize: '0.72rem',
};

const canvasContainerStyle: React.CSSProperties = {
    flex: 1,
    overflow: 'hidden',
    position: 'relative',
};

const legendStyle: React.CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    padding: '6px 10px',
    borderTop: '1px solid #21262d',
    background: '#0d1117',
    fontSize: '0.7rem',
};

const legendTitleStyle: React.CSSProperties = {
    color: TEXT_SECONDARY,
    fontWeight: 600,
    marginRight: '4px',
};

const legendItemStyle: React.CSSProperties = {
    padding: '2px 8px',
    borderLeft: '3px solid',
    color: TEXT_PRIMARY,
};

const detailsPanelStyle: React.CSSProperties = {
    padding: '10px 12px',
    borderTop: '1px solid #21262d',
    background: '#0d1117',
};
