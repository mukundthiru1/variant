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

const NODE_RADIUS = 22;

const STATUS_COLORS: Record<NetworkNode['status'], string> = {
    up: '#3DA67A',
    down: '#666',
    compromised: '#ff5555',
    unknown: '#f1fa8c',
};

const TYPE_ICONS: Record<NetworkNode['type'], string> = {
    workstation: '\u{1F5A5}',  // 🖥
    server: '\u{1F5A7}',       // 🖧
    router: '\u{1F310}',       // 🌐
    firewall: '\u{1F6E1}',     // 🛡
    cloud: '\u{2601}',         // ☁
    attacker: '\u{1F480}',     // 💀
};

export function NetworkMapLens({ nodes, edges, traffic, focused }: NetworkMapLensProps): JSX.Element {
    const canvasRef = useRef<HTMLCanvasElement | null>(null);
    const containerRef = useRef<HTMLDivElement | null>(null);
    const [dimensions, setDimensions] = useState({ width: 800, height: 600 });
    const [hoveredNode, setHoveredNode] = useState<string | null>(null);
    const [selectedNode, setSelectedNode] = useState<string | null>(null);
    const animFrameRef = useRef<number>(0);

    // Auto-size canvas
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

    // Node positions map
    const nodeMap = useMemo(() => {
        const map = new Map<string, NetworkNode>();
        for (const node of nodes) {
            map.set(node.id, node);
        }
        return map;
    }, [nodes]);

    // Render loop
    useEffect(() => {
        const canvas = canvasRef.current;
        if (canvas === null) return;
        const ctx = canvas.getContext('2d');
        if (ctx === null) return;

        let running = true;

        function draw(): void {
            if (!running || ctx === null || canvas === null) return;

            ctx.clearRect(0, 0, canvas.width, canvas.height);

            // Draw edges
            for (const edge of edges) {
                const from = nodeMap.get(edge.from);
                const to = nodeMap.get(edge.to);
                if (from === undefined || to === undefined) continue;

                ctx.beginPath();
                ctx.moveTo(from.x, from.y);
                ctx.lineTo(to.x, to.y);
                ctx.strokeStyle = '#21262d';
                ctx.lineWidth = 1.5;
                ctx.stroke();

                if (edge.label !== undefined) {
                    const mx = (from.x + to.x) / 2;
                    const my = (from.y + to.y) / 2;
                    ctx.fillStyle = '#555';
                    ctx.font = '10px monospace';
                    ctx.textAlign = 'center';
                    ctx.fillText(edge.label, mx, my - 4);
                }
            }

            // Draw traffic animations
            const now = Date.now();
            for (const flow of traffic) {
                const from = nodeMap.get(flow.from);
                const to = nodeMap.get(flow.to);
                if (from === undefined || to === undefined) continue;

                const age = now - flow.timestamp;
                const progress = Math.min(1, age / 1500);
                const x = from.x + (to.x - from.x) * progress;
                const y = from.y + (to.y - from.y) * progress;

                ctx.beginPath();
                ctx.arc(x, y, 3 + flow.size / 500, 0, Math.PI * 2);
                ctx.fillStyle = flow.protocol === 'tcp' ? '#00aaff' : flow.protocol === 'udp' ? '#f1fa8c' : '#bd93f9';
                ctx.globalAlpha = 1 - progress * 0.7;
                ctx.fill();
                ctx.globalAlpha = 1;
            }

            // Draw nodes
            for (const node of nodes) {
                const isHovered = hoveredNode === node.id;
                const isSelected = selectedNode === node.id;
                const radius = isHovered || isSelected ? NODE_RADIUS + 4 : NODE_RADIUS;

                // Glow for compromised
                if (node.status === 'compromised') {
                    ctx.beginPath();
                    ctx.arc(node.x, node.y, radius + 8, 0, Math.PI * 2);
                    ctx.fillStyle = 'rgba(255, 85, 85, 0.15)';
                    ctx.fill();
                }

                // Node circle
                ctx.beginPath();
                ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
                ctx.fillStyle = isSelected ? '#1c2128' : '#0d1117';
                ctx.fill();
                ctx.strokeStyle = STATUS_COLORS[node.status];
                ctx.lineWidth = isSelected ? 2.5 : 1.5;
                ctx.stroke();

                // Icon
                ctx.fillStyle = STATUS_COLORS[node.status];
                ctx.font = '14px sans-serif';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(TYPE_ICONS[node.type], node.x, node.y);

                // Label
                ctx.fillStyle = isHovered ? '#e6edf3' : '#8b949e';
                ctx.font = '11px monospace';
                ctx.textBaseline = 'top';
                ctx.fillText(node.label, node.x, node.y + radius + 4);

                // IP
                ctx.fillStyle = '#555';
                ctx.font = '9px monospace';
                ctx.fillText(node.ip, node.x, node.y + radius + 17);
            }

            animFrameRef.current = requestAnimationFrame(draw);
        }

        draw();

        return () => {
            running = false;
            cancelAnimationFrame(animFrameRef.current);
        };
    }, [nodes, edges, traffic, nodeMap, hoveredNode, selectedNode, dimensions]);

    // Hit-test mouse events
    const findNodeAt = useCallback((clientX: number, clientY: number): NetworkNode | null => {
        const canvas = canvasRef.current;
        if (canvas === null) return null;
        const rect = canvas.getBoundingClientRect();
        const x = clientX - rect.left;
        const y = clientY - rect.top;

        for (const node of nodes) {
            const dx = node.x - x;
            const dy = node.y - y;
            if (dx * dx + dy * dy < (NODE_RADIUS + 4) ** 2) {
                return node;
            }
        }
        return null;
    }, [nodes]);

    const handleMouseMove = useCallback((e: React.MouseEvent) => {
        const node = findNodeAt(e.clientX, e.clientY);
        setHoveredNode(node?.id ?? null);
    }, [findNodeAt]);

    const handleClick = useCallback((e: React.MouseEvent) => {
        const node = findNodeAt(e.clientX, e.clientY);
        setSelectedNode(node?.id ?? null);
    }, [findNodeAt]);

    const selectedInfo = selectedNode !== null ? nodeMap.get(selectedNode) ?? null : null;

    return (
        <div style={rootStyle}>
            <div style={toolbarStyle}>
                <span style={{ color: '#D4A03A', fontWeight: 600 }}>NETWORK MAP</span>
                <span style={{ color: '#8b949e' }}>
                    {nodes.length} nodes | {edges.length} links | {traffic.length} flows
                </span>
            </div>

            <div ref={containerRef} style={canvasContainerStyle}>
                <canvas
                    ref={canvasRef}
                    width={dimensions.width}
                    height={dimensions.height}
                    onMouseMove={handleMouseMove}
                    onClick={handleClick}
                    style={{ cursor: hoveredNode !== null ? 'pointer' : 'default' }}
                    data-focused={focused}
                />
            </div>

            {selectedInfo !== null && (
                <div style={detailsPanelStyle}>
                    <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                        <span style={{ fontSize: '1.2rem' }}>{TYPE_ICONS[selectedInfo.type]}</span>
                        <div>
                            <div style={{ fontWeight: 600, color: '#e6edf3' }}>{selectedInfo.label}</div>
                            <div style={{ color: '#8b949e' }}>{selectedInfo.ip}</div>
                        </div>
                        <span style={{
                            marginLeft: 'auto',
                            padding: '2px 8px',
                            border: `1px solid ${STATUS_COLORS[selectedInfo.status]}40`,
                            color: STATUS_COLORS[selectedInfo.status],
                            fontSize: '0.7rem',
                            borderRadius: '3px',
                        }}>
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
    background: '#0a0e14',
    color: '#e6edf3',
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

const detailsPanelStyle: React.CSSProperties = {
    padding: '10px 12px',
    borderTop: '1px solid #21262d',
    background: '#0d1117',
};
