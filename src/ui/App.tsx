/**
 * VARIANT — Application Shell
 *
 * The root React component. Hosts the simulation
 * or the level selection screen.
 *
 * The terminal is always the primary view. Everything else
 * (browser, email, network map) opens from terminal commands.
 *
 * What lenses are available is configured by the WorldSpec
 * (level designer controls the player's toolset).
 */

import { useState, useCallback, useEffect, useRef, useReducer, useMemo } from 'react';
import type { TerminalIO } from '../core/vm/types';
import type { Simulation, SimulationState } from '../core/engine';
import { createSimulation } from '../core/engine';
import { createModuleRegistry } from '../core/modules';
import { createSimulacrumBackend } from '../backends/simulacrum';
import { createBackendRouter } from '../backends/backend-router';
import { createObjectiveDetector } from '../modules/objective-detector';
import { createScoringEngine } from '../modules/scoring-engine';
import { injectXtermCSS } from '../modules/terminal';
import { DEMO_01 } from '../levels/demo-01';
import { DEMO_02 } from '../levels/demo-02';
import { DEMO_03 } from '../levels/demo-03';
import { DEMO_04 } from '../levels/demo-04';
import { DEMO_05 } from '../levels/demo-05';
import type { WorldSpec, GameMode } from '../core/world/types';
import type { LevelPackage, LevelDifficulty, LevelMetadata, LevelAuthor } from '../lib/marketplace/types';
import { createMarketplaceStore, createLevelBuilder } from '../lib/marketplace';
import { LandingPage } from './pages/LandingPage';
import { MarketplacePage } from './pages/MarketplacePage';
import { SettingsPage } from './pages/SettingsPage';
import type { LensInstance } from './lens/types';
import { compositorReducer, createInitialState, generateLensId } from './lens/compositor-state';
import { LensCompositor } from './lenses/LensCompositor';
import { TerminalLens } from './lenses/TerminalLens';
import { BrowserLens } from './lenses/BrowserLens';
import type { BrowserResponse } from './lenses/BrowserLens';
import { EmailLens } from './lenses/EmailLens';
import type { EmailMessage } from './lenses/EmailLens';
import { LogViewerLens } from './lenses/LogViewerLens';
import type { LogEntry } from './lenses/LogViewerLens';
import { FileManagerLens } from './lenses/FileManagerLens';
import type { FileEntry } from './lenses/FileManagerLens';
import { NetworkMapLens } from './lenses/NetworkMapLens';
import type { NetworkNode, NetworkEdge, TrafficFlow } from './lenses/NetworkMapLens';
import { ProcessViewerLens } from './lenses/ProcessViewerLens';
import type { ProcessInfo } from './lenses/ProcessViewerLens';
import { PacketCaptureLens } from './lenses/PacketCaptureLens';
import type { CapturedPacket } from './lenses/PacketCaptureLens';
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts';
import { useNotifications } from './hooks/useNotifications';
import { NotificationToast } from './components/NotificationToast';
import { HelpOverlay } from './components/HelpOverlay';

// ── App State Machine ──────────────────────────────────────────

type AppState =
    | { readonly screen: 'landing' }
    | { readonly screen: 'menu' }
    | { readonly screen: 'marketplace' }
    | { readonly screen: 'level-editor' }
    | { readonly screen: 'settings' }
    | { readonly screen: 'booting'; readonly levelId: string; readonly levelPackage?: LevelPackage }
    | { readonly screen: 'simulation'; readonly levelId: string; readonly levelPackage?: LevelPackage }
    | { readonly screen: 'error'; readonly message: string };

type MenuLevel = {
    readonly id: string;
    readonly title: string;
    readonly difficulty: string;
    readonly time: string;
    readonly desc: string;
    readonly tags: readonly string[];
};

const formatTag = (tag: string): string =>
    tag
        .split('-')
        .map(part => part.length > 0 ? `${part[0]?.toUpperCase() ?? ''}${part.slice(1)}` : part)
        .join(' ');

const LEVEL_SPECS: Record<string, WorldSpec> = {
    'demo-01': DEMO_01,
    'demo-02': DEMO_02,
    'demo-03': DEMO_03,
    'demo-04': DEMO_04,
    'demo-05': DEMO_05,
};

const LEVELS: readonly MenuLevel[] = [
    {
        id: 'demo-01',
        title: 'The Leak',
        difficulty: 'BEGINNER',
        time: '~5 min',
        desc: 'A company web server has an exposed backup directory. Find the admin credentials before the sysadmin rotates them.',
        tags: ['Enumeration'],
    },
    {
        id: 'demo-02',
        title: DEMO_02.meta.title,
        difficulty: DEMO_02.meta.difficulty.toUpperCase(),
        time: `~${DEMO_02.meta.estimatedMinutes} min`,
        desc: DEMO_02.meta.scenario,
        tags: DEMO_02.meta.tags.map(formatTag).slice(0, 3),
    },
    {
        id: 'demo-03',
        title: DEMO_03.meta.title,
        difficulty: DEMO_03.meta.difficulty.toUpperCase(),
        time: `~${DEMO_03.meta.estimatedMinutes} min`,
        desc: DEMO_03.meta.scenario,
        tags: DEMO_03.meta.tags.map(formatTag).slice(0, 3),
    },
    {
        id: 'demo-04',
        title: DEMO_04.meta.title,
        difficulty: DEMO_04.meta.difficulty.toUpperCase(),
        time: `~${DEMO_04.meta.estimatedMinutes} min`,
        desc: DEMO_04.meta.scenario,
        tags: DEMO_04.meta.tags.map(formatTag).slice(0, 3),
    },
    {
        id: 'demo-05',
        title: DEMO_05.meta.title,
        difficulty: DEMO_05.meta.difficulty.toUpperCase(),
        time: `~${DEMO_05.meta.estimatedMinutes} min`,
        desc: DEMO_05.meta.scenario,
        tags: DEMO_05.meta.tags.map(formatTag).slice(0, 3),
    },
] as const;

// ── App Component ──────────────────────────────────────────────

export function App(): JSX.Element {
    const [state, setState] = useState<AppState>({ screen: 'landing' });
    const marketplaceStore = useMemo(() => createMarketplaceStore(), []);

    const handleLaunch = useCallback(() => setState({ screen: 'menu' }), []);
    const handleMarketplace = useCallback(() => setState({ screen: 'marketplace' }), []);
    const handleCreate = useCallback(() => setState({ screen: 'level-editor' }), []);
    const handleSettings = useCallback(() => setState({ screen: 'settings' }), []);
    const handleBackToLanding = useCallback(() => setState({ screen: 'landing' }), []);

    const handleLevelSelect = useCallback((levelId: string) => {
        setState({ screen: 'booting', levelId });
    }, []);

    const handleBackToMenu = useCallback(() => {
        setState({ screen: 'menu' });
    }, []);

    const handlePlayLevel = useCallback((pkg: LevelPackage) => {
        setState({ screen: 'booting', levelId: pkg.id, levelPackage: pkg });
    }, []);

    const handleSaveToMarketplace = useCallback((pkg: LevelPackage) => {
        marketplaceStore.importLevel(pkg).then(() => {
            setState({ screen: 'marketplace' });
        }).catch(err => {
            console.error('Failed to import level:', err);
            setState({ screen: 'marketplace' });
        });
    }, [marketplaceStore]);

    const handleError = useCallback((message: string) => {
        setState({ screen: 'error', message });
    }, []);

    const worldSpecForSimulation = (s: { levelId: string; levelPackage?: LevelPackage }): WorldSpec =>
        s.levelPackage?.worldSpec ?? LEVEL_SPECS[s.levelId] ?? DEMO_01;

    switch (state.screen) {
        case 'landing':
            return (
                <LandingPage
                    onLaunch={handleLaunch}
                    onMarketplace={handleMarketplace}
                    onCreate={handleCreate}
                    onSettings={handleSettings}
                />
            );
        case 'menu':
            return (
                <MenuScreen
                    onSelectLevel={handleLevelSelect}
                    onBackToLanding={handleBackToLanding}
                    onSettings={handleSettings}
                />
            );
        case 'marketplace':
            return (
                <>
                    <MarketplaceNav onBack={handleBackToLanding} onSettings={handleSettings} />
                    <MarketplacePage store={marketplaceStore} onPlayLevel={handlePlayLevel} />
                </>
            );
        case 'level-editor':
            return (
                <LevelEditor
                    onSave={handleSaveToMarketplace}
                    onTest={handlePlayLevel}
                    onBack={handleBackToLanding}
                    onSettings={handleSettings}
                />
            );
        case 'settings':
            return <SettingsPage onBack={handleBackToLanding} />;
        case 'booting':
        case 'simulation':
            return (
                <SimulationScreen
                    worldSpec={worldSpecForSimulation(state)}
                    levelId={state.levelId}
                    onExit={handleBackToMenu}
                    onError={handleError}
                    onSettings={handleSettings}
                />
            );
        case 'error':
            return <ErrorScreen message={state.message} onBack={handleBackToMenu} />;
    }
}

// ── Marketplace Nav (Back, Settings) ─────────────────────────────

function MarketplaceNav({
    onBack,
    onSettings,
}: {
    readonly onBack: () => void;
    readonly onSettings: () => void;
}): JSX.Element {
    const barStyle: React.CSSProperties = {
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: '12px 16px',
        background: '#0d0d0d',
        borderBottom: '1px solid #1a1a2e',
        fontFamily: '"JetBrains Mono", "Fira Code", monospace',
    };
    return (
        <nav style={barStyle}>
            <button type="button" onClick={onBack} style={navBtnStyle}>Back</button>
            <button type="button" onClick={onSettings} style={navBtnStyle}>Settings</button>
        </nav>
    );
}

// ── Level Editor ────────────────────────────────────────────────

function LevelEditor({
    onSave,
    onTest,
    onBack,
    onSettings,
}: {
    readonly onSave: (pkg: LevelPackage) => void;
    readonly onTest: (pkg: LevelPackage) => void;
    readonly onBack: () => void;
    readonly onSettings: () => void;
}): JSX.Element {
    const [title, setTitle] = useState('');
    const [slug, setSlug] = useState('');
    const [description, setDescription] = useState('');
    const [briefing, setBriefing] = useState('');
    const [difficulty, setDifficulty] = useState<LevelDifficulty>('beginner');
    const [mode, setMode] = useState<GameMode>('attack');
    const [tags, setTags] = useState('');
    const [estimatedMins, setEstimatedMins] = useState<number>(15);
    
    const initialJson = JSON.stringify({
        version: "2.0",
        trust: "community",
        machines: {
            "target": {
                "hostname": "target",
                "image": "alpine-nginx",
                "memoryMB": 64,
                "role": "target",
                "interfaces": [{ "ip": "10.0.1.10", "segment": "lan" }]
            }
        },
        startMachine: "target",
        network: { "segments": [{ "id": "lan", "subnet": "10.0.1.0/24" }], "edges": [] },
        credentials: [],
        objectives: []
    }, null, 2);

    const [worldSpecJson, setWorldSpecJson] = useState(initialJson);
    const [error, setError] = useState<string | null>(null);
    const [success, setSuccess] = useState<string | null>(null);

    const parseAndValidate = async (): Promise<LevelPackage | null> => {
        try {
            setError(null);
            setSuccess(null);
            
            let spec: WorldSpec;
            try {
                spec = JSON.parse(worldSpecJson) as WorldSpec;
            } catch (err) {
                throw new Error('Invalid JSON: ' + (err instanceof Error ? err.message : String(err)));
            }
            
            if (!spec.machines || typeof spec.machines !== 'object') throw new Error('WorldSpec requires a "machines" object');
            if (!spec.network || typeof spec.network !== 'object') throw new Error('WorldSpec requires a "network" object');
            if (!spec.objectives || !Array.isArray(spec.objectives)) throw new Error('WorldSpec requires an "objectives" array');

            const parsedTags = tags.split(',').map(t => t.trim()).filter(Boolean);
            
            const metadata: LevelMetadata = {
                title: title || 'Untitled',
                tagline: slug || 'custom-level',
                description: description || 'No description',
                difficulty,
                estimatedMinutes: estimatedMins,
                tags: parsedTags,
                mitreTechniques: [],
                machineCount: Object.keys(spec.machines).length,
                objectiveCount: spec.objectives.length,
                skills: [],
            };

            const author: LevelAuthor = {
                name: 'Level Designer',
            };

            const builder = createLevelBuilder();
            const pkg = await builder.build(
                {
                    ...spec,
                    meta: {
                        title: title || 'Untitled',
                        scenario: description || 'No description',
                        briefing: briefing.split('\\n').filter(Boolean),
                        difficulty,
                        mode,
                        vulnClasses: [],
                        tags: parsedTags,
                        estimatedMinutes: estimatedMins,
                        author: { name: 'Level Designer', id: 'local', type: 'community' }
                    }
                },
                metadata,
                author
            );

            const errors = builder.validate(pkg);
            if (errors.length > 0) {
                throw new Error(`Validation failed: ${errors.join(', ')}`);
            }
            return pkg;
        } catch (e: unknown) {
            setError(e instanceof Error ? e.message : String(e));
            return null;
        }
    };

    const handleValidate = async () => {
        const pkg = await parseAndValidate();
        if (pkg !== null) {
            setSuccess('Validation passed. WorldSpec is valid.');
        }
    };

    const handleTest = async () => {
        const pkg = await parseAndValidate();
        if (pkg !== null) {
            onTest(pkg);
        }
    };

    const handleSave = async () => {
        const pkg = await parseAndValidate();
        if (pkg !== null) {
            onSave(pkg);
        }
    };

    const containerStyle: React.CSSProperties = {
        display: 'flex',
        flexDirection: 'column',
        height: '100vh',
        background: '#0A0A0A',
        color: '#E0E0E0',
        fontFamily: '"JetBrains Mono", "Fira Code", monospace',
    };
    const barStyle: React.CSSProperties = {
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: '12px 16px',
        borderBottom: '1px solid #1a1a2e',
        background: '#111111',
    };
    const inputStyle: React.CSSProperties = {
        background: '#111111',
        border: '1px solid #1a1a2e',
        color: '#E0E0E0',
        padding: '8px',
        fontFamily: 'inherit',
        fontSize: '0.85rem',
        borderRadius: '2px',
        width: '100%',
        boxSizing: 'border-box' as const,
    };
    const labelStyle: React.CSSProperties = {
        fontSize: '0.8rem',
        color: '#D4A03A',
        marginBottom: '4px',
        display: 'block'
    };
    const columnStyle: React.CSSProperties = {
        display: 'flex',
        flexDirection: 'column',
        gap: '12px',
        flex: 1,
        overflowY: 'auto',
        paddingRight: '16px'
    };

    return (
        <div style={containerStyle}>
            <nav style={barStyle}>
                <button type="button" onClick={onBack} style={navBtnStyle}>Back</button>
                <div style={{ display: 'flex', gap: '8px' }}>
                    <button type="button" onClick={handleTest} style={navBtnStyle}>Test</button>
                    <button type="button" onClick={handleSave} style={{ ...navBtnStyle, color: '#D4A03A' }}>Save to Marketplace</button>
                    <button type="button" onClick={onSettings} style={navBtnStyle}>Settings</button>
                </div>
            </nav>
            <main style={{ flex: 1, display: 'flex', padding: '16px', gap: '16px', overflow: 'hidden' }}>
                <div style={columnStyle}>
                    <h2 style={{ color: '#D4A03A', fontSize: '1.2rem', margin: '0 0 8px 0' }}>Level Metadata</h2>
                    {error !== null && <div style={{ color: '#ff5555', background: 'rgba(255, 85, 85, 0.1)', padding: '8px', border: '1px solid #ff5555', borderRadius: '2px', fontSize: '0.85rem' }}>{error}</div>}
                    {success !== null && <div style={{ color: '#3DA67A', background: 'rgba(61, 166, 122, 0.1)', padding: '8px', border: '1px solid #3DA67A', borderRadius: '2px', fontSize: '0.85rem' }}>{success}</div>}
                    
                    <div>
                        <label style={labelStyle}>Title</label>
                        <input value={title} onChange={e => setTitle(e.target.value)} style={inputStyle} placeholder="My Level" />
                    </div>
                    <div>
                        <label style={labelStyle}>Slug / Tagline</label>
                        <input value={slug} onChange={e => setSlug(e.target.value)} style={inputStyle} placeholder="my-level" />
                    </div>
                    <div>
                        <label style={labelStyle}>Description</label>
                        <textarea value={description} onChange={e => setDescription(e.target.value)} style={{ ...inputStyle, resize: 'vertical', minHeight: '60px' }} placeholder="Scenario description..." />
                    </div>
                    <div>
                        <label style={labelStyle}>Briefing (one line per bullet)</label>
                        <textarea value={briefing} onChange={e => setBriefing(e.target.value)} style={{ ...inputStyle, resize: 'vertical', minHeight: '80px' }} placeholder="Objective 1...\\nObjective 2..." />
                    </div>
                    <div style={{ display: 'flex', gap: '12px' }}>
                        <div style={{ flex: 1 }}>
                            <label style={labelStyle}>Difficulty</label>
                            <select value={difficulty} onChange={e => setDifficulty(e.target.value as LevelDifficulty)} style={inputStyle}>
                                <option value="beginner">Beginner</option>
                                <option value="easy">Easy</option>
                                <option value="medium">Medium</option>
                                <option value="hard">Hard</option>
                                <option value="expert">Expert</option>
                                <option value="insane">Insane</option>
                            </select>
                        </div>
                        <div style={{ flex: 1 }}>
                            <label style={labelStyle}>Mode</label>
                            <select value={mode} onChange={e => setMode(e.target.value as GameMode)} style={inputStyle}>
                                <option value="attack">Attack</option>
                                <option value="defense">Defense</option>
                                <option value="mixed">Mixed</option>
                            </select>
                        </div>
                        <div style={{ flex: 1 }}>
                            <label style={labelStyle}>Estimated Mins</label>
                            <input type="number" value={estimatedMins} onChange={e => setEstimatedMins(parseInt(e.target.value) || 0)} style={inputStyle} />
                        </div>
                    </div>
                    <div>
                        <label style={labelStyle}>Tags (comma-separated)</label>
                        <input value={tags} onChange={e => setTags(e.target.value)} style={inputStyle} placeholder="web, enumeration, beginner" />
                    </div>
                </div>

                <div style={{ flex: 2, display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <h2 style={{ color: '#D4A03A', fontSize: '1.2rem', margin: 0 }}>WorldSpec JSON</h2>
                        <button type="button" onClick={handleValidate} style={navBtnStyle}>Validate</button>
                    </div>
                    <textarea 
                        value={worldSpecJson} 
                        onChange={e => setWorldSpecJson(e.target.value)}
                        style={{ ...inputStyle, flex: 1, fontFamily: '"JetBrains Mono", "Fira Code", monospace', whiteSpace: 'pre', resize: 'none', lineHeight: '1.5' }}
                        spellCheck={false}
                    />
                </div>
            </main>
        </div>
    );
}

const navBtnStyle: React.CSSProperties = {
    background: 'transparent',
    border: '1px solid #1a1a2e',
    color: '#e0e0e0',
    padding: '6px 14px',
    fontFamily: 'inherit',
    fontSize: '0.8rem',
    cursor: 'pointer',
    borderRadius: '2px',
};

// ── Menu Screen ────────────────────────────────────────────────

function MenuScreen({
    onSelectLevel,
    onBackToLanding,
    onSettings,
}: {
    readonly onSelectLevel: (id: string) => void;
    readonly onBackToLanding: () => void;
    readonly onSettings: () => void;
}): JSX.Element {
    return (
        <div style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'flex-start',
            height: '100vh',
            background: '#0A0A0A',
            color: '#e0e0e0',
            fontFamily: '"JetBrains Mono", "Fira Code", monospace',
            overflowY: 'auto',
            padding: '72px 24px 56px 24px',
            boxSizing: 'border-box',
        }}>
            <div style={{
                position: 'absolute',
                top: '16px',
                left: '16px',
                right: '16px',
                display: 'flex',
                justifyContent: 'space-between',
                pointerEvents: 'none',
            }}>
                <div style={{ pointerEvents: 'auto' }}>
                    <button type="button" onClick={onBackToLanding} style={navBtnStyle}>Back</button>
                </div>
                <div style={{ pointerEvents: 'auto' }}>
                    <button type="button" onClick={onSettings} style={navBtnStyle}>Settings</button>
                </div>
            </div>
            <div style={{ textAlign: 'center', marginBottom: '3rem' }}>
                <h1 style={{
                    fontSize: '4rem',
                    fontWeight: 800,
                    color: '#D4A03A',
                    margin: 0,
                    letterSpacing: '-0.04em',
                    textShadow: '0 0 30px rgba(212, 160, 58, 0.25)',
                }}>
                    VARIANT
                </h1>
                <p style={{
                    fontSize: '0.85rem',
                    color: '#444',
                    marginTop: '0.5rem',
                    letterSpacing: '0.15em',
                    textTransform: 'uppercase',
                }}>
                    Security Simulation Engine
                </p>
            </div>

            <div style={{
                width: 'min(1100px, 100%)',
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                gap: '16px',
            }}>
                {LEVELS.map((level, index) => (
                    <button
                        key={level.id}
                        type="button"
                        onClick={() => { onSelectLevel(level.id); }}
                        style={{
                            border: '1px solid #262626',
                            borderRadius: '4px',
                            padding: '18px',
                            background: '#111111',
                            cursor: 'pointer',
                            transition: 'border-color 0.2s ease, box-shadow 0.2s ease, transform 0.2s ease',
                            textAlign: 'left',
                            color: 'inherit',
                            fontFamily: 'inherit',
                        }}
                        onMouseEnter={(e) => {
                            e.currentTarget.style.borderColor = 'rgba(212, 160, 58, 0.6)';
                            e.currentTarget.style.boxShadow = '0 0 20px rgba(212, 160, 58, 0.1)';
                            e.currentTarget.style.transform = 'translateY(-2px)';
                        }}
                        onMouseLeave={(e) => {
                            e.currentTarget.style.borderColor = '#262626';
                            e.currentTarget.style.boxShadow = 'none';
                            e.currentTarget.style.transform = 'translateY(0px)';
                        }}
                    >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                            <span style={{ color: '#D4A03A', fontSize: '0.72rem', fontWeight: 600 }}>
                                LEVEL {String(index + 1).padStart(2, '0')}
                            </span>
                            <span style={{
                                fontSize: '0.65rem',
                                padding: '2px 8px',
                                border: '1px solid rgba(212, 160, 58, 0.45)',
                                color: '#D4A03A',
                                borderRadius: '2px',
                            }}>
                                {level.difficulty}
                            </span>
                        </div>
                        <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#e0e0e0', margin: '0 0 10px 0' }}>
                            {level.title}
                        </h2>
                        <p style={{ fontSize: '0.8rem', color: '#888', lineHeight: 1.5, margin: '0 0 14px 0' }}>
                            {level.desc}
                        </p>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap', fontSize: '0.7rem', color: '#666' }}>
                            <span>{level.time}</span>
                            {level.tags.map(tag => (
                                <span
                                    key={tag}
                                    style={{
                                        border: '1px solid #2f2f2f',
                                        background: '#141414',
                                        color: '#9a9a9a',
                                        borderRadius: '2px',
                                        padding: '2px 6px',
                                    }}
                                >
                                    {tag}
                                </span>
                            ))}
                        </div>
                    </button>
                ))}
            </div>

            <p style={{
                position: 'absolute',
                bottom: '16px',
                right: '16px',
                fontSize: '0.65rem',
                color: '#222',
            }}>
                VARIANT v0.1.0 — Santh
            </p>
        </div>
    );
}

// ── Simulation Screen ──────────────────────────────────────────

function SimulationScreen({
    worldSpec,
    levelId: _levelId,
    onExit,
    onError: _onError,
    onSettings,
}: {
    readonly worldSpec: WorldSpec;
    readonly levelId: string;
    readonly onExit: () => void;
    readonly onError: (message: string) => void;
    readonly onSettings: () => void;
}): JSX.Element {
    const simulationRef = useRef<Simulation | null>(null);
    const [terminalIO, setTerminalIO] = useState<TerminalIO | null>(null);
    const [simState, setSimState] = useState<SimulationState | null>(null);
    const [bootMessage, setBootMessage] = useState<string>('Initializing v86 emulator...');

    // ── Compositor state ────────────────────────────────────────
    const [compositorState, dispatchCompositor] = useReducer(compositorReducer, undefined, createInitialState);

    const { notifications, dismissNotification, clearAll } = useNotifications();
    const { registerShortcut } = useKeyboardShortcuts();

    const [helpOverlayVisible, setHelpOverlayVisible] = useState(false);
    const [hintPanelVisible, setHintPanelVisible] = useState(false);
    const [lastHint, setLastHint] = useState<string | null>(null);
    const lastNonTerminalLensIdRef = useRef<string | null>(null);
    const helpOverlayVisibleRef = useRef(false);
    helpOverlayVisibleRef.current = helpOverlayVisible;

    // Track last focused non-terminal lens for Ctrl+` toggle
    useEffect(() => {
        const fid = compositorState.focusedLensId;
        if (fid === null) return;
        const lens = compositorState.lenses.get(fid);
        if (lens !== undefined && lens.type !== 'terminal') {
            lastNonTerminalLensIdRef.current = fid;
        }
    }, [compositorState.focusedLensId, compositorState.lenses]);

    // ── Lens data refs (populated from event bus) ───────────────
    const emailsRef = useRef<readonly EmailMessage[]>([]);
    const logsRef = useRef<readonly LogEntry[]>([]);
    const networkNodesRef = useRef<readonly NetworkNode[]>([]);
    const networkEdgesRef = useRef<readonly NetworkEdge[]>([]);
    const trafficFlowsRef = useRef<readonly TrafficFlow[]>([]);
    const processesRef = useRef<readonly ProcessInfo[]>([]);
    const packetsRef = useRef<readonly CapturedPacket[]>([]);
    const [capturing, setCapturing] = useState(true);

    // Subscribe to event bus for lens data
    useEffect(() => {
        const sim = simulationRef.current;
        if (sim === null) return;

        const unsubs: Array<() => void> = [];

        unsubs.push(sim.events.on('custom:email-received', (event) => {
            const msg = (event as { data: unknown }).data as EmailMessage;
            emailsRef.current = [...emailsRef.current, msg];
        }));

        unsubs.push(sim.events.on('custom:email-sent', (event) => {
            const msg = (event as { data: unknown }).data as EmailMessage;
            emailsRef.current = [...emailsRef.current, msg];
        }));

        unsubs.push(sim.events.on('custom:log-entry', (event) => {
            const entry = (event as { data: unknown }).data as LogEntry;
            logsRef.current = [...logsRef.current.slice(-9999), entry];
        }));

        unsubs.push(sim.events.on('custom:network-topology', (event) => {
            const topo = (event as { data: unknown }).data as {
                nodes: readonly NetworkNode[];
                edges: readonly NetworkEdge[];
            };
            networkNodesRef.current = topo.nodes;
            networkEdgesRef.current = topo.edges;
        }));

        unsubs.push(sim.events.on('custom:traffic-flow', (event) => {
            const flow = (event as { data: unknown }).data as TrafficFlow;
            // Keep last 200 flows for animation
            trafficFlowsRef.current = [...trafficFlowsRef.current.slice(-199), flow];
        }));

        unsubs.push(sim.events.on('custom:process-list', (event) => {
            const procs = (event as { data: unknown }).data as readonly ProcessInfo[];
            processesRef.current = procs;
        }));

        // Tap fabric for packet capture
        unsubs.push(sim.events.on('custom:packet-captured', (event) => {
            const pkt = (event as { data: unknown }).data as CapturedPacket;
            packetsRef.current = [...packetsRef.current.slice(-9999), pkt];
        }));

        return () => { unsubs.forEach(fn => { fn(); }); };
    }, [terminalIO]); // re-subscribe when terminal is ready (sim is booted)

    // ── Email handlers ──────────────────────────────────────────
    const handleEmailSend = useCallback((to: string, subject: string, body: string) => {
        const sim = simulationRef.current;
        if (sim === null) return;

        const sent: EmailMessage = {
            id: `email-${Date.now()}`,
            from: 'operator@variant.local',
            to,
            subject,
            body,
            date: new Date().toISOString(),
            read: true,
            folder: 'sent',
        };

        emailsRef.current = [...emailsRef.current, sent];
        sim.events.emit({ type: 'custom:email-sent', data: sent, timestamp: Date.now() });
    }, []);

    const handleEmailMarkRead = useCallback((emailId: string) => {
        emailsRef.current = emailsRef.current.map(e =>
            e.id === emailId ? { ...e, read: true } : e,
        );
    }, []);

    // ── Log refresh handler ─────────────────────────────────────
    const handleLogRefresh = useCallback(() => {
        const sim = simulationRef.current;
        if (sim === null) return;
        sim.events.emit({ type: 'custom:log-refresh', data: {}, timestamp: Date.now() });
    }, []);

    // ── File manager handlers ───────────────────────────────────
    const handleListDir = useCallback((path: string): readonly FileEntry[] => {
        const sim = simulationRef.current;
        if (sim === null) return [];

        // Query VFS through event bus — modules respond with file listings
        const entries: FileEntry[] = [];
        const unsub = sim.events.on('custom:vfs-listing', (event) => {
            const listing = (event as { data: unknown }).data as { path: string; entries: readonly FileEntry[] };
            if (listing.path === path) {
                entries.push(...listing.entries);
            }
        });
        sim.events.emit({ type: 'custom:vfs-list', data: { path }, timestamp: Date.now() });
        unsub();
        return entries;
    }, []);

    const handleReadFile = useCallback((path: string): string | null => {
        const sim = simulationRef.current;
        if (sim === null) return null;

        let content: string | null = null;
        const unsub = sim.events.on('custom:vfs-content', (event) => {
            const result = (event as { data: unknown }).data as { path: string; content: string };
            if (result.path === path) {
                content = result.content;
            }
        });
        sim.events.emit({ type: 'custom:vfs-read', data: { path }, timestamp: Date.now() });
        unsub();
        return content;
    }, []);

    // ── Process viewer handler ──────────────────────────────────
    const handleProcessRefresh = useCallback(() => {
        const sim = simulationRef.current;
        if (sim === null) return;
        sim.events.emit({ type: 'custom:process-refresh', data: {}, timestamp: Date.now() });
    }, []);

    // ── Packet capture handlers ─────────────────────────────────
    const handleToggleCapture = useCallback(() => {
        setCapturing(prev => !prev);
    }, []);

    const handleClearPackets = useCallback(() => {
        packetsRef.current = [];
    }, []);

    // ── Open new lens (from terminal OSC or keyboard shortcut) ──
    const handleOpenLens = useCallback((type: string, config: Readonly<Record<string, unknown>>) => {
        const id = generateLensId();
        const titles: Record<string, string> = {
            'terminal': 'Terminal',
            'browser': 'Browser',
            'browse': 'Browser',
            'file-manager': 'Files',
            'email': 'Email',
            'network-map': 'Network',
            'log-viewer': 'Logs',
            'process-viewer': 'Processes',
            'packet-capture': 'Packets',
        };
        const normalizedType = type === 'browse' ? 'browser' : type;

        const lens: LensInstance = {
            id,
            type: normalizedType,
            title: titles[type] ?? type,
            targetMachine: worldSpec.startMachine,
            config,
        };
        dispatchCompositor({ type: 'open-lens', lens, position: 'right' });
    }, [worldSpec]);

    // ── Register Shortcuts ──────────────────────────────────────
    useEffect(() => {
        registerShortcut('ctrl+shift+t', () => { handleOpenLens('terminal', {}); });
        registerShortcut('ctrl+shift+b', () => { handleOpenLens('browser', { url: 'about:blank' }); });
        registerShortcut('ctrl+shift+e', () => { handleOpenLens('email', {}); });
        registerShortcut('ctrl+shift+f', () => { handleOpenLens('file-manager', {}); });
        registerShortcut('ctrl+shift+n', () => { handleOpenLens('network-map', {}); });
        registerShortcut('ctrl+shift+l', () => { handleOpenLens('log-viewer', {}); });
        registerShortcut('ctrl+shift+p', () => { handleOpenLens('process-viewer', {}); });
        registerShortcut('ctrl+shift+k', () => { handleOpenLens('packet-capture', {}); });

        registerShortcut('ctrl+tab', () => {
            if (compositorState.taskbar.length <= 1) return;
            const currentIdx = compositorState.taskbar.indexOf(compositorState.focusedLensId ?? '');
            const nextIdx = currentIdx === -1 || currentIdx === compositorState.taskbar.length - 1 ? 0 : currentIdx + 1;
            dispatchCompositor({ type: 'focus-lens', lensId: compositorState.taskbar[nextIdx]! });
        });

        registerShortcut('ctrl+shift+tab', () => {
            if (compositorState.taskbar.length <= 1) return;
            const currentIdx = compositorState.taskbar.indexOf(compositorState.focusedLensId ?? '');
            const prevIdx = currentIdx <= 0 ? compositorState.taskbar.length - 1 : currentIdx - 1;
            dispatchCompositor({ type: 'focus-lens', lensId: compositorState.taskbar[prevIdx]! });
        });

        for (let i = 1; i <= 8; i++) {
            const idx = i - 1;
            registerShortcut(`ctrl+${i}`, () => {
                if (compositorState.taskbar.length > idx) {
                    const lensId = compositorState.taskbar[idx];
                    if (lensId !== undefined) {
                        dispatchCompositor({ type: 'focus-lens', lensId });
                    }
                }
            });
        }

        registerShortcut('ctrl+`', () => {
            const taskbar = compositorState.taskbar;
            if (taskbar.length === 0) return;
            const focusedId = compositorState.focusedLensId;
            const focusedLens = focusedId !== null ? compositorState.lenses.get(focusedId) : undefined;
            const terminalId = taskbar.find((id) => compositorState.lenses.get(id)?.type === 'terminal');
            if (focusedLens?.type === 'terminal') {
                const last = lastNonTerminalLensIdRef.current;
                if (last !== null && compositorState.lenses.has(last)) {
                    dispatchCompositor({ type: 'focus-lens', lensId: last });
                }
            } else if (terminalId !== undefined) {
                dispatchCompositor({ type: 'focus-lens', lensId: terminalId });
            }
        });

        registerShortcut('ctrl+h', () => { setHintPanelVisible((v) => !v); });
        registerShortcut('f1', () => { setHelpOverlayVisible(true); });
        registerShortcut('shift+?', () => { setHelpOverlayVisible(true); });

        registerShortcut('ctrl+w', () => {
            const focusedId = compositorState.focusedLensId;
            if (focusedId === null) return;
            const lens = compositorState.lenses.get(focusedId);
            if (lens?.type === 'terminal') {
                if (!window.confirm('Are you sure you want to close this terminal?')) return;
            }
            dispatchCompositor({ type: 'close-lens', lensId: focusedId });
        });

        registerShortcut('f11', () => {
            const focusedId = compositorState.focusedLensId;
            if (focusedId !== null) {
                dispatchCompositor({ type: 'toggle-maximize', lensId: focusedId });
            }
        });

        registerShortcut('escape', () => {
            if (helpOverlayVisibleRef.current) {
                setHelpOverlayVisible(false);
                return;
            }
            if (compositorState.maximizedLensId !== null) {
                dispatchCompositor({ type: 'toggle-maximize', lensId: compositorState.maximizedLensId });
                return;
            }
            clearAll();
        });
    }, [registerShortcut, handleOpenLens, compositorState, dispatchCompositor, clearAll]);

    // Inject xterm.js CSS on mount
    useEffect(() => { injectXtermCSS(); }, []);

    // Boot simulation
    useEffect(() => {
        let destroyed = false;

        async function boot(): Promise<void> {
            try {
                setBootMessage('Creating VM backend...');
                const simulacrum = createSimulacrumBackend();
                const backend = createBackendRouter({
                    backends: new Map([['simulacrum', simulacrum]]),
                    selector: () => 'simulacrum',
                    fallback: 'simulacrum',
                });

                setBootMessage('Initializing modules...');
                const registry = createModuleRegistry();
                registry.register('objective-detector', createObjectiveDetector);
                registry.register('scoring-engine', createScoringEngine);

                setBootMessage('Validating WorldSpec...');
                const sim = createSimulation({
                    worldSpec,
                    backend,
                    imageBaseUrl: '/images',
                    biosUrl: '/v86/seabios.bin',
                    vgaBiosUrl: '/v86/vgabios.bin',
                    moduleRegistry: registry,
                });

                if (destroyed) { sim.destroy(); return; }

                simulationRef.current = sim;

                setBootMessage('Booting virtual machine...');
                await sim.boot();

                if (destroyed) { sim.destroy(); return; }

                const playerTerminal = sim.getPlayerTerminal();
                setTerminalIO(playerTerminal);
                setSimState(sim.getState());

                // Open initial terminal lens
                const termLensId = generateLensId();
                const termLens: LensInstance = {
                    id: termLensId,
                    type: 'terminal',
                    title: 'Terminal',
                    targetMachine: worldSpec.startMachine,
                    config: {},
                };
                dispatchCompositor({ type: 'open-lens', lens: termLens });
            } catch (error: unknown) {
                if (!destroyed) {
                    setBootMessage(
                        `Boot failed: ${error instanceof Error ? error.message : String(error)}`,
                    );
                }
            }
        }

        boot().catch(() => { });

        return () => {
            destroyed = true;
            const sim = simulationRef.current;
            if (sim !== null) {
                sim.destroy();
                simulationRef.current = null;
            }
        };
    }, [worldSpec]); // eslint-disable-line react-hooks/exhaustive-deps

    // Update sim state periodically + on objective completion
    useEffect(() => {
        const interval = setInterval(() => {
            const sim = simulationRef.current;
            if (sim !== null) { setSimState(sim.getState()); }
        }, 1000);

        // Immediate update on objective events
        const sim = simulationRef.current;
        const unsubs: (() => void)[] = [];
        if (sim !== null) {
            unsubs.push(sim.events.on('objective:complete', () => {
                setSimState(sim.getState());
            }));
            unsubs.push(sim.events.on('objective:progress', () => {
                setSimState(sim.getState());
            }));
            unsubs.push(sim.events.onPrefix('custom:', (event) => {
                if (event.type === 'custom:score-update') {
                    setSimState(sim.getState());
                }
            }));
        }

        return () => {
            clearInterval(interval);
            for (const unsub of unsubs) unsub();
        };
    }, [terminalIO]); // Re-subscribe when terminal connects (sim is ready)

    // ── Browser navigation handler ──────────────────────────────
    // Routes HTTP requests through the fabric's registered external
    // service handlers — the same ones that serve VM HTTP traffic.
    // This means the browser sees exactly what curl/wget would see.
    const handleBrowserNavigate = useCallback((url: string, method?: string, body?: string): BrowserResponse => {
        const sim = simulationRef.current;
        if (sim === null) {
            return {
                status: 503,
                statusText: 'Service Unavailable',
                headers: new Map(),
                body: '<html><body style="font-family:monospace;background:#1a1a1a;color:#ff5555;padding:40px"><h1>Connection Failed</h1><p style="color:#999">ERR_CONNECTION_REFUSED — No simulation running.</p></body></html>',
                contentType: 'text/html',
            };
        }

        try {
            const hostname = extractHostname(url);
            const path = extractPath(url);

            // Look up the handler from the fabric (same handlers that serve VMs)
            const handler = sim.fabric.getExternalHandler(hostname);
            if (handler === undefined) {
                // Realistic DNS failure — looks like a real browser error
                const availableDomains = sim.fabric.getExternalDomains();
                return {
                    status: 0,
                    statusText: 'DNS Resolution Failed',
                    headers: new Map(),
                    body: `<html><body style="font-family:-apple-system,sans-serif;background:#1a1a1a;color:#e0e0e0;padding:40px;max-width:600px;margin:0 auto">` +
                        `<h1 style="color:#ff5555;font-size:1.2rem">This site can\u2019t be reached</h1>` +
                        `<p style="color:#999"><strong>${hostname}</strong>\u2019s server DNS address could not be found.</p>` +
                        `<p style="color:#666;font-size:0.85rem">ERR_NAME_NOT_RESOLVED</p>` +
                        `<hr style="border:none;border-top:1px solid #333;margin:20px 0">` +
                        (availableDomains.length > 0
                            ? `<p style="color:#666;font-size:0.8rem">Available services on this network:</p><ul style="color:#D4A03A;font-size:0.8rem">${availableDomains.map(d => `<li><a href="http://${d}" style="color:#00aaff">${d}</a></li>`).join('')}</ul>`
                            : `<p style="color:#666;font-size:0.8rem">No HTTP services are available on this network.</p>`) +
                        `</body></html>`,
                    contentType: 'text/html',
                };
            }

            // Build request matching ExternalRequest interface
            const reqHeaders = new Map<string, string>();
            reqHeaders.set('host', hostname);
            reqHeaders.set('user-agent', 'VARIANT-Browser/1.0');
            reqHeaders.set('accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8');
            if (body !== undefined) {
                reqHeaders.set('content-type', 'application/x-www-form-urlencoded');
                reqHeaders.set('content-length', String(new TextEncoder().encode(body).length));
            }

            const response = handler.handleRequest({
                method: method ?? 'GET',
                path,
                headers: reqHeaders,
                body: body !== undefined ? new TextEncoder().encode(body) : null,
            });

            const decoder = new TextDecoder();
            const bodyText = decoder.decode(response.body);
            const contentType = response.headers.get('content-type') ?? 'text/html';

            const statusTexts: Record<number, string> = {
                200: 'OK', 201: 'Created', 204: 'No Content',
                301: 'Moved Permanently', 302: 'Found', 304: 'Not Modified',
                400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden',
                404: 'Not Found', 405: 'Method Not Allowed', 429: 'Too Many Requests',
                500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable',
            };

            return {
                status: response.status,
                statusText: statusTexts[response.status] ?? `HTTP ${response.status}`,
                headers: response.headers,
                body: bodyText,
                contentType,
            };
        } catch (err: unknown) {
            return {
                status: 500,
                statusText: 'Internal Server Error',
                headers: new Map(),
                body: `<html><body style="font-family:monospace;background:#1a1a1a;color:#ff5555;padding:40px"><h1>500 Internal Server Error</h1><pre style="color:#999">${err instanceof Error ? err.message : String(err)}</pre></body></html>`,
                contentType: 'text/html',
            };
        }
    }, []);

    const handleExit = useCallback(() => {
        const sim = simulationRef.current;
        if (sim !== null) {
            sim.destroy();
            simulationRef.current = null;
        }
        onExit();
    }, [onExit]);

    const handleHint = useCallback(() => {
        const sim = simulationRef.current;
        if (sim === null) return;
        const hint = sim.useHint();
        if (hint !== null) {
            setLastHint(hint);
            setSimState(sim.getState());
        }
    }, []);

    // ── Render lens by type ─────────────────────────────────────
    const renderLens = useCallback((lens: LensInstance, focused: boolean): JSX.Element => {
        switch (lens.type) {
            case 'terminal':
                return (
                    <TerminalLens
                        terminalIO={terminalIO}
                        lensContext={{
                            instance: lens,
                            definition: {
                                type: 'terminal',
                                displayName: 'Terminal',
                                description: 'VM terminal',
                                icon: '>_',
                                capabilities: { targetMachine: 'required', compatibleBackends: null, writable: true, custom: {} },
                                constraints: { minWidth: 200, minHeight: 150, preferredAspectRatio: null, preferredSize: 0.5 },
                                shortcut: null,
                                allowMultiple: true,
                            },
                            events: simulationRef.current?.events ?? { emit() { }, on() { return () => { }; }, once() { return () => { }; }, waitFor() { return new Promise(() => { }); }, onPrefix() { return () => { }; }, getLog() { return []; }, clearLog() { }, removeAllListeners() { } },
                            sendMessage: () => false,
                            broadcastMessage: () => 0,
                            requestOpenLens: (req) => { handleOpenLens(req.type, req.config ?? {}); },
                            setTitle: (title) => { dispatchCompositor({ type: 'set-title', lensId: lens.id, title }); },
                            requestFocus: () => { dispatchCompositor({ type: 'focus-lens', lensId: lens.id }); },
                        }}
                        focused={focused}
                    />
                );

            case 'browser':
                return (
                    <BrowserLens
                        initialUrl={typeof lens.config['url'] === 'string' ? lens.config['url'] : typeof lens.config['initialUrl'] === 'string' ? lens.config['initialUrl'] : 'about:blank'}
                        onNavigate={handleBrowserNavigate}
                        focused={focused}
                    />
                );

            case 'email':
                return (
                    <EmailLens
                        account={typeof lens.config['account'] === 'string' ? lens.config['account'] : 'operator@variant.local'}
                        emails={emailsRef.current}
                        onSend={handleEmailSend}
                        onMarkRead={handleEmailMarkRead}
                        focused={focused}
                    />
                );

            case 'log-viewer':
                return (
                    <LogViewerLens
                        logs={logsRef.current}
                        onRefresh={handleLogRefresh}
                        focused={focused}
                    />
                );

            case 'file-manager':
                return (
                    <FileManagerLens
                        onListDir={handleListDir}
                        onReadFile={handleReadFile}
                        focused={focused}
                    />
                );

            case 'network-map':
                return (
                    <NetworkMapLens
                        nodes={networkNodesRef.current}
                        edges={networkEdgesRef.current}
                        traffic={trafficFlowsRef.current}
                        focused={focused}
                    />
                );

            case 'process-viewer':
                return (
                    <ProcessViewerLens
                        processes={processesRef.current}
                        machineName={lens.targetMachine ?? 'unknown'}
                        onRefresh={handleProcessRefresh}
                        focused={focused}
                    />
                );

            case 'packet-capture':
                return (
                    <PacketCaptureLens
                        packets={packetsRef.current}
                        capturing={capturing}
                        onToggleCapture={handleToggleCapture}
                        onClear={handleClearPackets}
                        focused={focused}
                    />
                );

            default:
                return (
                    <div style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        height: '100%',
                        color: '#666',
                        fontSize: '0.8rem',
                        fontFamily: 'var(--font-mono)',
                    }}>
                        Lens type "{lens.type}" not yet implemented
                    </div>
                );
        }
    }, [terminalIO, handleOpenLens, handleBrowserNavigate, handleEmailSend, handleEmailMarkRead, handleLogRefresh, handleListDir, handleReadFile, handleProcessRefresh, handleToggleCapture, handleClearPackets, capturing]);

    // ── Pre-boot screen ─────────────────────────────────────────
    if (terminalIO === null) {
        return (
            <div style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100vh',
                background: '#0a0e14',
                fontFamily: '"JetBrains Mono", "Fira Code", monospace',
            }}>
                <div style={{
                    fontSize: '1.5rem',
                    fontWeight: 700,
                    color: '#D4A03A',
                    textShadow: '0 0 20px rgba(212, 160, 58, 0.3)',
                    letterSpacing: '0.1em',
                    marginBottom: '2rem',
                }}>
                    VARIANT
                </div>
                <div style={{
                    width: '40px',
                    height: '40px',
                    border: '3px solid #21262d',
                    borderTopColor: '#D4A03A',
                    borderRadius: '50%',
                    animation: 'spin 0.8s linear infinite',
                    marginBottom: '1rem',
                }} />
                <div style={{ color: '#8b949e', fontSize: '0.8rem' }}>
                    {bootMessage}
                </div>
                <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
            </div>
        );
    }

    // ── Simulation UI ───────────────────────────────────────────
    return (
        <div style={{
            display: 'flex',
            flexDirection: 'column',
            height: '100vh',
            background: 'var(--bg-primary, #0a0e14)',
            fontFamily: '"JetBrains Mono", "Fira Code", monospace',
        }}>
            {/* Status Bar */}
            <StatusBar
                simState={simState}
                onExit={handleExit}
                onHint={handleHint}
                onOpenLens={handleOpenLens}
                onSettings={onSettings}
            />

            {/* Lens Compositor */}
            <div style={{ flex: 1, overflow: 'hidden' }}>
                <LensCompositor
                    state={compositorState}
                    dispatch={dispatchCompositor}
                    renderLens={renderLens}
                />
            </div>

            {/* Objective Panel */}
            {simState !== null && (
                <ObjectivePanel
                    objectives={worldSpec.objectives}
                    status={simState.objectiveStatus}
                />
            )}

            {/* Notifications */}
            <NotificationToast notifications={notifications} onDismiss={dismissNotification} />

            {/* Keyboard shortcuts help overlay */}
            <HelpOverlay open={helpOverlayVisible} onClose={() => setHelpOverlayVisible(false)} />

            {/* Hint panel (Ctrl+H to toggle) */}
            {hintPanelVisible && (
                <div
                    style={{
                        position: 'fixed',
                        bottom: '32px',
                        left: '16px',
                        right: '16px',
                        maxWidth: '420px',
                        padding: '12px 14px',
                        background: '#0a0a0a',
                        border: '1px solid rgba(212, 160, 58, 0.35)',
                        borderRadius: '6px',
                        color: '#e0e0e0',
                        fontSize: '0.8rem',
                        fontFamily: '"JetBrains Mono", "Fira Code", monospace',
                        boxShadow: '0 4px 20px rgba(0,0,0,0.4)',
                        zIndex: 9999,
                    }}
                >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                        <span style={{ color: '#D4A03A', fontWeight: 600, fontSize: '0.7rem' }}>HINT</span>
                        <button
                            type="button"
                            onClick={() => setHintPanelVisible(false)}
                            style={{
                                background: 'transparent',
                                border: 'none',
                                color: '#666',
                                cursor: 'pointer',
                                fontFamily: 'inherit',
                                fontSize: '0.75rem',
                            }}
                        >
                            Close
                        </button>
                    </div>
                    <div style={{ color: '#999', lineHeight: 1.5 }}>
                        {lastHint !== null ? lastHint : 'Use the HINT button in the status bar to request a hint.'}
                    </div>
                </div>
            )}
        </div>
    );
}

// ── Status Bar ─────────────────────────────────────────────────

function StatusBar({
    simState,
    onExit,
    onHint,
    onOpenLens,
    onSettings,
}: {
    readonly simState: SimulationState | null;
    readonly onExit: () => void;
    readonly onHint: () => void;
    readonly onOpenLens: (type: string, config: Readonly<Record<string, unknown>>) => void;
    readonly onSettings: () => void;
}): JSX.Element {
    const formatTime = (ms: number): string => {
        const totalSeconds = Math.floor(ms / 1000);
        const minutes = Math.floor(totalSeconds / 60);
        const seconds = totalSeconds % 60;
        return `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    };

    return (
        <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '4px 12px',
            borderBottom: '1px solid var(--border-default, #21262d)',
            fontSize: '0.7rem',
            color: '#666',
            background: 'var(--bg-secondary, #0d1117)',
            minHeight: '28px',
            flexShrink: 0,
        }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <span style={{ color: '#D4A03A', fontWeight: 700 }}>VARIANT</span>

                {simState !== null && (
                    <>
                        <span style={{
                            color: simState.phase === 'running' ? '#3DA67A'
                                : simState.phase === 'completed' ? '#D4A03A'
                                    : simState.phase === 'failed' ? '#ff5555'
                                        : '#666',
                            fontWeight: simState.phase === 'completed' ? 700 : 400,
                            textShadow: simState.phase === 'completed' ? '0 0 8px rgba(212, 160, 58, 0.4)' : 'none',
                        }}>
                            {'\u25CF'} {simState.phase.toUpperCase()}
                        </span>
                        <span>{formatTime(simState.elapsedMs)}</span>
                        <span>Score: {simState.score}</span>
                    </>
                )}
            </div>

            <div style={{ display: 'flex', gap: '4px' }}>
                {/* Quick-open lens buttons */}
                <button type="button" onClick={() => { onOpenLens('terminal', {}); }} style={statusBtnStyle} title="New Terminal">
                    {'[>_]'}
                </button>
                <button type="button" onClick={() => { onOpenLens('browser', { url: 'about:blank' }); }} style={statusBtnStyle} title="Open Browser (Ctrl+Shift+B)">
                    {'[www]'}
                </button>
                <button type="button" onClick={() => { onOpenLens('email', {}); }} style={statusBtnStyle} title="Open Email (Ctrl+Shift+E)">
                    {'[@]'}
                </button>
                <button type="button" onClick={() => { onOpenLens('file-manager', {}); }} style={statusBtnStyle} title="Open File Manager (Ctrl+Shift+F)">
                    {'[dir]'}
                </button>
                <button type="button" onClick={() => { onOpenLens('log-viewer', {}); }} style={statusBtnStyle} title="Open Log Viewer (Ctrl+Shift+L)">
                    {'[log]'}
                </button>
                <button type="button" onClick={() => { onOpenLens('network-map', {}); }} style={statusBtnStyle} title="Network Map (Ctrl+Shift+N)">
                    {'[net]'}
                </button>
                <button type="button" onClick={() => { onOpenLens('process-viewer', {}); }} style={statusBtnStyle} title="Process Viewer (Ctrl+Shift+P)">
                    {'[ps]'}
                </button>
                <button type="button" onClick={() => { onOpenLens('packet-capture', {}); }} style={statusBtnStyle} title="Packet Capture (Ctrl+Shift+K)">
                    {'[pcap]'}
                </button>

                <div style={{ width: '1px', background: '#21262d', margin: '0 4px' }} />

                <button type="button" onClick={onHint} style={{ ...statusBtnStyle, color: '#f1fa8c' }}>
                    HINT
                </button>
                <button type="button" onClick={onSettings} style={statusBtnStyle} title="Settings">
                    SETTINGS
                </button>
                <button type="button" onClick={onExit} style={{ ...statusBtnStyle, color: '#ff5555' }}>
                    EXIT
                </button>
            </div>
        </div>
    );
}

// ── Objective Panel ────────────────────────────────────────────

interface ObjectivePanelProps {
    readonly objectives: readonly import('../core/world/types').ObjectiveSpec[];
    readonly status: ReadonlyMap<string, import('../core/engine').ObjectiveStatus>;
}

function ObjectivePanel({ objectives, status }: ObjectivePanelProps): JSX.Element {
    // Track which objectives just completed for flash animation
    const [flashCompleted, setFlashCompleted] = useState<Set<string>>(new Set());
    // Track which objectives just unlocked for transition animation
    const [newlyUnlocked, setNewlyUnlocked] = useState<Set<string>>(new Set());
    const prevStatusRef = useRef<ReadonlyMap<string, import('../core/engine').ObjectiveStatus> | null>(null);

    // Detect status changes for animations
    useEffect(() => {
        const prevStatus = prevStatusRef.current;
        if (prevStatus) {
            const completed = new Set<string>();
            const unlocked = new Set<string>();

            for (const obj of objectives) {
                const current = status.get(obj.id);
                const previous = prevStatus.get(obj.id);

                // Flash when transitioning to completed
                if (current === 'completed' && previous !== 'completed') {
                    completed.add(obj.id);
                }
                // Transition when unlocking
                if (current === 'available' && previous === 'locked') {
                    unlocked.add(obj.id);
                }
            }

            if (completed.size > 0) {
                setFlashCompleted(completed);
                const timer = setTimeout(() => setFlashCompleted(new Set()), 500);
                return () => clearTimeout(timer);
            }
            if (unlocked.size > 0) {
                setNewlyUnlocked(unlocked);
                const timer = setTimeout(() => setNewlyUnlocked(new Set()), 300);
                return () => clearTimeout(timer);
            }
        }
        prevStatusRef.current = status;
    }, [status, objectives]);

    // Calculate progress
    const completedCount = objectives.filter(obj => status.get(obj.id) === 'completed').length;
    const totalCount = objectives.length;
    const requiredCount = objectives.filter(obj => obj.required).length;
    const completedRequiredCount = objectives.filter(obj => obj.required && status.get(obj.id) === 'completed').length;
    const allRequiredCompleted = requiredCount > 0 && completedRequiredCount === requiredCount;

    // Calculate total score from completed objectives
    const totalScore = objectives
        .filter(obj => status.get(obj.id) === 'completed')
        .reduce((sum, obj) => sum + (obj.reward ?? 0), 0);

    return (
        <div style={{ flexShrink: 0 }}>
            {/* Mission Complete Banner */}
            {allRequiredCompleted && (
                <div style={{
                    background: 'linear-gradient(90deg, rgba(212, 160, 58, 0.2) 0%, rgba(212, 160, 58, 0.4) 50%, rgba(212, 160, 58, 0.2) 100%)',
                    borderTop: '1px solid rgba(212, 160, 58, 0.5)',
                    padding: '6px 12px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    animation: 'missionCompletePulse 0.5s ease-out',
                }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ color: '#D4A03A', fontSize: '0.9rem' }}>★</span>
                        <span style={{ color: '#D4A03A', fontSize: '0.7rem', fontWeight: 'bold', letterSpacing: '0.1em' }}>
                            MISSION COMPLETE
                        </span>
                    </div>
                    <span style={{ color: '#D4A03A', fontSize: '0.7rem', fontWeight: 'bold' }}>
                        SCORE: {totalScore} pts
                    </span>
                </div>
            )}

            {/* Objective Panel */}
            <div style={{
                borderTop: '1px solid var(--border-default, #21262d)',
                background: 'var(--bg-secondary, #0d1117)',
                fontSize: '0.7rem',
                flexShrink: 0,
            }}>
                {/* Header with progress */}
                <div style={{
                    padding: '6px 12px',
                    borderBottom: '1px solid var(--border-default, #21262d)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    color: '#8b949e',
                }}>
                    <span style={{ fontWeight: 'bold', letterSpacing: '0.05em' }}>OBJECTIVES</span>
                    <span style={{ color: completedCount === totalCount ? '#3DA67A' : '#8b949e', transition: 'color 0.3s' }}>
                        {completedCount}/{totalCount}
                    </span>
                </div>

                {/* Scrollable objective list */}
                <div style={{
                    maxHeight: '200px',
                    overflowY: 'auto',
                    padding: '6px 12px',
                }}>
                    {objectives.map(obj => {
                        const objStatus = status.get(obj.id) ?? 'locked';
                        const isFlashing = flashCompleted.has(obj.id);
                        const isNewlyUnlocked = newlyUnlocked.has(obj.id);

                        const icon = objStatus === 'completed' ? '\u2713'
                            : objStatus === 'available' ? '\u25CB'
                                : objStatus === 'in-progress' ? '\u25D0'
                                    : '\u25CC';

                        // Base colors with transition
                        const baseColor = objStatus === 'completed' ? '#3DA67A'
                            : objStatus === 'available' ? '#e0e0e0'
                                : '#444';

                        // Flash amber on completion
                        const color = isFlashing ? '#D4A03A' : baseColor;
                        const bgColor = isFlashing ? 'rgba(212, 160, 58, 0.15)' : 'transparent';

                        return (
                            <div
                                key={obj.id}
                                style={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '8px',
                                    padding: '3px 0',
                                    opacity: isNewlyUnlocked ? 1 : objStatus === 'locked' ? 0.4 : 1,
                                    transform: isNewlyUnlocked ? 'translateX(4px)' : 'translateX(0)',
                                    transition: 'all 0.3s ease',
                                    backgroundColor: bgColor,
                                    borderRadius: '2px',
                                }}
                            >
                                <span style={{
                                    color,
                                    fontSize: '0.8rem',
                                    transition: 'color 0.3s',
                                    width: '14px',
                                    textAlign: 'center',
                                }}>{icon}</span>
                                <span style={{
                                    color,
                                    transition: 'color 0.3s',
                                    flex: 1,
                                    textDecoration: objStatus === 'completed' ? 'line-through' : 'none',
                                    textDecorationColor: '#3DA67A40',
                                    opacity: objStatus === 'completed' ? 0.7 : 1,
                                }}>
                                    {obj.title}
                                </span>
                                {/* Bonus reward indicator */}
                                {!obj.required && obj.reward !== undefined && obj.reward > 0 && (
                                    <span style={{
                                        color: objStatus === 'completed' ? '#3DA67A' : '#D4A03A',
                                        fontSize: '0.6rem',
                                        fontWeight: 'bold',
                                        transition: 'color 0.3s',
                                    }}>
                                        +{obj.reward} pts
                                    </span>
                                )}
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* Animation keyframes */}
            <style>{`
                @keyframes missionCompletePulse {
                    0% { opacity: 0; transform: translateY(-10px); }
                    50% { opacity: 1; transform: translateY(0); }
                    100% { opacity: 1; transform: translateY(0); }
                }
            `}</style>
        </div>
    );
}

// ── Error Screen ───────────────────────────────────────────────

function ErrorScreen({ message, onBack }: { readonly message: string; readonly onBack: () => void }): JSX.Element {
    return (
        <div style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            height: '100vh',
            background: '#0a0a0a',
            color: '#ff5555',
            fontFamily: '"JetBrains Mono", "Fira Code", monospace',
        }}>
            <h1 style={{ fontSize: '1.5rem', marginBottom: '1rem' }}>ERROR</h1>
            <p style={{ fontSize: '0.85rem', color: '#999', maxWidth: '500px', textAlign: 'center', lineHeight: 1.6 }}>
                {message}
            </p>
            <button
                onClick={onBack}
                style={{
                    marginTop: '2rem',
                    background: 'transparent',
                    border: '1px solid #ff555560',
                    color: '#ff5555',
                    padding: '8px 24px',
                    fontFamily: 'inherit',
                    fontSize: '0.85rem',
                    cursor: 'pointer',
                }}
            >
                Back to Menu
            </button>
        </div>
    );
}

// ── Helpers ──────────────────────────────────────────────────────

function extractHostname(url: string): string {
    try {
        return new URL(url).hostname;
    } catch {
        return url.replace(/^https?:\/\//, '').split('/')[0] ?? '';
    }
}

function extractPath(url: string): string {
    try {
        const u = new URL(url);
        return u.pathname + u.search;
    } catch {
        const idx = url.indexOf('/', url.indexOf('//') + 2);
        return idx === -1 ? '/' : url.slice(idx);
    }
}

const statusBtnStyle: React.CSSProperties = {
    background: 'transparent',
    border: '1px solid #21262d',
    color: '#666',
    padding: '2px 8px',
    fontFamily: 'inherit',
    fontSize: '0.65rem',
    cursor: 'pointer',
    borderRadius: '2px',
};
