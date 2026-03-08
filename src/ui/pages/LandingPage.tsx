/**
 * VARIANT — Landing Page
 *
 * Santh Signal Design System: monochrome field, amber signal (threat product).
 * Professional, minimal, information-dense. Unified brand with santh.io.
 */

import type { CSSProperties, ReactNode } from 'react';
import { useState, useEffect } from 'react';

// ── Types ──────────────────────────────────────────────────────

export interface LandingPageProps {
    readonly onLaunch: () => void;
    readonly onMarketplace: () => void;
    readonly onCreate?: () => void;
    readonly onSettings?: () => void;
}

// ── Constants ───────────────────────────────────────────────────

const C = {
    bg: '#0A0A0A',
    surface: '#111111',
    elevated: '#181818',
    text: '#E0E0E0',
    muted: '#707070',
    dim: '#404040',
    border: 'rgba(255, 255, 255, 0.08)',
    signal: '#D4A03A',
    signalDim: 'rgba(212, 160, 58, 0.15)',
    signalGlow: 'rgba(212, 160, 58, 0.25)',
    signalSubtle: 'rgba(212, 160, 58, 0.06)',
    defense: '#4A9EFF',
    defenseDim: 'rgba(74, 158, 255, 0.15)',
} as const;

const FONT_DISPLAY = "'Space Grotesk', -apple-system, system-ui, sans-serif";
const FONT_MONO = "'JetBrains Mono', 'Fira Code', monospace";
const FONT_BODY = "'Inter', -apple-system, system-ui, sans-serif";

const FEATURES = [
    {
        title: 'Real x86 Emulation',
        description: 'v86 runs real Linux in the browser. Your tools. Your commands. No simulation shortcuts.',
    },
    {
        title: 'Air-Gapped Network',
        description: 'Ethernet-level fabric with DNS, ARP, firewall rules, and cross-segment routing. Nothing leaves your machine.',
    },
    {
        title: 'Protocol Handlers',
        description: 'SSH, MySQL, SMTP, FTP, DNS, Redis, LDAP — real wire protocols respond to real tools.',
    },
    {
        title: 'MITRE ATT&CK Coverage',
        description: 'Every technique mapped to real-world TTPs. Track your progress across the kill chain.',
    },
    {
        title: 'Community Marketplace',
        description: 'Browse, create, and share scenarios. WorldSpec format — pure data, zero code.',
    },
    {
        title: 'INVARIANT Integration',
        description: 'Defense reasoning engine watches your attacks. 46 invariant classes detect anomalies in real time.',
    },
] as const;

const STEPS = [
    { step: 1, title: 'Choose a scenario', desc: 'Pick from beginner enumeration to expert red-team simulations.' },
    { step: 2, title: 'Boot the simulation', desc: 'Real Linux boots in your browser. Target machines materialize on the network.' },
    { step: 3, title: 'Execute', desc: 'Use real tools against real protocols. Complete objectives. Beat the clock.' },
] as const;

const SAMPLE_LEVELS = [
    { id: 'demo-01', title: 'The Leak', difficulty: 'BEGINNER', time: '~5 min', tags: ['Enumeration', 'Single machine'] },
    { id: 'web-01', title: 'Broken Auth', difficulty: 'INTERMEDIATE', time: '~15 min', tags: ['Web', 'JWT', 'SQLi'] },
    { id: 'net-01', title: 'Lateral Move', difficulty: 'EXPERT', time: '~30 min', tags: ['Network', 'Pivoting', 'Cred Relay'] },
] as const;

function getDifficultyColor(difficulty: string): string {
    switch (difficulty) {
        case 'BEGINNER': return '#22c55e';
        case 'INTERMEDIATE': return '#d4a03a';
        case 'EXPERT': return '#ef4444';
        default: return '#d4a03a';
    }
}

// ── Helpers ─────────────────────────────────────────────────────

function Section({ id, children, style = {} }: { id: string; children: ReactNode; style?: CSSProperties }): JSX.Element {
    return (
        <section id={id} style={{ width: '100%', maxWidth: '1100px', margin: '0 auto', padding: '5rem 1.5rem', boxSizing: 'border-box', ...style }}>
            {children}
        </section>
    );
}

function SectionTitle({ children }: { children: ReactNode }): JSX.Element {
    return (
        <h2 style={{ fontFamily: FONT_DISPLAY, fontSize: 'clamp(1.4rem, 3.5vw, 1.75rem)', fontWeight: 600, color: C.text, margin: '0 0 0.4rem 0', letterSpacing: '-0.02em' }}>
            {children}
        </h2>
    );
}

function SectionSub({ children }: { children: ReactNode }): JSX.Element {
    return (
        <p style={{ fontFamily: FONT_BODY, fontSize: '0.85rem', color: C.muted, marginBottom: '2.5rem', lineHeight: 1.6 }}>
            {children}
        </p>
    );
}

// ── Landing Page ────────────────────────────────────────────────

const VERSION = 'v1.0.0';

const TAGLINE = 'Boot real Linux in your browser. Attack real protocols. Complete objectives. No servers. No data leaves your machine.';

export function LandingPage({ onLaunch, onMarketplace, onCreate, onSettings }: LandingPageProps): JSX.Element {
    const [displayedTagline, setDisplayedTagline] = useState('');
    const [showGlow, setShowGlow] = useState(true);

    useEffect(() => {
        let index = 0;
        const interval = setInterval(() => {
            if (index <= TAGLINE.length) {
                setDisplayedTagline(TAGLINE.slice(0, index));
                index++;
            } else {
                clearInterval(interval);
            }
        }, 30);
        return () => clearInterval(interval);
    }, []);

    useEffect(() => {
        const interval = setInterval(() => {
            setShowGlow(prev => !prev);
        }, 1500);
        return () => clearInterval(interval);
    }, []);

    return (
        <div style={{ background: C.bg, color: C.text, fontFamily: FONT_BODY, minHeight: '100vh', overflowX: 'hidden', scrollBehavior: 'smooth' }}>
            <style>{`
                @keyframes blink {
                    0%, 100% { opacity: 1; }
                    50% { opacity: 0; }
                }
            `}</style>
            {/* NAV */}
            <nav style={{
                position: 'fixed', top: 0, left: 0, right: 0, zIndex: 100,
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '0 1.5rem', height: '48px',
                background: 'rgba(10, 10, 10, 0.85)', backdropFilter: 'blur(12px)',
                borderBottom: `1px solid ${C.border}`,
            }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ fontFamily: FONT_DISPLAY, fontWeight: 700, fontSize: '0.85rem', color: C.signal, letterSpacing: '0.06em' }}>
                        VARIANT
                    </span>
                    <span style={{ color: C.dim, fontSize: '0.7rem' }}>by Santh</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <a href="#features" style={{ color: C.muted, textDecoration: 'none', fontSize: '0.75rem', fontFamily: FONT_MONO }}>Features</a>
                    <a href="#marketplace" style={{ color: C.muted, textDecoration: 'none', fontSize: '0.75rem', fontFamily: FONT_MONO }}>Levels</a>
                    {onCreate !== undefined && (
                        <button type="button" onClick={onCreate} style={{ color: C.muted, background: 'none', border: 'none', fontSize: '0.75rem', fontFamily: FONT_MONO, cursor: 'pointer' }}>
                            Create
                        </button>
                    )}
                    {onSettings !== undefined && (
                        <button type="button" onClick={onSettings} style={{ color: C.muted, background: 'none', border: 'none', fontSize: '0.75rem', fontFamily: FONT_MONO, cursor: 'pointer' }}>
                            Settings
                        </button>
                    )}
                    <button type="button" onClick={onLaunch} style={{
                        background: C.signal, color: C.bg, border: 'none', borderRadius: '2px',
                        padding: '6px 16px', fontSize: '0.75rem', fontWeight: 600, fontFamily: FONT_MONO,
                        cursor: 'pointer', letterSpacing: '0.03em',
                    }}>
                        Launch
                    </button>
                </div>
            </nav>

            {/* HERO */}
            <section id="hero" style={{
                minHeight: '100vh', display: 'flex', flexDirection: 'column',
                alignItems: 'center', justifyContent: 'center', padding: '2rem 1.5rem', textAlign: 'center',
            }}>
                <div style={{
                    fontSize: '0.65rem', fontFamily: FONT_MONO, color: C.muted,
                    letterSpacing: '0.15em', textTransform: 'uppercase', marginBottom: '1.5rem',
                }}>
                    Security Simulation Engine
                </div>
                <h1 style={{
                    fontFamily: FONT_DISPLAY, fontSize: 'clamp(3.5rem, 14vw, 7rem)', fontWeight: 700,
                    color: C.text, margin: 0, letterSpacing: '-0.04em', lineHeight: 0.9,
                }}>
                    VARIANT
                </h1>
                <p style={{
                    fontFamily: FONT_BODY, fontSize: 'clamp(0.9rem, 2vw, 1rem)', color: C.muted,
                    marginTop: '1.25rem', maxWidth: '420px', lineHeight: 1.6, letterSpacing: '0.01em',
                    minHeight: '3.2em',
                }}>
                    {displayedTagline}
                    <span style={{ animation: 'blink 1s step-end infinite' }}>▋</span>
                </p>
                <div style={{ display: 'flex', gap: '0.75rem', marginTop: '2.5rem' }}>
                    <button type="button" onClick={onLaunch} style={{
                        padding: '12px 28px', fontSize: '0.85rem', fontWeight: 600, fontFamily: FONT_MONO,
                        color: C.bg, background: C.signal, border: 'none', borderRadius: '2px',
                        cursor: 'pointer', letterSpacing: '0.04em',
                        boxShadow: showGlow ? `0 0 40px ${C.signalGlow}` : `0 0 24px ${C.signalGlow}`,
                        transition: 'box-shadow 0.3s ease',
                    }}>
                        Launch Simulation
                    </button>
                    <button type="button" onClick={onMarketplace} style={{
                        padding: '12px 28px', fontSize: '0.85rem', fontWeight: 600, fontFamily: FONT_MONO,
                        color: C.signal, background: 'transparent', border: `1px solid ${C.signal}40`,
                        borderRadius: '2px', cursor: 'pointer', letterSpacing: '0.04em',
                        transition: 'all 200ms ease',
                    }}
                    onMouseEnter={e => { e.currentTarget.style.background = C.signalSubtle; }}
                    onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}
                    >
                        Browse Levels
                    </button>
                </div>
                <div style={{
                    marginTop: '1rem', fontSize: '0.7rem', fontFamily: FONT_MONO, color: C.dim,
                }}>
                    Press Enter to launch
                </div>
                <div style={{
                    marginTop: '4rem', fontSize: '0.65rem', fontFamily: FONT_MONO, color: C.dim,
                    display: 'flex', gap: '1.5rem', flexWrap: 'wrap', justifyContent: 'center',
                }}>
                    <span>267 source files</span>
                    <span>2730+ tests</span>
                    <span>13 protocol handlers</span>
                    <span>MITRE ATT&CK mapped</span>
                </div>
            </section>

            {/* FEATURES */}
            <Section id="features">
                <SectionTitle>Architecture</SectionTitle>
                <SectionSub>
                    Not a CTF platform. A full-spectrum simulation engine with real network fabric.
                </SectionSub>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1px', background: C.border }}>
                    {FEATURES.map((f) => (
                        <div key={f.title} style={{
                            padding: '1.5rem', background: C.bg,
                            transition: 'transform 0.2s ease, box-shadow 0.2s ease',
                        }}
                        onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-2px)'; e.currentTarget.style.boxShadow = `0 4px 12px rgba(0,0,0,0.4)`; }}
                        onMouseLeave={e => { e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.boxShadow = 'none'; }}
                        >
                            <div style={{
                                fontFamily: FONT_MONO, color: C.signal, fontSize: '0.7rem',
                                fontWeight: 500, letterSpacing: '0.06em', marginBottom: '0.5rem',
                                textTransform: 'uppercase',
                            }}>
                                {f.title}
                            </div>
                            <p style={{
                                margin: 0, fontFamily: FONT_BODY, fontSize: '0.82rem',
                                color: C.muted, lineHeight: 1.55,
                            }}>
                                {f.description}
                            </p>
                        </div>
                    ))}
                </div>
            </Section>

            {/* HOW IT WORKS */}
            <Section id="how-it-works">
                <SectionTitle>How it works</SectionTitle>
                <SectionSub>Three steps. Zero setup.</SectionSub>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', justifyContent: 'center' }}>
                    {STEPS.map((s) => (
                        <div key={s.step} style={{
                            border: `1px solid ${C.border}`, borderRadius: '2px',
                            padding: '1.25rem 1.5rem', background: C.bg,
                            flex: '1 1 260px', minWidth: 0,
                        }}>
                            <span style={{
                                display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                                width: '24px', height: '24px', background: C.signal, color: C.bg,
                                fontSize: '0.7rem', fontWeight: 700, fontFamily: FONT_MONO,
                                borderRadius: '2px', marginBottom: '0.75rem',
                            }}>
                                {s.step}
                            </span>
                            <div style={{ fontFamily: FONT_DISPLAY, fontWeight: 600, color: C.text, fontSize: '0.95rem' }}>
                                {s.title}
                            </div>
                            <p style={{ margin: '0.25rem 0 0 0', fontFamily: FONT_BODY, fontSize: '0.8rem', color: C.muted, lineHeight: 1.5 }}>
                                {s.desc}
                            </p>
                        </div>
                    ))}
                </div>
            </Section>

            {/* LEVELS */}
            <Section id="marketplace">
                <SectionTitle>Scenarios</SectionTitle>
                <SectionSub>From first exploit to full red-team engagement.</SectionSub>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', justifyContent: 'center' }}>
                    {SAMPLE_LEVELS.map((level) => (
                        <div key={level.id} role="button" tabIndex={0}
                            style={{
                                border: `1px solid ${C.border}`, borderRadius: '2px',
                                padding: '1.25rem 1.5rem', background: C.bg,
                                flex: '1 1 280px', minWidth: 0, maxWidth: '360px', cursor: 'pointer',
                                transition: 'border-color 200ms ease',
                            }}
                            onClick={onMarketplace}
                            onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onMarketplace(); } }}
                            onMouseEnter={e => { e.currentTarget.style.borderColor = `${C.signal}40`; }}
                            onMouseLeave={e => { e.currentTarget.style.borderColor = C.border; }}
                        >
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                                <span style={{ fontFamily: FONT_MONO, color: C.signal, fontSize: '0.65rem', fontWeight: 500, letterSpacing: '0.04em' }}>
                                    {level.id.toUpperCase()}
                                </span>
                                <span style={{
                                    fontFamily: FONT_MONO, fontSize: '0.6rem', padding: '2px 8px',
                                    border: `1px solid ${getDifficultyColor(level.difficulty)}40`, 
                                    color: getDifficultyColor(level.difficulty),
                                    borderRadius: '2px', letterSpacing: '0.04em',
                                    background: `${getDifficultyColor(level.difficulty)}10`,
                                }}>
                                    {level.difficulty}
                                </span>
                            </div>
                            <div style={{ fontFamily: FONT_DISPLAY, fontSize: '1.05rem', fontWeight: 600, color: C.text }}>
                                {level.title}
                            </div>
                            <div style={{ display: 'flex', gap: '0.75rem', fontFamily: FONT_MONO, fontSize: '0.65rem', color: C.dim, marginTop: '0.5rem' }}>
                                <span>{level.time}</span>
                                {level.tags.map((t) => (
                                    <span key={t}>{t}</span>
                                ))}
                            </div>
                        </div>
                    ))}
                </div>
                <div style={{ textAlign: 'center', marginTop: '1.5rem' }}>
                    <button type="button" onClick={onMarketplace} style={{
                        padding: '10px 24px', fontSize: '0.8rem', fontWeight: 500, fontFamily: FONT_MONO,
                        color: C.signal, background: 'transparent', border: `1px solid ${C.signal}40`,
                        borderRadius: '2px', cursor: 'pointer', letterSpacing: '0.03em',
                        transition: 'all 200ms ease',
                    }}
                    onMouseEnter={e => { e.currentTarget.style.background = C.signalSubtle; }}
                    onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}
                    >
                        Browse marketplace
                    </button>
                </div>
            </Section>

            {/* FOOTER */}
            <footer style={{
                borderTop: `1px solid ${C.border}`, padding: '2rem 1.5rem',
                textAlign: 'center', fontSize: '0.7rem', color: C.dim,
            }}>
                <div style={{ marginBottom: '0.5rem' }}>
                    <span style={{ fontFamily: FONT_DISPLAY, color: C.signal, fontWeight: 600 }}>VARIANT</span>
                    <span style={{ margin: '0 0.5rem', color: C.dim }}>·</span>
                    <span style={{ fontFamily: FONT_BODY, color: C.muted }}>Powered by Santh</span>
                    <span style={{ margin: '0 0.5rem', color: C.dim }}>·</span>
                    <span style={{ fontFamily: FONT_MONO, color: C.dim, fontSize: '0.65rem' }}>{VERSION}</span>
                </div>
                <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', fontFamily: FONT_MONO, fontSize: '0.65rem' }}>
                    <a href="https://santh.io" style={{ color: C.dim, textDecoration: 'none' }}>santh.io</a>
                    <a href="https://invariant.santh.io" style={{ color: C.dim, textDecoration: 'none' }}>invariant</a>
                </div>
            </footer>
        </div>
    );
}
