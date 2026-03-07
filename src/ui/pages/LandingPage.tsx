/**
 * VARIANT — Landing Page
 *
 * Professional first-impression page: hero, features, how it works,
 * marketplace preview, stats, footer. Hacker aesthetic, minimal and clean.
 */

import type { CSSProperties, ReactNode } from 'react';

// ── Types ──────────────────────────────────────────────────────

export interface LandingPageProps {
    readonly onLaunch: () => void;
    readonly onMarketplace: () => void;
}

// ── Constants ───────────────────────────────────────────────────

const COLORS = {
    bg: '#0a0a0a',
    text: '#e0e0e0',
    accent: '#00ff41',
    border: '#1a1a2e',
    muted: '#666',
    dim: '#444',
} as const;

const FONT = '"JetBrains Mono", "Fira Code", monospace';

const FEATURES = [
    {
        title: '100% Client-Side',
        description: 'No servers, no data leaves your machine.',
    },
    {
        title: 'Real VM Emulation',
        description: 'v86 x86 emulator running real Linux.',
    },
    {
        title: '9 Integrated Tools',
        description: 'Terminal, Browser, Email, Files, Logs, Network Map, Processes, Packets, and more.',
    },
    {
        title: 'MITRE ATT&CK Mapped',
        description: 'Every technique mapped to real-world TTPs.',
    },
    {
        title: 'Community Levels',
        description: 'Browse, create, and share scenarios.',
    },
    {
        title: '30+ Detection Engines',
        description: 'SQLi, XSS, SSRF, XXE, SSTI, JWT, and more.',
    },
] as const;

const STEPS = [
    { step: 1, title: 'Choose a level', desc: 'Pick from beginner to advanced scenarios.' },
    { step: 2, title: 'Boot the simulation', desc: 'Real Linux boots in your browser via v86.' },
    { step: 3, title: 'Hack / Defend', desc: 'Use terminal, browser, and tools to complete objectives.' },
] as const;

const SAMPLE_LEVELS = [
    { id: 'demo-01', title: 'The Leak', difficulty: 'BEGINNER', time: '~5 min', tags: ['Enumeration', 'Single machine'] },
    { id: 'web-01', title: 'Broken Auth', difficulty: 'INTERMEDIATE', time: '~15 min', tags: ['Web', 'JWT'] },
    { id: 'net-01', title: 'Lateral Move', difficulty: 'ADVANCED', time: '~30 min', tags: ['Network', 'Pivoting'] },
] as const;

// ── Section container ───────────────────────────────────────────

function Section({
    id,
    children,
    style = {},
}: {
    id: string;
    children: ReactNode;
    style?: CSSProperties;
}): JSX.Element {
    return (
        <section
            id={id}
            style={{
                width: '100%',
                maxWidth: '1200px',
                margin: '0 auto',
                padding: '4rem 1.5rem',
                boxSizing: 'border-box',
                ...style,
            }}
        >
            {children}
        </section>
    );
}

// ── Landing Page ────────────────────────────────────────────────

export function LandingPage({ onLaunch, onMarketplace }: LandingPageProps): JSX.Element {
    const pageStyle: CSSProperties = {
        background: COLORS.bg,
        color: COLORS.text,
        fontFamily: FONT,
        minHeight: '100vh',
        overflowX: 'hidden',
        scrollBehavior: 'smooth',
    };

    const heroStyle: CSSProperties = {
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '2rem 1.5rem',
        textAlign: 'center',
    };

    const titleStyle: CSSProperties = {
        fontSize: 'clamp(3rem, 12vw, 6rem)',
        fontWeight: 800,
        color: COLORS.accent,
        margin: 0,
        letterSpacing: '-0.04em',
        textShadow: '0 0 40px rgba(0, 255, 65, 0.25)',
        lineHeight: 1,
    };

    const taglineStyle: CSSProperties = {
        fontSize: 'clamp(0.9rem, 2.5vw, 1.1rem)',
        color: COLORS.muted,
        marginTop: '1rem',
        letterSpacing: '0.02em',
        maxWidth: '480px',
    };

    const ctaStyle: CSSProperties = {
        marginTop: '2.5rem',
        padding: '14px 32px',
        fontSize: '0.9rem',
        fontWeight: 600,
        fontFamily: FONT,
        color: COLORS.bg,
        background: COLORS.accent,
        border: 'none',
        borderRadius: '2px',
        cursor: 'pointer',
        letterSpacing: '0.05em',
        boxShadow: '0 0 24px rgba(0, 255, 65, 0.2)',
    };

    const sectionTitleStyle: CSSProperties = {
        fontSize: 'clamp(1.5rem, 4vw, 2rem)',
        fontWeight: 700,
        color: COLORS.text,
        margin: '0 0 0.5rem 0',
        letterSpacing: '-0.02em',
    };

    const sectionSubStyle: CSSProperties = {
        fontSize: '0.85rem',
        color: COLORS.muted,
        marginBottom: '2.5rem',
    };

    const featureCardStyle: CSSProperties = {
        border: `1px solid ${COLORS.border}`,
        borderRadius: '2px',
        padding: '1.5rem',
        background: 'rgba(26, 26, 46, 0.3)',
        flex: '1 1 280px',
        minWidth: 0,
        maxWidth: '380px',
    };

    const stepCardStyle: CSSProperties = {
        border: `1px solid ${COLORS.border}`,
        borderRadius: '2px',
        padding: '1.5rem 1.75rem',
        background: 'rgba(26, 26, 46, 0.25)',
        flex: '1 1 240px',
        minWidth: 0,
    };

    const levelCardStyle: CSSProperties = {
        border: `1px solid ${COLORS.border}`,
        borderRadius: '2px',
        padding: '1.25rem 1.5rem',
        background: 'rgba(26, 26, 46, 0.35)',
        flex: '1 1 280px',
        minWidth: 0,
        maxWidth: '360px',
        cursor: 'pointer',
    };

    const statsStyle: CSSProperties = {
        display: 'flex',
        flexWrap: 'wrap',
        justifyContent: 'center',
        gap: '2rem 3rem',
        fontSize: '0.8rem',
        color: COLORS.muted,
        letterSpacing: '0.03em',
    };

    const footerStyle: CSSProperties = {
        borderTop: `1px solid ${COLORS.border}`,
        padding: '2rem 1.5rem',
        textAlign: 'center',
        fontSize: '0.75rem',
        color: COLORS.dim,
    };

    return (
        <div style={pageStyle}>
            {/* HERO */}
            <section id="hero" style={heroStyle}>
                <h1 style={titleStyle}>VARIANT</h1>
                <p style={taglineStyle}>
                    Full-spectrum security simulation. In your browser.
                </p>
                <button
                    type="button"
                    onClick={onLaunch}
                    style={ctaStyle}
                    onMouseEnter={(e) => {
                        e.currentTarget.style.background = '#00dd38';
                        e.currentTarget.style.boxShadow = '0 0 32px rgba(0, 255, 65, 0.35)';
                    }}
                    onMouseLeave={(e) => {
                        e.currentTarget.style.background = COLORS.accent;
                        e.currentTarget.style.boxShadow = '0 0 24px rgba(0, 255, 65, 0.2)';
                    }}
                >
                    Launch Simulation
                </button>
            </section>

            {/* FEATURES */}
            <Section id="features">
                <h2 style={sectionTitleStyle}>Features</h2>
                <p style={sectionSubStyle}>
                    Everything you need to learn and practice security in one place.
                </p>
                <div
                    style={{
                        display: 'flex',
                        flexWrap: 'wrap',
                        gap: '1.25rem',
                        justifyContent: 'center',
                    }}
                >
                    {FEATURES.map((f) => (
                        <div key={f.title} style={featureCardStyle}>
                            <div
                                style={{
                                    color: COLORS.accent,
                                    fontSize: '0.7rem',
                                    fontWeight: 600,
                                    letterSpacing: '0.08em',
                                    marginBottom: '0.5rem',
                                }}
                            >
                                {f.title}
                            </div>
                            <p style={{ margin: 0, fontSize: '0.85rem', color: COLORS.muted, lineHeight: 1.5 }}>
                                {f.description}
                            </p>
                        </div>
                    ))}
                </div>
            </Section>

            {/* HOW IT WORKS */}
            <Section id="how-it-works" style={{ background: 'rgba(0,0,0,0.2)' }}>
                <h2 style={sectionTitleStyle}>How it works</h2>
                <p style={sectionSubStyle}>
                    Three steps from zero to hands-on practice.
                </p>
                <div
                    style={{
                        display: 'flex',
                        flexWrap: 'wrap',
                        gap: '1rem',
                        justifyContent: 'center',
                    }}
                >
                    {STEPS.map((s) => (
                        <div key={s.step} style={stepCardStyle}>
                            <span
                                style={{
                                    display: 'inline-block',
                                    width: '28px',
                                    height: '28px',
                                    lineHeight: '28px',
                                    textAlign: 'center',
                                    background: COLORS.accent,
                                    color: COLORS.bg,
                                    fontSize: '0.8rem',
                                    fontWeight: 700,
                                    borderRadius: '2px',
                                    marginBottom: '0.75rem',
                                }}
                            >
                                {s.step}
                            </span>
                            <div style={{ fontWeight: 600, color: COLORS.text, fontSize: '0.95rem' }}>
                                {s.title}
                            </div>
                            <p style={{ margin: '0.25rem 0 0 0', fontSize: '0.8rem', color: COLORS.muted }}>
                                {s.desc}
                            </p>
                        </div>
                    ))}
                </div>
            </Section>

            {/* MARKETPLACE PREVIEW */}
            <Section id="marketplace">
                <h2 style={sectionTitleStyle}>Levels</h2>
                <p style={sectionSubStyle}>
                    Sample scenarios — more in the marketplace.
                </p>
                <div
                    style={{
                        display: 'flex',
                        flexWrap: 'wrap',
                        gap: '1rem',
                        justifyContent: 'center',
                    }}
                >
                    {SAMPLE_LEVELS.map((level) => (
                        <div
                            key={level.id}
                            role="button"
                            tabIndex={0}
                            style={levelCardStyle}
                            onClick={onMarketplace}
                            onKeyDown={(e) => {
                                if (e.key === 'Enter' || e.key === ' ') {
                                    e.preventDefault();
                                    onMarketplace();
                                }
                            }}
                            onMouseEnter={(e) => {
                                e.currentTarget.style.borderColor = `${COLORS.accent}60`;
                                e.currentTarget.style.boxShadow = '0 0 20px rgba(0, 255, 65, 0.08)';
                            }}
                            onMouseLeave={(e) => {
                                e.currentTarget.style.borderColor = COLORS.border;
                                e.currentTarget.style.boxShadow = 'none';
                            }}
                        >
                            <div
                                style={{
                                    display: 'flex',
                                    justifyContent: 'space-between',
                                    alignItems: 'center',
                                    marginBottom: '0.5rem',
                                }}
                            >
                                <span style={{ color: COLORS.accent, fontSize: '0.7rem', fontWeight: 600 }}>
                                    {level.id.toUpperCase()}
                                </span>
                                <span
                                    style={{
                                        fontSize: '0.65rem',
                                        padding: '2px 8px',
                                        border: `1px solid ${COLORS.accent}40`,
                                        color: COLORS.accent,
                                        borderRadius: '2px',
                                    }}
                                >
                                    {level.difficulty}
                                </span>
                            </div>
                            <div style={{ fontSize: '1.1rem', fontWeight: 700, color: COLORS.text }}>
                                {level.title}
                            </div>
                            <div style={{ display: 'flex', gap: '0.75rem', fontSize: '0.7rem', color: COLORS.muted, marginTop: '0.5rem' }}>
                                <span>{level.time}</span>
                                {level.tags.map((t) => (
                                    <span key={t}>{t}</span>
                                ))}
                            </div>
                        </div>
                    ))}
                </div>
                <div style={{ textAlign: 'center', marginTop: '1.5rem' }}>
                    <button
                        type="button"
                        onClick={onMarketplace}
                        style={{
                            ...ctaStyle,
                            background: 'transparent',
                            color: COLORS.accent,
                            border: `1px solid ${COLORS.accent}`,
                        }}
                        onMouseEnter={(e) => {
                            e.currentTarget.style.background = 'rgba(0, 255, 65, 0.08)';
                        }}
                        onMouseLeave={(e) => {
                            e.currentTarget.style.background = 'transparent';
                        }}
                    >
                        Browse marketplace
                    </button>
                </div>
            </Section>

            {/* STATS */}
            <Section id="stats" style={{ padding: '3rem 1.5rem' }}>
                <div style={statsStyle}>
                    <span>267 source files</span>
                    <span>2730+ tests</span>
                    <span>50+ engines</span>
                    <span>MITRE ATT&CK coverage</span>
                </div>
            </Section>

            {/* FOOTER */}
            <footer style={footerStyle}>
                <div style={{ marginBottom: '0.5rem' }}>
                    <span style={{ color: COLORS.accent, fontWeight: 700 }}>VARIANT</span>
                    {' · '}
                    Santh
                </div>
                <a
                    href="#"
                    style={{ color: COLORS.muted, textDecoration: 'none' }}
                    onClick={(e) => {
                        e.preventDefault();
                        // Placeholder: could open GitHub when URL is set
                    }}
                >
                    GitHub
                </a>
            </footer>
        </div>
    );
}
