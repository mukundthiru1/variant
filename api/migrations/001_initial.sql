-- VARIANT Database Schema (variant-db on Neon)
-- Separate from santh-intel. This database stores:
--   - User accounts & profiles
--   - Community levels (WorldSpec JSON)
--   - Marketplace: ratings, downloads, reports
--   - Leaderboards & achievements
--   - Session analytics (anonymized)

-- ── Extensions ────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ── Users ─────────────────────────────────────────────────────────

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username        TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    email           TEXT UNIQUE,                    -- nullable: anonymous accounts allowed
    password_hash   TEXT,                            -- bcrypt; null for OAuth-only accounts
    avatar_url      TEXT,
    bio             TEXT DEFAULT '',
    role            TEXT NOT NULL DEFAULT 'player'
                    CHECK (role IN ('player', 'creator', 'moderator', 'admin')),
    reputation      INTEGER NOT NULL DEFAULT 0,
    levels_created  INTEGER NOT NULL DEFAULT 0,
    levels_played   INTEGER NOT NULL DEFAULT 0,
    total_score     BIGINT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_active_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    banned          BOOLEAN NOT NULL DEFAULT FALSE,
    ban_reason      TEXT
);

CREATE INDEX idx_users_username ON users (username);
CREATE INDEX idx_users_reputation ON users (reputation DESC);

-- ── Sessions ──────────────────────────────────────────────────────

CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,            -- SHA-256 of JWT
    ip_hash         TEXT,                            -- SHA-256 of IP (privacy)
    user_agent      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked         BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_sessions_user ON sessions (user_id);
CREATE INDEX idx_sessions_token ON sessions (token_hash);
CREATE INDEX idx_sessions_expires ON sessions (expires_at);

-- ── Levels (Community Marketplace) ────────────────────────────────

CREATE TABLE levels (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    author_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    slug            TEXT NOT NULL UNIQUE,            -- URL-friendly: "lateral-movement-lab"
    title           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    briefing        TEXT NOT NULL DEFAULT '',        -- In-game briefing text
    difficulty      TEXT NOT NULL DEFAULT 'medium'
                    CHECK (difficulty IN ('beginner', 'easy', 'medium', 'hard', 'expert')),
    mode            TEXT NOT NULL DEFAULT 'attack'
                    CHECK (mode IN ('attack', 'defense', 'mixed')),
    tags            TEXT[] NOT NULL DEFAULT '{}',
    vuln_classes    TEXT[] NOT NULL DEFAULT '{}',    -- e.g. {'sqli', 'xss', 'privesc'}
    estimated_mins  INTEGER NOT NULL DEFAULT 30,

    -- The actual level data (WorldSpec JSON, compressed)
    worldspec       JSONB NOT NULL,
    worldspec_hash  TEXT NOT NULL,                   -- SHA-256 for integrity

    -- Marketplace metadata
    version         INTEGER NOT NULL DEFAULT 1,
    status          TEXT NOT NULL DEFAULT 'draft'
                    CHECK (status IN ('draft', 'published', 'unlisted', 'removed', 'featured')),
    featured        BOOLEAN NOT NULL DEFAULT FALSE,
    downloads       INTEGER NOT NULL DEFAULT 0,
    plays           INTEGER NOT NULL DEFAULT 0,
    completions     INTEGER NOT NULL DEFAULT 0,
    avg_rating      REAL NOT NULL DEFAULT 0,
    rating_count    INTEGER NOT NULL DEFAULT 0,
    avg_completion_mins REAL,

    -- Moderation
    reviewed        BOOLEAN NOT NULL DEFAULT FALSE,
    reviewer_id     UUID REFERENCES users(id),
    reviewed_at     TIMESTAMPTZ,
    flagged         BOOLEAN NOT NULL DEFAULT FALSE,
    flag_reason     TEXT,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at    TIMESTAMPTZ
);

CREATE INDEX idx_levels_author ON levels (author_id);
CREATE INDEX idx_levels_status ON levels (status);
CREATE INDEX idx_levels_difficulty ON levels (difficulty);
CREATE INDEX idx_levels_mode ON levels (mode);
CREATE INDEX idx_levels_featured ON levels (featured) WHERE featured = TRUE;
CREATE INDEX idx_levels_downloads ON levels (downloads DESC);
CREATE INDEX idx_levels_rating ON levels (avg_rating DESC) WHERE rating_count >= 3;
CREATE INDEX idx_levels_tags ON levels USING GIN (tags);
CREATE INDEX idx_levels_vulns ON levels USING GIN (vuln_classes);
CREATE INDEX idx_levels_slug ON levels (slug);
CREATE INDEX idx_levels_search ON levels USING GIN (
    to_tsvector('english', title || ' ' || description || ' ' || briefing)
);

-- ── Ratings ───────────────────────────────────────────────────────

CREATE TABLE ratings (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    level_id        UUID NOT NULL REFERENCES levels(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    score           INTEGER NOT NULL CHECK (score >= 1 AND score <= 5),
    review          TEXT,                            -- Optional text review
    difficulty_felt TEXT CHECK (difficulty_felt IN ('too-easy', 'just-right', 'too-hard')),
    completed       BOOLEAN NOT NULL DEFAULT FALSE,
    completion_mins INTEGER,                         -- How long it took
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (level_id, user_id)                      -- One rating per user per level
);

CREATE INDEX idx_ratings_level ON ratings (level_id);
CREATE INDEX idx_ratings_user ON ratings (user_id);

-- ── Downloads (analytics) ─────────────────────────────────────────

CREATE TABLE level_downloads (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    level_id        UUID NOT NULL REFERENCES levels(id) ON DELETE CASCADE,
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,  -- null = anonymous
    ip_hash         TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_downloads_level ON level_downloads (level_id);
CREATE INDEX idx_downloads_date ON level_downloads (created_at);

-- ── Play Sessions (anonymized analytics) ──────────────────────────

CREATE TABLE play_sessions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    level_id        UUID NOT NULL REFERENCES levels(id) ON DELETE CASCADE,
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at        TIMESTAMPTZ,
    completed       BOOLEAN NOT NULL DEFAULT FALSE,
    score           INTEGER,
    duration_secs   INTEGER,
    objectives_met  INTEGER NOT NULL DEFAULT 0,
    objectives_total INTEGER NOT NULL DEFAULT 0,
    hints_used      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_play_level ON play_sessions (level_id);
CREATE INDEX idx_play_user ON play_sessions (user_id);
CREATE INDEX idx_play_completed ON play_sessions (completed) WHERE completed = TRUE;

-- ── Achievements ──────────────────────────────────────────────────

CREATE TABLE achievements (
    id              TEXT PRIMARY KEY,                -- e.g. 'first-blood', 'sql-master'
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    icon            TEXT NOT NULL DEFAULT 'trophy',
    category        TEXT NOT NULL DEFAULT 'general',
    points          INTEGER NOT NULL DEFAULT 10,
    rarity          TEXT NOT NULL DEFAULT 'common'
                    CHECK (rarity IN ('common', 'uncommon', 'rare', 'epic', 'legendary'))
);

CREATE TABLE user_achievements (
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    achievement_id  TEXT NOT NULL REFERENCES achievements(id) ON DELETE CASCADE,
    earned_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    level_id        UUID REFERENCES levels(id) ON DELETE SET NULL,

    PRIMARY KEY (user_id, achievement_id)
);

CREATE INDEX idx_user_achievements_user ON user_achievements (user_id);

-- ── Leaderboards ──────────────────────────────────────────────────

CREATE TABLE leaderboard_entries (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    level_id        UUID NOT NULL REFERENCES levels(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    score           INTEGER NOT NULL,
    time_secs       INTEGER NOT NULL,
    hints_used      INTEGER NOT NULL DEFAULT 0,
    achieved_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (level_id, user_id)                      -- Best score per user per level
);

CREATE INDEX idx_leaderboard_level ON leaderboard_entries (level_id, score DESC);
CREATE INDEX idx_leaderboard_global ON leaderboard_entries (score DESC);

-- ── Reports (abuse/moderation) ────────────────────────────────────

CREATE TABLE reports (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    reporter_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    level_id        UUID REFERENCES levels(id) ON DELETE CASCADE,
    user_id         UUID REFERENCES users(id) ON DELETE CASCADE,   -- reported user
    reason          TEXT NOT NULL
                    CHECK (reason IN ('inappropriate', 'malicious', 'copyright', 'broken', 'spam', 'other')),
    details         TEXT,
    status          TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'reviewed', 'resolved', 'dismissed')),
    resolved_by     UUID REFERENCES users(id),
    resolved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_reports_status ON reports (status) WHERE status = 'open';

-- ── Collections (curated level lists) ─────────────────────────────

CREATE TABLE collections (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    author_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    is_official     BOOLEAN NOT NULL DEFAULT FALSE,  -- Santh-curated collections
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE collection_levels (
    collection_id   UUID NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    level_id        UUID NOT NULL REFERENCES levels(id) ON DELETE CASCADE,
    position        INTEGER NOT NULL DEFAULT 0,

    PRIMARY KEY (collection_id, level_id)
);

-- ── Trigger: auto-update updated_at ───────────────────────────────

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_levels_updated BEFORE UPDATE ON levels
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_ratings_updated BEFORE UPDATE ON ratings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_collections_updated BEFORE UPDATE ON collections
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
