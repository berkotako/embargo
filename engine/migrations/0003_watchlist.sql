-- Watchlist: packages/scopes the operator asks Embargo to track continuously.
-- A background worker periodically re-resolves each enabled entry so new
-- releases are evaluated proactively (cooldown, signals, advisories,
-- typosquatting) rather than only when a client first resolves them.
--
-- Per-entry `enabled` and `interval_seconds` let an operator change the cadence
-- or turn tracking off for a target without deleting it.

CREATE TABLE watchlist (
    id               UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- A package name (`lodash`, `@scope/name`) or a scope/glob pattern.
    target           TEXT        NOT NULL UNIQUE,
    kind             TEXT        NOT NULL DEFAULT 'package'
                                 CHECK (kind IN ('package', 'scope')),
    enabled          BOOLEAN     NOT NULL DEFAULT TRUE,
    -- How often to check, in seconds. Floor of 60s to avoid hammering upstream.
    interval_seconds BIGINT      NOT NULL DEFAULT 3600
                                 CHECK (interval_seconds >= 60),
    last_checked_at  TIMESTAMPTZ,
    -- Free-form status of the most recent check (e.g. "ok", or an error).
    last_status      TEXT,
    created_by       UUID,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The tracking worker scans for due entries (enabled, and either never checked
-- or last checked longer than their interval ago).
CREATE INDEX idx_watchlist_due ON watchlist (enabled, last_checked_at);
