-- M1 initial schema.
-- All tables use UUID primary keys. Audit log is append-only with hash chaining.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ---------------------------------------------------------------------------
-- Policies
-- ---------------------------------------------------------------------------
CREATE TABLE policies (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    schema_version  INTEGER     NOT NULL DEFAULT 1,
    yaml_content    TEXT        NOT NULL,
    active          BOOLEAN     NOT NULL DEFAULT false,
    actor_id        UUID,
    justification   TEXT        NOT NULL DEFAULT '',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_policies_active ON policies (active) WHERE active = true;

-- ---------------------------------------------------------------------------
-- Verdicts
-- ---------------------------------------------------------------------------
CREATE TABLE verdicts (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    package     TEXT        NOT NULL,
    version     TEXT        NOT NULL,
    verdict     SMALLINT    NOT NULL,  -- 1=ALLOW 2=HOLD 3=DENY
    reasons     JSONB       NOT NULL DEFAULT '[]',
    signals     JSONB       NOT NULL DEFAULT '[]',
    provenance  JSONB,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ,
    CONSTRAINT uq_verdict_pkg_ver UNIQUE (package, version)
);

CREATE INDEX idx_verdicts_verdict ON verdicts (verdict);
CREATE INDEX idx_verdicts_expires ON verdicts (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_verdicts_package ON verdicts (package);

-- ---------------------------------------------------------------------------
-- Signals
-- ---------------------------------------------------------------------------
CREATE TABLE signals (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    package     TEXT        NOT NULL,
    version     TEXT        NOT NULL,
    signal_type TEXT        NOT NULL,
    severity    TEXT        NOT NULL,
    weight      INTEGER     NOT NULL,
    evidence    JSONB       NOT NULL DEFAULT '{}',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_signals_pkg_ver ON signals (package, version);
CREATE INDEX idx_signals_type ON signals (signal_type);

-- ---------------------------------------------------------------------------
-- Approvals
-- ---------------------------------------------------------------------------
CREATE TABLE approvals (
    id                UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    package           TEXT        NOT NULL,
    version           TEXT        NOT NULL,
    requester_id      UUID        NOT NULL,
    approver_id       UUID        NOT NULL,
    justification     TEXT        NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    status            TEXT        NOT NULL DEFAULT 'active'
                                  CHECK (status IN ('active', 'expired', 'revoked')),
    revocation_reason TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_approvals_pkg_ver ON approvals (package, version);
CREATE INDEX idx_approvals_status  ON approvals (status);
CREATE INDEX idx_approvals_expires ON approvals (expires_at) WHERE status = 'active';

-- ---------------------------------------------------------------------------
-- Audit log (immutable, hash-chained)
-- ---------------------------------------------------------------------------
CREATE SEQUENCE audit_log_seq START 1;

CREATE TABLE audit_log (
    id           UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    sequence     BIGINT      NOT NULL DEFAULT nextval('audit_log_seq'),
    actor        JSONB       NOT NULL,
    action       TEXT        NOT NULL,
    target       JSONB       NOT NULL,
    before_state JSONB,
    after_state  JSONB,
    timestamp    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    prev_hash    TEXT,
    content_hash TEXT        NOT NULL
);

-- Enforce strictly monotonic insertion order for hash chain integrity.
CREATE UNIQUE INDEX idx_audit_sequence ON audit_log (sequence);
CREATE INDEX idx_audit_timestamp ON audit_log (timestamp);
CREATE INDEX idx_audit_action ON audit_log (action);
