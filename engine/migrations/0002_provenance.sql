-- M2: provenance verification results, written by the signal extractor and
-- read by resolve to enforce the require_provenance policy gate.

CREATE TABLE provenance (
    package     TEXT        NOT NULL,
    version     TEXT        NOT NULL,
    status      TEXT        NOT NULL CHECK (status IN ('verified', 'invalid', 'absent')),
    source_repo TEXT,
    workflow    TEXT,
    reason      TEXT,
    checked_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (package, version)
);

CREATE INDEX idx_provenance_status ON provenance (status);
