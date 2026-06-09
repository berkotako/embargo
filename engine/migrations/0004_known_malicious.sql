-- Known-malicious feed: confirmed-malicious (package, version) pairs ingested
-- from an external curated dataset (default: Datadog's
-- malicious-software-packages-dataset, Apache-2.0 — see NOTICE).
--
-- version = '*' means every version of the package is malicious; otherwise the
-- row pins a specific compromised version. A resolve that matches here is an
-- immediate DENY (highest-confidence signal, near-zero false positives).

CREATE TABLE known_malicious (
    package   TEXT        NOT NULL,
    version   TEXT        NOT NULL,           -- '*' = all versions
    source    TEXT        NOT NULL DEFAULT 'datadog',
    synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (source, package, version)
);

-- Hot-path lookup by (package, version).
CREATE INDEX idx_known_malicious_lookup ON known_malicious (package, version);
