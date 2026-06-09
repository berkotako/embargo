-- Add an ecosystem dimension to the known-malicious feed so a non-npm (e.g.
-- PyPI) entry can never false-match an npm resolve. Embargo gates npm, so the
-- resolve-time lookup filters ecosystem = 'npm'; other ecosystems are stored for
-- visibility/counts only. Existing rows are npm.

ALTER TABLE known_malicious
    ADD COLUMN ecosystem TEXT NOT NULL DEFAULT 'npm'
    CHECK (ecosystem IN ('npm', 'pypi'));

ALTER TABLE known_malicious DROP CONSTRAINT known_malicious_pkey;
ALTER TABLE known_malicious ADD PRIMARY KEY (ecosystem, source, package, version);

DROP INDEX IF EXISTS idx_known_malicious_lookup;
CREATE INDEX idx_known_malicious_lookup ON known_malicious (ecosystem, package, version);
