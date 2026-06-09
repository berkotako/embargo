-- Runtime-managed known-malicious feed sources. Operators add/enable sources
-- from the console while using the product; a worker syncs each enabled source
-- on its interval into `known_malicious` (tagged with the source name +
-- ecosystem). `name` doubles as the `source` tag on known_malicious rows.
--
-- Seeded (disabled) with Datadog's npm + PyPI manifests so they're one toggle
-- away. `format` selects the parser; today only the Datadog manifest shape
-- ({ "pkg": null | ["1.0.0", ...] }) is supported.

CREATE TABLE feed_sources (
    id               UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    name             TEXT        NOT NULL UNIQUE,
    url              TEXT        NOT NULL,
    ecosystem        TEXT        NOT NULL DEFAULT 'npm' CHECK (ecosystem IN ('npm', 'pypi')),
    format           TEXT        NOT NULL DEFAULT 'datadog-manifest'
                                 CHECK (format IN ('datadog-manifest')),
    enabled          BOOLEAN     NOT NULL DEFAULT FALSE,
    interval_seconds BIGINT      NOT NULL DEFAULT 21600 CHECK (interval_seconds >= 300),
    last_synced_at   TIMESTAMPTZ,
    last_status      TEXT,
    created_by       UUID,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO feed_sources (name, url, ecosystem, format, enabled) VALUES
  ('datadog-npm',
   'https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/npm/manifest.json',
   'npm', 'datadog-manifest', FALSE),
  ('datadog-pypi',
   'https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/pypi/manifest.json',
   'pypi', 'datadog-manifest', FALSE);
