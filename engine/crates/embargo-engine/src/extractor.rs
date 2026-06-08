//! Signal extractor — the background worker that turns a published version into
//! stored signals. It fetches the version's tarball (and its predecessor),
//! builds `VersionArtifact`s enriched with packument metadata, runs the pure
//! `extract_signals` pipeline, and persists the findings so a later resolve
//! escalates the verdict.
//!
//! This never runs on the resolve hot path — it is invoked out-of-band during
//! the HOLD window (or by a queue worker).

use anyhow::Result;
use embargo_core::signals::{extract_signals, VersionArtifact};
use embargo_core::types::{Provenance, Signal};
use sqlx::PgPool;
use tracing::{info, instrument};

use crate::registry::{self, Packument, RegistryClient};
use crate::{db, tarball};

/// Fetch + analyze `package@version`, persist its signals, and return them.
#[instrument(skip(client, pool), fields(pkg = package, ver = version))]
pub async fn extract_and_store(
    client: &dyn RegistryClient,
    pool: &PgPool,
    package: &str,
    version: &str,
) -> Result<Vec<Signal>> {
    let packument = client.packument(package).await?;

    let (current, provenance) = build_artifact(client, &packument, package, version).await?;

    // The immediately-preceding published version, for diff-based signals.
    let prior = match registry::prior_version(&packument, version) {
        Some(pv) => Some(build_artifact(client, &packument, package, &pv).await?.0),
        None => None,
    };

    let signals = extract_signals(&current, prior.as_ref());
    info!(count = signals.len(), provenance = ?provenance, "extracted signals");

    db::signals::replace_for_version(pool, package, version, &signals).await?;
    db::provenance::set(pool, package, version, &provenance).await?;
    Ok(signals)
}

/// Build a fully-populated `VersionArtifact` (tarball + packument metadata +
/// provenance) and return it alongside the `Provenance` verdict to persist.
async fn build_artifact(
    client: &dyn RegistryClient,
    packument: &Packument,
    package: &str,
    version: &str,
) -> Result<(VersionArtifact, Provenance)> {
    let meta = packument
        .versions
        .get(version)
        .ok_or_else(|| anyhow::anyhow!("version {version} not in packument for {package}"))?;

    let tgz = client.tarball(&meta.tarball_url).await?;
    let mut artifact = tarball::parse(&tgz)?;

    // Layer registry metadata the tarball can't carry.
    artifact.package = package.to_string();
    artifact.version = version.to_string();
    // claimed_repo prefers the per-version repository, falling back to the manifest's.
    artifact.claimed_repo = meta
        .repository
        .clone()
        .or_else(|| artifact.manifest.repository.clone());
    if let Some(user) = &meta.npm_user {
        artifact.publisher.npm_user = user.clone();
    }
    artifact.publisher.maintainers = meta.maintainers.clone();
    artifact.republish_burst = registry::republish_burst(packument, version);

    // Provenance: fetch + verify the npm attestation, feeding both the signal
    // pipeline (via the artifact) and the require_provenance gate (via the
    // returned verdict).
    let atts = client.attestations(package, version).await?;
    let info = atts.as_ref().and_then(crate::provenance::parse);
    let provenance = crate::provenance::verify(info.as_ref(), artifact.claimed_repo.as_deref());
    artifact.provenance_repo = info.and_then(|i| i.source_repo);
    artifact.provenance_verified = provenance.is_verified();

    Ok((artifact, provenance))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::stealer_registry;
    use embargo_core::types::SignalType;

    #[tokio::test]
    async fn build_artifact_layers_metadata() {
        let client = stealer_registry();
        let p = client.packument.clone();
        let (art, prov) = build_artifact(&client, &p, "demo", "1.1.0").await.unwrap();
        assert_eq!(
            art.claimed_repo.as_deref(),
            Some("https://github.com/acme/demo")
        );
        assert_eq!(art.publisher.npm_user, "alice");
        assert!(art.manifest.scripts.contains_key("postinstall"));
        // No attestation served by the mock → provenance is Absent.
        assert!(matches!(prov, embargo_core::types::Provenance::Absent));
        assert!(!art.provenance_verified);
    }

    #[tokio::test]
    async fn extracts_stealer_chain_via_diff() {
        // Without a DB we test the analysis half by calling extract_signals on the
        // built artifacts directly (extract_and_store's DB write is covered by the
        // ignored integration test).
        let client = stealer_registry();
        let p = client.packument.clone();
        let (current, _) = build_artifact(&client, &p, "demo", "1.1.0").await.unwrap();
        let (prior, _) = build_artifact(&client, &p, "demo", "1.0.0").await.unwrap();

        let signals = extract_signals(&current, Some(&prior));
        assert!(
            signals
                .iter()
                .any(|s| s.signal_type == SignalType::NewLifecycleScript),
            "added postinstall must fire: {signals:?}"
        );
        assert!(
            signals.iter().any(
                |s| matches!(&s.signal_type, SignalType::Other { name } if name == "stealer_chain")
            ),
            "stealer chain must fire: {signals:?}"
        );
    }
}
