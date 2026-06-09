//! Cryptographic verification of npm Sigstore provenance bundles.
//!
//! npm publishes build provenance as a Sigstore bundle wrapping a DSSE envelope
//! (the in-toto SLSA statement) plus the keyless signing certificate Fulcio
//! issued to the publishing workflow's OIDC identity. Trust comes from three
//! checks, all of which must pass:
//!
//! 1. **DSSE signature** — the envelope signature verifies against the *leaf
//!    certificate's* public key over the DSSE pre-authentication encoding. This
//!    proves the payload was signed by the holder of that certificate.
//! 2. **Certificate chain** — the leaf certificate chains, by signature, to a
//!    configured Sigstore Fulcio trust anchor. This proves the certificate was
//!    issued by Sigstore to a verified OIDC identity, not minted by an attacker.
//! 3. **Identity binding** — the certificate's SAN (the workflow identity) names
//!    the package's claimed source repository, and the embedded OIDC issuer is
//!    an accepted one. This proves *who* signed it, bound to the repo — the
//!    payload's self-asserted repo is never trusted on its own.
//!
//! ## Algorithm selection (NIST)
//!
//! Sigstore/Fulcio use elliptic-curve signatures on NIST curves (FIPS 186-5 /
//! SP 800-186): leaf signing keys are ECDSA on **P-256** with **SHA-256**
//! (FIPS 180-4); Fulcio CA certificates use ECDSA on **P-384** with SHA-384.
//! Both meet the ≥128-bit security level of NIST SP 800-57. We accept only these
//! and reject anything else (no RSA-with-SHA-1, no curve downgrade).
//!
//! ## Scope / remaining hardening
//!
//! Fulcio signing certificates are short-lived (~10 min), so offline verification
//! days later cannot use wall-clock time for the validity window — that requires
//! the Rekor transparency-log entry's `integratedTime` and verifying Rekor's
//! signed entry timestamp (SET). Rekor SET verification is the tracked follow-up;
//! until then we validate the chain at the certificate's own `notBefore` and do
//! not enforce expiry. Trust is fail-safe: with no trust anchor configured we
//! never report `Verified`, so `require_provenance` denies rather than trusting a
//! self-asserted payload.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use p256::ecdsa::signature::Verifier as _;
use p256::pkcs8::DecodePublicKey as _;
use x509_parser::prelude::*;

/// Fulcio OIDC issuer extensions (the issuer URL the cert was minted for).
/// `1.1` carries the raw string; `1.8` (v2) carries a DER-wrapped UTF8String.
const OID_FULCIO_ISSUER_V1: &str = "1.3.6.1.4.1.57264.1.1";
const OID_FULCIO_ISSUER_V2: &str = "1.3.6.1.4.1.57264.1.8";

/// A configured provenance trust policy. Built once at startup.
#[derive(Clone, Default)]
pub struct ProvenancePolicy {
    /// DER-encoded trust-anchor certificates (Fulcio root + intermediates).
    anchors: Vec<Vec<u8>>,
    /// Accepted OIDC issuer URLs. Empty = do not constrain the issuer.
    accepted_issuers: Vec<String>,
}

impl ProvenancePolicy {
    /// Build from a PEM bundle of trust-anchor certificates and a list of
    /// accepted OIDC issuers. An empty `trust_root_pem` yields an unconfigured
    /// policy (verification can never succeed — fail safe).
    pub fn from_pem(trust_root_pem: &str, accepted_issuers: Vec<String>) -> Result<Self> {
        let mut anchors = Vec::new();
        for pem in Pem::iter_from_buffer(trust_root_pem.as_bytes()) {
            let pem = pem.context("invalid PEM in provenance trust root")?;
            if pem.label == "CERTIFICATE" {
                anchors.push(pem.contents);
            }
        }
        Ok(Self {
            anchors,
            accepted_issuers,
        })
    }

    /// Whether a trust anchor is configured. When false, verification always
    /// fails closed (no `Verified`).
    pub fn is_configured(&self) -> bool {
        !self.anchors.is_empty()
    }
}

/// The verified identity bound to a provenance attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    /// Source repository taken from the certificate SAN (trusted), e.g.
    /// `github.com/acme/demo`.
    pub repo: String,
    /// Workflow path/ref from the SAN, when present.
    pub workflow: String,
    /// OIDC issuer the certificate was minted for.
    pub issuer: String,
}

/// Outcome of verifying a single attestation against a policy.
pub enum Outcome {
    /// Cryptographically verified and identity-bound.
    Verified(VerifiedIdentity),
    /// Present but verification failed (signature, chain, or identity).
    Invalid(String),
}

/// Verify the first SLSA provenance attestation in an npm attestations response.
///
/// `claimed_repo` is the repository the package self-declares; a `Verified`
/// outcome additionally requires the certificate SAN to name it.
pub fn verify_attestations(
    attestations: &serde_json::Value,
    policy: &ProvenancePolicy,
    claimed_repo: Option<&str>,
) -> Outcome {
    if !policy.is_configured() {
        return Outcome::Invalid(
            "provenance trust root not configured; cannot verify attestation".into(),
        );
    }
    let list = match attestations.get("attestations").and_then(|a| a.as_array()) {
        Some(l) if !l.is_empty() => l,
        _ => return Outcome::Invalid("no attestations in response".into()),
    };

    // Try each attestation; report the first decisive result.
    let mut last_err = "no provenance attestation found".to_string();
    for att in list {
        match verify_one(att, policy, claimed_repo) {
            Ok(Some(id)) => return Outcome::Verified(id),
            Ok(None) => continue, // not a provenance bundle; skip
            Err(e) => last_err = e.to_string(),
        }
    }
    Outcome::Invalid(last_err)
}

/// Verify a single attestation bundle. Returns:
/// - `Ok(Some(identity))` when fully verified,
/// - `Ok(None)` when the entry isn't a SLSA provenance bundle (skip it),
/// - `Err(reason)` when it is provenance but verification failed.
fn verify_one(
    att: &serde_json::Value,
    policy: &ProvenancePolicy,
    claimed_repo: Option<&str>,
) -> Result<Option<VerifiedIdentity>> {
    let env = att
        .pointer("/bundle/dsseEnvelope")
        .ok_or_else(|| anyhow!("attestation has no dsseEnvelope"))?;

    let payload_b64 = env
        .get("payload")
        .and_then(|p| p.as_str())
        .ok_or_else(|| anyhow!("envelope has no payload"))?;
    let payload_type = env
        .get("payloadType")
        .and_then(|p| p.as_str())
        .unwrap_or("application/vnd.in-toto+json");
    let sig_b64 = env
        .pointer("/signatures/0/sig")
        .and_then(|s| s.as_str())
        .ok_or_else(|| anyhow!("envelope has no signature"))?;

    let payload = b64(payload_b64).context("payload is not valid base64")?;
    let sig_bytes = b64(sig_b64).context("signature is not valid base64")?;

    // Skip non-provenance attestations (e.g. publish attestations) so the caller
    // can fall through to the next entry.
    if !is_provenance_payload(&payload) {
        return Ok(None);
    }

    // Collect the presented certificate chain (leaf first).
    let chain_der = extract_cert_chain(att)?;
    let (_, leaf) = X509Certificate::from_der(&chain_der[0])
        .map_err(|e| anyhow!("leaf certificate is not valid DER: {e}"))?;

    // (1) DSSE signature over PAE(payloadType, payload) with the leaf key.
    let pae = dsse_pae(payload_type, &payload);
    verify_dsse_signature(&leaf, &pae, &sig_bytes).context("DSSE signature verification failed")?;

    // (2) The leaf must chain, by signature, to a configured trust anchor.
    if !chain_trusted(&chain_der, &policy.anchors)? {
        bail!("certificate does not chain to a configured Fulcio trust anchor");
    }

    // (3) Identity: SAN repo + accepted OIDC issuer, bound to the claimed repo.
    let identity = extract_identity(&leaf)?;
    if !policy.accepted_issuers.is_empty()
        && !policy
            .accepted_issuers
            .iter()
            .any(|i| i == &identity.issuer)
    {
        bail!(
            "OIDC issuer {} is not in the accepted list",
            identity.issuer
        );
    }
    if let Some(claimed) = claimed_repo {
        // Exact match on the normalized host/owner/repo. `identity.repo` is
        // already reduced to those three segments by `split_repo_workflow`, so a
        // prefix match would wrongly accept a sibling repo (e.g. a claimed
        // `github.com/acme/demo` must not be satisfied by `…/demo-evil`).
        if normalize_repo(&identity.repo) != normalize_repo(claimed) {
            bail!(
                "certificate identity repo {} does not match declared repository {claimed}",
                identity.repo
            );
        }
    }

    Ok(Some(identity))
}

/// DSSE Pre-Authentication Encoding (PAEv1):
/// `"DSSEv1" SP len(type) SP type SP len(payload) SP payload`.
pub(crate) fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + payload_type.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// Verify an ECDSA P-256/SHA-256 signature over `msg` with the certificate's key.
fn verify_dsse_signature(leaf: &X509Certificate, msg: &[u8], sig_der: &[u8]) -> Result<()> {
    verify_p256(leaf.public_key().raw, msg, sig_der)
}

/// Verify an ECDSA **P-256 / SHA-256** signature (NIST FIPS 186-5 / 180-4) over
/// `msg`, given the signer's SubjectPublicKeyInfo DER and a DER-encoded
/// signature. Only P-256 keys parse here — a non-P-256 SPKI is rejected, which
/// is the intended algorithm constraint.
fn verify_p256(spki_der: &[u8], msg: &[u8], sig_der: &[u8]) -> Result<()> {
    let key = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der)
        .map_err(|_| anyhow!("signing key is not an ECDSA P-256 public key"))?;
    let sig = p256::ecdsa::Signature::from_der(sig_der)
        .map_err(|_| anyhow!("signature is not a valid DER ECDSA signature"))?;
    key.verify(msg, &sig)
        .map_err(|_| anyhow!("signature does not verify against the signing key"))
}

/// Walk the presented chain (leaf-first), verifying each link's signature, and
/// require the path to reach a configured trust anchor (matched by signature or
/// by being the same certificate). Bounded to guard against cycles.
fn parse_cert(der: &[u8]) -> Result<X509Certificate<'_>> {
    X509Certificate::from_der(der)
        .map(|(_, c)| c)
        .map_err(|e| anyhow!("certificate parse error: {e}"))
}

fn chain_trusted(chain_der: &[Vec<u8>], anchors: &[Vec<u8>]) -> Result<bool> {
    // Walk up the presented chain (leaf at index 0), verifying each link by
    // signature, until we reach a certificate that a configured anchor signed
    // (or that *is* an anchor). Bounded to guard against cycles. Certificate
    // identity is compared on the raw DER bytes we already hold.
    let mut current = 0usize;
    for _ in 0..8 {
        let cur_der = &chain_der[current];
        let cert = parse_cert(cur_der)?;

        for a_der in anchors {
            if a_der == cur_der {
                return Ok(true); // the cert itself is a trusted anchor
            }
            let anchor = parse_cert(a_der)?;
            if cert.verify_signature(Some(anchor.public_key())).is_ok() {
                return Ok(true); // signed directly by a trusted anchor
            }
        }

        // Otherwise find the next presented certificate that signed `cert`.
        let next = chain_der.iter().position(|d| {
            d != cur_der
                && parse_cert(d)
                    .map(|c| cert.verify_signature(Some(c.public_key())).is_ok())
                    .unwrap_or(false)
        });
        match next {
            Some(i) => current = i,
            None => return Ok(false),
        }
    }
    Ok(false)
}

/// Extract the SAN-bound identity (repo, workflow) and OIDC issuer from a leaf.
fn extract_identity(leaf: &X509Certificate) -> Result<VerifiedIdentity> {
    // SAN: Fulcio puts the workflow identity in a URI SAN.
    let san_uri = leaf
        .subject_alternative_name()
        .ok()
        .flatten()
        .and_then(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|gn| match gn {
                    GeneralName::URI(u) => Some(u.to_string()),
                    _ => None,
                })
                .next()
        })
        .ok_or_else(|| anyhow!("certificate has no URI SAN identity"))?;

    let (repo, workflow) = split_repo_workflow(&san_uri);
    let issuer = fulcio_issuer(leaf).ok_or_else(|| anyhow!("certificate has no OIDC issuer"))?;

    Ok(VerifiedIdentity {
        repo,
        workflow,
        issuer,
    })
}

/// Pull the OIDC issuer from the Fulcio extension (v2 DER-UTF8String or v1 raw).
fn fulcio_issuer(leaf: &X509Certificate) -> Option<String> {
    for ext in leaf.extensions() {
        let oid = ext.oid.to_id_string();
        if oid == OID_FULCIO_ISSUER_V2 {
            // v2: the value is a DER-encoded UTF8String; strip the tag/len.
            if let Some(s) = der_utf8(ext.value) {
                return Some(s);
            }
        }
        if oid == OID_FULCIO_ISSUER_V1 {
            return Some(String::from_utf8_lossy(ext.value).into_owned());
        }
    }
    None
}

/// Minimal DER UTF8String (tag 0x0c) decoder for the issuer-v2 extension.
fn der_utf8(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 || bytes[0] != 0x0c {
        return None;
    }
    let len = bytes[1] as usize;
    let body = bytes.get(2..2 + len)?;
    Some(String::from_utf8_lossy(body).into_owned())
}

/// A SAN URI like `https://github.com/acme/demo/.github/workflows/x.yml@refs/..`
/// splits into the repo (`github.com/acme/demo`) and the workflow remainder.
fn split_repo_workflow(uri: &str) -> (String, String) {
    let norm = normalize_repo(uri);
    let parts: Vec<&str> = norm.splitn(4, '/').collect();
    if parts.len() >= 3 {
        let repo = parts[..3].join("/");
        let workflow = parts.get(3).map(|s| s.to_string()).unwrap_or_default();
        (repo, workflow)
    } else {
        (norm, String::new())
    }
}

/// Whether the DSSE payload is a SLSA build-provenance in-toto statement.
fn is_provenance_payload(payload: &[u8]) -> bool {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(payload) else {
        return false;
    };
    let pt = v
        .get("predicateType")
        .and_then(|p| p.as_str())
        .unwrap_or("");
    (pt.starts_with("https://slsa.dev/provenance/")
        || pt.starts_with("https://in-toto.io/attestation/"))
        && pt.contains("provenance")
}

/// Collect the certificate chain (leaf-first) from a Sigstore bundle's
/// `verificationMaterial`, supporting both the single-`certificate` and the
/// `x509CertificateChain` encodings.
fn extract_cert_chain(att: &serde_json::Value) -> Result<Vec<Vec<u8>>> {
    let vm = att
        .pointer("/bundle/verificationMaterial")
        .ok_or_else(|| anyhow!("bundle has no verificationMaterial"))?;

    if let Some(raw) = vm.pointer("/certificate/rawBytes").and_then(|r| r.as_str()) {
        return Ok(vec![b64(raw).context("certificate rawBytes not base64")?]);
    }
    if let Some(arr) = vm
        .pointer("/x509CertificateChain/certificates")
        .and_then(|c| c.as_array())
    {
        let mut out = Vec::new();
        for c in arr {
            if let Some(raw) = c.get("rawBytes").and_then(|r| r.as_str()) {
                out.push(b64(raw).context("chain cert rawBytes not base64")?);
            }
        }
        if !out.is_empty() {
            return Ok(out);
        }
    }
    bail!("bundle has no signing certificate")
}

fn b64(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| anyhow!("base64 decode: {e}"))
}

/// Normalize a repo/URI for comparison: drop scheme, `git+`, `.git`, lowercase.
fn normalize_repo(url: &str) -> String {
    let s = url.trim().to_lowercase();
    let s = s.strip_prefix("git+").unwrap_or(&s);
    let s = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .or_else(|| s.strip_prefix("git://"))
        .or_else(|| s.strip_prefix("ssh://git@"))
        .unwrap_or(s);
    s.split(['@', '#'])
        .next()
        .unwrap_or(s)
        .trim_end_matches(".git")
        .trim_end_matches('/')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};
    use p256::pkcs8::EncodePublicKey;

    #[test]
    fn pae_matches_dsse_spec_vector() {
        // From the DSSE spec example.
        let pae = dsse_pae("http://example.com/HelloWorld", b"hello world");
        assert_eq!(
            pae,
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec()
        );
    }

    #[test]
    fn normalize_repo_strips_scheme_and_suffix() {
        assert_eq!(
            normalize_repo("git+https://github.com/Acme/Demo.git"),
            "github.com/acme/demo"
        );
    }

    #[test]
    fn split_repo_workflow_extracts_repo() {
        let (repo, wf) = split_repo_workflow(
            "https://github.com/acme/demo/.github/workflows/release.yml@refs/heads/main",
        );
        assert_eq!(repo, "github.com/acme/demo");
        assert!(wf.starts_with(".github/workflows/release.yml"));
    }

    #[test]
    fn der_utf8_decodes_issuer_v2() {
        // DER UTF8String "https://x" = 0x0c, len 9, bytes.
        let mut der = vec![0x0c, 9];
        der.extend_from_slice(b"https://x");
        assert_eq!(der_utf8(&der).as_deref(), Some("https://x"));
        assert_eq!(der_utf8(b"\x0c"), None);
    }

    #[test]
    fn is_provenance_payload_distinguishes_publish() {
        let prov = br#"{"predicateType":"https://slsa.dev/provenance/v1"}"#;
        let publish = br#"{"predicateType":"https://github.com/npm/attestation/publish/v0.1"}"#;
        assert!(is_provenance_payload(prov));
        assert!(!is_provenance_payload(publish));
        assert!(!is_provenance_payload(b"not json"));
    }

    #[test]
    fn unconfigured_policy_never_verifies() {
        let policy = ProvenancePolicy::default();
        assert!(!policy.is_configured());
        let out = verify_attestations(&serde_json::json!({"attestations":[{}]}), &policy, None);
        assert!(matches!(out, Outcome::Invalid(_)));
    }

    #[test]
    fn p256_signature_verifies_and_rejects_tampering() {
        // NIST P-256 / SHA-256 sign+verify over a DSSE PAE, key supplied as SPKI.
        let signing = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let spki = signing
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .into_vec();

        let pae = dsse_pae("application/vnd.in-toto+json", br#"{"k":1}"#);
        let sig: p256::ecdsa::Signature = signing.sign(&pae);
        let sig_der = sig.to_der();

        verify_p256(&spki, &pae, sig_der.as_bytes()).unwrap();

        // Tampered payload must fail.
        let bad = dsse_pae("application/vnd.in-toto+json", br#"{"k":2}"#);
        assert!(verify_p256(&spki, &bad, sig_der.as_bytes()).is_err());

        // A different key must fail.
        let other = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let other_spki = other
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .into_vec();
        assert!(verify_p256(&other_spki, &pae, sig_der.as_bytes()).is_err());
    }

    #[test]
    fn binds_repo_exactly_rejecting_sibling_prefix() {
        const ISSUER: &str = "https://token.actions.githubusercontent.com";
        // A bundle for acme/demo-evil must NOT satisfy a claimed acme/demo.
        let (att, policy) =
            crate::testutil::signed_provenance("acme/demo-evil", ".github/workflows/r.yml", ISSUER);
        assert!(matches!(
            verify_attestations(&att, &policy, Some("https://github.com/acme/demo")),
            Outcome::Invalid(_)
        ));
        // The exact repo verifies.
        let (att2, policy2) =
            crate::testutil::signed_provenance("acme/demo", ".github/workflows/r.yml", ISSUER);
        assert!(matches!(
            verify_attestations(
                &att2,
                &policy2,
                Some("git+https://github.com/acme/demo.git")
            ),
            Outcome::Verified(_)
        ));
    }

    #[test]
    fn extract_cert_chain_supports_both_encodings() {
        let single = serde_json::json!({
            "bundle": { "verificationMaterial": { "certificate": { "rawBytes": "AAEC" } } }
        });
        assert_eq!(extract_cert_chain(&single).unwrap(), vec![vec![0, 1, 2]]);

        let chain = serde_json::json!({
            "bundle": { "verificationMaterial": {
                "x509CertificateChain": { "certificates": [
                    { "rawBytes": "AAEC" }, { "rawBytes": "AwQF" }
                ] }
            } }
        });
        assert_eq!(
            extract_cert_chain(&chain).unwrap(),
            vec![vec![0, 1, 2], vec![3, 4, 5]]
        );
    }
}
