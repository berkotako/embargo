//! Shared test helpers: build in-memory npm tarballs and a mock registry that
//! serves a benign→malicious version pair (the stealer-chain scenario).

use crate::registry::{MockRegistryClient, Packument, PackumentVersion};
use base64::Engine as _;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::collections::{BTreeMap, HashMap};
use std::io::Write;

/// Build a minimal gzip+tar npm package tarball from (path, bytes) pairs.
pub fn make_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar_buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);
        for (path, bytes) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("package/{path}"), *bytes)
                .unwrap();
        }
        builder.finish().unwrap();
    }
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(&tar_buf).unwrap();
    gz.finish().unwrap()
}

/// A registry serving a benign 1.0.0 and a malicious 1.1.0 that adds a
/// credential-stealing postinstall — the stealer chain.
pub fn stealer_registry() -> MockRegistryClient {
    let prior_pkg = br#"{"name":"demo","version":"1.0.0","scripts":{"build":"tsc"}}"#;
    let prior_tgz = make_tarball(&[("package.json", prior_pkg)]);

    let cur_pkg = br#"{"name":"demo","version":"1.1.0","scripts":{"postinstall":"node steal.js"}}"#;
    let steal = b"const https=require('https');https.request(process.env.NPM_TOKEN);";
    let cur_tgz = make_tarball(&[("package.json", cur_pkg), ("steal.js", steal)]);

    let mut versions = BTreeMap::new();
    versions.insert(
        "1.0.0".to_string(),
        PackumentVersion {
            version: "1.0.0".into(),
            tarball_url: "https://r/demo-1.0.0.tgz".into(),
            repository: Some("https://github.com/acme/demo".into()),
            npm_user: Some("alice".into()),
            maintainers: vec!["alice".into()],
        },
    );
    versions.insert(
        "1.1.0".to_string(),
        PackumentVersion {
            version: "1.1.0".into(),
            tarball_url: "https://r/demo-1.1.0.tgz".into(),
            repository: Some("https://github.com/acme/demo".into()),
            npm_user: Some("alice".into()),
            maintainers: vec!["alice".into()],
        },
    );
    let mut time = BTreeMap::new();
    time.insert("1.0.0".into(), "2024-01-01T00:00:00.000Z".into());
    time.insert("1.1.0".into(), "2024-06-01T00:00:00.000Z".into());

    let mut tarballs = HashMap::new();
    tarballs.insert("https://r/demo-1.0.0.tgz".to_string(), prior_tgz);
    tarballs.insert("https://r/demo-1.1.0.tgz".to_string(), cur_tgz);

    MockRegistryClient {
        packument: Packument {
            name: "demo".into(),
            versions,
            time,
        },
        tarballs,
        attestation: None,
    }
}

/// Build an npm attestations response wrapping a SLSA v1 provenance statement
/// for `repo` / `workflow`.
pub fn attestations_json(repo: &str, workflow: &str) -> serde_json::Value {
    let statement = serde_json::json!({
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{ "name": "pkg", "digest": { "sha512": "abc" } }],
        "predicate": {
            "buildDefinition": {
                "externalParameters": { "workflow": { "repository": repo, "path": workflow } },
                "resolvedDependencies": [{ "uri": format!("git+{repo}.git") }]
            }
        }
    });
    let payload =
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&statement).unwrap());
    serde_json::json!({
        "attestations": [
            { "predicateType": "https://slsa.dev/provenance/v1",
              "bundle": { "dsseEnvelope": { "payload": payload } } }
        ]
    })
}

/// Build a *cryptographically signed* npm Sigstore provenance bundle plus the
/// matching trust policy, for end-to-end provenance-verification tests.
///
/// Generates a self-signed test CA, a leaf certificate signed by it carrying the
/// workflow URI SAN and the Fulcio OIDC-issuer extension, and a DSSE envelope
/// (ECDSA P-256 / SHA-256) over the SLSA statement signed by the leaf key. The
/// returned policy trusts the test CA and the given issuer, so
/// `sigstore::verify_attestations` accepts the bundle.
pub fn signed_provenance(
    repo: &str,
    workflow: &str,
    issuer: &str,
) -> (
    serde_json::Value,
    crate::provenance::sigstore::ProvenancePolicy,
) {
    use p256::ecdsa::{signature::Signer, SigningKey};
    use p256::pkcs8::EncodePrivateKey;
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, Issuer, KeyPair,
        SanType,
    };

    // Self-signed test CA standing in for Fulcio.
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Embargo Test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    // Leaf signing key (P-256), reused both for the cert and the DSSE signature.
    let leaf_sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let leaf_pkcs8 = leaf_sk.to_pkcs8_der().unwrap();
    let leaf_kp = KeyPair::try_from(leaf_pkcs8.as_bytes()).unwrap();

    let san_uri = format!("https://github.com/{repo}/{workflow}@refs/heads/main");
    let mut leaf_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    leaf_params.subject_alt_names = vec![SanType::URI(san_uri.parse().unwrap())];
    // Fulcio OIDC issuer extension (v1, raw string): 1.3.6.1.4.1.57264.1.1.
    leaf_params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 57264, 1, 1],
            issuer.as_bytes().to_vec(),
        ));
    let issuer_obj = Issuer::from_params(&ca_params, &ca_key);
    let leaf_cert = leaf_params.signed_by(&leaf_kp, &issuer_obj).unwrap();
    let leaf_der = leaf_cert.der().to_vec();

    // DSSE envelope over the SLSA provenance statement.
    let statement = serde_json::json!({
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{ "name": "pkg", "digest": { "sha512": "abc" } }],
        "predicate": { "buildDefinition": { "externalParameters": {
            "workflow": { "repository": format!("https://github.com/{repo}"), "path": workflow }
        } } }
    });
    let payload = serde_json::to_vec(&statement).unwrap();
    let payload_type = "application/vnd.in-toto+json";
    let pae = crate::provenance::sigstore::dsse_pae(payload_type, &payload);
    let sig: p256::ecdsa::Signature = leaf_sk.sign(&pae);

    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let attestation = serde_json::json!({
        "attestations": [{
            "bundle": {
                "dsseEnvelope": {
                    "payloadType": payload_type,
                    "payload": b64(&payload),
                    "signatures": [{ "sig": b64(sig.to_der().as_bytes()) }]
                },
                "verificationMaterial": {
                    "certificate": { "rawBytes": b64(&leaf_der) }
                }
            }
        }]
    });

    let policy = crate::provenance::sigstore::ProvenancePolicy::from_pem(
        &ca_cert.pem(),
        vec![issuer.to_string()],
    )
    .unwrap();
    (attestation, policy)
}

/// A registry serving a single benign version 1.0.0 from `github.com/acme/demo`,
/// optionally with a matching provenance attestation.
pub fn benign_registry(with_provenance: bool) -> MockRegistryClient {
    let pkg = br#"{"name":"demo","version":"1.0.0","scripts":{"build":"tsc"},"repository":"https://github.com/acme/demo"}"#;
    let tgz = make_tarball(&[("package.json", pkg)]);

    let mut versions = BTreeMap::new();
    versions.insert(
        "1.0.0".to_string(),
        PackumentVersion {
            version: "1.0.0".into(),
            tarball_url: "https://r/demo-1.0.0.tgz".into(),
            repository: Some("https://github.com/acme/demo".into()),
            npm_user: Some("alice".into()),
            maintainers: vec!["alice".into()],
        },
    );
    let mut time = BTreeMap::new();
    time.insert("1.0.0".into(), "2024-01-01T00:00:00.000Z".into());

    let mut tarballs = HashMap::new();
    tarballs.insert("https://r/demo-1.0.0.tgz".to_string(), tgz);

    let attestation = with_provenance.then(|| {
        attestations_json(
            "https://github.com/acme/demo",
            ".github/workflows/release.yml",
        )
    });

    MockRegistryClient {
        packument: Packument {
            name: "demo".into(),
            versions,
            time,
        },
        tarballs,
        attestation,
    }
}
