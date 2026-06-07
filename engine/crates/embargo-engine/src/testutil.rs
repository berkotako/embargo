//! Shared test helpers: build in-memory npm tarballs and a mock registry that
//! serves a benign→malicious version pair (the stealer-chain scenario).

use crate::registry::{MockRegistryClient, Packument, PackumentVersion};
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
    }
}
