//! Pure npm-tarball parser: gzip+tar bytes → a partial `VersionArtifact`
//! (manifest, file list, install-script sources). No network here — the
//! registry client fetches bytes; this only decodes them. Bounded against
//! decompression bombs.

use anyhow::{anyhow, Result};
use embargo_core::signals::{FileEntry, Manifest, VersionArtifact, LIFECYCLE_KEYS};
use flate2::read::GzDecoder;
use std::collections::BTreeMap;
use std::io::Read;
use tar::Archive;

/// Hard caps so a malicious tarball can't exhaust memory during inspection.
const MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024; // 32 MiB decompressed
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024; // 4 MiB per captured file
const MAX_FILES: usize = 20_000;

/// Reader that errors once more than `limit` bytes have flowed through it. The
/// cap is on bytes *actually decompressed*, so a gzip bomb can't expand unbounded
/// regardless of the (attacker-controlled) tar header `size` fields — those are
/// not trustworthy for sizing.
struct LimitedReader<R> {
    inner: R,
    remaining: u64,
}

impl<R: Read> LimitedReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
        }
    }
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n as u64 > self.remaining {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "tarball exceeds decompressed-size limit",
            ));
        }
        self.remaining -= n as u64;
        Ok(n)
    }
}

/// Parse an npm package tarball into a `VersionArtifact`. The packument
/// metadata (publisher, repo, provenance) is layered on afterward by the
/// extractor — this fills `manifest`, `files`, and `script_sources`.
pub fn parse(gz_bytes: &[u8]) -> Result<VersionArtifact> {
    // Cap decompressed bytes at the source (real bytes read), not via the tar
    // header sizes which a bomb can understate.
    let decoder = LimitedReader::new(GzDecoder::new(gz_bytes), MAX_TOTAL_BYTES);
    let mut archive = Archive::new(decoder);

    let mut contents: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut files: Vec<FileEntry> = Vec::new();
    let mut total: u64 = 0;

    for entry in archive.entries()? {
        let entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        if files.len() >= MAX_FILES {
            return Err(anyhow!("tarball exceeds {MAX_FILES} files"));
        }

        let raw_path = entry.path()?.to_string_lossy().to_string();
        // Entry paths key the file list and script lookups downstream; a `..`
        // or absolute path could impersonate package.json or dodge path-based
        // signals, so reject the tarball outright.
        if raw_path.starts_with('/') || raw_path.split(['/', '\\']).any(|c| c == "..") {
            return Err(anyhow!("tarball entry has unsafe path: {raw_path}"));
        }
        // npm tarballs nest everything under a leading `package/` directory.
        let rel = raw_path
            .strip_prefix("package/")
            .unwrap_or(&raw_path)
            .to_string();

        let size = entry.header().size().unwrap_or(0);
        total = total.saturating_add(size);
        if total > MAX_TOTAL_BYTES {
            return Err(anyhow!(
                "tarball exceeds {MAX_TOTAL_BYTES} decompressed bytes"
            ));
        }
        files.push(FileEntry {
            path: rel.clone(),
            size,
        });

        // Capture package.json and small JS files (script bodies) for scanning.
        let is_pkg_json = rel == "package.json";
        let is_script = rel.ends_with(".js") || rel.ends_with(".cjs") || rel.ends_with(".mjs");
        if (is_pkg_json || is_script) && size <= MAX_FILE_BYTES {
            let mut buf = Vec::with_capacity(size as usize);
            entry.take(MAX_FILE_BYTES).read_to_end(&mut buf)?;
            contents.insert(rel, buf);
        }
    }

    let pkg_json = contents
        .get("package.json")
        .ok_or_else(|| anyhow!("tarball has no package.json"))?;
    let manifest = parse_manifest(pkg_json)?;

    // Resolve install-script source files (e.g. `node scripts/setup.js`).
    let mut script_sources = BTreeMap::new();
    for key in LIFECYCLE_KEYS {
        if let Some(cmd) = manifest.scripts.get(*key) {
            let mut combined = String::new();
            for token in cmd.split_whitespace() {
                if token.ends_with(".js") || token.ends_with(".cjs") || token.ends_with(".mjs") {
                    if let Some(bytes) = contents.get(token) {
                        combined.push_str(&String::from_utf8_lossy(bytes));
                        combined.push('\n');
                    }
                }
            }
            if !combined.is_empty() {
                script_sources.insert((*key).to_string(), combined);
            }
        }
    }

    let (package, version) = parse_name_version(pkg_json)?;

    Ok(VersionArtifact {
        package,
        version,
        manifest,
        files,
        script_sources,
        ..Default::default()
    })
}

fn parse_manifest(pkg_json: &[u8]) -> Result<Manifest> {
    let v: serde_json::Value = serde_json::from_slice(pkg_json)?;

    let mut scripts = BTreeMap::new();
    if let Some(obj) = v.get("scripts").and_then(|s| s.as_object()) {
        for (k, val) in obj {
            scripts.insert(k.clone(), val.as_str().unwrap_or("").to_string());
        }
    }
    let mut dependencies = BTreeMap::new();
    if let Some(obj) = v.get("dependencies").and_then(|d| d.as_object()) {
        for (k, val) in obj {
            dependencies.insert(k.clone(), val.as_str().unwrap_or("").to_string());
        }
    }
    let repository = parse_repository(&v);

    Ok(Manifest {
        scripts,
        dependencies,
        repository,
    })
}

/// `repository` is either a string or `{ type, url }`.
pub fn parse_repository(v: &serde_json::Value) -> Option<String> {
    match v.get("repository") {
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(serde_json::Value::Object(o)) => {
            o.get("url").and_then(|u| u.as_str()).map(String::from)
        }
        _ => None,
    }
}

fn parse_name_version(pkg_json: &[u8]) -> Result<(String, String)> {
    let v: serde_json::Value = serde_json::from_slice(pkg_json)?;
    let name = v
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let version = v
        .get("version")
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    // Empty keys would store this artifact's signals under ("", ""), detached
    // from the verdict computed for the real (package, version) — fail loudly.
    if name.is_empty() || version.is_empty() {
        return Err(anyhow!("package.json is missing name or version"));
    }
    Ok((name, version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    /// Build a minimal npm tarball in-memory from (path, bytes) pairs.
    fn make_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
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

    #[test]
    fn parses_manifest_files_and_script_sources() {
        let pkg = br#"{
            "name": "demo",
            "version": "1.2.3",
            "repository": "https://github.com/acme/demo",
            "scripts": { "postinstall": "node scripts/setup.js", "build": "tsc" },
            "dependencies": { "chalk": "^5.0.0" }
        }"#;
        let setup = b"const https = require('https'); https.request(process.env.TOKEN);";
        let tgz = make_tarball(&[
            ("package.json", pkg),
            ("scripts/setup.js", setup),
            ("index.js", b"module.exports = 1;"),
        ]);

        let art = parse(&tgz).unwrap();
        assert_eq!(art.package, "demo");
        assert_eq!(art.version, "1.2.3");
        assert_eq!(
            art.manifest.scripts.get("postinstall").unwrap(),
            "node scripts/setup.js"
        );
        assert_eq!(art.claimed_repo, None); // layered on by extractor, not the tarball
        assert_eq!(
            art.manifest.repository.as_deref(),
            Some("https://github.com/acme/demo")
        );
        // script body for postinstall was resolved from scripts/setup.js
        let src = art.script_sources.get("postinstall").unwrap();
        assert!(src.contains("https.request"));
        assert!(src.contains("process.env"));
        // files list includes all three, with the package/ prefix stripped
        let paths: Vec<&str> = art.files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&"package.json"));
        assert!(paths.contains(&"scripts/setup.js"));
        assert!(paths.contains(&"index.js"));
    }

    #[test]
    fn errors_without_package_json() {
        let tgz = make_tarball(&[("index.js", b"x")]);
        assert!(parse(&tgz).is_err());
    }

    #[test]
    fn rejects_path_traversal_entries() {
        // tar::Builder refuses to *write* `..` paths, so forge the header name
        // bytes directly — exactly what a hand-crafted malicious tarball does.
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            let body: &[u8] = b"x";
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o644);
            let name = b"package/../escape.js";
            header.as_gnu_mut().unwrap().name[..name.len()].copy_from_slice(name);
            header.set_cksum();
            builder.append(&header, body).unwrap();
            builder.finish().unwrap();
        }
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&tar_buf).unwrap();
        let tgz = gz.finish().unwrap();

        let err = parse(&tgz).unwrap_err().to_string();
        assert!(err.contains("unsafe path"), "got: {err}");
    }

    #[test]
    fn rejects_manifest_without_name_or_version() {
        let tgz = make_tarball(&[("package.json", br#"{"name":"x"}"#.as_slice())]);
        let err = parse(&tgz).unwrap_err().to_string();
        assert!(err.contains("missing name or version"), "got: {err}");
    }

    #[test]
    fn rejects_decompression_bomb() {
        // ~33 MiB of highly-compressible data: tiny on the wire, over the cap once
        // decompressed. Must be rejected rather than read into memory.
        let pkg: &[u8] = br#"{"name":"x","version":"1.0.0"}"#;
        let big = vec![0u8; 33 * 1024 * 1024];
        let tgz = make_tarball(&[("package.json", pkg), ("blob.bin", big.as_slice())]);
        let err = parse(&tgz).unwrap_err().to_string();
        assert!(
            err.contains("limit") || err.contains("decompressed"),
            "expected a size-cap error, got: {err}"
        );
    }
}
