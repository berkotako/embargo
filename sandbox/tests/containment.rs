//! End-to-end containment test: run the real sandbox binary (single-threaded,
//! so its fork→userns→exec path is safe) with a `probe` payload that attempts
//! outbound connections. Assert the non-allowlisted destination is blocked and
//! captured, while loopback is permitted.
//!
//! Requires unprivileged user namespaces + seccomp user-notify. Marked #[ignore]
//! so the default suite stays portable; a dedicated CI job runs it.

use std::process::Command;

const NON_ALLOWLISTED: &str = "93.184.216.34:443"; // example.com — never allowlisted here
const LOOPBACK: &str = "127.0.0.1:9"; // discard port; allowed (connect may refuse)

fn sandbox_bin() -> &'static str {
    env!("CARGO_BIN_EXE_embargo-sandbox")
}

#[test]
#[ignore = "requires unprivileged userns + seccomp user-notify"]
fn blocks_and_captures_non_allowlisted_egress() {
    let report = std::env::temp_dir().join(format!("embargo-sbx-{}.json", std::process::id()));
    let bin = sandbox_bin();

    let status = Command::new(bin)
        .args([
            "run",
            "--allow",
            "127.0.0.1",
            "--report-file",
            report.to_str().unwrap(),
            "--",
            bin,
            "probe",
            "--connect",
            NON_ALLOWLISTED,
            "--connect",
            LOOPBACK,
        ])
        .status()
        .expect("spawn sandbox");
    assert!(status.success() || status.code().is_some(), "sandbox ran");

    let report_json = std::fs::read_to_string(&report).expect("report written");
    let parsed: serde_json::Value = serde_json::from_str(&report_json).unwrap();
    let dests: Vec<String> = parsed["blocked"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["dest"].as_str().unwrap_or("").to_string())
        .collect();

    assert!(
        dests.iter().any(|d| d == NON_ALLOWLISTED),
        "non-allowlisted egress must be captured, got: {dests:?}"
    );
    assert!(
        !dests.iter().any(|d| d == LOOPBACK),
        "loopback must be allowed, not blocked: {dests:?}"
    );

    let _ = std::fs::remove_file(&report);
}

/// Runtime chain detection: a process that reads a secret-looking file and then
/// connects to a non-allowlisted host triggers a compromise-chain detection.
#[test]
#[ignore = "requires unprivileged userns + seccomp user-notify"]
fn detects_secret_read_then_egress_chain() {
    let dir = std::env::temp_dir().join(format!("embargo-sbx-chain-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let secret = dir.join(".npmrc");
    std::fs::write(&secret, b"//registry.npmjs.org/:_authToken=deadbeef").unwrap();
    let report = dir.join("report.json");
    let bin = sandbox_bin();

    let status = Command::new(bin)
        .args([
            "run",
            "--allow",
            "127.0.0.1",
            "--detect-chain",
            "--report-file",
            report.to_str().unwrap(),
            "--",
            bin,
            "probe",
            "--read-secret",
            secret.to_str().unwrap(),
            "--connect",
            NON_ALLOWLISTED,
        ])
        .status()
        .expect("spawn sandbox");
    assert!(status.code().is_some(), "sandbox ran");

    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report).expect("report")).unwrap();
    let chains = parsed["chains"].as_array().expect("chains array");
    assert!(
        !chains.is_empty(),
        "a compromise chain must be detected: {parsed}"
    );
    let c = &chains[0];
    assert_eq!(c["dest"].as_str().unwrap(), NON_ALLOWLISTED);
    assert!(
        c["secret_path"].as_str().unwrap().ends_with(".npmrc"),
        "chain should name the secret read: {c}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
