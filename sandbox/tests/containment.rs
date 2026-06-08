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
    let blocked: serde_json::Value = serde_json::from_str(&report_json).unwrap();
    let dests: Vec<String> = blocked
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
