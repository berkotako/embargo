//! Runtime compromise-chain detection (pure, source-agnostic).
//!
//! "A single syscall has no intent; the chain does." This correlates a stream
//! of per-process runtime events and fires when one process exhibits the
//! stealer chain: **read a secret → then egress to a non-allowlisted host**
//! within a time window. (Serialization sits between the two in the wild; it is
//! not separately observable here, so the read→egress pair is the trigger.)
//!
//! No I/O, no `unsafe` — fully unit-testable. The data source (the seccomp
//! supervisor today, an eBPF ring buffer in production) feeds `RuntimeEvent`s.

use std::collections::HashMap;
use std::net::SocketAddr;

/// Sensitive paths whose read is the first link of the stealer chain.
const SECRET_MARKERS: &[&str] = &[
    ".npmrc",
    ".aws/credentials",
    ".aws/config",
    "id_rsa",
    "id_ed25519",
    "/.ssh/",
    "/proc/self/environ",
    "/proc/self/cmdline",
    ".env",
    ".netrc",
    ".docker/config.json",
    ".kube/config",
    "gcloud/credentials",
    ".git-credentials",
];

/// True if `path` looks like a credential/secret store.
pub fn is_secret_path(path: &str) -> bool {
    SECRET_MARKERS.iter().any(|m| path.contains(m))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    /// A process read a sensitive file.
    SecretRead { path: String },
    /// A process attempted an outbound connection.
    Egress { dest: SocketAddr, allowlisted: bool },
}

/// A timestamped per-process runtime event. `at_ms` is a logical millisecond
/// clock supplied by the source (monotonic), keeping the detector pure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEvent {
    pub pid: u32,
    pub kind: EventKind,
    pub at_ms: u64,
}

/// A detected compromise chain on one process.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ChainDetection {
    pub pid: u32,
    pub secret_path: String,
    pub dest: SocketAddr,
    /// Whether the egress destination was outside the allowlist.
    pub dest_non_allowlisted: bool,
}

#[derive(Debug, Clone)]
struct SecretState {
    path: String,
    at_ms: u64,
}

/// Correlates events per pid and fires when the chain completes.
pub struct ChainDetector {
    /// Max gap between the secret read and the egress to still count as a chain.
    window_ms: u64,
    /// Most recent secret read per pid.
    secrets: HashMap<u32, SecretState>,
    /// Pids we've already reported, so we fire once per process.
    fired: HashMap<u32, ()>,
}

impl ChainDetector {
    pub fn new(window_ms: u64) -> Self {
        Self {
            window_ms,
            secrets: HashMap::new(),
            fired: HashMap::new(),
        }
    }

    /// Feed one event; returns a detection when this event completes a chain.
    pub fn observe(&mut self, ev: &RuntimeEvent) -> Option<ChainDetection> {
        match &ev.kind {
            EventKind::SecretRead { path } => {
                self.secrets.insert(
                    ev.pid,
                    SecretState {
                        path: path.clone(),
                        at_ms: ev.at_ms,
                    },
                );
                None
            }
            EventKind::Egress { dest, allowlisted } => {
                // Only a non-allowlisted egress completes the stealer chain.
                if *allowlisted {
                    return None;
                }
                if self.fired.contains_key(&ev.pid) {
                    return None;
                }
                let secret = self.secrets.get(&ev.pid)?;
                if ev.at_ms.saturating_sub(secret.at_ms) > self.window_ms {
                    return None; // too long after the read
                }
                self.fired.insert(ev.pid, ());
                Some(ChainDetection {
                    pid: ev.pid,
                    secret_path: secret.path.clone(),
                    dest: *dest,
                    dest_non_allowlisted: true,
                })
            }
        }
    }

    /// Drop per-pid state when a process exits. Reserved for the supervisor's
    /// future per-process lifecycle tracking (multi-process installs).
    #[allow(dead_code)]
    pub fn forget(&mut self, pid: u32) {
        self.secrets.remove(&pid);
        self.fired.remove(&pid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn egress(pid: u32, at_ms: u64, allow: bool) -> RuntimeEvent {
        RuntimeEvent {
            pid,
            at_ms,
            kind: EventKind::Egress {
                dest: "93.184.216.34:443".parse().unwrap(),
                allowlisted: allow,
            },
        }
    }
    fn secret(pid: u32, at_ms: u64, path: &str) -> RuntimeEvent {
        RuntimeEvent {
            pid,
            at_ms,
            kind: EventKind::SecretRead { path: path.into() },
        }
    }

    #[test]
    fn secret_paths_classified() {
        assert!(is_secret_path("/home/u/.npmrc"));
        assert!(is_secret_path("/home/u/.aws/credentials"));
        assert!(is_secret_path("/proc/self/environ"));
        assert!(!is_secret_path("/usr/lib/node_modules/lodash/index.js"));
    }

    #[test]
    fn read_then_egress_fires_chain() {
        let mut d = ChainDetector::new(5_000);
        assert!(d.observe(&secret(100, 0, "/home/u/.npmrc")).is_none());
        let hit = d
            .observe(&egress(100, 200, false))
            .expect("chain should fire");
        assert_eq!(hit.pid, 100);
        assert_eq!(hit.secret_path, "/home/u/.npmrc");
        assert!(hit.dest_non_allowlisted);
    }

    #[test]
    fn egress_without_prior_secret_does_not_fire() {
        let mut d = ChainDetector::new(5_000);
        assert!(d.observe(&egress(100, 200, false)).is_none());
    }

    #[test]
    fn allowlisted_egress_never_fires() {
        let mut d = ChainDetector::new(5_000);
        d.observe(&secret(100, 0, "/home/u/.npmrc"));
        assert!(d.observe(&egress(100, 50, true)).is_none());
    }

    #[test]
    fn egress_outside_window_does_not_fire() {
        let mut d = ChainDetector::new(1_000);
        d.observe(&secret(100, 0, "/home/u/.npmrc"));
        assert!(d.observe(&egress(100, 5_000, false)).is_none());
    }

    #[test]
    fn fires_once_per_pid() {
        let mut d = ChainDetector::new(5_000);
        d.observe(&secret(100, 0, "/home/u/.npmrc"));
        assert!(d.observe(&egress(100, 100, false)).is_some());
        assert!(d.observe(&egress(100, 200, false)).is_none());
    }

    #[test]
    fn distinct_pids_tracked_separately() {
        let mut d = ChainDetector::new(5_000);
        d.observe(&secret(1, 0, "/home/u/.npmrc"));
        // pid 2 egresses without reading a secret → no chain.
        assert!(d.observe(&egress(2, 10, false)).is_none());
        // pid 1 egresses after its read → chain.
        assert!(d.observe(&egress(1, 20, false)).is_some());
    }

    #[test]
    fn forget_clears_state() {
        let mut d = ChainDetector::new(5_000);
        d.observe(&secret(100, 0, "/home/u/.npmrc"));
        d.forget(100);
        assert!(d.observe(&egress(100, 100, false)).is_none());
    }
}
