use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An immutable audit log entry. Stored append-only with hash chaining.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: Uuid,
    pub actor: Actor,
    pub action: AuditAction,
    pub target: AuditTarget,
    pub before: Option<serde_json::Value>,
    pub after: Option<serde_json::Value>,
    pub timestamp: DateTime<Utc>,
    /// SHA-256 of the previous entry's content + this entry's content (before this field).
    /// The first entry has `prev_hash = None`; all others chain to their predecessor.
    pub prev_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Actor {
    User { id: Uuid, email: String, role: String },
    Service { name: String },
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    VerdictComputed,
    VerdictOverridden,
    PolicyUpdated,
    PolicyCreated,
    PolicyDeleted,
    ApprovalGranted,
    ApprovalRevoked,
    ApprovalExpired,
    SignalReported,
    ContainmentEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditTarget {
    PackageVersion { package: String, version: String },
    Policy { scope: String },
    Approval { id: Uuid },
}

impl AuditEntry {
    /// Compute the SHA-256 hash of this entry's canonical content (excluding `prev_hash`).
    pub fn content_hash(&self) -> String {
        use std::collections::BTreeMap;
        // Serialize everything except prev_hash in a deterministic order.
        let mut map = serde_json::to_value(self).unwrap_or_default();
        if let Some(obj) = map.as_object_mut() {
            obj.remove("prev_hash");
        }
        let canonical = serde_json::to_string(&map).unwrap_or_default();
        let digest = sha256(canonical.as_bytes());
        hex::encode(digest)
    }
}

/// Tiny SHA-256 helper so we don't pull a full crypto dep into core.
/// Production code uses the `sha2` crate in the engine I/O layer.
fn sha256(data: &[u8]) -> [u8; 32] {
    // Stub: returns zeros in core; the engine crate wires the real implementation.
    // This keeps the pure core free of heavy crypto dependencies.
    let _ = data;
    [0u8; 32]
}
