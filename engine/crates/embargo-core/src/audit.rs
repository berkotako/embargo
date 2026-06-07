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
    User {
        id: Uuid,
        email: String,
        role: String,
    },
    Service {
        name: String,
    },
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
    /// Canonical JSON of this entry's content, excluding `prev_hash`.
    /// The engine I/O layer SHA-256-hashes this (with `sha2`) to build the
    /// chain — core stays free of crypto deps and remains a pure data type.
    pub fn canonical_content(&self) -> String {
        let mut map = serde_json::to_value(self).unwrap_or_default();
        if let Some(obj) = map.as_object_mut() {
            obj.remove("prev_hash");
        }
        serde_json::to_string(&map).unwrap_or_default()
    }
}
