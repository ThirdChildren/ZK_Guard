//! Suppression domain types.
//!
//! A [`SuppressedFinding`] is a [`Finding`] that a rule *did* produce but that
//! configuration or an inline directive asked to hide from the active result
//! set (with a required, human-written `reason`). The matching policy itself
//! lives in `zkguard-config`; this crate only defines the shape so that
//! [`crate::ScanResult`] and the report emitters can carry it.
//!
//! Suppression never changes rule *semantics*: a suppressed finding was still
//! detected. It is recorded (and, with `--show-suppressed`, displayed) so the
//! decision to ignore it stays auditable rather than silent.

use serde::{Deserialize, Serialize};

use crate::finding::Finding;

/// Where a suppression came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SuppressionKind {
    /// An inline `// zkguard:ignore RULE_ID reason="..."` directive in the
    /// scanned source.
    Inline,
    /// A `[[suppress]]` entry in `zkguard.toml`.
    Config,
}

/// A finding that was detected but suppressed, plus why.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SuppressedFinding {
    /// The original finding, flattened so its fields sit alongside `reason`
    /// and `suppressed_by` in JSON output (no nested `finding` object).
    #[serde(flatten)]
    pub finding: Finding,
    /// The required, non-empty human explanation for the suppression.
    pub reason: String,
    /// How the suppression was declared (inline directive vs config file).
    pub suppressed_by: SuppressionKind,
}

impl SuppressedFinding {
    #[must_use]
    pub fn new(
        finding: Finding,
        reason: impl Into<String>,
        suppressed_by: SuppressionKind,
    ) -> Self {
        Self {
            finding,
            reason: reason.into(),
            suppressed_by,
        }
    }
}
