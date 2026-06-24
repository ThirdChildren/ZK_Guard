//! Finding confidence scale.
//!
//! Per `docs/rule-taxonomy.md` ("Confidence scale (fixed set, per
//! CLAUDE.md)"): confidence is about the *detection*, not the *impact* —
//! kept as a separate enum from [`crate::Severity`] rather than folded into
//! it, so rule authors cannot accidentally conflate "how bad" with "how
//! sure."

use serde::{Deserialize, Serialize};

/// How sure the scanner is that the matched pattern is really present,
/// independent of how severe it would be if so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// The pattern is matched and the scanner can also positively confirm
    /// the absence of a known mitigating pattern.
    High,
    /// The pattern is matched but the scanner's visibility is incomplete
    /// (cross-file/cross-function flow, macro indirection, etc.).
    Medium,
    /// The pattern is matched on weak/structural grounds only (e.g. a
    /// naming convention) with no semantic check at all.
    Low,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn serializes_lowercase() {
        let json = serde_json::to_string(&Confidence::High).expect("serialize");
        assert_eq!(json, "\"high\"");
        let json = serde_json::to_string(&Confidence::Low).expect("serialize");
        assert_eq!(json, "\"low\"");
    }

    #[test]
    fn round_trips_through_json() {
        for c in [Confidence::High, Confidence::Medium, Confidence::Low] {
            let json = serde_json::to_string(&c).expect("serialize");
            let back: Confidence = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(c, back);
        }
    }
}
