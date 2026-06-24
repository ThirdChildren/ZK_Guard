//! Finding severity scale.
//!
//! Mirrors CLAUDE.md's "Reporting schema" and the scale fixed in
//! `docs/rule-taxonomy.md` ("Severity scale (fixed set, per CLAUDE.md)"):
//! exactly five values, serialized as lowercase strings so JSON output
//! matches the taxonomy doc verbatim.

use serde::{Deserialize, Serialize};

/// How bad the *consequence* would be if the matched pattern were a real,
/// exploitable bug.
///
/// Ordering (via `Ord`/`PartialOrd`) is **most-severe-first**: `Critical` is
/// the maximum value and sorts before everything else. This lets callers do
/// `findings.sort_by_key(|f| f.severity)` ... but note that sorts ascending
/// by default, so [`ScanResult::sorted_by_severity`] reverses the
/// comparison to get most-severe-first output. The derived ordering itself
/// (`Critical > High > Medium > Low > Info`) is what "most severe" means
/// for this enum; see the variant declaration order below, which is also
/// most-severe-first and is what `derive(PartialOrd, Ord)` uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Direct, realistic compromise with no further conditions required.
    /// Per the taxonomy doc, a rule defaults to `Critical` only when the
    /// matched pattern, if real, leads straight to compromise.
    Critical,
    High,
    Medium,
    Low,
    /// Informational only; not a security finding on its own.
    Info,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ordering_is_most_severe_first() {
        let mut levels = [
            Severity::Low,
            Severity::Critical,
            Severity::Info,
            Severity::High,
            Severity::Medium,
        ];
        levels.sort();
        assert_eq!(
            levels,
            [
                Severity::Critical,
                Severity::High,
                Severity::Medium,
                Severity::Low,
                Severity::Info,
            ]
        );
    }

    #[test]
    fn serializes_lowercase() {
        let json = serde_json::to_string(&Severity::Critical).expect("serialize");
        assert_eq!(json, "\"critical\"");
        let json = serde_json::to_string(&Severity::Info).expect("serialize");
        assert_eq!(json, "\"info\"");
    }

    #[test]
    fn round_trips_through_json() {
        for s in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            let json = serde_json::to_string(&s).expect("serialize");
            let back: Severity = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(s, back);
        }
    }
}
