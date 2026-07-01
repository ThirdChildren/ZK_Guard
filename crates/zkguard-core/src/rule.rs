//! Rule metadata and the [`Rule`] trait.
//!
//! This module fixes the *shape* every rule implementation must have, not
//! any specific rule. Concrete rules (`NOIR-PUBLIC-001` etc.) are
//! implemented in `zkguard-rules` starting at Step 4 of
//! `docs/agent-workflow.md`; nothing in this crate knows about Noir syntax.

use serde::{Deserialize, Serialize};

use crate::confidence::Confidence;
use crate::finding::Finding;
use crate::severity::Severity;

/// Static, rule-level metadata: the part of a rule that does not vary
/// per-finding.
///
/// Per-finding `severity`/`confidence` in a [`Finding`] are expected to
/// default to these values (see `docs/rule-taxonomy.md`'s "Finding field
/// mapping": *"The rule's 'Default severity' — fixed per rule, not computed
/// per finding in the MVP"*). A rule implementation may still emit a
/// finding with a different confidence than its default (e.g. downgraded
/// per a documented false-positive note), but severity and confidence
/// always start from these defaults.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleMetadata {
    /// Stable identifier, e.g. `"NOIR-PUBLIC-001"`. Never reused.
    pub rule_id: String,
    /// Human-readable title, used verbatim (or near-verbatim) as
    /// `Finding::title` for findings this rule produces.
    pub title: String,
    /// Default severity for findings from this rule.
    pub default_severity: Severity,
    /// Default confidence for findings from this rule.
    pub default_confidence: Confidence,
    /// One- or two-sentence description of what the rule detects, suitable
    /// for `zk-guard rules list` output (CLI work deferred to Step 6).
    pub description: String,
}

impl RuleMetadata {
    /// Convenience constructor; all fields are required so there is no
    /// builder needed here (unlike [`Finding`], which has several optional
    /// fields).
    #[must_use]
    pub fn new(
        rule_id: impl Into<String>,
        title: impl Into<String>,
        default_severity: Severity,
        default_confidence: Confidence,
        description: impl Into<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            title: title.into(),
            default_severity,
            default_confidence,
            description: description.into(),
        }
    }
}

/// A minimal, language-agnostic view of one source file to be scanned.
///
/// This is intentionally a placeholder input type: it holds just enough
/// (`path` + raw `source` text) for the trait signature below to be
/// meaningful before any real parsing exists. **Step 4 of
/// `docs/agent-workflow.md`** (`noir-static-analyzer`) is expected to
/// either use this type directly for simple text-pattern rules, or
/// introduce a richer Noir-specific source representation in
/// `zkguard-noir` that wraps or replaces it for rules that need more than
/// raw text (e.g. parsed function signatures). Changing or replacing this
/// type is an explicit, expected Step 4+ integration decision, not a defect
/// in this crate.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceView {
    /// Path to the source file, used to populate `Finding::file`.
    pub path: std::path::PathBuf,
    /// Raw source text of the file.
    pub source: String,
}

impl SourceView {
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>, source: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            source: source.into(),
        }
    }
}

/// Implemented by every concrete rule.
///
/// Kept deliberately small: a rule exposes its metadata and a single
/// analysis method. There is no registration mechanism, rule
/// configuration, or severity-override hook yet — those are added only
/// when `zkguard-rules`' rule registry (Step 4+) actually needs them, per
/// CLAUDE.md's guidance to avoid premature complexity.
pub trait Rule {
    /// Returns this rule's static metadata.
    fn metadata(&self) -> &RuleMetadata;

    /// Analyzes one source file and returns zero or more findings.
    ///
    /// Takes a single [`SourceView`] rather than a whole-project view
    /// because the MVP rules in `docs/rule-taxonomy.md` are scoped to
    /// single-function/single-file analysis, with project-level rules
    /// (e.g. `ZK-REPLAY-001`) explicitly documented as a known, later
    /// extension. Project-level rules are expected to be implemented by
    /// calling this method per file and aggregating, or by a separate
    /// trait method added in Step 4/7 once a concrete need exists — not
    /// speculatively added here.
    fn check(&self, source: &SourceView) -> Vec<Finding>;
}

/// Implemented by rules that must reason over a **whole project** at once,
/// rather than one file in isolation.
///
/// Some checks are inherently cross-file: e.g. "the project has an entry
/// point but no negative test" (`ZK-TEST-001`) needs to see every `.nr`
/// source before deciding, because the entry point and the tests may live in
/// different files. `docs/rule-taxonomy.md` and `docs/architecture.md` flag
/// this as the expected home for project-level rules; they are run once over
/// the full source set by the orchestration layer, separately from the
/// per-file [`Rule`] loop, and their metadata joins the same registry surface
/// (`rules list`, SARIF `reportingDescriptor`s, `rules_run`).
pub trait ProjectRule {
    /// Returns this rule's static metadata (same shape as a per-file rule).
    fn metadata(&self) -> &RuleMetadata;

    /// Analyzes every source in the project and returns zero or more
    /// findings. Called once per scan with all discovered `.nr` sources.
    fn check_project(&self, sources: &[SourceView]) -> Vec<Finding>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysEmptyRule(RuleMetadata);

    impl Rule for AlwaysEmptyRule {
        fn metadata(&self) -> &RuleMetadata {
            &self.0
        }

        fn check(&self, _source: &SourceView) -> Vec<Finding> {
            Vec::new()
        }
    }

    #[test]
    fn rule_trait_is_object_safe_and_callable() {
        let rule = AlwaysEmptyRule(RuleMetadata::new(
            "NOIR-PUBLIC-001",
            "Public input declared but unused",
            Severity::High,
            Confidence::Medium,
            "Detects public inputs never used in a constraint-relevant expression.",
        ));
        let source = SourceView::new("src/main.nr", "fn main() {}");

        assert_eq!(rule.metadata().rule_id, "NOIR-PUBLIC-001");
        assert!(rule.check(&source).is_empty());

        // Object safety: rules must be usable as `Box<dyn Rule>` so a
        // future registry (Step 4+) can hold a heterogeneous collection.
        let boxed: Box<dyn Rule> = Box::new(AlwaysEmptyRule(RuleMetadata::new(
            "ZK-TEST-001",
            "Circuit has no negative tests",
            Severity::Low,
            Confidence::High,
            "Detects missing should_fail tests.",
        )));
        assert_eq!(boxed.metadata().rule_id, "ZK-TEST-001");
    }
}
