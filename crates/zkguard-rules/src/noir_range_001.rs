//! `NOIR-RANGE-001` — numeric value used in a security-sensitive context
//! without an obvious range check.
//!
//! Spec source: `docs/rule-taxonomy.md`, section "NOIR-RANGE-001". This
//! module is intentionally thin, mirroring `noir_public_001.rs`'s split: all
//! Noir-aware text scanning lives in `zkguard_noir::heuristics`, and this
//! file only wires that helper output into `Finding`s.

use zkguard_core::{Confidence, Finding, Rule, RuleMetadata, Severity, SourceView};
use zkguard_noir::heuristics::{
    find_fn_entry_points, find_range_sensitive_sites, has_range_check_for_identifier,
};

/// Default severity per `docs/rule-taxonomy.md` NOIR-RANGE-001: `medium`.
/// Lower than NOIR-PUBLIC-001/NOIR-CONSTRAINT-001 because a missing range
/// check is "missing a defense in depth" rather than necessarily an
/// immediately exploitable unconstrained value — see the taxonomy's
/// severity scale discussion. Do not change without updating the taxonomy.
const DEFAULT_SEVERITY: Severity = Severity::Medium;

/// Default confidence per `docs/rule-taxonomy.md` NOIR-RANGE-001: `low`.
/// Explicitly the most heuristic rule in the MVP set per the taxonomy's
/// false-positive notes: integer types already carry a bit-width, so a
/// "missing range check" is often a security-property-vs-type-width
/// distinction this syntactic scan cannot make. Do not raise without adding
/// real type-width-aware reasoning (see taxonomy).
const DEFAULT_CONFIDENCE: Confidence = Confidence::Low;

const RULE_ID: &str = "NOIR-RANGE-001";
const TITLE: &str =
    "Numeric value used in a security-sensitive context without an obvious range check";

/// Builds this rule's static metadata.
#[must_use]
pub fn metadata() -> RuleMetadata {
    RuleMetadata::new(
        RULE_ID,
        TITLE,
        DEFAULT_SEVERITY,
        DEFAULT_CONFIDENCE,
        "Detects array/slice indexing by a non-constant, non-loop-counter identifier, \
         narrowing integer casts, and unsigned subtraction inside `fn main` with no \
         apparent range-check idiom (assert with a bound, or a range_check/assert_max_bits/ \
         lt/lte helper call) referencing the same identifier.",
    )
}

/// `Rule` implementation for `NOIR-RANGE-001`.
///
/// See module docs and `docs/rule-taxonomy.md` for the detection strategy
/// and known false-positive classes. Stateless, matching the shape of the
/// other rules in this crate so all can be boxed as `Box<dyn Rule>` in the
/// registry.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoirRange001;

impl Rule for NoirRange001 {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: std::sync::OnceLock<RuleMetadata> = std::sync::OnceLock::new();
        METADATA.get_or_init(metadata)
    }

    fn check(&self, source: &SourceView) -> Vec<Finding> {
        check_source(source)
    }
}

/// Core detection logic, exposed as a free function for direct unit testing
/// without going through the `Rule` trait object.
///
/// Per `docs/rule-taxonomy.md` NOIR-RANGE-001 detection strategy:
/// 1. Identify security-sensitive syntactic sites in `fn main`'s body via
///    [`find_range_sensitive_sites`]: non-constant/non-loop-counter array
///    indexing, narrowing casts, and unsigned subtraction.
/// 2. For each site, search the same function body for a range-check idiom
///    referencing the same identifier via [`has_range_check_for_identifier`].
/// 3. If no such idiom is found, emit a finding at the sensitive-context
///    site.
///
/// Scope note: restricted to `fn main` (the only entry point
/// [`find_fn_entry_points`] currently recognizes), matching
/// NOIR-PUBLIC-001/NOIR-CONSTRAINT-001's existing scope decision. A range
/// check performed in a *caller* function before passing the value in is
/// not visible to this single-function scan — an explicitly documented gap
/// per the taxonomy, reflected in this rule's `low` default confidence
/// rather than silently suppressed.
#[must_use]
pub fn check_source(source: &SourceView) -> Vec<Finding> {
    let mut findings = Vec::new();

    for entry in find_fn_entry_points(&source.source) {
        for site in find_range_sensitive_sites(&entry.body) {
            if has_range_check_for_identifier(&entry.body, &site.identifier) {
                continue;
            }

            let absolute_line = entry.body_start_line + site.line.saturating_sub(1);

            findings.push(
                Finding::new(
                    RULE_ID,
                    TITLE,
                    DEFAULT_SEVERITY,
                    DEFAULT_CONFIDENCE,
                    source.path.clone(),
                )
                .with_line(absolute_line)
                .with_evidence(site.evidence.clone())
                .with_why_it_matters(
                    "Using an unbounded or wraparound-prone value as an index, bound, or \
                     arithmetic operand without an explicit range constraint can let a \
                     malicious prover supply out-of-range or wrapped values, producing \
                     witnesses that are valid in the field but not in the intended integer \
                     domain — a classic source of soundness bugs distinct from normal type \
                     checking.",
                )
                .with_remediation(
                    "Add an explicit assert bounding the value's range before it is used in \
                     indexing, truncating casts, or unsigned subtraction. Prefer well-known, \
                     named range-check helpers over ad hoc inequality chains so later static \
                     analysis (and human reviewers) can recognize the pattern.",
                ),
            );
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(text: &str) -> SourceView {
        SourceView::new("src/main.nr", text)
    }

    /// `docs/rule-taxonomy.md` suggested test name:
    /// `noir_range_001_flags_unbounded_index`.
    #[test]
    fn noir_range_001_flags_unbounded_index() {
        let src = source(
            "fn main(index: Field, items: [Field; 8]) {\n\
             \x20   let i = index as u32;\n\
             \x20   let v = items[i];\n\
             }\n",
        );

        let findings = check_source(&src);

        assert!(
            findings.iter().any(|f| f.evidence.contains("items[i]")),
            "expected an indexing finding, got: {findings:#?}"
        );
        for finding in &findings {
            assert_eq!(finding.rule_id, "NOIR-RANGE-001");
            assert_eq!(finding.severity, Severity::Medium);
            assert_eq!(finding.confidence, Confidence::Low);
        }
    }

    /// `docs/rule-taxonomy.md` suggested test name:
    /// `noir_range_001_flags_narrowing_cast_without_bound`.
    #[test]
    fn noir_range_001_flags_narrowing_cast_without_bound() {
        let src = source(
            "fn main(index: Field) {\n\
             \x20   let i = index as u32;\n\
             }\n",
        );

        let findings = check_source(&src);

        assert!(
            findings.iter().any(|f| f.evidence.contains("index as u32")),
            "expected a narrowing-cast finding, got: {findings:#?}"
        );
    }

    /// `docs/rule-taxonomy.md` suggested test name:
    /// `noir_range_001_allows_bounded_index`.
    #[test]
    fn noir_range_001_allows_bounded_index() {
        let src = source(
            "fn main(index: Field, items: [Field; 8]) {\n\
             \x20   assert(index as u32 < 8);\n\
             \x20   let i = index as u32;\n\
             \x20   let v = items[i];\n\
             }\n",
        );

        let findings = check_source(&src);

        assert!(
            findings.is_empty(),
            "an explicit bound on `index` must suppress findings on both the cast and the \
             index it produces, got: {findings:#?}"
        );
    }

    /// `docs/rule-taxonomy.md` suggested test name (false-positive guard):
    /// `noir_range_001_no_finding_on_for_loop_counter`.
    #[test]
    fn noir_range_001_no_finding_on_for_loop_counter() {
        let src = source(
            "fn main(items: [Field; 4]) {\n\
             \x20   let mut total = 0;\n\
             \x20   for i in 0..4 {\n\
             \x20       total = total + items[i];\n\
             \x20   }\n\
             }\n",
        );

        let findings = check_source(&src);

        assert!(
            findings.is_empty(),
            "for _ in 0..N loop counter index must not be flagged: {findings:#?}"
        );
    }

    #[test]
    fn flags_unsigned_subtraction_without_bound() {
        let src = source(
            "fn main(balance: u64, amount: u64) {\n\
             \x20   let diff = balance - amount;\n\
             }\n",
        );

        let findings = check_source(&src);

        assert!(
            findings
                .iter()
                .any(|f| f.evidence.contains("balance - amount")),
            "expected an unsigned-subtraction finding, got: {findings:#?}"
        );
    }

    #[test]
    fn allows_unsigned_subtraction_with_named_range_check_helper() {
        let src = source(
            "fn main(balance: u64, amount: u64) {\n\
             \x20   range_check(balance, 64);\n\
             \x20   let diff = balance - amount;\n\
             }\n",
        );

        let findings = check_source(&src);

        assert!(findings.is_empty(), "findings: {findings:#?}");
    }

    #[test]
    fn rule_object_exposes_expected_metadata() {
        let rule = NoirRange001;
        assert_eq!(rule.metadata().rule_id, "NOIR-RANGE-001");
        assert_eq!(rule.metadata().default_severity, Severity::Medium);
        assert_eq!(rule.metadata().default_confidence, Confidence::Low);
    }
}
