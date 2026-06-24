//! `NOIR-PUBLIC-001` — public input declared but unused in a
//! constraint-relevant expression.
//!
//! Spec source: `docs/rule-taxonomy.md`, section "NOIR-PUBLIC-001". This
//! module is intentionally thin: all Noir-aware text scanning lives in
//! `zkguard_noir::heuristics` (per the `noir-static-analyzer` charter:
//! "if you need a Noir-aware helper put parsing heuristics in zkguard-noir
//! and keep the rule thin"). This file only wires that helper output into
//! `Finding`s.

use zkguard_core::{Confidence, Finding, Rule, RuleMetadata, Severity, SourceView};
use zkguard_noir::heuristics::{find_fn_entry_points, identifier_appears_in_constraint};

/// Default severity per `docs/rule-taxonomy.md` NOIR-PUBLIC-001: `high`.
/// A public input that is never bound to a constraint is the canonical
/// under-constrained-circuit bug, but the taxonomy caps it at `high`
/// (rather than `critical`) because the rule cannot semantically confirm
/// the absence of an out-of-Noir-source mitigation — see "Severity scale"
/// in the taxonomy doc. Do not change without updating the taxonomy.
const DEFAULT_SEVERITY: Severity = Severity::High;

/// Default confidence per `docs/rule-taxonomy.md` NOIR-PUBLIC-001: `medium`.
/// The detection is a textual co-occurrence/one-hop check, not full
/// dataflow, so the taxonomy fixes this at `medium` rather than `high`. Do
/// not change without updating the taxonomy.
const DEFAULT_CONFIDENCE: Confidence = Confidence::Medium;

const RULE_ID: &str = "NOIR-PUBLIC-001";
const TITLE: &str = "Public input declared but unused in a constraint-relevant expression";

/// Builds this rule's static metadata.
#[must_use]
pub fn metadata() -> RuleMetadata {
    RuleMetadata::new(
        RULE_ID,
        TITLE,
        DEFAULT_SEVERITY,
        DEFAULT_CONFIDENCE,
        "Detects `pub` parameters of `fn main` that never reach an \
         assert/assert_eq/constrain expression, directly or via one \
         intermediate `let` binding.",
    )
}

/// `Rule` implementation for `NOIR-PUBLIC-001`.
///
/// See module docs and `docs/rule-taxonomy.md` for the detection strategy
/// and known false-positive classes. This struct holds no state; it exists
/// so the rule can be registered as `Box<dyn Rule>` alongside future rules
/// (Step 7), per `zkguard_core::Rule`'s object-safety requirement.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoirPublic001;

impl Rule for NoirPublic001 {
    fn metadata(&self) -> &RuleMetadata {
        // `RuleMetadata` is cheap to construct and not `Copy` (it owns
        // `String`s), so a `Rule::metadata(&self) -> &RuleMetadata`
        // signature would normally require a stored field. We use a
        // `std::sync::OnceLock` to build it once lazily rather than
        // storing a field that would have to be threaded through
        // `Default`/`new()` for no behavioral benefit.
        static METADATA: std::sync::OnceLock<RuleMetadata> = std::sync::OnceLock::new();
        METADATA.get_or_init(metadata)
    }

    fn check(&self, source: &SourceView) -> Vec<Finding> {
        check_source(source)
    }
}

/// Core detection logic, exposed as a free function for direct unit
/// testing without going through the `Rule` trait object.
///
/// Per `docs/rule-taxonomy.md` NOIR-PUBLIC-001 detection strategy:
/// 1. Collect `pub` parameters of `fn main` (and, per the false-positive
///    notes, *only* `fn main` — helper/test functions are excluded to
///    avoid flagging legitimately-unconstrained debug parameters).
/// 2. For each public parameter, check whether its identifier appears in
///    a constraint-relevant expression in the function body (direct or
///    one-hop indirect, per `zkguard_noir::heuristics`).
/// 3. Emit a finding for every public parameter that does not.
#[must_use]
pub fn check_source(source: &SourceView) -> Vec<Finding> {
    let mut findings = Vec::new();

    for entry in find_fn_entry_points(&source.source) {
        for param in &entry.public_params {
            if identifier_appears_in_constraint(&entry.body, &param.name) {
                continue;
            }

            findings.push(
                Finding::new(
                    RULE_ID,
                    TITLE,
                    DEFAULT_SEVERITY,
                    DEFAULT_CONFIDENCE,
                    source.path.clone(),
                )
                .with_line(param.line)
                .with_evidence(param.declaration_text.clone())
                .with_why_it_matters(
                    "A public input that never reaches an assert/constrain is not actually \
                     bound by the proof — a malicious prover can set it to any value, \
                     defeating the purpose of making it public in the first place. This is \
                     the canonical \"under-constrained circuit\" bug class in ZK audits.",
                )
                .with_remediation(
                    "Bind every public input to at least one constraint that a malicious \
                     prover cannot satisfy arbitrarily. If a public input is intentionally \
                     informational only, document that decision in code comments next to the \
                     parameter and accept the finding as a documented exception.",
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
    /// `noir_public_001_flags_unused_pub_input`.
    #[test]
    fn noir_public_001_flags_unused_pub_input() {
        let src = source(
            "fn main(secret: Field, pub claimed_total: Field) {\n\
             \x20   let computed = secret * 2;\n\
             }\n",
        );

        let findings = check_source(&src);

        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.rule_id, "NOIR-PUBLIC-001");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::Medium);
        assert_eq!(finding.line, Some(1));
        assert_eq!(finding.evidence, "pub claimed_total: Field");
        assert!(!finding.why_it_matters.is_empty());
        assert!(!finding.remediation.is_empty());
    }

    /// `docs/rule-taxonomy.md` suggested test name:
    /// `noir_public_001_allows_constrained_pub_input`.
    #[test]
    fn noir_public_001_allows_constrained_pub_input() {
        let src = source(
            "fn main(secret: Field, pub claimed_total: Field) {\n\
             \x20   let computed = secret * 2;\n\
             \x20   assert(computed == claimed_total);\n\
             }\n",
        );

        let findings = check_source(&src);

        assert!(findings.is_empty());
    }

    /// `docs/rule-taxonomy.md` suggested test name (false-positive guard):
    /// `noir_public_001_no_finding_on_helper_function_params`.
    ///
    /// Per the taxonomy's false-positive notes, the rule is restricted to
    /// `fn main` so unconstrained `pub` parameters on helper functions
    /// (which are not Noir circuit entry points) are not flagged.
    #[test]
    fn noir_public_001_no_finding_on_helper_function_params() {
        let src = source(
            "fn helper(pub debug_value: Field) {\n\
             \x20   println(debug_value);\n\
             }\n\
             fn main(secret: Field) {\n\
             \x20   assert(secret == 1);\n\
             }\n",
        );

        let findings = check_source(&src);

        assert!(findings.is_empty());
    }

    #[test]
    fn one_hop_indirect_use_does_not_fire() {
        let src = source(
            "fn main(secret: Field, pub claimed_total: Field) {\n\
             \x20   let x = claimed_total + 1;\n\
             \x20   assert(x == secret);\n\
             }\n",
        );

        let findings = check_source(&src);

        assert!(findings.is_empty());
    }

    #[test]
    fn println_only_use_still_fires() {
        let src = source(
            "fn main(secret: Field, pub claimed_total: Field) {\n\
             \x20   println(claimed_total);\n\
             \x20   assert(secret == 1);\n\
             }\n",
        );

        let findings = check_source(&src);

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn multiple_public_params_each_evaluated_independently() {
        let src = source(
            "fn main(pub a: Field, pub b: Field) {\n\
             \x20   assert(a == 1);\n\
             }\n",
        );

        let findings = check_source(&src);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence, "pub b: Field");
    }

    #[test]
    fn no_public_params_yields_no_findings() {
        let src = source("fn main(secret: Field) {\n    assert(secret == 1);\n}\n");

        let findings = check_source(&src);

        assert!(findings.is_empty());
    }

    #[test]
    fn rule_object_exposes_expected_metadata() {
        let rule = NoirPublic001;
        assert_eq!(rule.metadata().rule_id, "NOIR-PUBLIC-001");
        assert_eq!(rule.metadata().default_severity, Severity::High);
        assert_eq!(rule.metadata().default_confidence, Confidence::Medium);
    }
}
