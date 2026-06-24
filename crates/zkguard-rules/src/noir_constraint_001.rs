//! `NOIR-CONSTRAINT-001` — boolean/equality/range expression computed but
//! not asserted/constrained.
//!
//! Spec source: `docs/rule-taxonomy.md`, section "NOIR-CONSTRAINT-001". This
//! module is intentionally thin, mirroring `noir_public_001.rs`'s split: all
//! Noir-aware text scanning lives in `zkguard_noir::heuristics`, and this
//! file only wires that helper output into `Finding`s.

use zkguard_core::{Confidence, Finding, Rule, RuleMetadata, Severity, SourceView};
use zkguard_noir::heuristics::{
    find_boolean_let_bindings, find_fn_entry_points, identifier_used_as_constraint_condition,
};

/// Default severity per `docs/rule-taxonomy.md` NOIR-CONSTRAINT-001: `high`.
/// A computed-but-unasserted boolean exerts zero constraint pressure on the
/// proof, which the taxonomy treats as severe as an unconstrained public
/// input. Do not change without updating the taxonomy.
const DEFAULT_SEVERITY: Severity = Severity::High;

/// Default confidence per `docs/rule-taxonomy.md` NOIR-CONSTRAINT-001:
/// `medium`. The detection is a textual binding-then-usage scan within one
/// function body, not full dataflow or branch tracing, so the taxonomy
/// fixes this at `medium` rather than `high`. Do not change without
/// updating the taxonomy.
const DEFAULT_CONFIDENCE: Confidence = Confidence::Medium;

const RULE_ID: &str = "NOIR-CONSTRAINT-001";
const TITLE: &str = "Computed boolean/equality/range check not asserted";

/// Builds this rule's static metadata.
#[must_use]
pub fn metadata() -> RuleMetadata {
    RuleMetadata::new(
        RULE_ID,
        TITLE,
        DEFAULT_SEVERITY,
        DEFAULT_CONFIDENCE,
        "Detects `let <ident> = <comparison>;` bindings inside `fn main` whose \
         resulting boolean is never passed to assert/assert_eq/constrain, directly \
         or via one intermediate `let` binding.",
    )
}

/// `Rule` implementation for `NOIR-CONSTRAINT-001`.
///
/// See module docs and `docs/rule-taxonomy.md` for the detection strategy
/// and known false-positive classes. Stateless, matching
/// [`zkguard_rules::NoirPublic001`]'s shape so both can be boxed as
/// `Box<dyn Rule>` in the registry.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoirConstraint001;

impl Rule for NoirConstraint001 {
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
/// Per `docs/rule-taxonomy.md` NOIR-CONSTRAINT-001 detection strategy:
/// 1. Scan `fn main`'s body (and any other recognized entry point, per
///    [`find_fn_entry_points`]'s current `fn main`-only scope) for
///    `let <ident> = <expr>;` bindings where `<expr>` contains a top-level
///    comparison operator (`==`, `!=`, `<`, `<=`, `>`, `>=`).
/// 2. For each such binding, check whether `<ident>` is subsequently used as
///    a constraint condition (directly inside `assert`/`assert_eq`/
///    `constrain`, or via one `let`-hop indirection), reusing exactly the
///    same logic NOIR-PUBLIC-001 uses for public-input usage tracking.
/// 3. If not, emit a finding at the `let` binding's location.
///
/// Scope note: like NOIR-PUBLIC-001, this rule is restricted to `fn main`
/// (the only entry point [`find_fn_entry_points`] currently recognizes), per
/// the taxonomy's false-positive notes about helper/test functions
/// legitimately computing unconstrained booleans for non-circuit purposes.
/// Booleans computed in helper functions are not scanned in this v1 — a
/// documented, accepted scope limitation, not a silent gap.
#[must_use]
pub fn check_source(source: &SourceView) -> Vec<Finding> {
    let mut findings = Vec::new();

    for entry in find_fn_entry_points(&source.source) {
        for binding in find_boolean_let_bindings(&entry.body) {
            if identifier_used_as_constraint_condition(&entry.body, &binding.name) {
                continue;
            }

            // Translate the binding's line (relative to `entry.body`, which
            // starts counting from line 1) into an absolute file line: the
            // body's first line is `entry.body_start_line`, so a binding on
            // body-relative line N is at absolute line
            // `entry.body_start_line + (N - 1)`.
            let absolute_line = entry.body_start_line + binding.line.saturating_sub(1);

            findings.push(
                Finding::new(
                    RULE_ID,
                    TITLE,
                    DEFAULT_SEVERITY,
                    DEFAULT_CONFIDENCE,
                    source.path.clone(),
                )
                .with_line(absolute_line)
                .with_evidence(binding.statement_text.clone())
                .with_why_it_matters(
                    "Computing a check without asserting it produces a witness value that \
                     looks meaningful but exerts zero constraint pressure on the proof — the \
                     circuit accepts inputs the developer intended to reject. This is a \
                     frequent root cause of \"the circuit compiles and tests pass but proves \
                     false statements\" bugs.",
                )
                .with_remediation(
                    "Every security-relevant boolean computed in a circuit must flow into an \
                     assert/constrain (or a return-Err-equivalent path enforced by the \
                     verifier integration). If the boolean is purely informational, rename it \
                     clearly and isolate it from security-relevant variable names to reduce \
                     audit ambiguity.",
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
    /// `noir_constraint_001_flags_unasserted_boolean_binding`.
    #[test]
    fn noir_constraint_001_flags_unasserted_boolean_binding() {
        let src = source(
            "fn main(a: Field, b: Field) {\n\
             \x20   let is_equal = a == b;\n\
             }\n",
        );

        let findings = check_source(&src);

        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.rule_id, "NOIR-CONSTRAINT-001");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::Medium);
        assert_eq!(finding.line, Some(2));
        assert_eq!(finding.evidence, "let is_equal = a == b;");
        assert!(!finding.why_it_matters.is_empty());
        assert!(!finding.remediation.is_empty());
    }

    /// `docs/rule-taxonomy.md` suggested test name:
    /// `noir_constraint_001_allows_asserted_boolean_binding`.
    #[test]
    fn noir_constraint_001_allows_asserted_boolean_binding() {
        let src = source(
            "fn main(a: Field, b: Field) {\n\
             \x20   let is_equal = a == b;\n\
             \x20   assert(is_equal);\n\
             }\n",
        );

        let findings = check_source(&src);

        assert!(findings.is_empty());
    }

    /// `docs/rule-taxonomy.md` suggested test name (false-positive guard):
    /// `noir_constraint_001_allows_inline_assert_no_binding`. Per the
    /// taxonomy's detection strategy step 4: "Treat direct inline
    /// comparisons passed straight into `assert(...)` (no intermediate
    /// `let`) as the safe pattern — they never reach this rule because
    /// there is no unused intermediate binding to flag."
    #[test]
    fn noir_constraint_001_allows_inline_assert_no_binding() {
        let src = source(
            "fn main(a: Field, b: Field) {\n\
             \x20   assert(a == b);\n\
             }\n",
        );

        let findings = check_source(&src);

        assert!(findings.is_empty());
    }

    #[test]
    fn allows_asserted_boolean_binding_via_assert_eq_true() {
        let src = source(
            "fn main(a: Field, b: Field) {\n\
             \x20   let is_equal = a == b;\n\
             \x20   assert_eq(is_equal, true);\n\
             }\n",
        );

        let findings = check_source(&src);

        assert!(findings.is_empty());
    }

    #[test]
    fn allows_one_hop_indirect_boolean_binding() {
        let src = source(
            "fn main(a: Field, b: Field) {\n\
             \x20   let is_equal = a == b;\n\
             \x20   let ok = is_equal;\n\
             \x20   assert(ok);\n\
             }\n",
        );

        let findings = check_source(&src);

        assert!(findings.is_empty());
    }

    #[test]
    fn non_boolean_let_binding_does_not_fire() {
        let src = source(
            "fn main(a: Field, b: Field) {\n\
             \x20   let total = a + b;\n\
             }\n",
        );

        let findings = check_source(&src);

        assert!(findings.is_empty());
    }

    #[test]
    fn range_like_comparison_fires_when_unasserted() {
        let src = source(
            "fn main(a: Field, b: Field) {\n\
             \x20   let in_range = a < b;\n\
             }\n",
        );

        let findings = check_source(&src);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence, "let in_range = a < b;");
    }

    #[test]
    fn multiple_unasserted_bindings_each_produce_a_finding() {
        let src = source(
            "fn main(a: Field, b: Field, c: Field) {\n\
             \x20   let is_equal = a == b;\n\
             \x20   let in_range = b < c;\n\
             \x20   assert(is_equal);\n\
             }\n",
        );

        let findings = check_source(&src);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence, "let in_range = b < c;");
    }

    #[test]
    fn rule_object_exposes_expected_metadata() {
        let rule = NoirConstraint001;
        assert_eq!(rule.metadata().rule_id, "NOIR-CONSTRAINT-001");
        assert_eq!(rule.metadata().default_severity, Severity::High);
        assert_eq!(rule.metadata().default_confidence, Confidence::Medium);
    }
}
