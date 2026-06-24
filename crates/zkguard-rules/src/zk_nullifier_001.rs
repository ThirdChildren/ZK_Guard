//! `ZK-NULLIFIER-001` — nullifier-like value generated without a visible
//! domain separator.
//!
//! Spec source: `docs/rule-taxonomy.md`, section "ZK-NULLIFIER-001". This
//! module is intentionally thin, mirroring `noir_public_001.rs`'s split: all
//! Noir-aware text scanning lives in `zkguard_noir::heuristics`, and this
//! file only wires that helper output into `Finding`s.
//!
//! Like `ZK-HASH-001` (whose hash-call detection this rule directly reuses
//! via [`as_hash_call`]), this rule scans the *whole file's* text rather
//! than a single `fn main` body, since the taxonomy's example
//! (`fn compute_nullifier`) is an ordinary helper function.

use zkguard_core::{Confidence, Finding, Rule, RuleMetadata, Severity, SourceView};
use zkguard_noir::heuristics::{as_hash_call, find_nullifier_like_sites};

/// Default severity per `docs/rule-taxonomy.md` ZK-NULLIFIER-001: `high`.
/// Do not change without updating the taxonomy.
const DEFAULT_SEVERITY: Severity = Severity::High;

/// Default confidence per `docs/rule-taxonomy.md` ZK-NULLIFIER-001: `low`.
/// This is the taxonomy's explicitly lowest-confidence rule: detection is
/// naming-convention-only ("there is no semantic way to recognize 'this
/// value is meant to prevent replay' from syntax alone"). Per the
/// taxonomy's false-positive notes, this "must never be emitted above
/// `medium` confidence given the name-only basis" — this implementation
/// never raises above the `low` default at all. Do not change without
/// updating the taxonomy.
const DEFAULT_CONFIDENCE: Confidence = Confidence::Low;

const RULE_ID: &str = "ZK-NULLIFIER-001";
const TITLE: &str = "Nullifier-like value generated without a visible domain separator";

/// Builds this rule's static metadata.
#[must_use]
pub fn metadata() -> RuleMetadata {
    RuleMetadata::new(
        RULE_ID,
        TITLE,
        DEFAULT_SEVERITY,
        DEFAULT_CONFIDENCE,
        "Detects `let`/function bindings whose name matches a nullifier naming \
         convention (nullifier, null_hash, spent_tag) where the computed value is either \
         not the output of a hash at all, or is a hash call with no apparent domain/context \
         tag argument.",
    )
}

/// `Rule` implementation for `ZK-NULLIFIER-001`.
///
/// See module docs and `docs/rule-taxonomy.md` for the detection strategy
/// and known false-positive classes. Stateless, matching the shape of the
/// other rules in this crate so all can be boxed as `Box<dyn Rule>` in the
/// registry.
#[derive(Debug, Default, Clone, Copy)]
pub struct ZkNullifier001;

impl Rule for ZkNullifier001 {
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
/// Per `docs/rule-taxonomy.md` ZK-NULLIFIER-001 detection strategy:
/// 1. Find every nullifier-like `let` binding or single-expression-body
///    function via [`find_nullifier_like_sites`] (name-based only, per the
///    taxonomy).
/// 2. For each match, check whether its computed expression is a hash call
///    ([`as_hash_call`], reusing `ZK-HASH-001`'s detection shape).
/// 3. If it is **not** a hash call at all (a raw value reused directly as
///    the nullifier), emit a finding unconditionally — the taxonomy's
///    stronger structural signal.
/// 4. If it **is** a hash call but [`HashCallSite::lacks_apparent_domain_tag`]
///    is true, also emit a finding (weaker signal, same `low` confidence
///    default per the taxonomy: "must never be emitted above `medium`
///    confidence given the name-only basis," and this implementation keeps
///    both cases at the rule's default `low`).
/// 5. If it is a hash call **with** an apparent domain tag, no finding.
#[must_use]
pub fn check_source(source: &SourceView) -> Vec<Finding> {
    let mut findings = Vec::new();

    for site in find_nullifier_like_sites(&source.source) {
        let (is_finding, detail) = match as_hash_call(&site.expression_text) {
            None => (
                true,
                "this value is reused directly with no hash at all, which is a stronger \
                 structural signal of missing domain separation than an untagged hash"
                    .to_string(),
            ),
            Some(hash_call) if hash_call.lacks_apparent_domain_tag() => (
                true,
                "this value is the output of a hash call with no apparent domain/context tag \
                 argument"
                    .to_string(),
            ),
            Some(_) => (false, String::new()),
        };

        if !is_finding {
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
            .with_line(site.line)
            .with_evidence(format!(
                "{} = {} ({detail})",
                site.name, site.expression_text
            ))
            .with_why_it_matters(
                "A nullifier without a domain separator can potentially be replayed across \
                 different circuits, actions, or deployments that share the same underlying \
                 secret/index inputs, weakening the uniqueness property the nullifier is \
                 meant to guarantee.",
            )
            .with_remediation(
                "Always mix a fixed, action/circuit-specific domain constant into nullifier \
                 computation, in addition to (not instead of) the nullifier actually being \
                 checked against a set of previously-seen values by the verifier/contract \
                 integration.",
            ),
        );
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
    /// `zk_nullifier_001_flags_unhashed_raw_nullifier`.
    #[test]
    fn zk_nullifier_001_flags_unhashed_raw_nullifier() {
        let src = source(
            "fn main(secret: Field) -> Field {\n\
             \x20   let nullifier = secret;\n\
             \x20   nullifier\n\
             }\n",
        );

        let findings = check_source(&src);

        assert_eq!(findings.len(), 1, "findings: {findings:#?}");
        let finding = &findings[0];
        assert_eq!(finding.rule_id, "ZK-NULLIFIER-001");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::Low);
        assert!(finding.evidence.contains("nullifier"));
        assert!(!finding.why_it_matters.is_empty());
        assert!(!finding.remediation.is_empty());
    }

    /// `docs/rule-taxonomy.md` suggested test name:
    /// `zk_nullifier_001_flags_untagged_hashed_nullifier`.
    #[test]
    fn zk_nullifier_001_flags_untagged_hashed_nullifier() {
        let src = source(
            "fn compute_nullifier(secret: Field, leaf_index: Field) -> Field {\n\
             \x20   poseidon::bn254::hash_2([secret, leaf_index])\n\
             }\n",
        );

        let findings = check_source(&src);

        assert_eq!(findings.len(), 1, "findings: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].confidence, Confidence::Low);
    }

    /// `docs/rule-taxonomy.md` suggested test name:
    /// `zk_nullifier_001_allows_domain_tagged_nullifier`.
    #[test]
    fn zk_nullifier_001_allows_domain_tagged_nullifier() {
        let src = source(
            "global NULLIFIER_DOMAIN: Field = 0x4e554c4c;\n\
             fn compute_nullifier(secret: Field, leaf_index: Field) -> Field {\n\
             \x20   poseidon::bn254::hash_3([NULLIFIER_DOMAIN, secret, leaf_index])\n\
             }\n",
        );

        let findings = check_source(&src);

        assert!(findings.is_empty(), "findings: {findings:#?}");
    }

    #[test]
    fn unrelated_name_is_not_flagged() {
        let src = source(
            "fn leaf_commitment(secret: Field, leaf_index: Field) -> Field {\n\
             \x20   poseidon::bn254::hash_2([secret, leaf_index])\n\
             }\n",
        );

        let findings = check_source(&src);

        assert!(findings.is_empty(), "findings: {findings:#?}");
    }

    #[test]
    fn rule_object_exposes_expected_metadata() {
        let rule = ZkNullifier001;
        assert_eq!(rule.metadata().rule_id, "ZK-NULLIFIER-001");
        assert_eq!(rule.metadata().default_severity, Severity::High);
        assert_eq!(rule.metadata().default_confidence, Confidence::Low);
    }
}
