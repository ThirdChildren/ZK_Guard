//! `ZK-HASH-001` — hash commitment built from ambiguous concatenation or
//! missing domain tag.
//!
//! Spec source: `docs/rule-taxonomy.md`, section "ZK-HASH-001". This module
//! is intentionally thin, mirroring `noir_public_001.rs`'s split: all
//! Noir-aware text scanning lives in `zkguard_noir::heuristics`, and this
//! file only wires that helper output into `Finding`s.
//!
//! Unlike `NOIR-PUBLIC-001`/`NOIR-CONSTRAINT-001`/`NOIR-RANGE-001` (which
//! all scope to `fn main`'s body), this rule scans the *whole file's* text,
//! per `docs/rule-taxonomy.md` ZK-HASH-001 detection strategy step 1's
//! example (`leaf_commitment`/`nullifier_hash` are ordinary helper
//! functions, not `fn main`), and per step 2's second condition requiring
//! comparison of call sites across the file.

use zkguard_core::{Confidence, Finding, Rule, RuleMetadata, Severity, SourceView};
use zkguard_noir::heuristics::{find_hash_calls, HashCallSite};

/// Default severity per `docs/rule-taxonomy.md` ZK-HASH-001: `medium`.
/// Do not change without updating the taxonomy.
const DEFAULT_SEVERITY: Severity = Severity::Medium;

/// Default confidence per `docs/rule-taxonomy.md` ZK-HASH-001: `medium`,
/// for a call site that lacks an apparent domain tag AND has a matching
/// arity/shape collision with another hash call elsewhere in the file (the
/// taxonomy's "corroborating second commitment-shape match"). Per the
/// taxonomy's false-positive notes: "should drop to `low` when only the 'no
/// apparent constant tag' heuristic fired without a corroborating second
/// commitment-shape match" — see [`LOW_CONFIDENCE_NO_COLLISION`]. Do not
/// change the `medium` default without updating the taxonomy.
const DEFAULT_CONFIDENCE: Confidence = Confidence::Medium;

/// Downgraded confidence used when a hash call lacks an apparent domain tag
/// but no corroborating same-arity collision was found elsewhere in the
/// file, per the taxonomy's false-positive notes (quoted on
/// [`DEFAULT_CONFIDENCE`]).
const LOW_CONFIDENCE_NO_COLLISION: Confidence = Confidence::Low;

const RULE_ID: &str = "ZK-HASH-001";
const TITLE: &str = "Hash commitment built from ambiguous concatenation or missing domain tag";

/// Builds this rule's static metadata.
#[must_use]
pub fn metadata() -> RuleMetadata {
    RuleMetadata::new(
        RULE_ID,
        TITLE,
        DEFAULT_SEVERITY,
        DEFAULT_CONFIDENCE,
        "Detects calls to hash/commitment functions (callee path containing `hash`, \
         `sha256`, or `pedersen`) built from an inline array literal with no apparent \
         domain/context tag argument, downgrading confidence when no corroborating \
         same-arity call exists elsewhere in the file.",
    )
}

/// `Rule` implementation for `ZK-HASH-001`.
///
/// See module docs and `docs/rule-taxonomy.md` for the detection strategy
/// and known false-positive classes. Stateless, matching the shape of the
/// other rules in this crate so all can be boxed as `Box<dyn Rule>` in the
/// registry.
#[derive(Debug, Default, Clone, Copy)]
pub struct ZkHash001;

impl Rule for ZkHash001 {
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
/// Per `docs/rule-taxonomy.md` ZK-HASH-001 detection strategy:
/// 1. Find every hash/commitment call with an inline array literal argument
///    via [`find_hash_calls`] (runs unconditionally, "the cheaper check").
/// 2. For each call lacking an apparent domain tag
///    ([`HashCallSite::lacks_apparent_domain_tag`]), emit a finding.
/// 3. If at least one *other* call site in the same file has the same
///    arity and also lacks a domain tag (the taxonomy's "corroborating
///    second commitment-shape match," approximating "two different
///    commitments could collide"), keep the rule's default `medium`
///    confidence; otherwise downgrade to `low`, per the taxonomy's
///    false-positive notes.
///
/// Scope note: unlike the other three rules implemented so far, this scan
/// is **not** restricted to `fn main` — hash/commitment helper functions
/// are ordinary, named functions elsewhere in the file (see the taxonomy's
/// own vulnerable-pattern example, `fn leaf_commitment`), so
/// [`find_hash_calls`] is given the whole file's source text.
#[must_use]
pub fn check_source(source: &SourceView) -> Vec<Finding> {
    let sites = find_hash_calls(&source.source);
    let untagged: Vec<&HashCallSite> = sites
        .iter()
        .filter(|site| site.lacks_apparent_domain_tag())
        .collect();

    let mut findings = Vec::new();
    for site in &untagged {
        let has_arity_collision = untagged
            .iter()
            .any(|other| !std::ptr::eq(*other, *site) && other.arity() == site.arity());

        let confidence = if has_arity_collision {
            DEFAULT_CONFIDENCE
        } else {
            LOW_CONFIDENCE_NO_COLLISION
        };

        let evidence = if has_arity_collision {
            format!(
                "{} (no domain tag; another untagged hash call elsewhere in this file shares \
                 the same {}-argument shape)",
                site.evidence,
                site.arity()
            )
        } else {
            format!("{} (no apparent domain tag)", site.evidence)
        };

        findings.push(
            Finding::new(
                RULE_ID,
                TITLE,
                DEFAULT_SEVERITY,
                confidence,
                source.path.clone(),
            )
            .with_line(site.line)
            .with_evidence(evidence)
            .with_why_it_matters(
                "Hashing the same shape of inputs for two different semantic purposes \
                     (e.g. a leaf commitment and a nullifier) without a domain tag can let \
                     values collide across contexts, undermining the uniqueness guarantees \
                     the commitment scheme was supposed to provide.",
            )
            .with_remediation(
                "Include a fixed, protocol-specific domain separator (a constant tag) as \
                     one of the hash inputs for every distinct commitment purpose, and never \
                     reuse the exact same (tag, arity, ordering) shape for two different \
                     semantic commitments.",
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
    /// `zk_hash_001_flags_untagged_colliding_commitments`.
    #[test]
    fn zk_hash_001_flags_untagged_colliding_commitments() {
        let src = source(
            "fn leaf_commitment(a: Field, b: Field) -> Field {\n\
             \x20   poseidon::bn254::hash_2([a, b])\n\
             }\n\
             fn nullifier_hash(c: Field, d: Field) -> Field {\n\
             \x20   poseidon::bn254::hash_2([c, d])\n\
             }\n",
        );

        let findings = check_source(&src);

        assert_eq!(findings.len(), 2, "findings: {findings:#?}");
        for finding in &findings {
            assert_eq!(finding.rule_id, "ZK-HASH-001");
            assert_eq!(finding.severity, Severity::Medium);
            // Both share arity 2, so the arity-collision corroboration
            // keeps confidence at the default `medium`.
            assert_eq!(finding.confidence, Confidence::Medium);
        }
    }

    /// `docs/rule-taxonomy.md` suggested test name:
    /// `zk_hash_001_allows_domain_tagged_hash`.
    #[test]
    fn zk_hash_001_allows_domain_tagged_hash() {
        let src = source(
            "global LEAF_DOMAIN: Field = 0x4c454146;\n\
             fn leaf_commitment(a: Field, b: Field) -> Field {\n\
             \x20   poseidon::bn254::hash_3([LEAF_DOMAIN, a, b])\n\
             }\n",
        );

        let findings = check_source(&src);

        assert!(findings.is_empty(), "findings: {findings:#?}");
    }

    #[test]
    fn single_untagged_hash_call_with_no_collision_is_low_confidence() {
        let src = source(
            "fn leaf_commitment(a: Field, b: Field) -> Field {\n\
             \x20   poseidon::bn254::hash_2([a, b])\n\
             }\n",
        );

        let findings = check_source(&src);

        assert_eq!(findings.len(), 1, "findings: {findings:#?}");
        assert_eq!(findings[0].confidence, Confidence::Low);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn untagged_calls_with_different_arity_do_not_corroborate_each_other() {
        let src = source(
            "fn leaf_commitment(a: Field, b: Field) -> Field {\n\
             \x20   poseidon::bn254::hash_2([a, b])\n\
             }\n\
             fn triple_commitment(a: Field, b: Field, c: Field) -> Field {\n\
             \x20   poseidon::bn254::hash_3([a, b, c])\n\
             }\n",
        );

        let findings = check_source(&src);

        assert_eq!(findings.len(), 2, "findings: {findings:#?}");
        assert!(findings.iter().all(|f| f.confidence == Confidence::Low));
    }

    #[test]
    fn hash_call_without_inline_array_literal_is_not_flagged() {
        let src = source(
            "fn leaf_commitment(inputs: [Field; 2]) -> Field {\n\
             \x20   poseidon::bn254::hash_2(inputs)\n\
             }\n",
        );

        let findings = check_source(&src);

        assert!(findings.is_empty(), "findings: {findings:#?}");
    }

    #[test]
    fn rule_object_exposes_expected_metadata() {
        let rule = ZkHash001;
        assert_eq!(rule.metadata().rule_id, "ZK-HASH-001");
        assert_eq!(rule.metadata().default_severity, Severity::Medium);
        assert_eq!(rule.metadata().default_confidence, Confidence::Medium);
    }
}
