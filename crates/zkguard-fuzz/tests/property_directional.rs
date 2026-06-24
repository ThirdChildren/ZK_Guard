//! Property 4 (Step 9): structured-input directional properties.
//!
//! Unlike `property_no_panic.rs`/`property_determinism.rs`/
//! `property_well_formed.rs` (which use unstructured/pathological text and
//! assert *robustness*), this file uses the small, controlled Noir-shaped
//! generators in `zkguard_fuzz::generators` to assert the specific
//! directional safe/vulnerable guarantees each rule's
//! `docs/rule-taxonomy.md` entry already commits to:
//!
//! - `NOIR-PUBLIC-001`: zero findings when the only `pub` parameter is
//!   asserted against a different identifier (the taxonomy's documented
//!   safe pattern); exactly one finding when it is left completely unused
//!   (the taxonomy's documented vulnerable pattern).
//! - `NOIR-CONSTRAINT-001`: zero findings when a boolean `let` binding is
//!   immediately asserted; exactly one finding when it is left dangling.
//! - `ZK-HASH-001`: zero findings when two same-arity hash calls both carry
//!   a named domain-tag constant; findings (at `medium` confidence, since
//!   the generator deliberately creates the taxonomy's "corroborating
//!   second commitment-shape match" condition) when neither does.
//!
//! ## What this file intentionally does *not* assert
//!
//! Per Step 9's explicit instruction ("Do NOT encode known-limitation cases
//! as hard guarantees — only the directional properties the taxonomy
//! actually promises"):
//! - No property here asserts anything about `NOIR-RANGE-001` or
//!   `ZK-NULLIFIER-001`'s directional safe/vulnerable shapes as a
//!   *generated, randomized* property. Both rules' safe/vulnerable patterns
//!   are already covered by fixed example-based unit tests in
//!   `crates/zkguard-rules/src/noir_range_001.rs` and
//!   `.../zk_nullifier_001.rs` (e.g. `noir_range_001_allows_bounded_index`,
//!   `zk_nullifier_001_allows_domain_tagged_nullifier`); adding randomized
//!   generators for them was judged not to add coverage proportional to the
//!   added generator-maintenance surface for this step, and is left as a
//!   documented, deliberate scope decision rather than a silent gap.
//! - No property asserts a specific *line number* or *evidence text* for
//!   the safe case (there is nothing to assert — the safe case's whole
//!   point is "zero findings"), nor for the vulnerable case beyond what
//!   `property_well_formed.rs` already covers generically.
//! - No property asserts behavior for inputs the taxonomy's own
//!   false-positive notes already document as out of scope (e.g. multi-hop
//!   `let` chains beyond one hop, domain tags passed via a wrapper
//!   function) — those remain documented limitations, not properties this
//!   harness pretends to guarantee.
//!
//! ## Determinism / CI bound
//!
//! `cases: 64` per property (these generators have a tiny state space —
//! effectively one boolean toggle plus a short identifier — so 64 cases is
//! already far more than enough to hit both branches many times over,
//! while keeping total runtime negligible).

use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use zkguard_core::{Confidence, Rule, Severity, SourceView};
use zkguard_fuzz::generators::{
    boolean_binding_snippet, hash_domain_snippet, public_param_snippet,
};
use zkguard_rules::{NoirConstraint001, NoirPublic001, ZkHash001};

/// Fixed proptest seed for this file's properties, per CLAUDE.md principles
/// 5/6 (deterministic local analysis, reproducible output) and Step 9's
/// explicit instruction ("set a fixed proptest seed/config ... so the
/// default `cargo test` run is reproducible"). `proptest`'s own default
/// (`RngSeed::Random`) draws a fresh OS-random seed on every run, which
/// would make `cargo test` non-deterministic across runs even though each
/// individual run's case count stays bounded — this constant closes that
/// gap. The exact value is arbitrary; what matters is that it is fixed and
/// committed, not derived from wall-clock time or `/dev/urandom`.
const FIXED_SEED: RngSeed = RngSeed::Fixed(0x5a4b_5f47_5541_5244);

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, rng_seed: FIXED_SEED, ..ProptestConfig::default() })]

    /// NOIR-PUBLIC-001 directional property, per
    /// `docs/rule-taxonomy.md`'s NOIR-PUBLIC-001 vulnerable/safe patterns
    /// and fixture requirements ("the public parameter is the direct
    /// operand of an `assert_eq`/`assert` that the prover cannot trivially
    /// satisfy").
    #[test]
    fn noir_public_001_matches_documented_safe_and_vulnerable_shapes(
        snippet in public_param_snippet(),
    ) {
        let source = SourceView::new("fuzz/main.nr", snippet.source.clone());
        let findings = NoirPublic001.check(&source);

        if snippet.is_safe {
            assert!(
                findings.is_empty(),
                "NOIR-PUBLIC-001 fired on the taxonomy's documented safe pattern \
                 (asserted pub param `{}`); source:\n{}\nfindings: {findings:#?}",
                snippet.param_name,
                snippet.source
            );
        } else {
            assert_eq!(
                findings.len(),
                1,
                "NOIR-PUBLIC-001 did not fire exactly once on the taxonomy's documented \
                 vulnerable pattern (unused pub param `{}`); source:\n{}\nfindings: \
                 {findings:#?}",
                snippet.param_name,
                snippet.source
            );
            assert!(findings[0].evidence.contains(&snippet.param_name));
            assert_eq!(findings[0].severity, Severity::High);
            assert_eq!(findings[0].confidence, Confidence::Medium);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, rng_seed: FIXED_SEED, ..ProptestConfig::default() })]

    /// NOIR-CONSTRAINT-001 directional property, per
    /// `docs/rule-taxonomy.md`'s NOIR-CONSTRAINT-001 vulnerable/safe
    /// patterns ("the resulting identifier passed to `assert(...)` on the
    /// next line").
    #[test]
    fn noir_constraint_001_matches_documented_safe_and_vulnerable_shapes(
        snippet in boolean_binding_snippet(),
    ) {
        let source = SourceView::new("fuzz/main.nr", snippet.source.clone());
        let findings = NoirConstraint001.check(&source);

        if snippet.is_safe {
            assert!(
                findings.is_empty(),
                "NOIR-CONSTRAINT-001 fired on the taxonomy's documented safe pattern \
                 (asserted boolean binding); source:\n{}\nfindings: {findings:#?}",
                snippet.source
            );
        } else {
            assert_eq!(
                findings.len(),
                1,
                "NOIR-CONSTRAINT-001 did not fire exactly once on the taxonomy's documented \
                 vulnerable pattern (dangling boolean binding); source:\n{}\nfindings: \
                 {findings:#?}",
                snippet.source
            );
            assert_eq!(findings[0].severity, Severity::High);
            assert_eq!(findings[0].confidence, Confidence::Medium);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, rng_seed: FIXED_SEED, ..ProptestConfig::default() })]

    /// ZK-HASH-001 directional property, per `docs/rule-taxonomy.md`'s
    /// ZK-HASH-001 vulnerable/safe patterns ("each prefixing its hash
    /// inputs with a distinct named domain constant").
    #[test]
    fn zk_hash_001_matches_documented_safe_and_vulnerable_shapes(
        snippet in hash_domain_snippet(),
    ) {
        let source = SourceView::new("fuzz/main.nr", snippet.source.clone());
        let findings = ZkHash001.check(&source);

        if snippet.is_safe {
            assert!(
                findings.is_empty(),
                "ZK-HASH-001 fired on the taxonomy's documented safe pattern (both hash \
                 calls domain-tagged); source:\n{}\nfindings: {findings:#?}",
                snippet.source
            );
        } else {
            // The generator always produces two same-arity untagged calls,
            // which is the taxonomy's "corroborating second commitment-
            // shape match" condition, so both findings should keep the
            // rule's default `medium` confidence (not the `low` downgrade
            // path) per `zk_hash_001.rs`'s documented confidence logic.
            assert_eq!(
                findings.len(),
                2,
                "ZK-HASH-001 did not fire on both untagged colliding-shape hash calls; \
                 source:\n{}\nfindings: {findings:#?}",
                snippet.source
            );
            for finding in &findings {
                assert_eq!(finding.severity, Severity::Medium);
                assert_eq!(finding.confidence, Confidence::Medium);
            }
        }
    }
}
