//! Property 1 (Step 9): no panic / total function.
//!
//! For any arbitrary string used as a `SourceView::source`, running every
//! registered rule's `check()` (via `zkguard_rules::registry()`) must never
//! panic and must terminate. This is the core fuzzing value for this
//! crate: every rule's detection logic is a hand-written text/brace scanner
//! (`zkguard_noir::heuristics`), not a real parser with a totality proof, so
//! it must be defended empirically against hostile input.
//!
//! Covers all 5 registered rules at once (`NOIR-PUBLIC-001`,
//! `NOIR-CONSTRAINT-001`, `NOIR-RANGE-001`, `ZK-HASH-001`,
//! `ZK-NULLIFIER-001`) by iterating `zkguard_rules::registry()`, so adding a
//! 6th rule to the registry automatically gets this robustness coverage
//! with no test-file change required.
//!
//! ## Determinism / CI bound (CLAUDE.md principles 5 & 6)
//!
//! Each `proptest!` block below uses an explicit, small `ProptestConfig`
//! (`cases` between 64 and 256, see each block) and a fixed `rng_seed`
//! (`FIXED_SEED`, defined below) rather than `proptest`'s own default
//! (`RngSeed::Random`, which draws a fresh OS-random seed on every run and
//! would otherwise make two `cargo test` invocations explore different
//! cases). No `PROPTEST_RNG_SEED`/`PROPTEST_CASES` environment override is
//! set or required — the seed and case count are both committed in source,
//! so `cargo test -p zkguard-fuzz` runs the exact same bounded cases every
//! time in CI and locally, never an open-ended fuzz campaign. `cases: 256`
//! keeps total runtime in the low-single-digit-second range per property,
//! measured in this task's final report.
//!
//! A heavier, manually-invoked campaign is provided as an `#[ignore]`d test
//! in the `manual_only` module at the bottom of this file — see that
//! module's doc comment for exactly how to run it. It is never executed by
//! `cargo test --workspace` or by CI.

use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use zkguard_core::SourceView;
use zkguard_fuzz::generators::{arbitrary_text, huge_identifier, pathological_noir_like_text};

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

/// Runs every registered rule's `check()` against `source_text` and asserts
/// only that the call returns (no panic). The returned `Vec<Finding>` is
/// intentionally not inspected here — well-formedness is
/// `tests/property_well_formed.rs`'s job, kept separate so a well-formedness
/// regression doesn't get masked by (or confused with) a panic regression.
fn assert_no_rule_panics(source_text: &str) {
    let source = SourceView::new("fuzz/main.nr", source_text);
    for rule in zkguard_rules::registry() {
        // The call itself is the assertion: if `check` panics, the test
        // harness reports the panic (with proptest's shrunk minimal input)
        // as a failure. No explicit `assert!` is needed for "did not
        // panic" — but we do force the result to be used so the optimizer
        // can never elide the call.
        let findings = rule.check(&source);
        std::hint::black_box(&findings);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, rng_seed: FIXED_SEED, ..ProptestConfig::default() })]

    /// Fully arbitrary UTF-8 text (including multi-byte characters and
    /// control characters), per Step 9's "random bytes-as-text, random
    /// UTF-8" requirement.
    #[test]
    fn no_rule_panics_on_arbitrary_utf8_text(text in arbitrary_text()) {
        assert_no_rule_panics(&text);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, rng_seed: FIXED_SEED, ..ProptestConfig::default() })]

    /// Noir-syntax-shaped token soup: deeply nested brackets, unbalanced
    /// braces, comment/string-marker edge cases, per Step 9's pathological
    /// input list. Far more likely than `arbitrary_text` to actually
    /// exercise the brace-matching and keyword-search code paths in
    /// `zkguard_noir::heuristics`.
    #[test]
    fn no_rule_panics_on_pathological_noir_like_text(text in pathological_noir_like_text()) {
        assert_no_rule_panics(&text);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, rng_seed: FIXED_SEED, ..ProptestConfig::default() })]

    /// A single huge identifier-like token (up to ~5000 chars) embedded in
    /// an otherwise minimal `fn main` shell, per Step 9's explicit "huge
    /// identifiers" pathological case. Lower case count than the other two
    /// properties since each case is already large; 64 cases keeps this
    /// property's total generated-text volume bounded.
    #[test]
    fn no_rule_panics_on_huge_identifier(ident in huge_identifier()) {
        let source_text = format!("fn main(pub {ident}: Field) {{\n    let x = 1;\n}}\n");
        assert_no_rule_panics(&source_text);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, rng_seed: FIXED_SEED, ..ProptestConfig::default() })]

    /// Very long single line (Step 9's explicit "very long lines" case): a
    /// single line built by repeating a short pathological fragment with no
    /// newlines at all, which stresses any code path that assumes lines are
    /// short (none currently should, but this is exactly the kind of
    /// assumption a text scanner can silently grow over time).
    #[test]
    fn no_rule_panics_on_very_long_single_line(repeat_count in 0usize..2_000) {
        let source_text: String = "fn main(pub a: Field) { assert(a == 1); } "
            .repeat(repeat_count.min(2_000) / 10 + 1);
        assert_no_rule_panics(&source_text);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, rng_seed: FIXED_SEED, ..ProptestConfig::default() })]

    /// Deeply nested brackets/braces specifically, per Step 9's explicit
    /// "deeply nested brackets" case — generated independently of the
    /// general token-soup generator so nesting depth is not diluted by
    /// other tokens.
    #[test]
    fn no_rule_panics_on_deeply_nested_brackets(depth in 0usize..500, close in 0usize..500) {
        let opens = "{".repeat(depth);
        let closes = "}".repeat(close);
        let source_text = format!("fn main() {opens}{closes}\n");
        assert_no_rule_panics(&source_text);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, rng_seed: FIXED_SEED, ..ProptestConfig::default() })]

    /// Unbalanced braces (more opens than closes, or vice versa), a
    /// distinct case from "deeply nested" above because nesting depth there
    /// is always eventually balanced by `close` independently of `depth`,
    /// whereas this explicitly biases toward imbalance by only ever
    /// emitting one brace kind after a balanced prefix.
    #[test]
    fn no_rule_panics_on_unbalanced_braces(
        balanced_pairs in 0usize..50,
        extra_opens in 0usize..50,
    ) {
        let balanced = "{}".repeat(balanced_pairs);
        let extra = "{".repeat(extra_opens);
        let source_text = format!("fn main() {{ {balanced}{extra}\n");
        assert_no_rule_panics(&source_text);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, rng_seed: FIXED_SEED, ..ProptestConfig::default() })]

    /// Comment/string edge cases: unterminated block comments, nested-
    /// looking (but not actually nested, since Noir/this scanner does not
    /// support nested block comments) comment markers, and stray quotes —
    /// the exact inputs `mask_comments` in `zkguard_noir::heuristics` must
    /// stay total against.
    #[test]
    fn no_rule_panics_on_comment_and_string_edge_cases(
        variant in 0u8..6,
        filler in pathological_noir_like_text(),
    ) {
        let source_text = match variant {
            0 => format!("fn main() {{ /* unterminated {filler}"),
            1 => format!("fn main() {{ // {filler}"),
            2 => format!("fn main() {{ /*/ {filler} */ }}"),
            3 => format!("fn main() {{ \"{filler}"),
            4 => format!("/* {filler} fn main() {{ }}"),
            _ => format!("fn main() {{ {filler} */ }}"),
        };
        assert_no_rule_panics(&source_text);
    }
}

/// Manually-invoked, heavier campaigns. Per Step 9's constraint ("Do NOT
/// add any long-running / unbounded fuzzing... gate it behind a non-default
/// feature flag or an `#[ignore]`d test"), nothing in this module runs
/// under `cargo test --workspace` or `cargo test -p zkguard-fuzz` by
/// default.
///
/// To run this manually with a much larger case count:
/// ```sh
/// PROPTEST_CASES=20000 cargo test -p zkguard-fuzz --release \
///     -- --ignored no_rule_panics_on_arbitrary_utf8_text_heavy
/// ```
mod manual_only {
    use super::*;

    #[test]
    #[ignore = "heavier-than-CI campaign; run manually with PROPTEST_CASES=<N> \
                cargo test -p zkguard-fuzz --release -- --ignored \
                no_rule_panics_on_arbitrary_utf8_text_heavy"]
    fn no_rule_panics_on_arbitrary_utf8_text_heavy() {
        // `PROPTEST_CASES`, if set in the environment, overrides this
        // `cases` value at runtime (proptest's documented override
        // mechanism), so a developer can scale this up arbitrarily without
        // editing this file. The in-code default (4096) is itself already
        // larger than every bounded property above, which is exactly why
        // this test stays `#[ignore]`d rather than running by default.
        //
        // Unlike every bounded property above, this campaign deliberately
        // does *not* set a fixed `rng_seed`: it uses `ProptestConfig`'s own
        // `RngSeed::Random` default, so each manual invocation explores a
        // fresh region of the input space rather than always replaying the
        // same cases — appropriate for an opt-in deep search, but exactly
        // the non-determinism this crate's default (bounded) properties
        // must avoid per CLAUDE.md principles 5/6.
        let config = ProptestConfig {
            cases: 4096,
            ..ProptestConfig::default()
        };
        let mut runner = proptest::test_runner::TestRunner::new(config);
        let result = runner.run(&arbitrary_text(), |text| {
            assert_no_rule_panics(&text);
            Ok(())
        });
        if let Err(e) = result {
            panic!("heavy campaign found a failing case: {e}");
        }
    }
}
