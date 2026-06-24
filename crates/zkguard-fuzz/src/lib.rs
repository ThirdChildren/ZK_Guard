//! `zkguard-fuzz`: deterministic, bounded property-based tests for the
//! static rule set in `zkguard-rules`.
//!
//! Per CLAUDE.md non-negotiable design principle 1 ("Start narrow and
//! useful: Noir first, static rules first, fuzzing second") this crate was
//! populated only in Step 9 of `docs/agent-workflow.md`, after the MVP rules
//! (Steps 4 and 7), fixtures (Step 5), and CLI/reporting (Step 6) were
//! already stable. As of Step 9, all five MVP rules
//! (`NOIR-PUBLIC-001`, `NOIR-CONSTRAINT-001`, `NOIR-RANGE-001`,
//! `ZK-HASH-001`, `ZK-NULLIFIER-001`) are registered in
//! `zkguard_rules::registry()` with passing unit, fixture, and integration
//! tests — the precondition this crate's task protocol required before
//! adding fuzzing.
//!
//! ## What this crate contains
//!
//! - [`generators`]: reusable `proptest` `Strategy` builders, shared between
//!   the property tests under `tests/`. Exposed as a library module (rather
//!   than duplicated per test file) so future rules can reuse the same
//!   "arbitrary hostile text" and "Noir-shaped `fn main` snippet" strategies
//!   without copy-paste drift.
//! - `tests/property_no_panic.rs`: robustness/totality — no rule panics on
//!   arbitrary (including pathological) input text.
//! - `tests/property_determinism.rs`: running the same rule on the same
//!   input twice yields byte-for-byte identical findings.
//! - `tests/property_well_formed.rs`: every emitted `Finding` satisfies
//!   CLAUDE.md's reporting schema (non-empty required fields, rule_id
//!   matches the emitting rule, severity/confidence match the rule's
//!   declared defaults, in-range line numbers).
//! - `tests/property_directional.rs`: structured Noir-shaped generators
//!   asserting the specific safe/vulnerable directional guarantees each
//!   rule's taxonomy entry already commits to (e.g. NOIR-PUBLIC-001 must
//!   not fire when every `pub` parameter is asserted).
//! - `tests/property_line_endings.rs`: CRLF/trailing-whitespace invariance,
//!   gated to only assert the directional safe/vulnerable shape (not byte-
//!   for-byte evidence equality), per Step 9's "only if it holds" guidance.
//!
//! ## Determinism and CI scope (CLAUDE.md principles 5 & 6)
//!
//! Every bounded property test here uses a fixed, explicit `ProptestConfig`
//! with a small `cases` count (64-256 depending on the property) **and** a
//! fixed `rng_seed` (a `FIXED_SEED` constant defined per test file). This
//! is a deliberate, explicit override of `proptest`'s own default
//! (`RngSeed::Random`), which draws a fresh OS-random seed on every test
//! run and would otherwise make `cargo test` non-deterministic across runs
//! even with a fixed `cases` count — exploring different random inputs
//! each time rather than the same committed set. No `PROPTEST_RNG_SEED`/
//! `PROPTEST_CASES` environment override is set or required for the
//! default run. This keeps `cargo test --workspace` fast (single-digit
//! seconds for this crate's whole suite) and reproducible, never a
//! long-running fuzz campaign.
//!
//! No `cargo-fuzz`/libFuzzer target is wired into this crate or into any
//! default test/CI path — per Step 9's explicit constraint, a heavier
//! campaign is left to an `#[ignore]`d test (see
//! `tests/property_no_panic.rs`'s `manual_only` module) that a developer
//! opts into manually, never run by `cargo test --workspace`.

pub mod generators;
