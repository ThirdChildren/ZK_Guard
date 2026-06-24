//! `zkguard-rules`: rule registry and rule implementations.
//!
//! This crate hosts the "rules" stage of the pipeline in
//! `docs/architecture.md` (discovery -> parse -> **rules** -> findings ->
//! report). It consumes the Noir source model from `zkguard-noir` and the
//! domain types (`Finding`, `Severity`, `Confidence`, scanner traits) from
//! `zkguard-core`, and emits `Finding` values.
//!
//! ## What this crate contains (Step 4 of `docs/agent-workflow.md`)
//!
//! - [`noir_public_001`]: the `NOIR-PUBLIC-001` rule ("public input
//!   declared but unused in a constraint-relevant expression"), per
//!   `docs/rule-taxonomy.md`.
//!
//! ## What this crate does not yet contain (deferred to Step 7)
//!
//! The remaining MVP rule implementations from CLAUDE.md's "MVP rule
//! families" section: `NOIR-CONSTRAINT-001`, `NOIR-RANGE-001`,
//! `ZK-NULLIFIER-001`, `ZK-REPLAY-001`, `ZK-HASH-001`, `ZK-TEST-001`. Each
//! rule lands with its own fixture pair and tests, per non-negotiable
//! design principle 9, when implemented.
//!
//! There is also no rule registry yet (no `Box<dyn Rule>` collection keyed
//! by `rule_id`) — `zkguard-cli`'s `zk-guard rules list` command (Step 6)
//! will need one, but a single-rule crate does not need it yet, per
//! CLAUDE.md's guidance to avoid premature complexity.
//!
//! Per design principle 2, every emitted `Finding` must carry rule_id,
//! title, severity, confidence, location, evidence, why_it_matters, and
//! remediation.

pub mod noir_public_001;

pub use noir_public_001::NoirPublic001;
