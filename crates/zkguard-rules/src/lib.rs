//! `zkguard-rules`: rule registry and rule implementations.
//!
//! This crate hosts the "rules" stage of the pipeline in
//! `docs/architecture.md` (discovery -> parse -> **rules** -> findings ->
//! report). It consumes the Noir source model from `zkguard-noir` and the
//! domain types (`Finding`, `Severity`, `Confidence`, scanner traits) from
//! `zkguard-core`, and emits `Finding` values.
//!
//! ## What this crate contains (Step 4 + Step 7 of `docs/agent-workflow.md`)
//!
//! - [`noir_public_001`]: the `NOIR-PUBLIC-001` rule ("public input
//!   declared but unused in a constraint-relevant expression"), per
//!   `docs/rule-taxonomy.md`.
//! - [`noir_constraint_001`]: the `NOIR-CONSTRAINT-001` rule ("computed
//!   boolean/equality/range check not asserted"), per
//!   `docs/rule-taxonomy.md`.
//! - [`noir_range_001`]: the `NOIR-RANGE-001` rule ("numeric value used in a
//!   security-sensitive context without an obvious range check"), per
//!   `docs/rule-taxonomy.md`.
//! - [`zk_hash_001`]: the `ZK-HASH-001` rule ("hash commitment built from
//!   ambiguous concatenation or missing domain tag"), per
//!   `docs/rule-taxonomy.md`.
//! - [`zk_nullifier_001`]: the `ZK-NULLIFIER-001` rule ("nullifier-like
//!   value generated without a visible domain separator"), per
//!   `docs/rule-taxonomy.md`.
//! - [`zk_test_001`]: the `ZK-TEST-001` rule ("circuit has an entry point but
//!   no negative test"), per `docs/rule-taxonomy.md`. This is a
//!   **project-level** rule ([`zkguard_core::ProjectRule`]): it reasons over
//!   all `.nr` sources at once, not one file in isolation.
//!
//! ## What this crate does not yet contain (deferred)
//!
//! `ZK-REPLAY-001` from CLAUDE.md's "MVP rule families" section: it is
//! project-level replay/uniqueness binding and remains unscheduled (see
//! `docs/roadmap.md`).
//!
//! [`registry::registry`] (per-file rules) and [`registry::project_registry`]
//! (project-level rules) are the single source of truth for "which rules
//! exist": both `zk-guard scan` and `zk-guard rules list` call them, so the
//! two commands can never disagree about the rule set.
//!
//! Per design principle 2, every emitted `Finding` must carry rule_id,
//! title, severity, confidence, location, evidence, why_it_matters, and
//! remediation.

pub mod noir_constraint_001;
pub mod noir_public_001;
pub mod noir_range_001;
pub mod registry;
pub mod zk_hash_001;
pub mod zk_nullifier_001;
pub mod zk_test_001;

pub use noir_constraint_001::NoirConstraint001;
pub use noir_public_001::NoirPublic001;
pub use noir_range_001::NoirRange001;
pub use registry::{project_registry, registry};
pub use zk_hash_001::ZkHash001;
pub use zk_nullifier_001::ZkNullifier001;
pub use zk_test_001::ZkTest001;
