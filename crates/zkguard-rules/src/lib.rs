//! `zkguard-rules`: rule registry and rule implementations.
//!
//! This crate hosts the "rules" stage of the pipeline in
//! `docs/architecture.md` (discovery -> parse -> **rules** -> findings ->
//! report). It consumes the Noir source model from `zkguard-noir` and the
//! domain types (`Finding`, `Severity`, `Confidence`, scanner traits) from
//! `zkguard-core`, and emits `Finding` values.
//!
//! ## What this crate will contain (deferred work)
//!
//! - A rule registry keyed by rule_id (e.g. `NOIR-PUBLIC-001`,
//!   `ZK-NULLIFIER-001`) so the CLI's `zk-guard rules list` command and the
//!   scan pipeline share one source of truth.
//! - The seven MVP rule implementations from CLAUDE.md's "MVP rule
//!   families" section: `NOIR-PUBLIC-001`, `NOIR-CONSTRAINT-001`,
//!   `NOIR-RANGE-001`, `ZK-NULLIFIER-001`, `ZK-REPLAY-001`, `ZK-HASH-001`,
//!   `ZK-TEST-001`. Each rule lands with its own fixture pair and tests, per
//!   non-negotiable design principle 9. Implemented in Steps 4 and 7.
//! - Per design principle 2, every emitted `Finding` must carry rule_id,
//!   title, severity, confidence, location, evidence, why_it_matters, and
//!   remediation.
//!
//! This is currently a placeholder so the workspace compiles.

pub mod placeholder;
