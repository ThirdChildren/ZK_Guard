//! `zkguard-fuzz`: optional mutation and property-based testing harnesses.
//!
//! This crate is explicitly out of scope until the static rule set is
//! stable. Per CLAUDE.md non-negotiable design principle 1 ("Start narrow
//! and useful: Noir first, static rules first, fuzzing second") and the
//! agent workflow, this crate is only populated in Step 9, after the MVP
//! rules (Steps 4 and 7) and CLI/reporting (Step 6) are in place.
//!
//! ## What this crate will contain (deferred work)
//!
//! - Deterministic property-based tests that exercise existing static rules
//!   against generated/mutated Noir fixtures (Step 9).
//! - Optionally, mutation-based checks for witness/test harness brittleness
//!   feeding into `ZK-TEST-001`.
//! - This crate must not introduce long-running fuzzing into default CI, per
//!   Step 9's instructions.
//!
//! This is currently a placeholder so the workspace compiles.

pub mod placeholder;
