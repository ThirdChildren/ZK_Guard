//! `zkguard-noir`: Noir project discovery and Noir-specific source analysis.
//!
//! This crate is responsible for the "discovery" and "parse" stages of the
//! pipeline described in `docs/architecture.md`:
//!
//! ```text
//! discovery -> parse -> rules -> findings -> report
//! ```
//!
//! ## What this crate will contain (deferred work)
//!
//! - Noir project discovery: locating `Nargo.toml` files and `src/` trees
//!   under a scan root, per CLAUDE.md's safe filesystem traversal
//!   requirement (no symlink loops, no execution of discovered scripts).
//!   Implemented in Step 4 of `docs/agent-workflow.md`.
//! - Noir source representation used by rule implementations in
//!   `zkguard-rules` (e.g. public input declarations, constraint
//!   expressions, hash/nullifier call sites). Implemented incrementally in
//!   Steps 4 and 7.
//! - This crate intentionally does not depend on `zkguard-cli` or
//!   `zkguard-report`, keeping analysis independent from presentation.
//!
//! This is currently a placeholder so the workspace compiles.

pub mod placeholder;
