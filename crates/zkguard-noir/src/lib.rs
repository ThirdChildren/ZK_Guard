//! `zkguard-noir`: Noir project discovery and Noir-specific source analysis.
//!
//! This crate is responsible for the "discovery" and "parse" stages of the
//! pipeline described in `docs/architecture.md`:
//!
//! ```text
//! discovery -> parse -> rules -> findings -> report
//! ```
//!
//! ## What this crate contains (Step 4 of `docs/agent-workflow.md`)
//!
//! - [`discovery`]: safe Noir project discovery — locating `Nargo.toml`
//!   files, `.nr` source files, and building [`zkguard_core::SourceView`]
//!   values, per CLAUDE.md's safe filesystem traversal requirement (no
//!   symlink loops, no execution of discovered scripts, no reads outside
//!   the given root).
//! - [`heuristics`]: text-level Noir heuristics shared by rule
//!   implementations in `zkguard-rules` (entry-point/`pub`-parameter
//!   extraction, constraint-keyword usage checks). Deliberately not a full
//!   Noir parser — see that module's doc comment for the rationale and
//!   known limitations.
//!
//! ## What this crate does **not** contain
//!
//! No concrete rule implementations (those live in `zkguard-rules`), no
//! CLI wiring, no report formatting. This crate intentionally does not
//! depend on `zkguard-cli` or `zkguard-report`, keeping analysis
//! independent from presentation.
//!
//! Additional NOIR-*/ZK-* heuristics needed by Step 7 rules
//! (`NOIR-CONSTRAINT-001`, `NOIR-RANGE-001`, `ZK-HASH-001`,
//! `ZK-NULLIFIER-001`) are deferred to that step, not scaffolded ahead of
//! need.

pub mod discovery;
pub mod heuristics;

pub use discovery::{discover, DiscoveryError, NoirProject};
