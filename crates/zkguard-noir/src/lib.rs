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
//!   extraction, constraint-keyword usage checks, boolean-binding
//!   detection, range-sensitive-site detection, hash-call detection, and
//!   nullifier-naming-convention detection, added across Steps 4 and 7).
//!   Deliberately not a full Noir parser — see that module's doc comment
//!   for the rationale and known limitations.
//!
//! ## What this crate does **not** contain
//!
//! No concrete rule implementations (those live in `zkguard-rules`), no
//! CLI wiring, no report formatting. This crate intentionally does not
//! depend on `zkguard-cli` or `zkguard-report`, keeping analysis
//! independent from presentation.
//!
//! As of Step 7, this module also fixes a genuine bug in
//! [`heuristics::find_fn_entry_points`] (comment-blindness when searching
//! for the literal `"fn main"` substring) by masking `//`/`/* */` comments
//! before any text search — see [`heuristics::mask_comments`].

pub mod discovery;
pub mod heuristics;

pub use discovery::{discover, DiscoveryError, NoirProject};
