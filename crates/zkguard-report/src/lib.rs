//! `zkguard-report`: JSON, Markdown, and (later) SARIF report emitters.
//!
//! This crate is the "report" stage of the pipeline in
//! `docs/architecture.md` (discovery -> parse -> rules -> findings ->
//! **report**). It consumes `Finding` values from `zkguard-core` and
//! renders them for humans and machines. It must remain independent of the
//! CLI argument-parsing layer (`zkguard-cli`), per CLAUDE.md design
//! principle 7.
//!
//! ## What this crate will contain (deferred work)
//!
//! - A JSON emitter matching the `Finding` schema in CLAUDE.md's
//!   "Reporting schema" section, machine-readable per design principle 6.
//!   Implemented in Step 6.
//! - A Markdown emitter for human-readable reports (`--format markdown
//!   --output report.md`), implemented in Step 6.
//! - A SARIF emitter, explicitly deferred ("later") past the 0.1.0 release
//!   per CLAUDE.md's crate description for `zkguard-report`.
//!
//! This is currently a placeholder so the workspace compiles.

pub mod placeholder;
