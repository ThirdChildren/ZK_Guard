//! `zkguard-report`: JSON, Markdown, SARIF, and human report emitters.
//!
//! This crate is the "report" stage of the pipeline in
//! `docs/architecture.md` (discovery -> parse -> rules -> findings ->
//! **report**). It consumes [`zkguard_core::ScanResult`]/[`zkguard_core::Finding`]
//! values and renders them for humans and machines. It must remain
//! independent of the CLI argument-parsing layer (`zkguard-cli`), per
//! CLAUDE.md design principle 7: every function here is a pure
//! `&ScanResult -> String` (or `Result<String, _>`) transform with no
//! filesystem access, no network calls, and no process exit-code logic —
//! those are `zkguard-cli`'s job.
//!
//! ## What this crate contains (Step 6 of `docs/agent-workflow.md`)
//!
//! - [`json`]: machine-readable JSON emitter, matching CLAUDE.md's
//!   "Reporting schema" field names exactly (the schema is already encoded
//!   in `zkguard_core::Finding`'s `serde` derive; this module just exposes
//!   a stable pretty-printing entry point).
//! - [`markdown`]: human-readable Markdown emitter, readable directly on
//!   GitHub (summary table + one section per finding).
//! - [`human`]: human-readable terminal emitter (the default `zk-guard
//!   scan` output with no `--format` flag).
//! - [`sarif`]: SARIF 2.1.0 emitter for GitHub code scanning / CI upload
//!   (`zk-guard scan --format sarif`; see `docs/sarif.md`). Unlike the other
//!   emitters it also needs the rule registry metadata, since every rule
//!   becomes a `reportingDescriptor`.

pub mod human;
pub mod json;
pub mod markdown;
pub mod sarif;

pub use json::JsonReportError;
pub use sarif::SarifReportError;
