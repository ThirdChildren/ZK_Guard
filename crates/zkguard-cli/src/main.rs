//! `zkguard-cli`: CLI entrypoint (binary name `zk-guard`).
//!
//! This crate must contain CLI wiring only: argument parsing, dispatching
//! to `zkguard-noir` / `zkguard-rules` / `zkguard-report`, and process exit
//! codes. Per CLAUDE.md design principle 7, the core analysis engine
//! (`zkguard-core`, `zkguard-noir`, `zkguard-rules`) must stay independent
//! of this crate; this crate depends on them, never the other way around.
//!
//! ## What this crate will contain (deferred work, Step 6)
//!
//! - `zk-guard scan <path>` with `--format json|markdown` and `--output`.
//! - `zk-guard rules list`.
//! - `zk-guard fixtures validate`.
//! - Documented process exit codes (e.g. findings-found vs. error vs.
//!   clean scan), per CLAUDE.md's MVP commands section.
//!
//! This binary currently only prints a placeholder so the workspace
//! compiles and the binary target is exercisable end-to-end before any
//! argument parsing or scan pipeline exists.

fn main() {
    println!(
        "zk-guard {} (architecture skeleton, no commands implemented yet)",
        env!("CARGO_PKG_VERSION")
    );
    println!("See docs/roadmap.md for the MVP command implementation plan.");
}
