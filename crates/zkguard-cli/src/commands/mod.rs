//! Command implementations for the `zk-guard` binary.
//!
//! Each submodule corresponds to exactly one CLI subcommand and exposes a
//! `run` function that takes parsed arguments plus `stdout`/`stderr`
//! writers and returns a process exit code (see `crate::exit_code`). Kept
//! as plain functions over generic `Write`rs (not trait objects, not a
//! command framework) so they stay trivially unit-testable without
//! spawning the compiled binary, per CLAUDE.md's guidance against
//! premature complexity.

pub mod fixtures;
pub mod rules;
pub mod scan;
