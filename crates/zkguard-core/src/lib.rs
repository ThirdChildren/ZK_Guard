//! `zkguard-core`: shared domain types for the zk-guard scanner.
//!
//! This crate is the dependency boundary between the CLI and every analysis
//! crate (`zkguard-noir`, `zkguard-rules`, `zkguard-report`, `zkguard-fuzz`).
//! Per CLAUDE.md design principle 7, the core engine must stay independent
//! of the CLI: nothing in this crate may depend on `zkguard-cli`, and this
//! crate must never perform process execution, network access, or terminal
//! I/O.
//!
//! ## What this crate will contain (Step 3 - Core domain model)
//!
//! This is currently a placeholder. The following are intentionally **not**
//! implemented yet and are deferred to Step 3 of `docs/agent-workflow.md`:
//!
//! - The `Finding` struct (rule_id, title, severity, confidence, location,
//!   evidence, why_it_matters, remediation) as specified in CLAUDE.md's
//!   "Reporting schema" section.
//! - `Severity` (`critical`, `high`, `medium`, `low`, `info`) and
//!   `Confidence` (`high`, `medium`, `low`) enums.
//! - Scanner traits that `zkguard-rules` and `zkguard-noir` will implement.
//! - A `ScanResult` / project model shared across rule implementations.
//!
//! Until Step 3 lands, this crate exposes only a placeholder module so the
//! workspace compiles and downstream crates have something to depend on.

pub mod placeholder;
