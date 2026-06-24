//! `zkguard-core`: shared domain types for the zk-guard scanner.
//!
//! This crate is the dependency boundary between the CLI and every analysis
//! crate (`zkguard-noir`, `zkguard-rules`, `zkguard-report`, `zkguard-fuzz`).
//! Per CLAUDE.md design principle 7, the core analysis engine must stay
//! independent of the CLI: nothing in this crate may depend on
//! `zkguard-cli`, and this crate must never perform process execution,
//! network access, or terminal I/O.
//!
//! ## What this crate contains (Step 3 - Core domain model)
//!
//! - [`Finding`]: the struct every rule produces (rule_id, title, severity,
//!   confidence, location, evidence, why_it_matters, remediation), per
//!   CLAUDE.md's "Reporting schema" and the field mapping in
//!   `docs/rule-taxonomy.md`.
//! - [`Severity`] (`critical`, `high`, `medium`, `low`, `info`) and
//!   [`Confidence`] (`high`, `medium`, `low`), serialized as lowercase
//!   strings to match the taxonomy doc.
//! - [`RuleMetadata`] and the [`Rule`] trait: the contract concrete rules in
//!   `zkguard-rules` implement starting at Step 4.
//! - [`SourceView`]: a minimal, language-agnostic placeholder input type for
//!   `Rule::check`. Noir-specific source representations (Step 4+, in
//!   `zkguard-noir`) may wrap or replace this as rule needs grow.
//! - [`ScanResult`]: the aggregate of one scan run, consumed by
//!   `zkguard-report` and `zkguard-cli` starting at Step 6.
//!
//! ## What this crate does **not** contain
//!
//! No Noir discovery or parsing (Step 4, `zkguard-noir`), no concrete rule
//! implementations (Step 4/7, `zkguard-rules`), no CLI wiring (Step 6,
//! `zkguard-cli`), no report formatting (Step 6, `zkguard-report`). This
//! crate only defines the shared vocabulary those steps build on.

mod confidence;
mod finding;
mod rule;
mod scan;
mod severity;

pub use confidence::Confidence;
pub use finding::Finding;
pub use rule::{Rule, RuleMetadata, SourceView};
pub use scan::ScanResult;
pub use severity::Severity;
