//! Placeholder module for `zkguard-core`.
//!
//! Replaced by the real domain model (Finding, Severity, Confidence,
//! scanner traits) in Step 3 of `docs/agent-workflow.md`. Kept here only so
//! the crate has a non-empty, documented surface during the architecture
//! skeleton phase.

/// Marks that this crate is intentionally not yet implemented beyond
/// scaffolding. Will be removed once Step 3 introduces the real domain
/// types.
pub const PLACEHOLDER: &str = "zkguard-core: domain model pending (see docs/roadmap.md, Step 3)";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_is_set() {
        assert!(!PLACEHOLDER.is_empty());
    }
}
