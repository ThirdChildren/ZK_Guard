//! Placeholder module for `zkguard-report`.
//!
//! Replaced by JSON and Markdown emitters in Step 6 of
//! `docs/agent-workflow.md`. SARIF emission is explicitly a later
//! extension, not part of the 0.1.0 scope.

/// Marks that report emitters are not yet implemented.
pub const PLACEHOLDER: &str =
    "zkguard-report: JSON/Markdown emitters pending (see docs/roadmap.md, Step 6)";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_is_set() {
        assert!(!PLACEHOLDER.is_empty());
    }
}
