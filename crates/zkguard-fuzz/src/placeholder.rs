//! Placeholder module for `zkguard-fuzz`.
//!
//! Replaced by deterministic property-based / mutation harnesses in Step 9
//! of `docs/agent-workflow.md`, only after static rules (Steps 4, 7) and
//! CLI/reporting (Step 6) are stable.

/// Marks that fuzzing/mutation harnesses are not yet implemented.
pub const PLACEHOLDER: &str =
    "zkguard-fuzz: fuzzing/mutation harnesses pending (see docs/roadmap.md, Step 9)";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_is_set() {
        assert!(!PLACEHOLDER.is_empty());
    }
}
