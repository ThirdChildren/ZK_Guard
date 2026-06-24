//! Placeholder module for `zkguard-rules`.
//!
//! Replaced by the rule registry and the MVP rule implementations
//! (NOIR-PUBLIC-001, NOIR-CONSTRAINT-001, NOIR-RANGE-001, ZK-NULLIFIER-001,
//! ZK-REPLAY-001, ZK-HASH-001, ZK-TEST-001) in Steps 4 and 7 of
//! `docs/agent-workflow.md`. See `docs/rule-taxonomy.md` (Step 2) for rule
//! definitions once it exists.

/// Marks that the rule registry and rule implementations are not yet
/// implemented.
pub const PLACEHOLDER: &str =
    "zkguard-rules: rule registry and MVP rules pending (see docs/roadmap.md, Steps 4 and 7)";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_is_set() {
        assert!(!PLACEHOLDER.is_empty());
    }
}
