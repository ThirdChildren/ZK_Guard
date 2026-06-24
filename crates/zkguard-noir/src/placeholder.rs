//! Placeholder module for `zkguard-noir`.
//!
//! Replaced by project discovery and Noir source analysis in Step 4 of
//! `docs/agent-workflow.md` (NOIR-PUBLIC-001 first, then the remaining
//! NOIR-* / ZK-* rule families in Step 7).

/// Marks that Noir project discovery and parsing are not yet implemented.
pub const PLACEHOLDER: &str =
    "zkguard-noir: project discovery and source analysis pending (see docs/roadmap.md, Step 4)";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_is_set() {
        assert!(!PLACEHOLDER.is_empty());
    }
}
