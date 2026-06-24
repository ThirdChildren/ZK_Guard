//! The rule registry: the single source of truth for "which rules exist."
//!
//! Both `zk-guard scan` and `zk-guard rules list` (Step 6 of
//! `docs/agent-workflow.md`) must agree on exactly the same set of rules, so
//! this module is the one place that constructs the list. Per CLAUDE.md
//! design principle 7, this lives in `zkguard-rules` (an analysis crate),
//! not in `zkguard-cli` — the CLI only calls [`registry`] and renders the
//! result.
//!
//! Adding a new rule (Step 7+) means adding one line to [`registry`]; no
//! other crate needs to change to pick it up.

use zkguard_core::Rule;

use crate::noir_public_001::NoirPublic001;

/// Returns every rule currently implemented, in a stable, deterministic
/// order (declaration order below). `zk-guard rules list` and `zk-guard
/// scan` both call this function so their output can never disagree about
/// which rules exist.
///
/// Boxed as `Box<dyn Rule>` per `zkguard_core::Rule`'s object-safety
/// requirement, so the registry can hold a heterogeneous collection of rule
/// types without an enum.
#[must_use]
pub fn registry() -> Vec<Box<dyn Rule>> {
    vec![Box::new(NoirPublic001)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_contains_noir_public_001() {
        let rules = registry();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].metadata().rule_id, "NOIR-PUBLIC-001");
    }

    #[test]
    fn registry_rule_ids_are_unique() {
        let rules = registry();
        let mut ids: Vec<&str> = rules
            .iter()
            .map(|r| r.metadata().rule_id.as_str())
            .collect();
        let original_len = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(
            ids.len(),
            original_len,
            "rule registry must not contain duplicate rule_id values"
        );
    }
}
