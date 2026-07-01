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

use zkguard_core::{ProjectRule, Rule};

use crate::noir_constraint_001::NoirConstraint001;
use crate::noir_public_001::NoirPublic001;
use crate::noir_range_001::NoirRange001;
use crate::zk_hash_001::ZkHash001;
use crate::zk_nullifier_001::ZkNullifier001;
use crate::zk_test_001::ZkTest001;

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
    vec![
        Box::new(NoirPublic001),
        Box::new(NoirConstraint001),
        Box::new(NoirRange001),
        Box::new(ZkHash001),
        Box::new(ZkNullifier001),
    ]
}

/// Returns every **project-level** rule (see [`zkguard_core::ProjectRule`]),
/// in a stable order. These run once over all discovered sources, separately
/// from the per-file [`registry`] loop, but share the same metadata surface
/// (`rules list`, SARIF descriptors, `rules_run`).
#[must_use]
pub fn project_registry() -> Vec<Box<dyn ProjectRule>> {
    vec![Box::new(ZkTest001)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_contains_noir_public_001() {
        let rules = registry();
        assert!(rules
            .iter()
            .any(|r| r.metadata().rule_id == "NOIR-PUBLIC-001"));
    }

    #[test]
    fn registry_contains_noir_constraint_001() {
        let rules = registry();
        assert!(rules
            .iter()
            .any(|r| r.metadata().rule_id == "NOIR-CONSTRAINT-001"));
    }

    #[test]
    fn registry_contains_noir_range_001() {
        let rules = registry();
        assert!(rules
            .iter()
            .any(|r| r.metadata().rule_id == "NOIR-RANGE-001"));
    }

    #[test]
    fn registry_contains_zk_hash_001() {
        let rules = registry();
        assert!(rules.iter().any(|r| r.metadata().rule_id == "ZK-HASH-001"));
    }

    #[test]
    fn registry_contains_zk_nullifier_001() {
        let rules = registry();
        assert!(rules
            .iter()
            .any(|r| r.metadata().rule_id == "ZK-NULLIFIER-001"));
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

    #[test]
    fn project_registry_contains_zk_test_001() {
        let rules = project_registry();
        assert!(rules.iter().any(|r| r.metadata().rule_id == "ZK-TEST-001"));
    }

    #[test]
    fn per_file_and_project_rule_ids_do_not_overlap() {
        let file_ids: Vec<String> = registry()
            .iter()
            .map(|r| r.metadata().rule_id.clone())
            .collect();
        for project_rule in project_registry() {
            assert!(
                !file_ids.contains(&project_rule.metadata().rule_id),
                "a rule_id must be either per-file or project-level, not both"
            );
        }
    }
}
