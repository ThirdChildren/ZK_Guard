//! `ZK-TEST-001` — circuit has an entry point but no negative test.
//!
//! Spec source: `docs/rule-taxonomy.md`, section "ZK-TEST-001". Unlike the
//! five per-file rules, this is a **project-level** check ([`ProjectRule`]):
//! the entry point (`fn main`) and its tests may live in different `.nr`
//! files, so the rule must see the whole source set before deciding.
//!
//! It never runs `nargo` or executes anything — it is a pure text/attribute
//! presence check over the discovered `.nr` sources.
//!
//! ## Detection
//!
//! 1. The project must declare an entry point (`fn main`). Libraries with no
//!    `fn main` are never flagged (there is no circuit to test).
//! 2. Collect every `#[test]`-annotated function.
//! 3. A test is a **negative test** if either:
//!    - its attribute uses Noir's `should_fail` / `should_fail_with` form, or
//!    - its function name contains one of `fail`, `invalid`, `reject`,
//!      `negative`, `should_fail` (case-insensitive).
//! 4. If the project has a `fn main` but **zero** negative tests (whether it
//!    has no tests at all, or only happy-path tests), emit one finding
//!    anchored at the entry-point file, line 1.
//!
//! ## False positives (documented, not bugs)
//!
//! - A project that exercises failing witnesses through an **external
//!   harness** (e.g. a Rust integration test driving `nargo`), outside
//!   Noir's in-tree `#[test]` mechanism, is flagged even though it does test
//!   rejection paths. This rule only inspects `.nr` test attributes/names.
//! - A genuine negative test whose name lacks the keywords **and** whose
//!   attribute lacks `should_fail` (e.g. `#[test] fn rejects_bad()` renamed
//!   to `fn case_7()`) will not be recognized, so the project may be flagged
//!   despite having one. Prefer the `#[test(should_fail)]` attribute.
//! - `fn main` appearing only inside a comment or string still counts as an
//!   entry point (the scan is textual, not a parsed AST).
//! - A multi-circuit project is judged in aggregate: one negative test
//!   anywhere clears the whole project, even for an untested second entry
//!   point.
//!
//! Because detection mixes a reliable attribute check with a heuristic
//! name check and a coarse `fn main` gate, the default confidence is
//! `medium` (the taxonomy's original attribute-only design was `high`; the
//! broader name-based match trades some precision for recall).

use zkguard_core::{Confidence, Finding, ProjectRule, RuleMetadata, Severity, SourceView};

/// Default severity per `docs/rule-taxonomy.md` ZK-TEST-001: `low`.
const DEFAULT_SEVERITY: Severity = Severity::Low;
/// Default confidence: `medium` (see module docs). Do not change without
/// updating the taxonomy.
const DEFAULT_CONFIDENCE: Confidence = Confidence::Medium;

const RULE_ID: &str = "ZK-TEST-001";
const TITLE: &str = "Circuit has an entry point but no negative test";

/// Name substrings that mark a `#[test]` function as a negative test.
const NEGATIVE_NAME_MARKERS: [&str; 5] = ["should_fail", "fail", "invalid", "reject", "negative"];

/// Builds this rule's static metadata.
#[must_use]
pub fn metadata() -> RuleMetadata {
    RuleMetadata::new(
        RULE_ID,
        TITLE,
        DEFAULT_SEVERITY,
        DEFAULT_CONFIDENCE,
        "Project-level: flags a Noir project that declares `fn main` but has no \
         negative test: no `#[test(should_fail)]`/`should_fail_with` attribute and no \
         `#[test]` whose name contains fail/invalid/reject/negative/should_fail. Never \
         runs nargo; a purely textual check over discovered `.nr` sources.",
    )
}

/// `ProjectRule` implementation for `ZK-TEST-001`.
#[derive(Debug, Default, Clone, Copy)]
pub struct ZkTest001;

impl ProjectRule for ZkTest001 {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: std::sync::OnceLock<RuleMetadata> = std::sync::OnceLock::new();
        METADATA.get_or_init(metadata)
    }

    fn check_project(&self, sources: &[SourceView]) -> Vec<Finding> {
        check_sources(sources)
    }
}

/// Core detection, exposed as a free function for direct unit testing.
#[must_use]
pub fn check_sources(sources: &[SourceView]) -> Vec<Finding> {
    // Anchor at the first source that declares an entry point; if none does,
    // there is no circuit and nothing to flag.
    let Some(entry_point) = sources.iter().find(|s| declares_main(&s.source)) else {
        return Vec::new();
    };

    let mut test_count = 0usize;
    let mut negative_count = 0usize;
    for source in sources {
        for test in tests_in(&source.source) {
            test_count += 1;
            if test.is_negative {
                negative_count += 1;
            }
        }
    }

    if negative_count > 0 {
        return Vec::new();
    }

    let evidence = if test_count == 0 {
        "project declares `fn main` but has no `#[test]` functions at all".to_string()
    } else {
        format!(
            "project declares `fn main` and has {test_count} `#[test]` function(s), \
             but none are negative tests (no `should_fail`/`should_fail_with` and no \
             fail/invalid/reject/negative name)"
        )
    };

    vec![Finding::new(
        RULE_ID,
        TITLE,
        DEFAULT_SEVERITY,
        DEFAULT_CONFIDENCE,
        entry_point.path.clone(),
    )
    .with_line(1)
    .with_evidence(evidence)
    .with_why_it_matters(
        "A circuit with only happy-path tests (or none) can silently accept malformed or \
         malicious witnesses, because nothing in the test suite ever exercises the rejection \
         path the circuit is meant to enforce.",
    )
    .with_remediation(
        "Add at least one `#[test(should_fail)]` (or `should_fail_with = \"...\"`) test that \
         feeds the circuit a witness it must reject, alongside the happy-path tests. If \
         failing-witness coverage lives in an external harness outside Noir's `#[test]` \
         mechanism, document that next to the entry point and treat this finding as a known \
         exception.",
    )]
}

/// Returns the code portion of a line, dropping any `//` line comment so that
/// commented-out code or prose mentioning `#[test]`/`fn main` is not parsed as
/// real source. (A `//` inside a string literal is treated as a comment too;
/// acceptable for this shape-level heuristic.)
fn code_of(line: &str) -> &str {
    line.split_once("//").map_or(line, |(code, _)| code)
}

/// Whether a line of source declares the `fn main` entry point (ignoring
/// `fn main_helper` etc. and commented-out code).
fn declares_main(source: &str) -> bool {
    source.lines().any(|line| {
        let code = code_of(line);
        let Some(pos) = code.find("fn main") else {
            return false;
        };
        // Reject `fn main_x`: the char after "main" must end the identifier.
        let after = code[pos + "fn main".len()..].chars().next();
        matches!(after, None | Some('(') | Some(' ') | Some('\t'))
    })
}

struct NoirTest {
    is_negative: bool,
}

/// Finds `#[test]`-annotated functions in one source and classifies each as
/// negative or not.
fn tests_in(source: &str) -> Vec<NoirTest> {
    // Strip comments up front so prose or commented-out code mentioning
    // `#[test(should_fail)]` is never counted as a real test.
    let lines: Vec<&str> = source.lines().map(code_of).collect();
    let mut tests = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let Some(attr_pos) = line.find("#[test") else {
            continue;
        };
        let attr = &line[attr_pos..];
        let mut is_negative = attr.contains("should_fail");
        if let Some(name) = fn_name_near(&lines, i) {
            let lower = name.to_lowercase();
            if NEGATIVE_NAME_MARKERS
                .iter()
                .any(|marker| lower.contains(marker))
            {
                is_negative = true;
            }
        }
        tests.push(NoirTest { is_negative });
    }
    tests
}

/// Extracts the function name from the first `fn <name>` at or shortly after
/// `start` (attributes may sit a few lines above the `fn`).
fn fn_name_near(lines: &[&str], start: usize) -> Option<String> {
    for line in lines.iter().skip(start).take(5) {
        if let Some(pos) = line.find("fn ") {
            let name: String = line[pos + 3..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(path: &str, body: &str) -> SourceView {
        SourceView::new(path, body)
    }

    #[test]
    fn no_entry_point_never_flags() {
        let sources = [src("lib.nr", "fn helper() {}\n#[test]\nfn t() {}\n")];
        assert!(check_sources(&sources).is_empty());
    }

    #[test]
    fn main_with_no_tests_is_flagged() {
        let sources = [src(
            "main.nr",
            "fn main(x: Field) {\n    assert(x == x);\n}\n",
        )];
        let findings = check_sources(&sources);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "ZK-TEST-001");
        assert_eq!(findings[0].line, Some(1));
        assert_eq!(findings[0].file.to_string_lossy(), "main.nr");
        assert!(findings[0].evidence.contains("no `#[test]` functions"));
    }

    #[test]
    fn main_with_only_happy_path_tests_is_flagged() {
        let sources = [src(
            "main.nr",
            "fn main(x: Field) { assert(x == x); }\n#[test]\nfn test_valid() {\n    let _ = main(1);\n}\n",
        )];
        let findings = check_sources(&sources);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("none are negative"));
    }

    #[test]
    fn should_fail_attribute_clears_the_project() {
        let sources = [src(
            "main.nr",
            "fn main(x: Field) { assert(x == x); }\n#[test(should_fail)]\nfn t_reject() {}\n",
        )];
        assert!(check_sources(&sources).is_empty());
    }

    #[test]
    fn negative_name_clears_the_project() {
        let sources = [src(
            "main.nr",
            "fn main(x: Field) { assert(x == x); }\n#[test]\nfn test_invalid_witness() {}\n",
        )];
        assert!(check_sources(&sources).is_empty());
    }

    #[test]
    fn negative_test_in_a_separate_file_clears_the_project() {
        let sources = [
            src("main.nr", "fn main(x: Field) { assert(x == x); }\n"),
            src("tests.nr", "#[test(should_fail)]\nfn rejects_bad() {}\n"),
        ];
        assert!(check_sources(&sources).is_empty());
    }

    #[test]
    fn fn_main_helper_does_not_count_as_entry_point() {
        let sources = [src("lib.nr", "fn main_helper() {}\n#[test]\nfn t() {}\n")];
        assert!(check_sources(&sources).is_empty());
    }

    #[test]
    fn commented_entry_point_is_ignored() {
        let sources = [src("main.nr", "// fn main(x: Field) {}\nfn other() {}\n")];
        assert!(check_sources(&sources).is_empty());
    }
}
