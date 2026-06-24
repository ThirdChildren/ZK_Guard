//! `zk-guard fixtures validate` command implementation.
//!
//! Per CLAUDE.md principle 8 ("Treat test fixtures as first-class security
//! examples"), this command gives developers and CI a quick way to confirm
//! that every fixture project under `fixtures/noir/{vulnerable,safe}` (or a
//! caller-given `--path`) still discovers cleanly: readable `.nr` sources,
//! no traversal errors, at least one source file per fixture directory.
//!
//! This command deliberately does **not** re-run rules against fixtures
//! and assert expected findings — that is `zkguard-rules`' own integration
//! test responsibility (see
//! `crates/zkguard-rules/tests/noir_public_001_fixtures.rs`), exercised via
//! `cargo test --workspace`, not duplicated here. `fixtures validate` is a
//! filesystem/discovery sanity check usable even by someone who has not run
//! `cargo test`, e.g. right after cloning the repo or adding a new fixture
//! directory.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::cli::FixturesValidateArgs;
use crate::exit_code;

/// Default fixtures root, relative to the current working directory.
/// Matches the workspace layout in `CLAUDE.md` (`fixtures/noir/`).
const DEFAULT_FIXTURES_ROOT: &str = "fixtures/noir";

pub fn run(args: &FixturesValidateArgs, stdout: &mut impl Write, stderr: &mut impl Write) -> i32 {
    let root = args
        .path
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_FIXTURES_ROOT));

    if !root.exists() {
        let _ = writeln!(
            stderr,
            "error: fixtures path does not exist: {}",
            root.display()
        );
        return exit_code::USAGE_ERROR;
    }

    let fixture_dirs = match collect_fixture_dirs(&root) {
        Ok(dirs) => dirs,
        Err(err) => {
            let _ = writeln!(stderr, "error: failed to read fixtures path: {err}");
            return exit_code::USAGE_ERROR;
        }
    };

    if fixture_dirs.is_empty() {
        let _ = writeln!(
            stderr,
            "error: no fixture project directories found under {}",
            root.display()
        );
        return exit_code::USAGE_ERROR;
    }

    let mut ok_count = 0usize;
    let mut failures = Vec::new();

    for dir in &fixture_dirs {
        match zkguard_noir::discover(dir) {
            Ok(project) if project.file_count() > 0 => ok_count += 1,
            Ok(_) => failures.push(format!(
                "{}: discovered zero .nr source files",
                dir.display()
            )),
            Err(err) => failures.push(format!("{}: {err}", dir.display())),
        }
    }

    let _ = writeln!(
        stdout,
        "Validated {} fixture project(s) under {}",
        fixture_dirs.len(),
        root.display()
    );
    let _ = writeln!(stdout, "  ok:     {ok_count}");
    let _ = writeln!(stdout, "  failed: {}", failures.len());

    if failures.is_empty() {
        exit_code::SUCCESS
    } else {
        for failure in &failures {
            let _ = writeln!(stderr, "error: {failure}");
        }
        exit_code::USAGE_ERROR
    }
}

/// Collects every directory two levels under `root` that looks like a
/// fixture project (contains a `Nargo.toml` or at least one `.nr` file
/// directly or in a `src/` subdirectory).
///
/// Walks exactly `root/<vulnerable-or-safe>/<fixture-name>/`, matching the
/// checked-in layout (`fixtures/noir/vulnerable/<rule-id>/`,
/// `fixtures/noir/safe/<rule-id>/`) rather than doing a generic recursive
/// search, so a stray non-fixture file under `fixtures/noir/` cannot be
/// silently treated as a fixture project.
fn collect_fixture_dirs(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut dirs = Vec::new();
    for category_entry in std::fs::read_dir(root)? {
        let category_entry = category_entry?;
        if !category_entry.file_type()?.is_dir() {
            continue;
        }
        for fixture_entry in std::fs::read_dir(category_entry.path())? {
            let fixture_entry = fixture_entry?;
            if fixture_entry.file_type()?.is_dir() {
                dirs.push(fixture_entry.path());
            }
        }
    }
    dirs.sort();
    Ok(dirs)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::fs;

    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "zkguard-cli-fixtures-test-{name}-{}-{}",
            std::process::id(),
            name.len()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn validates_well_formed_fixture_tree() {
        let root = temp_dir("well-formed");
        let vuln_dir = root.join("vulnerable/some-rule-001");
        fs::create_dir_all(&vuln_dir).expect("mkdir");
        fs::write(vuln_dir.join("Nargo.toml"), "[package]\nname=\"x\"\n").expect("write");
        fs::write(vuln_dir.join("main.nr"), "fn main() {}\n").expect("write");

        let safe_dir = root.join("safe/some-rule-001");
        fs::create_dir_all(&safe_dir).expect("mkdir");
        fs::write(safe_dir.join("Nargo.toml"), "[package]\nname=\"x\"\n").expect("write");
        fs::write(safe_dir.join("main.nr"), "fn main() {}\n").expect("write");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &FixturesValidateArgs {
                path: Some(root.clone()),
            },
            &mut out,
            &mut err,
        );

        assert_eq!(code, exit_code::SUCCESS);
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("ok:     2"));
        assert!(text.contains("failed: 0"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn flags_fixture_dir_with_no_noir_sources() {
        let root = temp_dir("empty-fixture");
        let empty_dir = root.join("vulnerable/empty-001");
        fs::create_dir_all(&empty_dir).expect("mkdir");
        // No .nr files at all.
        fs::write(empty_dir.join("README.md"), "oops").expect("write");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &FixturesValidateArgs {
                path: Some(root.clone()),
            },
            &mut out,
            &mut err,
        );

        assert_eq!(code, exit_code::USAGE_ERROR);
        let err_text = String::from_utf8(err).expect("utf8");
        assert!(err_text.contains("discovered zero"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_fixtures_path_is_usage_error() {
        let missing = std::env::temp_dir().join("zkguard-cli-fixtures-missing-xyz");
        let _ = fs::remove_dir_all(&missing);

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &FixturesValidateArgs {
                path: Some(missing),
            },
            &mut out,
            &mut err,
        );

        assert_eq!(code, exit_code::USAGE_ERROR);
        assert!(!err.is_empty());
    }

    #[test]
    fn empty_fixtures_root_is_usage_error() {
        let root = temp_dir("no-fixtures-at-all");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &FixturesValidateArgs {
                path: Some(root.clone()),
            },
            &mut out,
            &mut err,
        );

        assert_eq!(code, exit_code::USAGE_ERROR);

        let _ = fs::remove_dir_all(&root);
    }
}
