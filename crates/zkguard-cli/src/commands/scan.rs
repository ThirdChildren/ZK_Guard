//! `zk-guard scan` command implementation.
//!
//! Wiring only: this module discovers Noir sources via `zkguard_noir`, runs
//! every registered rule via `zkguard_rules::registry`, aggregates results
//! into a `zkguard_core::ScanResult`, renders via `zkguard_report`, and
//! decides an exit code. No discovery, parsing, or rule logic lives here —
//! per CLAUDE.md design principle 7, this function only calls into the
//! other crates and never reimplements what they already do.

use std::fs;
use std::io::Write;
use std::path::Path;

use zkguard_core::ScanResult;

use crate::cli::{OutputFormat, ScanArgs};
use crate::exit_code;

/// Runs `zk-guard scan` and returns the process exit code.
///
/// `stdout`/`stderr` are taken as generic writers (rather than calling
/// `println!`/`eprintln!` directly) so this function is testable without
/// spawning a process — see `crates/zkguard-cli/tests/cli.rs` for the
/// black-box binary tests that exercise this end-to-end, and unit tests
/// below for direct calls.
pub fn run(args: &ScanArgs, stdout: &mut impl Write, stderr: &mut impl Write) -> i32 {
    if !args.path.exists() {
        let _ = writeln!(
            stderr,
            "error: scan path does not exist: {}",
            args.path.display()
        );
        return exit_code::USAGE_ERROR;
    }

    let project = match zkguard_noir::discover(&args.path) {
        Ok(project) => project,
        Err(zkguard_noir::DiscoveryError::RootNotFound(path)) => {
            let _ = writeln!(
                stderr,
                "error: scan path does not exist: {}",
                path.display()
            );
            return exit_code::USAGE_ERROR;
        }
        Err(err @ zkguard_noir::DiscoveryError::Io { .. }) => {
            let _ = writeln!(stderr, "error: could not read scan path: {err}");
            return exit_code::USAGE_ERROR;
        }
    };

    let rules = zkguard_rules::registry();
    let mut findings = Vec::new();
    for source in &project.sources {
        for rule in &rules {
            findings.extend(rule.check(source));
        }
    }

    let result = ScanResult {
        findings,
        files_scanned: u32::try_from(project.file_count()).unwrap_or(u32::MAX),
        rules_run: rules
            .iter()
            .map(|rule| rule.metadata().rule_id.clone())
            .collect(),
    };

    let rendered = match render(&result, args.format) {
        Ok(text) => text,
        Err(message) => {
            let _ = writeln!(stderr, "error: failed to render report: {message}");
            return exit_code::INTERNAL_ERROR;
        }
    };

    if let Some(output_path) = &args.output {
        if args.format == OutputFormat::Human {
            let _ = writeln!(
                stderr,
                "warning: --output is ignored for --format human; writing to stdout"
            );
            let _ = write!(stdout, "{rendered}");
        } else if let Err(err) = write_to_file(output_path, &rendered) {
            let _ = writeln!(
                stderr,
                "error: failed to write report to {}: {err}",
                output_path.display()
            );
            return exit_code::INTERNAL_ERROR;
        }
    } else {
        let _ = write!(stdout, "{rendered}");
    }

    if result.has_finding_at_or_above(args.fail_on.to_severity()) {
        exit_code::FINDINGS_PRESENT
    } else {
        exit_code::SUCCESS
    }
}

fn render(result: &ScanResult, format: OutputFormat) -> Result<String, String> {
    match format {
        OutputFormat::Human => Ok(zkguard_report::human::render(result)),
        OutputFormat::Markdown => Ok(zkguard_report::markdown::render(result)),
        OutputFormat::Json => zkguard_report::json::render(result).map_err(|err| err.to_string()),
    }
}

fn write_to_file(path: &Path, contents: &str) -> std::io::Result<()> {
    fs::write(path, contents)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::fs;

    use super::*;
    use crate::cli::FailThreshold;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "zkguard-cli-scan-test-{name}-{}-{}",
            std::process::id(),
            name.len()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn args(path: std::path::PathBuf, format: OutputFormat) -> ScanArgs {
        ScanArgs {
            path,
            format,
            output: None,
            fail_on: FailThreshold::Low,
        }
    }

    #[test]
    fn missing_path_returns_usage_error() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let missing = std::env::temp_dir().join("zkguard-cli-scan-definitely-missing-xyz");
        let _ = fs::remove_dir_all(&missing);

        let code = run(&args(missing, OutputFormat::Human), &mut out, &mut err);

        assert_eq!(code, exit_code::USAGE_ERROR);
        assert!(!err.is_empty());
    }

    #[test]
    fn vulnerable_fixture_yields_findings_present_exit_code() {
        let root = temp_dir("vulnerable");
        fs::write(root.join("Nargo.toml"), "[package]\nname=\"x\"\n").expect("write");
        fs::write(
            root.join("main.nr"),
            "fn main(secret: Field, pub claimed_total: Field) {\n    let computed = secret * 2;\n}\n",
        )
        .expect("write");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&args(root.clone(), OutputFormat::Human), &mut out, &mut err);

        assert_eq!(code, exit_code::FINDINGS_PRESENT);
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("NOIR-PUBLIC-001"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_fixture_yields_success_exit_code() {
        let root = temp_dir("safe");
        fs::write(root.join("Nargo.toml"), "[package]\nname=\"x\"\n").expect("write");
        fs::write(
            root.join("main.nr"),
            "fn main(secret: Field, pub claimed_total: Field) {\n    let computed = secret * 2;\n    assert(computed == claimed_total);\n}\n",
        )
        .expect("write");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&args(root.clone(), OutputFormat::Human), &mut out, &mut err);

        assert_eq!(code, exit_code::SUCCESS);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn json_format_emits_parseable_scan_result() {
        let root = temp_dir("json");
        fs::write(root.join("Nargo.toml"), "[package]\nname=\"x\"\n").expect("write");
        fs::write(
            root.join("main.nr"),
            "fn main(secret: Field, pub claimed_total: Field) {\n    let computed = secret * 2;\n}\n",
        )
        .expect("write");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&args(root.clone(), OutputFormat::Json), &mut out, &mut err);

        assert_eq!(code, exit_code::FINDINGS_PRESENT);
        let text = String::from_utf8(out).expect("utf8");
        let parsed: ScanResult = serde_json::from_str(&text).expect("valid json");
        assert_eq!(parsed.findings[0].rule_id, "NOIR-PUBLIC-001");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn markdown_format_with_output_writes_file() {
        let root = temp_dir("markdown-output");
        fs::write(root.join("Nargo.toml"), "[package]\nname=\"x\"\n").expect("write");
        fs::write(
            root.join("main.nr"),
            "fn main(secret: Field, pub claimed_total: Field) {\n    let computed = secret * 2;\n}\n",
        )
        .expect("write");
        let report_path = root.join("report.md");

        let mut scan_args = args(root.clone(), OutputFormat::Markdown);
        scan_args.output = Some(report_path.clone());

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&scan_args, &mut out, &mut err);

        assert_eq!(code, exit_code::FINDINGS_PRESENT);
        assert!(
            out.is_empty(),
            "markdown with --output must not print to stdout"
        );
        let contents = fs::read_to_string(&report_path).expect("report written");
        assert!(contents.contains("NOIR-PUBLIC-001"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn fail_on_threshold_above_finding_severity_yields_success() {
        let root = temp_dir("fail-on-threshold");
        fs::write(root.join("Nargo.toml"), "[package]\nname=\"x\"\n").expect("write");
        fs::write(
            root.join("main.nr"),
            "fn main(secret: Field, pub claimed_total: Field) {\n    let computed = secret * 2;\n}\n",
        )
        .expect("write");

        // NOIR-PUBLIC-001 defaults to `high`; requiring `critical` to fail
        // the scan means this finding (still reported) does not flip the
        // exit code.
        let mut scan_args = args(root.clone(), OutputFormat::Human);
        scan_args.fail_on = FailThreshold::Critical;

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&scan_args, &mut out, &mut err);

        assert_eq!(code, exit_code::SUCCESS);
        let text = String::from_utf8(out).expect("utf8");
        assert!(
            text.contains("NOIR-PUBLIC-001"),
            "finding below threshold must still be reported"
        );

        let _ = fs::remove_dir_all(&root);
    }
}
