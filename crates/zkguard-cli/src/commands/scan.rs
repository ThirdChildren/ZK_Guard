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

use zkguard_core::{RuleMetadata, ScanResult};

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

    // Optional zkguard.toml lives in the project root: the scanned directory,
    // or the parent of a single scanned file.
    let config_dir = if args.path.is_dir() {
        args.path.clone()
    } else {
        args.path
            .parent()
            .map_or_else(|| std::path::PathBuf::from("."), Path::to_path_buf)
    };
    let config = match zkguard_config::load(&config_dir) {
        Ok(config) => config,
        Err(err) => {
            let _ = writeln!(stderr, "error: {err}");
            return exit_code::USAGE_ERROR;
        }
    };

    // Only run rules the config leaves enabled. `rules_meta` (registry order)
    // is also what the SARIF renderer lists as reportingDescriptors.
    let rules: Vec<_> = zkguard_rules::registry()
        .into_iter()
        .filter(|rule| config.is_rule_enabled(&rule.metadata().rule_id))
        .collect();
    let rules_meta: Vec<RuleMetadata> = rules.iter().map(|r| r.metadata().clone()).collect();

    let mut findings = Vec::new();
    for source in &project.sources {
        for rule in &rules {
            findings.extend(rule.check(source));
        }
    }

    // Partition into active vs suppressed (inline directives + config entries);
    // rule detection itself is unchanged.
    let outcome = zkguard_config::apply_suppressions(findings, &project.sources, &config);
    for warning in &outcome.warnings {
        let _ = writeln!(stderr, "warning: {warning}");
    }
    let suppressed_count = u32::try_from(outcome.suppressed.len()).unwrap_or(u32::MAX);

    let result = ScanResult {
        findings: outcome.active,
        files_scanned: u32::try_from(project.file_count()).unwrap_or(u32::MAX),
        rules_run: rules_meta.iter().map(|m| m.rule_id.clone()).collect(),
        suppressed_count,
        suppressed: if args.show_suppressed {
            outcome.suppressed
        } else {
            Vec::new()
        },
    };

    let fail_on = config.effective_fail_on(args.fail_on.map(|f| f.to_severity()));

    let rendered = match render(&result, args.format, &rules_meta) {
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

    if result.has_finding_at_or_above(fail_on) {
        exit_code::FINDINGS_PRESENT
    } else {
        exit_code::SUCCESS
    }
}

fn render(
    result: &ScanResult,
    format: OutputFormat,
    rules_meta: &[RuleMetadata],
) -> Result<String, String> {
    match format {
        OutputFormat::Human => Ok(zkguard_report::human::render(result)),
        OutputFormat::Markdown => Ok(zkguard_report::markdown::render(result)),
        OutputFormat::Json => zkguard_report::json::render(result).map_err(|err| err.to_string()),
        OutputFormat::Sarif => {
            zkguard_report::sarif::render(result, rules_meta).map_err(|err| err.to_string())
        }
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
            fail_on: None,
            show_suppressed: false,
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
    fn sarif_format_emits_parseable_log_with_rule_descriptors() {
        let root = temp_dir("sarif");
        fs::write(root.join("Nargo.toml"), "[package]\nname=\"x\"\n").expect("write");
        fs::write(
            root.join("main.nr"),
            "fn main(secret: Field, pub claimed_total: Field) {\n    let computed = secret * 2;\n}\n",
        )
        .expect("write");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&args(root.clone(), OutputFormat::Sarif), &mut out, &mut err);

        assert_eq!(code, exit_code::FINDINGS_PRESENT);
        let text = String::from_utf8(out).expect("utf8");
        let v: serde_json::Value = serde_json::from_str(&text).expect("valid sarif json");
        assert_eq!(v["version"], "2.1.0");
        // Every registered rule is present as a reportingDescriptor.
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .expect("rules array")
                .len(),
            zkguard_rules::registry().len()
        );
        assert_eq!(v["runs"][0]["results"][0]["ruleId"], "NOIR-PUBLIC-001");

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
        scan_args.fail_on = Some(FailThreshold::Critical);

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

    /// Writes a vulnerable project (one NOIR-PUBLIC-001 finding) with an
    /// optional `main.nr` body override and optional `zkguard.toml`.
    fn vulnerable_project(name: &str, main_nr: &str, config: Option<&str>) -> std::path::PathBuf {
        let root = temp_dir(name);
        fs::write(root.join("Nargo.toml"), "[package]\nname=\"x\"\n").expect("write");
        fs::write(root.join("main.nr"), main_nr).expect("write");
        if let Some(cfg) = config {
            fs::write(root.join("zkguard.toml"), cfg).expect("write");
        }
        root
    }

    const VULN_MAIN: &str =
        "fn main(secret: Field, pub claimed_total: Field) {\n    let computed = secret * 2;\n}\n";

    #[test]
    fn config_disabling_rule_removes_its_findings() {
        let root = vulnerable_project(
            "cfg-disable",
            VULN_MAIN,
            Some("[rules]\n\"NOIR-PUBLIC-001\" = false\n"),
        );

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&args(root.clone(), OutputFormat::Json), &mut out, &mut err);

        assert_eq!(
            code,
            exit_code::SUCCESS,
            "disabled rule can't fail the scan"
        );
        let parsed: ScanResult =
            serde_json::from_str(&String::from_utf8(out).expect("utf8")).expect("json");
        assert!(parsed.findings.is_empty());
        assert!(
            !parsed.rules_run.contains(&"NOIR-PUBLIC-001".to_string()),
            "disabled rule must not appear in rules_run"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn inline_directive_suppresses_finding() {
        let main_nr = "fn main(secret: Field, pub claimed_total: Field) { // zkguard:ignore NOIR-PUBLIC-001 reason=\"informational only\"\n    let computed = secret * 2;\n}\n";
        let root = vulnerable_project("inline-suppress", main_nr, None);

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&args(root.clone(), OutputFormat::Json), &mut out, &mut err);

        assert_eq!(code, exit_code::SUCCESS, "only finding was suppressed");
        let parsed: ScanResult =
            serde_json::from_str(&String::from_utf8(out).expect("utf8")).expect("json");
        assert!(parsed.findings.is_empty());
        assert_eq!(parsed.suppressed_count, 1);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn file_suppression_and_show_suppressed_lists_it() {
        let root = vulnerable_project(
            "file-suppress",
            VULN_MAIN,
            Some(
                "[[suppress]]\nrule = \"NOIR-PUBLIC-001\"\npath = \"main.nr\"\nreason = \"documented exception\"\n",
            ),
        );

        let mut scan_args = args(root.clone(), OutputFormat::Human);
        scan_args.show_suppressed = true;

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&scan_args, &mut out, &mut err);

        assert_eq!(code, exit_code::SUCCESS);
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("suppressed: 1"));
        assert!(text.contains("Suppressed findings:"));
        assert!(text.contains("documented exception"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cli_fail_on_overrides_config_fail_on() {
        // config says only `critical` fails; the finding is `high`.
        let root = vulnerable_project(
            "fail-on-precedence",
            VULN_MAIN,
            Some("fail_on = \"critical\"\n"),
        );

        // No CLI flag: config wins -> high finding does not fail.
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&args(root.clone(), OutputFormat::Human), &mut out, &mut err);
        assert_eq!(code, exit_code::SUCCESS, "config fail_on=critical applies");

        // CLI --fail-on high overrides config -> high finding fails.
        let mut scan_args = args(root.clone(), OutputFormat::Human);
        scan_args.fail_on = Some(FailThreshold::High);
        let mut out2 = Vec::new();
        let mut err2 = Vec::new();
        let code2 = run(&scan_args, &mut out2, &mut err2);
        assert_eq!(code2, exit_code::FINDINGS_PRESENT, "CLI fail_on wins");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn invalid_config_is_a_usage_error() {
        let root = vulnerable_project(
            "bad-config",
            VULN_MAIN,
            Some("[[suppress]]\nrule = \"X\"\npath = \"main.nr\"\nreason = \"\"\n"),
        );

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&args(root.clone(), OutputFormat::Human), &mut out, &mut err);

        assert_eq!(code, exit_code::USAGE_ERROR);
        assert!(String::from_utf8(err).expect("utf8").contains("reason"));

        let _ = fs::remove_dir_all(&root);
    }
}
