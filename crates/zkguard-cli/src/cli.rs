//! Argument parsing for the `zk-guard` binary, using `clap`'s derive API.
//!
//! This module defines *shape* only (which commands/flags exist, their
//! help text, their types). It contains no scanning, discovery, or
//! reporting logic — see `crates/zkguard-cli/src/main.rs` for the dispatch
//! that wires parsed arguments into `zkguard-noir` / `zkguard-rules` /
//! `zkguard-report`, per CLAUDE.md design principle 7 ("Keep the core
//! analysis engine independent from the CLI" — the inverse also holds here:
//! the CLI's argument layer stays independent of analysis logic).

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

/// `zk-guard`: a best-effort static security scanner for Noir
/// zero-knowledge circuits.
///
/// This is developer tooling, not a formal verifier: findings describe
/// suspicious source patterns, not proof of exploitability. See
/// `docs/rule-taxonomy.md` for the detection strategy and known
/// false-positive classes behind every rule.
#[derive(Debug, Parser)]
#[command(name = "zk-guard", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan a Noir project (or a single `.nr` file) for known bug patterns.
    Scan(ScanArgs),
    /// Inspect the rule registry.
    #[command(subcommand)]
    Rules(RulesCommand),
    /// Validate the checked-in fixture tree (or a given fixtures path).
    #[command(subcommand)]
    Fixtures(FixturesCommand),
}

#[derive(Debug, clap::Args)]
pub struct ScanArgs {
    /// Path to a Noir project directory (containing `Nargo.toml`/`src/`) or
    /// a single `.nr` file.
    pub path: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,

    /// Write the report to this file instead of stdout. Ignored (with a
    /// warning) for `--format human`, which is always printed to stdout.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Minimum severity that causes a nonzero exit code. Findings below
    /// this threshold are still reported, they just don't fail the scan.
    /// Overrides `fail_on` in `zkguard.toml`; when neither is set, defaults
    /// to `low` (any finding fails).
    #[arg(long, value_enum)]
    pub fail_on: Option<FailThreshold>,

    /// Also list findings that were suppressed (by an inline
    /// `// zkguard:ignore` directive or a `zkguard.toml` `[[suppress]]`
    /// entry). The suppressed *count* is always reported regardless.
    #[arg(long)]
    pub show_suppressed: bool,
}

#[derive(Debug, Subcommand)]
pub enum RulesCommand {
    /// List every rule in the registry.
    List(RulesListArgs),
}

#[derive(Debug, clap::Args)]
pub struct RulesListArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
}

#[derive(Debug, Subcommand)]
pub enum FixturesCommand {
    /// Validate that every fixture project under the fixtures tree
    /// discovers cleanly (readable `.nr` sources, no traversal errors).
    Validate(FixturesValidateArgs),
}

#[derive(Debug, clap::Args)]
pub struct FixturesValidateArgs {
    /// Root directory containing fixture projects. Defaults to the
    /// workspace's checked-in `fixtures/noir` tree.
    #[arg(long)]
    pub path: Option<PathBuf>,
}

/// Output format shared by `scan` and `rules list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Plain-text terminal output (default).
    Human,
    /// Machine-readable JSON.
    Json,
    /// GitHub-flavored Markdown.
    Markdown,
    /// SARIF 2.1.0 log for GitHub code scanning / CI upload. Supported by
    /// `scan` only (it encodes scan results, not the rule registry).
    Sarif,
}

/// Minimum severity that causes `zk-guard scan` to exit nonzero.
///
/// Named distinctly from `zkguard_core::Severity` (rather than reusing it
/// directly as the clap value enum) so CLI-facing argument parsing stays
/// decoupled from the core domain type; conversion happens once at the
/// dispatch boundary in `main.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailThreshold {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl FailThreshold {
    /// Converts to the corresponding `zkguard_core::Severity`.
    #[must_use]
    pub fn to_severity(self) -> zkguard_core::Severity {
        match self {
            FailThreshold::Critical => zkguard_core::Severity::Critical,
            FailThreshold::High => zkguard_core::Severity::High,
            FailThreshold::Medium => zkguard_core::Severity::Medium,
            FailThreshold::Low => zkguard_core::Severity::Low,
            FailThreshold::Info => zkguard_core::Severity::Info,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scan_with_defaults() {
        let cli = Cli::parse_from(["zk-guard", "scan", "./project"]);
        match cli.command {
            Command::Scan(args) => {
                assert_eq!(args.path, PathBuf::from("./project"));
                assert_eq!(args.format, OutputFormat::Human);
                assert_eq!(args.output, None);
            }
            other => panic!("expected Scan, got {other:?}"),
        }
    }

    #[test]
    fn parses_scan_with_format_and_output() {
        let cli = Cli::parse_from([
            "zk-guard",
            "scan",
            "./project",
            "--format",
            "markdown",
            "--output",
            "report.md",
        ]);
        match cli.command {
            Command::Scan(args) => {
                assert_eq!(args.format, OutputFormat::Markdown);
                assert_eq!(args.output, Some(PathBuf::from("report.md")));
            }
            other => panic!("expected Scan, got {other:?}"),
        }
    }

    #[test]
    fn parses_rules_list() {
        let cli = Cli::parse_from(["zk-guard", "rules", "list"]);
        match cli.command {
            Command::Rules(RulesCommand::List(args)) => {
                assert_eq!(args.format, OutputFormat::Human);
            }
            other => panic!("expected Rules(List), got {other:?}"),
        }
    }

    #[test]
    fn parses_fixtures_validate_with_optional_path() {
        let cli = Cli::parse_from(["zk-guard", "fixtures", "validate"]);
        match cli.command {
            Command::Fixtures(FixturesCommand::Validate(args)) => {
                assert_eq!(args.path, None);
            }
            other => panic!("expected Fixtures(Validate), got {other:?}"),
        }
    }

    #[test]
    fn parses_scan_with_sarif_format() {
        let cli = Cli::parse_from(["zk-guard", "scan", "./project", "--format", "sarif"]);
        match cli.command {
            Command::Scan(args) => assert_eq!(args.format, OutputFormat::Sarif),
            other => panic!("expected Scan, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_format_value() {
        let result = Cli::try_parse_from(["zk-guard", "scan", "./project", "--format", "xml"]);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_missing_scan_path() {
        let result = Cli::try_parse_from(["zk-guard", "scan"]);
        assert!(result.is_err());
    }
}
