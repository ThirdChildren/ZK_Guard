//! `zkguard-config`: optional `zkguard.toml` configuration and finding
//! suppression for zk-guard.
//!
//! This crate is orchestration *policy*, kept out of the analysis crates
//! (`zkguard-rules`, `zkguard-noir`) so it can never change rule semantics:
//! a rule still runs and still detects exactly what it did before. Config
//! only decides, after the fact, **which rules run** (enable/disable), **what
//! severity fails the scan** (`fail_on`), and **which findings are
//! suppressed** (hidden from the active result set, with a required reason).
//!
//! Two suppression sources are supported:
//!
//! - **Inline**: a `// zkguard:ignore RULE_ID reason="..."` comment in the
//!   scanned source, matching a finding of `RULE_ID` on that line or the line
//!   immediately below it.
//! - **Config file**: a `[[suppress]]` entry in `zkguard.toml` (rule + path,
//!   optional line, required reason).
//!
//! Every suppression requires a non-empty `reason`: an inline directive
//! without one is ignored (and warned about), and a `[[suppress]]` entry
//! without one is a load error. See `docs/configuration.md`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use zkguard_core::{Finding, Severity, SourceView, SuppressedFinding, SuppressionKind};

/// The config file name looked up in the scanned project's root directory.
pub const CONFIG_FILE_NAME: &str = "zkguard.toml";

const INLINE_MARKER: &str = "zkguard:ignore";

/// Parsed `zkguard.toml` (or an all-default config when no file is present).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Minimum severity that fails the scan. The CLI `--fail-on` flag, when
    /// given, takes precedence over this (see [`Config::effective_fail_on`]).
    #[serde(default)]
    fail_on: Option<Severity>,
    /// Per-rule enable/disable, keyed by `rule_id`. A rule absent from this
    /// map is enabled; `RULE-ID = false` disables it.
    #[serde(default)]
    rules: HashMap<String, bool>,
    /// File-based suppressions (`[[suppress]]` entries).
    #[serde(default)]
    suppress: Vec<FileSuppression>,
}

/// One `[[suppress]]` entry: hide findings of `rule` in `path` (optionally
/// only on `line`), with a required human `reason`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSuppression {
    /// The `rule_id` to suppress, e.g. `"NOIR-PUBLIC-001"`.
    pub rule: String,
    /// The reported file path to suppress in (matched after normalizing to
    /// forward slashes and stripping a leading `./`).
    pub path: String,
    /// If set, only suppress a finding on exactly this 1-based line.
    #[serde(default)]
    pub line: Option<u32>,
    /// Required, non-empty explanation. Enforced by [`load`].
    pub reason: String,
}

/// Errors from loading/validating `zkguard.toml`.
#[derive(Debug)]
pub enum ConfigError {
    /// The config file exists but could not be read.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The config file could not be parsed as TOML into [`Config`].
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    /// A `[[suppress]]` entry had an empty/whitespace-only `reason`.
    EmptySuppressReason { index: usize },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io { path, source } => {
                write!(f, "could not read {}: {source}", path.display())
            }
            ConfigError::Parse { path, source } => {
                write!(f, "could not parse {}: {source}", path.display())
            }
            ConfigError::EmptySuppressReason { index } => write!(
                f,
                "zkguard.toml: [[suppress]] entry #{} has an empty reason; \
                 every suppression must state a non-empty reason",
                index + 1
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Loads `zkguard.toml` from `dir`, or returns an all-default config when the
/// file is absent (config is optional).
///
/// # Errors
///
/// Returns [`ConfigError`] if the file exists but cannot be read/parsed, or
/// if any suppression is missing a reason.
pub fn load(dir: &Path) -> Result<Config, ConfigError> {
    let path = dir.join(CONFIG_FILE_NAME);
    if !path.exists() {
        return Ok(Config::default());
    }
    let text = std::fs::read_to_string(&path).map_err(|source| ConfigError::Io {
        path: path.clone(),
        source,
    })?;
    let config: Config = toml::from_str(&text).map_err(|source| ConfigError::Parse {
        path: path.clone(),
        source,
    })?;
    config.validate()?;
    Ok(config)
}

impl Config {
    fn validate(&self) -> Result<(), ConfigError> {
        for (index, entry) in self.suppress.iter().enumerate() {
            if entry.reason.trim().is_empty() {
                return Err(ConfigError::EmptySuppressReason { index });
            }
        }
        Ok(())
    }

    /// Whether `rule_id` should run. A rule is enabled unless the config
    /// explicitly sets it to `false`.
    #[must_use]
    pub fn is_rule_enabled(&self, rule_id: &str) -> bool {
        self.rules.get(rule_id).copied().unwrap_or(true)
    }

    /// Resolves the effective fail-on severity: the CLI value wins, then the
    /// config value, then the `low` default.
    #[must_use]
    pub fn effective_fail_on(&self, cli: Option<Severity>) -> Severity {
        cli.or(self.fail_on).unwrap_or(Severity::Low)
    }
}

/// Result of applying suppressions to a run's raw findings.
#[derive(Debug, Default)]
pub struct SuppressionOutcome {
    /// Findings that were not suppressed.
    pub active: Vec<Finding>,
    /// Findings that were suppressed, with reason and source.
    pub suppressed: Vec<SuppressedFinding>,
    /// Human-readable warnings (e.g. an inline directive missing a reason),
    /// already formatted as `path:line: message`.
    pub warnings: Vec<String>,
}

/// Partitions `findings` into active vs suppressed using inline directives
/// (parsed from `sources`) and the config's `[[suppress]]` entries.
///
/// Inline directives take precedence over config entries. Neither path
/// changes a finding's content; suppression only moves it out of `active`.
#[must_use]
pub fn apply_suppressions(
    findings: Vec<Finding>,
    sources: &[SourceView],
    config: &Config,
) -> SuppressionOutcome {
    let mut inline: Vec<(PathBuf, InlineDirective)> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    for source in sources {
        parse_inline(&source.path, &source.source, &mut inline, &mut warnings);
    }

    let mut outcome = SuppressionOutcome::default();
    for finding in findings {
        if let Some(reason) = match_inline(&finding, &inline) {
            outcome.suppressed.push(SuppressedFinding::new(
                finding,
                reason,
                SuppressionKind::Inline,
            ));
        } else if let Some(reason) = match_config(&finding, config) {
            outcome.suppressed.push(SuppressedFinding::new(
                finding,
                reason,
                SuppressionKind::Config,
            ));
        } else {
            outcome.active.push(finding);
        }
    }
    outcome.warnings = warnings;
    outcome
}

struct InlineDirective {
    rule_id: String,
    line: u32,
    reason: String,
}

fn parse_inline(
    path: &Path,
    source: &str,
    directives: &mut Vec<(PathBuf, InlineDirective)>,
    warnings: &mut Vec<String>,
) {
    for (i, raw) in source.lines().enumerate() {
        let Some(pos) = raw.find(INLINE_MARKER) else {
            continue;
        };
        let line = u32::try_from(i + 1).unwrap_or(u32::MAX);
        let rest = &raw[pos + INLINE_MARKER.len()..];
        let rule_id = rest.split_whitespace().next();
        let reason = extract_reason(rest);
        match (rule_id, reason) {
            (Some(rule), Some(reason)) if !reason.trim().is_empty() => {
                directives.push((
                    path.to_path_buf(),
                    InlineDirective {
                        rule_id: rule.to_string(),
                        line,
                        reason,
                    },
                ));
            }
            (Some(rule), _) => warnings.push(format!(
                "{}:{}: inline suppression for `{}` ignored: a non-empty reason=\"...\" is required",
                path.display(),
                line,
                rule
            )),
            (None, _) => warnings.push(format!(
                "{}:{}: malformed inline suppression (expected `{} RULE_ID reason=\"...\"`)",
                path.display(),
                line,
                INLINE_MARKER
            )),
        }
    }
}

/// Extracts the value of `reason="..."` from a directive tail, if present.
fn extract_reason(s: &str) -> Option<String> {
    const KEY: &str = "reason=\"";
    let start = s.find(KEY)? + KEY.len();
    let rest = &s[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn match_inline(finding: &Finding, inline: &[(PathBuf, InlineDirective)]) -> Option<String> {
    let line = finding.line?;
    inline.iter().find_map(|(path, dir)| {
        let same_target = *path == finding.file && dir.rule_id == finding.rule_id;
        // Directive on the finding's line, or the line directly above it.
        let anchors = dir.line == line || dir.line + 1 == line;
        (same_target && anchors).then(|| dir.reason.clone())
    })
}

fn match_config(finding: &Finding, config: &Config) -> Option<String> {
    let finding_path = normalize(&finding.file.to_string_lossy());
    config.suppress.iter().find_map(|entry| {
        let line_matches = match entry.line {
            Some(l) => Some(l) == finding.line,
            None => true,
        };
        let matches = entry.rule == finding.rule_id
            && path_matches(&entry.path, &finding_path)
            && line_matches;
        matches.then(|| entry.reason.clone())
    })
}

/// Whether a config `path` matches the reported `finding_path`. The config
/// path is written relative to the project root, while a reported path may
/// carry a longer prefix (absolute, or relative to the CWD), so a config path
/// matches when it equals the reported path or is a trailing path-segment
/// suffix of it (`main.nr` matches `/abs/proj/main.nr`, not `zmain.nr`).
fn path_matches(config_path: &str, finding_path: &str) -> bool {
    let want = normalize(config_path);
    finding_path == want || finding_path.ends_with(&format!("/{want}"))
}

/// Normalizes a path string for comparison: forward slashes, no leading `./`.
fn normalize(path: &str) -> String {
    let slashed = path.replace('\\', "/");
    slashed.strip_prefix("./").unwrap_or(&slashed).to_string()
}

#[cfg(test)]
mod tests;
