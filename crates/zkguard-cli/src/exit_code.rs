//! Process exit code policy for `zk-guard`.
//!
//! This is the **authoritative, documented** exit-code scheme for the
//! binary (mirrored in `README.md`'s "Exit codes" section — keep both in
//! sync if this changes). Per the `cli-reporting-engineer` charter's
//! "Recommended exit codes," with one early clarification baked in now
//! rather than left ambiguous (CLAUDE.md principle 10, no vague TODOs):
//!
//! | Code | Meaning |
//! |---|---|
//! | `0` | Scan (or `rules list` / `fixtures validate`) completed and found no findings at or above the `--fail-on` threshold (default: `low`, i.e. any finding at all fails the scan unless raised). |
//! | `1` | Scan completed and found at least one finding at or above the `--fail-on` threshold. This is the code CI pipelines should treat as "gate failed." |
//! | `2` | Invalid CLI usage or unreadable input: bad flags/arguments (handled by `clap` itself, which also uses exit code 2 by convention), a scan path that does not exist, or a path that exists but cannot be read/discovered (e.g. permission error). Nothing was scanned. |
//! | `3` | Internal scanner error: discovery or a rule panicked/failed in a way that is not attributable to user input (e.g. an I/O error reading a file that existed moments ago, or a report-rendering failure). Distinguished from `2` because the user did nothing wrong. |
//!
//! `zk-guard rules list` and `zk-guard fixtures validate` do not have a
//! "findings" concept, so they only ever return `0` (success) or `2`/`3`
//! (usage/internal error) — never `1`.

/// Exit code for a successful run with no qualifying findings.
pub const SUCCESS: i32 = 0;
/// Exit code for a successful run that found at least one finding at or
/// above the configured `--fail-on` threshold.
pub const FINDINGS_PRESENT: i32 = 1;
/// Exit code for invalid CLI usage or unreadable/missing input.
pub const USAGE_ERROR: i32 = 2;
/// Exit code for an internal scanner error not attributable to user input.
pub const INTERNAL_ERROR: i32 = 3;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_distinct() {
        let codes = [SUCCESS, FINDINGS_PRESENT, USAGE_ERROR, INTERNAL_ERROR];
        for (i, a) in codes.iter().enumerate() {
            for (j, b) in codes.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "exit codes must be pairwise distinct");
                }
            }
        }
    }
}
