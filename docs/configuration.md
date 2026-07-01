# Configuration & suppressions (`zkguard.toml`)

`zk-guard` runs with zero configuration. For repo-specific policy you can add
an optional `zkguard.toml` to the **project root** — the directory you scan
(or the parent directory of a single scanned `.nr` file). It controls three
things and **never changes rule detection semantics**: a rule still runs and
still detects the same patterns; config only decides which rules run, what
severity fails the scan, and which findings are hidden (with a reason).

## Example

```toml
# Minimum severity that fails the scan (exit code 1).
# The CLI --fail-on flag, if given, overrides this. Default: "low".
fail_on = "high"

# Per-rule enable/disable. A rule not listed here is enabled.
[rules]
"NOIR-RANGE-001" = false   # disable this rule entirely
"ZK-HASH-001"    = true    # explicit (redundant) enable

# File-based suppressions: hide a specific finding, with a required reason.
[[suppress]]
rule   = "NOIR-PUBLIC-001"
path   = "src/main.nr"      # matches the tail of the reported path
line   = 10                 # optional: only this 1-based line
reason = "claimed_total is intentionally informational; documented in the RFC"
```

## `fail_on`

Sets the minimum severity that produces a nonzero exit code. Precedence,
highest first:

1. CLI `--fail-on <sev>`
2. `fail_on` in `zkguard.toml`
3. default `low` (any finding fails)

Findings below the threshold are still reported; they just don't flip the exit
code. Valid values: `critical`, `high`, `medium`, `low`, `info`.

## `[rules]` enable/disable

Each key is a `rule_id`, each value a bool. A rule absent from the table is
**enabled**; setting it to `false` disables it. Disabled rules do not run, do
not appear in `rules_run`, and can never produce a finding.

## Suppressions

A suppression hides a finding that a rule *did* detect. Every suppression
**requires a non-empty `reason`** so the decision stays auditable — suppressed
findings are counted in every report (`suppressed_count`) and can be listed
with `--show-suppressed`. There are two kinds.

### Inline directives

Put a comment on the flagged line, or the line directly above it:

```rust
let idx = user_input as u32; // zkguard:ignore NOIR-RANGE-001 reason="bounded by assert above"
```

```rust
// zkguard:ignore NOIR-RANGE-001 reason="bounded by assert above"
let idx = user_input as u32;
```

Format: `zkguard:ignore RULE_ID reason="..."`. The directive suppresses a
finding of `RULE_ID` in the same file whose line is the directive's line or
the line immediately below it. An inline directive **without a reason is
ignored** and produces a warning on stderr (the finding stays active).

### `[[suppress]]` config entries

Each entry needs `rule`, `path`, and `reason`; `line` is optional.

- `path` is matched against the **tail** of the reported file path (so
  `src/main.nr` matches `/abs/proj/src/main.nr`), after normalizing to forward
  slashes and stripping a leading `./`.
- `line`, when present, restricts the match to that exact 1-based line.
- An empty/whitespace `reason` is a load error (exit code `2`).

Inline directives take precedence over config entries when both match.

## Reporting

- Every format's summary reports `suppressed_count` (JSON always includes the
  field; human/Markdown add a line only when it is nonzero).
- `--show-suppressed` additionally lists the suppressed findings — with their
  reason and source (inline vs config) — in human/Markdown, and includes them
  (flattened, with `reason` and `suppressed_by`) in JSON. SARIF output always
  contains active findings only.
