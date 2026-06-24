# zk-guard

`zk-guard` is a best-effort static security scanner for zero-knowledge
application source code. The first production target is
[Noir](https://noir-lang.org/). Circom and zkVM guest-code support are
future extensions (see `docs/roadmap.md`).

**This is developer tooling, not a formal verifier.** A finding describes a
*suspicious pattern in source code*. It is not proof that a circuit is
exploitable, formally under-constrained, or that an attack is realistic
against any specific deployment. See `docs/rule-taxonomy.md` for each
rule's detection strategy, severity/confidence rationale, and known
false-positive classes.

## Status

Pre-0.1.0. One rule is implemented end-to-end (`NOIR-PUBLIC-001`); the
remaining MVP rules from `CLAUDE.md` land incrementally (see
`docs/roadmap.md`). The CLI, exit codes, and JSON/Markdown report formats
described below are stable for this rule set and are not expected to
change shape as more rules are added — only the rule registry grows.

## Installation

From the workspace root:

```bash
cargo build --release -p zkguard-cli
# binary at target/release/zk-guard
```

Or run directly without installing:

```bash
cargo run -p zkguard-cli -- <command> [args]
```

The rest of this document uses `zk-guard` as shorthand for either
`./target/release/zk-guard` or `cargo run -p zkguard-cli --`.

## Usage

### Scan a Noir project

```bash
zk-guard scan ./path/to/noir-project
```

`<path>` may be a Noir project directory (containing `Nargo.toml`/`src/`)
or a single `.nr` file. Discovery never executes anything found in the
scanned tree, never follows symlinks, and never performs network access
(see `CLAUDE.md`'s "Security boundaries").

Default output is plain text to stdout:

```text
[HIGH] Public input declared but unused in a constraint-relevant expression (NOIR-PUBLIC-001)
  location:   src/main.nr:10
  confidence: medium
  evidence:   pub claimed_total: Field
  why:        A public input that never reaches an assert/constrain is not actually bound by the proof — a malicious prover can set it to any value, defeating the purpose of making it public in the first place. This is the canonical "under-constrained circuit" bug class in ZK audits.
  fix:        Bind every public input to at least one constraint that a malicious prover cannot satisfy arbitrarily. If a public input is intentionally informational only, document that decision in code comments next to the parameter and accept the finding as a documented exception.

Summary:
  files scanned: 1
  rules run:     1
  CRITICAL:  0
  HIGH:      1
  MEDIUM:    0
  LOW:       0
  INFO:      0
  total:     1
```

### Machine-readable output (CI)

```bash
zk-guard scan ./path/to/noir-project --format json
```

Emits the scan result as pretty-printed JSON to stdout. Field names and
lowercase `severity`/`confidence` strings match `CLAUDE.md`'s "Reporting
schema" exactly, so the shape is stable for CI parsing:

```json
{
  "findings": [
    {
      "rule_id": "NOIR-PUBLIC-001",
      "title": "Public input declared but unused in a constraint-relevant expression",
      "severity": "high",
      "confidence": "medium",
      "file": "src/main.nr",
      "line": 10,
      "column": null,
      "evidence": "pub claimed_total: Field",
      "why_it_matters": "...",
      "remediation": "..."
    }
  ],
  "files_scanned": 1,
  "rules_run": ["NOIR-PUBLIC-001"]
}
```

### Markdown report (PR comments, CI artifacts)

```bash
zk-guard scan ./path/to/noir-project --format markdown --output report.md
```

Without `--output`, Markdown is printed to stdout instead. The Markdown
report is written to render cleanly in GitHub's Markdown viewer: a summary
table of finding counts by severity, followed by one section per finding
covering rule ID, title, severity, confidence, file:line, evidence, why it
matters, and remediation.

### Choosing a failure threshold

```bash
zk-guard scan ./path/to/noir-project --fail-on high
```

`--fail-on` (default: `low`, i.e. any finding fails the scan) sets the
minimum severity that causes a nonzero exit code. Findings below the
threshold are still reported in the output — they just don't flip the exit
code. Valid values: `critical`, `high`, `medium`, `low`, `info`.

### List registered rules

```bash
zk-guard rules list
zk-guard rules list --format json
zk-guard rules list --format markdown
```

```text
RULE_ID          SEVERITY    CONFIDENCE  TITLE
NOIR-PUBLIC-001  high        medium      Public input declared but unused in a constraint-relevant expression
                 Detects `pub` parameters of `fn main` that never reach an assert/assert_eq/constrain expression, directly or via one intermediate `let` binding.
```

### Validate the fixture tree

```bash
zk-guard fixtures validate
```

Confirms every fixture project under `fixtures/noir/{vulnerable,safe}/`
(or a directory passed via `--path`) discovers cleanly — readable `.nr`
sources, no traversal errors, at least one source file per fixture
directory. This is a fast filesystem sanity check; it does not re-run
rules against fixtures and assert expected findings (that is covered by
`cargo test --workspace`, specifically `zkguard-rules`' fixture
integration tests).

```bash
zk-guard fixtures validate --path /some/other/fixtures/root
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan (or `rules list` / `fixtures validate`) completed and found no findings at or above the `--fail-on` threshold (default: `low`). |
| `1` | Scan completed and found at least one finding at or above the `--fail-on` threshold. CI pipelines should treat this as "gate failed." |
| `2` | Invalid CLI usage or unreadable input: bad flags, a scan path that does not exist, or a path that exists but cannot be read. Nothing was scanned. |
| `3` | Internal scanner error not attributable to user input (e.g. a report-rendering failure, or an I/O error reading a file that existed moments ago). |

`zk-guard rules list` and `zk-guard fixtures validate` never return `1` —
they have no "findings" concept, only success (`0`) or usage/internal
error (`2`/`3`).

See `crates/zkguard-cli/src/exit_code.rs` for the authoritative,
code-level documentation of this scheme.

## CI example

```bash
zk-guard scan ./circuits --format json --output scan-result.json
echo "exit code: $?"   # 1 if any finding was at or above the fail-on threshold
```

A nonzero exit code from `zk-guard scan` is the intended CI gating signal;
parse `scan-result.json` for finding detail in a CI annotation step.

## Limitations

- Heuristic, best-effort static detections only — no formal verification,
  no SMT solving, no semantic dataflow analysis. See
  `docs/rule-taxonomy.md`'s "Disclaimer" and each rule's "False-positive
  notes" for known gaps.
- Single rule implemented end-to-end so far (`NOIR-PUBLIC-001`); the
  remaining MVP rules in `CLAUDE.md` are tracked in `docs/roadmap.md`.
- Noir only. Circom and zkVM guest-code support are explicitly out of
  scope for now.
- No SARIF output yet (JSON and Markdown only, by 0.1.0 design).
- Findings are never proof of exploitability and never a substitute for a
  manual security audit.

## Development

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

See `docs/architecture.md` for crate boundaries and the scan pipeline, and
`docs/rule-taxonomy.md` for the rule specification format used by every
rule in `zkguard-rules`.
