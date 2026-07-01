# SARIF output

`zk-guard scan --format sarif` emits a [SARIF][sarif] 2.1.0 log. SARIF is the
format GitHub code scanning consumes, so this is the recommended output for CI
integration: upload the log with `github/codeql-action/upload-sarif` and
findings show up in the repository's **Security → Code scanning** tab and as
inline pull-request annotations.

SARIF is supported by `scan` only. `zk-guard rules list --format sarif` is a
usage error (exit code `2`): SARIF encodes *scan results*, not the rule
registry.

```bash
zk-guard scan ./path/to/noir-project --format sarif --output zkguard.sarif
```

Without `--output` the log is printed to stdout. The exit code is unchanged
from other formats (`0` clean / `1` findings at or above `--fail-on` / `2`
usage / `3` internal), so `--format sarif` still gates CI on its own; the
upload step is additive.

## Field mapping

The log has a single `run`. The tool driver lists **every registered rule** as
a `reportingDescriptor` (not just rules that fired), and each finding becomes
one `result`.

### `tool.driver`

| SARIF path | Source |
|---|---|
| `name` | `"zk-guard"` |
| `version` | the `zk-guard` crate version |
| `informationUri` | project repository URL |
| `rules[]` | one `reportingDescriptor` per rule in `zkguard_rules::registry()`, in registry order |

### `reportingDescriptor` (per rule)

| SARIF path | Source (`RuleMetadata`) |
|---|---|
| `id` | `rule_id` (stable, e.g. `NOIR-PUBLIC-001`) |
| `name` | `title` |
| `shortDescription.text` | `title` |
| `fullDescription.text` | `description` |
| `defaultConfiguration.level` | mapped from `default_severity` (see below) |
| `properties.security-severity` | GitHub severity score from `default_severity` |
| `properties.confidence` | `default_confidence` (`high`/`medium`/`low`) |
| `properties.tags` | `["security"]` |

### `result` (per finding)

| SARIF path | Source (`Finding`) |
|---|---|
| `ruleId` | `rule_id` (stable) |
| `ruleIndex` | index of the rule in `tool.driver.rules` (omitted if the rule is not registered) |
| `level` | mapped from `severity` (see below) |
| `message.text` | `why_it_matters`, plus `Evidence:` and `Remediation:` lines |
| `locations[0].physicalLocation.artifactLocation.uri` | `file`, normalized to a repository-relative, forward-slash path |
| `locations[0].physicalLocation.region.startLine` | `line` (falls back to `1` when unknown; SARIF requires `startLine >= 1`) |

### Severity → SARIF level and score

| `zk-guard` severity | SARIF `level` | `security-severity` |
|---|---|---|
| `critical` | `error` | `9.0` |
| `high` | `error` | `8.0` |
| `medium` | `warning` | `5.0` |
| `low` | `note` | `3.0` |
| `info` | `note` | `0.0` |

`ruleId` values are stable and never reused, so alerts stay correlated across
runs (SARIF dedups by `ruleId` + location).

## GitHub Actions example

A ready-to-copy workflow lives at
[`examples/github-actions/zkguard-sarif.yml`](../examples/github-actions/zkguard-sarif.yml):

```yaml
name: zk-guard

on:
  push:
    branches: [main, master]
  pull_request:

permissions:
  contents: read
  security-events: write   # required for upload-sarif

jobs:
  zkguard-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Build zk-guard
        run: cargo build --release -p zkguard-cli

      # continue-on-error so a finding (exit 1) still uploads the SARIF;
      # gate the build on the separate "fail" step below if you want.
      - name: Scan Noir sources
        id: scan
        continue-on-error: true
        run: ./target/release/zk-guard scan ./circuits --format sarif --output zkguard.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: zkguard.sarif
          category: zk-guard

      - name: Fail on findings
        if: steps.scan.outcome == 'failure'
        run: exit 1
```

Point `./circuits` at your Noir project (or a single `.nr` file). `zk-guard`
never executes anything in the scanned tree and makes no network calls, so it
is safe to run against untrusted code in CI.

[sarif]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
