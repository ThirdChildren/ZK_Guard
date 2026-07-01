# Security review — zk-guard

Step 8 of `docs/agent-workflow.md`. Audit of the scanner built in Steps 1–7,
against the security boundaries and non-negotiable design principles in
`CLAUDE.md`.

- **Scope reviewed:** `zkguard-core`, `zkguard-noir`, `zkguard-rules` (5 rules
  + registry), `zkguard-report`, `zkguard-cli`, and `fixtures/noir/`.
- **Method:** static read-through + `cargo test --workspace` and
  `cargo clippy --workspace --all-targets -- -D warnings` (both green).
- **Reviewer made no code changes.** All issues below are reported with a
  recommended fix and the owning agent/step.

## Verdict: PASS-WITH-ISSUES

No high-severity issues. No code execution of target content, no network
calls, no symlink escape/loop, no overclaimed cryptographic soundness. Two
medium issues are availability/credibility gaps, not scanning-logic
vulnerabilities.

## Per-boundary results (8 focus areas)

| # | Area | Result |
|---|------|--------|
| 1 | Dangerous execution of target content | PASS — no `Command`/exec/shell-out in production code; discovery only reads bytes via `fs::read_to_string` |
| 2 | Unsafe filesystem traversal | PASS (see M1) — `fs::symlink_metadata` everywhere; symlinks (file + dir) always skipped, never followed; honors scan root; unix tests cover both cases |
| 3 | Network / exfiltration | PASS — no network-capable dependency anywhere in the workspace |
| 4 | Misleading / overclaimed findings | PASS — hedged language in `why_it_matters`/`remediation`; explicit "not a formal verifier" disclaimers in README + taxonomy |
| 5 | Scanner correctness honesty | PASS — confidences match taxonomy; no critical+high-confidence pairing; known FP/FN documented per rule |
| 6 | Missing fixtures | PASS — all 5 implemented rules have ≥1 vulnerable + ≥1 safe fixture; several exceed minimum |
| 7 | Robustness / panics | PASS-WITH-ISSUES — no unwrap/expect/panic on attacker input in production paths; non-UTF8 handling gap (M1) |
| 8 | Determinism | PASS — discovery sorts by path; registry is fixed `Vec`; reporters are pure; explicit determinism tests in `human.rs`/`json.rs` |

## Findings

### M1 (medium) — one unreadable `.nr` file aborts the whole scan
- **Location:** `crates/zkguard-noir/src/discovery.rs:236-242` (`read_source`),
  propagated via `walk_dir` (`:216`) as a hard `Err` out of `discover()`.
- **Impact:** a hostile or malformed target repo can deny a full scan with a
  single non-UTF8/unreadable file, even when the rest of the tree is valid
  Noir. Availability-relevant for a tool meant to scan imperfect repos.
- **Fix:** in `walk_dir`, treat a per-file `read_to_string` failure as
  skip-with-warning (collect a `skipped`/`partial_errors` list surfaced in
  `ScanResult` or stderr) instead of failing `discover()`. Changes the
  `DiscoveryError`/`NoirProject` contract → more than a trivial fix.
- **Owner:** `noir-static-analyzer`. Status: reported, not fixed.

### M2 (medium) — stale README "Status"/"Limitations"
- **Location:** `README.md:17-21`, `README.md:193-194` claim a single rule is
  implemented; the registry (`crates/zkguard-rules/src/registry.rs`) actually
  ships 5.
- **Impact:** credibility risk — CLAUDE.md principle 10 ("no vague/stale
  claims") applied to docs.
- **Fix:** list all 5 implemented rules + the 2 deferred (ZK-REPLAY-001,
  ZK-TEST-001), consistent with roadmap/taxonomy.
- **Owner:** README owner (`cli-reporting-engineer` / `ci-release-engineer`,
  Step 10 doc polish). Status: reported, not fixed.

### L1 (low) — no documented file-size / recursion-depth bound
- **Location:** `crates/zkguard-noir/src/discovery.rs` (`discover`/`walk_dir`).
- **Impact:** large files read fully into memory; recursion uncapped. Not
  amplifiable (symlinks blocked), but the resource-bound stance is
  undocumented.
- **Fix:** either document "no size/depth limits in v1 (local repos the user
  chose to scan)" as an accepted gap, or add a conservative cap. Status: noted.

### L2 (low) — `unwrap_used`/`expect_used` are `warn`, not `deny`
- **Location:** `Cargo.toml:24-25`.
- **Impact:** enforcement relies on the `-D warnings` quality-gate flag, not
  the lint level; an IDE running bare `cargo clippy` would not flag a new
  production unwrap.
- **Fix:** none urgent — keep `-D warnings` as the enforcement point. Status: noted.

## Fixture coverage

All 5 implemented rules (NOIR-PUBLIC-001, NOIR-CONSTRAINT-001, NOIR-RANGE-001,
ZK-HASH-001, ZK-NULLIFIER-001) have both vulnerable and safe fixtures; no gaps.
ZK-REPLAY-001 and ZK-TEST-001 are unimplemented and unfixtured — expected and
documented (roadmap defers them; CLAUDE.md requires only 5 for 0.1.0).

## Recommended next actions

1. `noir-static-analyzer`: make `discover()` skip-and-warn on an unreadable
   single file instead of aborting (M1).
2. README owner: refresh Status/Limitations to the real 5-rule registry (M2).
3. Implement ZK-REPLAY-001 + ZK-TEST-001 to reach the full 7-rule taxonomy
   (note: ZK-REPLAY-001 is project-level/cross-file — the single-file
   `Rule::check(&SourceView)` signature will need cross-file aggregation or a
   trait change).
4. Optional: document the absence of size/depth bounds as an accepted v1
   limitation (L1).

## Post-v0.2.0 status

This is a status delta, not a fresh audit. The 0.2.0 line added the
`zkguard-config` crate (config + suppressions), SARIF output, and the
project-level `ZK-TEST-001` rule; a full re-review of that surface is a
0.3.0 task (see `docs/roadmap.md`). Against the findings above:

- **M2 (stale README) — RESOLVED.** The README now documents the real
  six-rule registry (`NOIR-PUBLIC-001`, `NOIR-CONSTRAINT-001`,
  `NOIR-RANGE-001`, `ZK-HASH-001`, `ZK-NULLIFIER-001`, `ZK-TEST-001`) and
  the current formats/config; `rules list` remains the source of truth.
- **M1 (one unreadable/non-UTF-8 `.nr` aborts the whole scan) — STILL
  OPEN.** Unchanged in 0.2.0. Scheduled as the "robust discovery
  (skip-with-warning)" item for 0.3.0.
- **ZK-TEST-001 — now IMPLEMENTED** (0.2.0), as a project-level rule via the
  `zkguard_core::ProjectRule` trait. `ZK-REPLAY-001` is now the *only*
  unimplemented MVP rule (recommended action #3 above is partially done).
- **New surface not yet audited:** `zkguard-config` (TOML parsing,
  suppression matching, inline-directive scanning) and the SARIF emitter.
  No new dangerous behavior is expected (no execution, no network; config is
  read-only TOML), but these warrant a dedicated pass in the 0.3.0 review
  refresh. L1 (no size/depth bounds) remains noted, not addressed.
