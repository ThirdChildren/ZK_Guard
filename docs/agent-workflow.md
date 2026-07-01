# Agent workflow for Claude Code

Use these prompts in Claude Code after copying this template into the repository.

## Step 1 - Architecture skeleton

```text
Use the zk-project-architect agent to initialize the Rust workspace for zk-guard according to CLAUDE.md. Create the minimal crate layout, architecture docs, and roadmap. Do not implement scanner rules yet. Run formatting and tests if possible.
```

## Step 2 - Rule taxonomy

```text
Use the zk-vulnerability-taxonomist agent to create docs/rule-taxonomy.md with the first MVP rules: NOIR-PUBLIC-001, NOIR-CONSTRAINT-001, NOIR-RANGE-001, ZK-HASH-001, ZK-NULLIFIER-001, ZK-REPLAY-001, and ZK-TEST-001. For each rule define severity, confidence, detection strategy, false-positive notes, vulnerable pattern, safe pattern, and fixture requirements.
```

## Step 3 - Core domain model

```text
Use the zk-project-architect agent to define the core Rust data model for findings, rules, scanner results, severities, confidences, and scanner traits. Keep implementation minimal and testable.
```

## Step 4 - First static rule

```text
Use the noir-static-analyzer agent to implement Noir project discovery and the NOIR-PUBLIC-001 rule. Add one vulnerable fixture and one safe fixture with tests. Do not add fuzzing yet.
```

## Step 5 - Fixture coverage

```text
Use the fixtures-test-engineer agent to review fixture coverage for implemented rules, add missing safe/vulnerable fixtures, and add regression tests.
```

## Step 6 - CLI and reports

```text
Use the cli-reporting-engineer agent to implement zk-guard scan, zk-guard rules list, JSON output, Markdown output, and documented exit codes. Add CLI tests where practical.
```

## Step 7 - Additional rules

```text
Use the noir-static-analyzer agent to implement NOIR-CONSTRAINT-001, NOIR-RANGE-001, ZK-HASH-001, and ZK-NULLIFIER-001 incrementally. For each rule, add metadata, vulnerable fixture, safe fixture, unit tests, and integration tests.
```

## Step 8 - Security review

```text
Use the security-reviewer agent to review the scanner for dangerous execution behavior, misleading findings, missing fixtures, unsafe filesystem traversal, and overclaimed ZK guarantees. Return pass, pass-with-issues, or fail.
```

## Step 9 - Optional fuzzing

```text
Use the fuzzing-harness-engineer agent to add deterministic property-based tests for the existing static rules. Do not add long-running fuzzing to default CI.
```

## Step 10 - CI and release prep

```text
Use the ci-release-engineer agent to add GitHub Actions for cargo fmt, clippy, tests, and fixture validation. Update README with installation, usage, examples, limitations, and 0.1.0 release checklist.
```
