---
status: complete
priority: p1
issue_id: "001"
tags: [correctness, sarif, cli]
dependencies: []
---

# Fix version drift between package.json and hardcoded strings

## Problem Statement

The CLI and SARIF output hardcode version `"0.1.0"` in two places while `package.json` is at `"0.1.3"`. For a security tool, version accuracy in SARIF reports is critical for audit trails and reproducibility.

## Findings

- `src/cli.ts:73` -- `.version("0.1.0")` (CLI `--version` output)
- `src/cli.ts:726` -- `version: "0.1.0"` (SARIF tool driver version)
- `package.json:2` -- `"version": "0.1.3"` (actual version)
- Identified by: Architecture, TypeScript, Simplicity agents (consensus across 3/6)

## Proposed Solutions

### Option 1: Import version from package.json

**Approach:** Use `createRequire` or a build-time constant to read the version from package.json.

**Pros:**

- Single source of truth
- No manual updates needed on version bumps

**Cons:**

- Requires resolving package.json path at runtime or build time

**Risk:** Low

### Option 2: Shared constant updated by npm version

**Approach:** Create a `src/version.ts` that exports the version string, updated by `npm version` hooks.

**Pros:**

- No runtime file resolution
- Works with bundlers

**Cons:**

- Requires npm version hook setup

**Risk:** Low

## Recommended Action

Use Option 1: Import version from package.json using `createRequire`. Single source of truth, no build step.

## Acceptance Criteria

- [ ] `vsix-audit --version` outputs the correct version from package.json
- [ ] SARIF output `tool.driver.version` matches package.json
- [ ] Version is defined in exactly one place
- [ ] Tests verify version consistency

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (multi-agent review)

**Actions:**

- Identified version drift across 3 independent review agents
- Confirmed the two hardcoded locations in cli.ts

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
