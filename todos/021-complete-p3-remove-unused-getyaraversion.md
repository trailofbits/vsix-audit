---
status: complete
priority: p3
issue_id: "021"
tags: [cleanup, dead-code, yara]
dependencies: []
---

# Remove or use getYaraVersion function

## Problem Statement

`getYaraVersion()` is defined and exported but never called anywhere in the codebase.

## Findings

- `src/scanner/checks/yara.ts` -- `getYaraVersion` defined and exported
- No callers found via grep
- May have been intended for version checking or diagnostics

## Proposed Solutions

### Option 1: Remove if unused

**Approach:** Delete the function. If needed later, it can be re-added.

**Pros:** Less dead code

**Risk:** Low

### Option 2: Add to --version or diagnostics output

**Approach:** Call it from CLI `--version` flag to show YARA-X version alongside scanner version.

**Pros:** Useful diagnostic info

**Risk:** Low

## Recommended Action

Prefer Option 2: Wire into `--version` output to show YARA-X version. Useful for debugging and issue reports. If issue 001 (version drift) is done first, add it alongside the fixed version output.

## Acceptance Criteria

- [ ] Function either removed or actively used
- [ ] No unused exports remain

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (code-simplicity-reviewer agent)

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
