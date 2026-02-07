---
status: complete
priority: p3
issue_id: "025"
tags: [cleanup, telemetry, simplification]
dependencies: []
---

# Simplify determineOptOut redundant double-checks

## Problem Statement

`determineOptOut()` performs redundant validation checks that duplicate logic already handled by callers or type constraints.

## Findings

- `src/scanner/checks/telemetry.ts` -- `determineOptOut` re-validates conditions that are guaranteed by the caller
- Adds unnecessary cyclomatic complexity

## Proposed Solutions

### Option 1: Remove redundant guards

**Approach:** Trust the type system and caller contracts. Remove checks that can't fail given the function's inputs.

**Pros:** Simpler, clearer logic flow

**Risk:** Low

## Recommended Action

Use Option 1: Remove redundant guards. Verify each guard is truly redundant by checking all callers before removing.

## Acceptance Criteria

- [ ] Redundant checks removed
- [ ] Function logic simplified
- [ ] Existing tests pass

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (code-simplicity-reviewer agent)

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
