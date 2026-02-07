---
status: complete
priority: p3
issue_id: "019"
tags: [testing, state, reliability]
dependencies: []
---

# Add reset mechanism for module-level mutable caches

## Problem Statement

Module-level mutable state (caches, Maps) in check modules persist across scans when the process is long-lived, potentially leaking state between scans and making tests order-dependent.

## Findings

- `src/scanner/checks/telemetry.ts` -- Module-level `allFileContents` Map
- `src/scanner/checks/obfuscation.ts` -- Cached regex compilations
- No observed bugs, but risk increases if scanner is used as a library or in watch mode

## Proposed Solutions

### Option 1: Export reset functions per module

**Approach:** Each module with mutable state exports a `reset()` function. Call from test setup or between scans.

**Pros:**

- Explicit control over state lifecycle
- Easy to test

**Risk:** Low

## Recommended Action

Use Option 1: Export `reset()` functions. If issue 012 (CheckModule interface) lands first, module-level state may be replaced by per-scan context, making this moot. Defer if 012 is in progress.

## Acceptance Criteria

- [ ] Each module with mutable state has a reset mechanism
- [ ] Tests call reset between runs if needed
- [ ] No cross-scan state leakage

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (pattern-recognition-specialist agent)

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
