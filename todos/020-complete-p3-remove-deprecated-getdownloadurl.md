---
status: complete
priority: p3
issue_id: "020"
tags: [cleanup, api, dead-code]
dependencies: []
---

# Remove deprecated getDownloadUrl export

## Problem Statement

`getDownloadUrl()` is marked deprecated but still exported from the public API surface, encouraging continued use.

## Findings

- `src/scanner/download.ts` -- `getDownloadUrl` exported with `@deprecated` JSDoc
- No internal callers found outside tests
- Replacement function exists and is preferred

## Proposed Solutions

### Option 1: Remove export, keep as private if needed

**Approach:** Remove from public exports. If tests need it, make it a test helper.

**Pros:** Clean API surface

**Risk:** Low (semver minor/patch if pre-1.0)

## Recommended Action

Use Option 1: Remove the export. Pre-1.0 so no semver concerns. If tests use it, inline the logic or make a test-only helper.

## Acceptance Criteria

- [ ] `getDownloadUrl` removed from public exports
- [ ] No internal callers broken
- [ ] Tests updated if needed

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (code-simplicity-reviewer agent)

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
