---
status: complete
priority: p1
issue_id: "004"
tags: [security, zip, path-traversal]
dependencies: []
---

# Harden path traversal protection in ZIP extraction and YARA temp

## Problem Statement

`isPathSafe()` doesn't handle backslash path separators, and YARA temp file writes don't re-validate resolved paths. On Windows, backslash-based traversal could escape the temp directory.

## Findings

- `src/scanner/vsix.ts:16-19` -- `isPathSafe()` splits on `/` only; `extension\..\..\etc\passwd` passes
- `src/scanner/checks/yara.ts:335-344` -- `join(tempDir, filename)` without verifying result stays within `tempDir`
- Mitigating factor: On macOS/Linux, `path.join` treats backslashes as literal characters
- Risk increases if tool is used on Windows or if `loadDirectory` populates files without `isPathSafe`

## Proposed Solutions

### Option 1: Reject backslashes + add resolved-path check

**Approach:**

1. In `isPathSafe()`: reject entries containing `\` -- `if (path.includes('\\')) return false`
2. In YARA temp write: after `join(tempDir, filename)`, verify `resolve(filePath).startsWith(resolve(tempDir))`

**Pros:**

- Defense in depth
- Trivial to implement
- Covers both current and future code paths

**Cons:**

- None significant

**Risk:** Low

## Recommended Action

Use Option 1: Two-line fix -- reject backslashes in `isPathSafe()` and add `resolve().startsWith()` guard in YARA temp writes. Defense in depth with near-zero risk.

## Acceptance Criteria

- [ ] `isPathSafe()` rejects paths containing backslashes
- [ ] YARA temp file writes validate resolved path is within tempDir
- [ ] Test with backslash traversal input
- [ ] Existing tests still pass

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (security-sentinel agent)

**Actions:**

- Identified backslash bypass in isPathSafe
- Identified missing resolved-path check in YARA temp writes

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
