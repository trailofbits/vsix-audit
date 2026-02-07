---
status: complete
priority: p1
issue_id: "005"
tags: [security, yara, temp-files]
dependencies: []
---

# Use unpredictable temp directory for YARA scanning

## Problem Statement

The YARA temp directory uses `Date.now()` which is predictable. On shared systems, an attacker could pre-create a symlink at the predicted path, causing extension files to be written to a sensitive directory.

## Findings

- `src/scanner/checks/yara.ts:328` -- `join(tmpdir(), \`vsix-audit-${Date.now()}\`)`
- `mkdir({ recursive: true })` succeeds silently if a symlink to a directory exists at that path
- `fs.mkdtemp()` creates directories atomically with unpredictable suffixes

## Proposed Solutions

### Option 1: Use fs.mkdtemp()

**Approach:** Replace `Date.now()` with `mkdtemp(join(tmpdir(), 'vsix-audit-'))`.

**Pros:**

- Atomic directory creation with random suffix
- Standard Node.js API
- One-line change

**Cons:**

- None

**Risk:** Low

## Recommended Action

Use Option 1: Replace `Date.now()` with `mkdtemp()`. One-line change, zero risk, standard Node.js API.

## Acceptance Criteria

- [ ] Temp directory created with `mkdtemp()` or `crypto.randomUUID()`
- [ ] Directory name is not predictable
- [ ] Existing tests still pass

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (security-sentinel agent)

**Actions:**

- Identified predictable temp directory name as symlink race vector

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
