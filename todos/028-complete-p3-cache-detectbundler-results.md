---
status: complete
priority: p3
issue_id: "028"
tags: [performance, obfuscation, duplication]
dependencies: ["013"]
---

# Cache detectBundler results to avoid redundant calls

## Problem Statement

`detectBundler()` is called multiple times per file across different check modules, each time re-running the same heuristic regex matching.

## Findings

- `src/scanner/checks/obfuscation.ts` -- `detectBundler` called per-file
- Multiple modules may call it on the same file content
- Each call runs 5+ regex tests against the full file

## Proposed Solutions

### Option 1: Cache per file path in scan context

**Approach:** Memoize `detectBundler` results in a `Map<string, BundlerInfo | null>` keyed by file path, shared across modules via scan context.

**Pros:** Zero redundant regex work

**Cons:** Requires shared context (related to issue 013)

**Risk:** Low

## Recommended Action

Use Option 1: Cache in scan context. Implement after issue 013 (pre-compute string contents) and 012 (CheckModule interface) which establish the shared `ScanContext` object.

## Acceptance Criteria

- [ ] Each file's bundler detected at most once per scan
- [ ] Results shared across modules
- [ ] Existing tests pass

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (performance-oracle agent)

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Blocked by issue 013 (pre-compute string contents)
