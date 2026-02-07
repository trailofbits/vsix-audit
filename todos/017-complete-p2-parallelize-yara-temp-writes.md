---
status: complete
priority: p2
issue_id: "017"
tags: [performance, yara, io]
dependencies: []
---

# Parallelize YARA temp file writes

## Problem Statement

YARA temp file writes are sequential -- 500 files = 500+ sequential `mkdir` + `writeFile` calls, adding 200-500ms of pure I/O time.

## Findings

- `src/scanner/checks/yara.ts:330-345` -- Sequential `await writeFile` in loop
- Each write pays system call overhead
- No parallelism despite being I/O-bound

## Proposed Solutions

### Option 1: Batch writes with Promise.all

**Approach:** Pre-compute unique directories, `mkdir` all at once, then `Promise.all` writeFile calls in batches of 50.

**Pros:**

- Significant I/O speedup
- Simple implementation

**Risk:** Low

## Recommended Action

Use Option 1: Batch writes with `Promise.all`. Use the existing `runWithConcurrency` pattern from the codebase if available, otherwise batch in groups of 50.

## Acceptance Criteria

- [ ] Temp file writes parallelized
- [ ] Directories created in batch
- [ ] Measurable reduction in YARA module time
- [ ] Existing tests pass

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (performance-oracle agent)

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
