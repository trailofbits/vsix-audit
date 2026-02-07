---
status: complete
priority: p2
issue_id: "015"
tags: [performance, duplication, utils]
dependencies: []
---

# Consolidate 4 line-number implementations into binary-search utility

## Problem Statement

Four different line-number-finding implementations exist across the codebase. `findLineNumberByString` is O(n) per call and used in loops, creating O(n \* matches) complexity for IOC scanning.

## Findings

- `src/scanner/utils.ts:9-16` -- `findLineNumberByString`: splits entire file per call
- `src/scanner/utils.ts:23-26` -- `findLineNumberByIndex`: slices + splits per call
- `src/scanner/checks/obfuscation.ts:177-183` -- `findLineAndColumn`: splits on newlines
- `src/scanner/checks/ast.ts:43-68` -- `computeLineStarts` + `offsetToLine`: binary search (best approach)
- For 10K-line file with 20 IOC matches: 20 arrays of 10K strings each
- Performance agent estimates 10-50x improvement for files with many matches

## Proposed Solutions

### Option 1: Extract ast.ts approach to utils.ts

**Approach:** Move `computeLineStarts` and `offsetToLine` from `ast.ts` to `utils.ts`. Replace all `findLineNumberByString` callers with `indexOf` + binary search on precomputed line starts.

**Pros:**

- Pattern already exists and is proven
- O(n + matches _ log(lines)) vs O(n _ matches)

**Cons:**

- Callers need to pre-compute line starts array

**Risk:** Low

## Recommended Action

Use Option 1: Extract `computeLineStarts` + `offsetToLine` from `ast.ts` to `utils.ts`. Proven pattern, already in the codebase. Pairs well with issue 013 (pre-computed strings) -- line starts can be cached alongside string contents.

## Acceptance Criteria

- [ ] Single line-number utility using binary search
- [ ] All modules use the shared utility
- [ ] No more `content.split("\n")` for line counting in hot paths
- [ ] Existing tests pass

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (performance + pattern agents)

**Actions:**

- Identified 4 implementations of the same utility
- Identified O(n\*m) complexity in IOC scanning

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
