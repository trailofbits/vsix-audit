---
status: complete
priority: p2
issue_id: "009"
tags: [duplication, download, refactor]
dependencies: []
---

# Deduplicate queryExtension and queryCursor into shared function

## Problem Statement

`queryExtension()` and `queryCursor()` are ~80 lines each of near-identical code. They differ only in the API URL and registry string. This is the largest code duplication in the codebase (~70 LOC).

## Findings

- `src/scanner/download.ts:137-217` -- `queryExtension()` (VS Code Marketplace)
- `src/scanner/download.ts:269-349` -- `queryCursor()` (Cursor)
- Identical: request body, headers, response parsing, version lookup, stats extraction
- Only differs: URL constant and `registry` field value
- Identified by all 4 non-security agents (consensus)

## Proposed Solutions

### Option 1: Extract queryGalleryApi(url, registry, ...)

**Approach:** Create a shared function parameterized on API URL and registry name.

**Pros:**

- ~70 LOC reduction
- Single point of change for Gallery API logic

**Cons:**

- Minor refactor

**Risk:** Low

## Recommended Action

Use Option 1: Extract shared `queryGalleryApi(url, registry)`. Pairs well with issue 006 (API response validation) -- validate once in the shared function.

## Acceptance Criteria

- [ ] Single shared Gallery API query function
- [ ] Marketplace and Cursor queries work identically to before
- [ ] Existing tests pass
- [ ] ~70 lines removed

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (multi-agent review)

**Actions:**

- Identified as highest-impact deduplication opportunity

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
