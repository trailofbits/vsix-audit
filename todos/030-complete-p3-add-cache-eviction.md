---
status: complete
priority: p3
issue_id: "030"
tags: [feature, cache, resource-management]
dependencies: []
---

# Add cache eviction mechanism

## Problem Statement

The VSIX cache grows unbounded. No eviction by age, size, or count. Long-running systems accumulate stale cached extensions indefinitely.

## Findings

- `src/scanner/cache.ts` -- Cache stores downloaded VSIX files and extracted contents
- `clearCache()` exists but must be called explicitly with a pattern
- No automatic eviction based on age, total size, or entry count
- Typical cached VSIX: 1-50MB each; 100 scans = potentially gigabytes

## Proposed Solutions

### Option 1: LRU eviction with configurable max size

**Approach:** Track cache entry timestamps and sizes. On new writes, evict oldest entries if total exceeds a configurable limit (default 1GB).

**Pros:** Bounded disk usage, automatic cleanup

**Risk:** Low

### Option 2: TTL-based eviction

**Approach:** Delete entries older than N days (default 14) on each cache access.

**Pros:** Simpler implementation

**Risk:** Low

## Recommended Action

Use Option 2: TTL-based eviction with 14-day default. Simpler to implement, easier to reason about. Check file mtime on cache access, evict entries older than 14 days.

## Acceptance Criteria

- [ ] Cache size bounded by configurable limit
- [ ] Stale entries evicted automatically
- [ ] Existing tests pass

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (architecture-strategist agent)

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- TTL default changed from 7 days to 14 days per user preference
- Ready to be picked up and worked on
