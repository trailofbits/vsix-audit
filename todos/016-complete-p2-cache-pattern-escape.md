---
status: complete
priority: p2
issue_id: "016"
tags: [security, regex, cache]
dependencies: []
---

# Escape ? in cache clear pattern regex construction

## Problem Statement

The cache `clearCache()` function escapes regex metacharacters but misses `?`, which passes through as a regex quantifier causing unexpected matching behavior.

## Findings

- `src/scanner/cache.ts:163` -- Escape regex: `/[.+^${}()|[\]\\]/g` is missing `?`
- A pattern containing `?` would be interpreted as "0 or 1" quantifier
- Low security impact (only affects which cached files are deleted in user-controlled directory)

## Proposed Solutions

### Option 1: Add ? to escape list

**Approach:** Change regex to `/[.+?^${}()|[\]\\]/g`

**Pros:** One-character fix

**Risk:** Low

## Recommended Action

Use Option 1: Add `?` to the escape character class. Also consider using `*` which is similarly missing -- audit the full set against standard regex metacharacters.

## Acceptance Criteria

- [ ] `?` is escaped in cache clear pattern
- [ ] Test with pattern containing `?`

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (security-sentinel agent)

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
