---
status: complete
priority: p3
issue_id: "018"
tags: [typescript, types, immutability]
dependencies: []
---

# Add readonly modifiers to type definitions

## Problem Statement

Type definitions in `types.ts` lack `readonly` modifiers, allowing accidental mutation of finding objects and scan results after construction.

## Findings

- `src/scanner/types.ts` -- All interface properties are mutable
- `Finding`, `ScanResult`, `ScanOptions` could all benefit from `readonly`
- No runtime bugs observed, but `readonly` prevents accidental mutation

## Proposed Solutions

### Option 1: Add readonly to output types

**Approach:** Add `readonly` to `Finding`, `ScanResult`, and their nested types. Leave `ScanOptions` mutable since callers construct it.

**Pros:**

- Catches accidental mutation at compile time
- Documents intent that findings are immutable after creation

**Risk:** Low

## Recommended Action

Use Option 1: Add `readonly` to output types only (`Finding`, `ScanResult`). Leave `ScanOptions` mutable. Best done alongside issue 011 (metadata type safety) to avoid touching types.ts twice.

## Acceptance Criteria

- [ ] `Finding` properties marked `readonly`
- [ ] `ScanResult` properties marked `readonly`
- [ ] Existing tests pass
- [ ] No `as` casts needed to work around readonly

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (kieran-typescript-reviewer agent)

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
