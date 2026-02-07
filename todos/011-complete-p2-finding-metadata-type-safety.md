---
status: complete
priority: p2
issue_id: "011"
tags: [type-safety, types, metadata]
dependencies: []
---

# Improve Finding.metadata type safety

## Problem Statement

`Finding.metadata` is `Record<string, unknown>`, forcing every consumer into unsafe access patterns with `as` casts and runtime narrowing.

## Findings

- `src/scanner/types.ts:35` -- `metadata?: Record<string, unknown>`
- Unsafe access in `capabilities.ts:216-225`, `ast.ts:491`, `cli.ts:174`, and multiple tests
- Common fields (`matched`, `legitimateUses`, `redFlags`) accessed repeatedly without type guarantees
- Identified by Architecture and TypeScript agents

## Proposed Solutions

### Option 1: Base metadata interface with known common fields

**Approach:** Define `FindingMetadata` with known optional fields plus index signature for extensibility.

```typescript
interface FindingMetadata {
  matched?: string;
  legitimateUses?: string[];
  redFlags?: string[];
  [key: string]: unknown;
}
```

**Pros:**

- Eliminates most common casts
- Backward compatible
- Low effort

**Cons:**

- Doesn't fully type per-finding metadata

**Risk:** Low

### Option 2: Discriminated union per category

**Approach:** Each check module defines its metadata shape; `Finding` becomes a union on `category`.

**Pros:**

- Full type safety
- Self-documenting

**Cons:**

- Significant coupling between finding IDs and metadata shapes
- Higher effort

**Risk:** Medium

## Recommended Action

Use Option 1: Base metadata interface with common fields. Pragmatic middle ground -- eliminates the worst casts without over-engineering. Option 2 can follow later if needed.

## Acceptance Criteria

- [ ] Common metadata fields are typed
- [ ] Reduction in `as` casts for metadata access
- [ ] Existing tests pass
- [ ] No runtime behavior change

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (multi-agent review)

**Actions:**

- Identified metadata type safety gap as cross-cutting issue

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
