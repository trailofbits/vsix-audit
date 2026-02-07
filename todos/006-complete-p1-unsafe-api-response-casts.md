---
status: complete
priority: p1
issue_id: "006"
tags: [type-safety, api, download]
dependencies: []
---

# Add runtime validation for external API response casts

## Problem Statement

Three external registry API responses are cast with `as` without any runtime validation. If a registry changes its response shape, the code silently produces undefined values.

## Findings

- `src/scanner/download.ts:168` -- `(await response.json()) as GalleryResponse`
- `src/scanner/download.ts:240` -- `(await response.json()) as OpenVSXExtension`
- `src/scanner/download.ts:300` -- `(await response.json()) as GalleryResponse`
- Subsequent optional chaining masks structural validation failures
- Identified by TypeScript and Pattern agents

## Proposed Solutions

### Option 1: Manual shape validation

**Approach:** Add a `validateGalleryResponse(data: unknown): GalleryResponse` function that checks critical fields exist and have correct types before returning.

**Pros:**

- No new dependencies
- Clear error messages on API changes

**Cons:**

- Verbose validation code

**Risk:** Low

### Option 2: Lightweight schema library

**Approach:** Use valibot or zod for response validation schemas.

**Pros:**

- Declarative, maintainable
- Type inference from schema

**Cons:**

- New dependency (against project philosophy of minimal deps)

**Risk:** Medium (dependency concern)

## Recommended Action

Use Option 1: Manual shape validation. Project has only 3 runtime deps and adding a schema library contradicts that philosophy. A small `validateGalleryResponse` / `validateOpenVSXResponse` pair keeps it dependency-free.

## Acceptance Criteria

- [ ] All three API responses are validated at runtime before use
- [ ] Clear error message when response shape is unexpected
- [ ] Existing tests still pass

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (multi-agent review)

**Actions:**

- Identified 3 unsafe response casts in download.ts

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
