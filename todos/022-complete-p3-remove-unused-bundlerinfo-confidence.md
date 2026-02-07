---
status: complete
priority: p3
issue_id: "022"
tags: [cleanup, dead-code, types]
dependencies: []
---

# Remove or use BundlerInfo.confidence field

## Problem Statement

`BundlerInfo.confidence` is defined in the type and assigned during detection but never read by any consumer.

## Findings

- `src/scanner/types.ts` -- `BundlerInfo` type includes `confidence` field
- `src/scanner/checks/obfuscation.ts` -- `detectBundler` sets confidence values
- No code reads `confidence` after detection

## Proposed Solutions

### Option 1: Remove the field

**Approach:** Delete `confidence` from `BundlerInfo` and from `detectBundler` return values.

**Pros:** No dead fields in types

**Risk:** Low

### Option 2: Use it in finding severity

**Approach:** Factor `confidence` into obfuscation finding severity (lower confidence = lower severity for bundler-related findings).

**Pros:** More nuanced findings

**Risk:** Low

## Recommended Action

Use Option 1: Remove the field. YAGNI -- if confidence-based severity is needed later, add it then with actual consumers in place.

## Acceptance Criteria

- [ ] `confidence` either removed or actively consumed
- [ ] Types match actual usage

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (pattern-recognition-specialist agent)

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
