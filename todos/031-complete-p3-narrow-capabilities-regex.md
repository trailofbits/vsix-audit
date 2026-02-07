---
status: complete
priority: p3
issue_id: "031"
tags: [accuracy, manifest, false-positives]
dependencies: []
---

# Narrow overly broad capabilities regex patterns

## Problem Statement

Some capabilities detection patterns in the manifest checker are too broad, matching common words and producing excessive false positives.

## Findings

- `src/scanner/checks/manifest.ts` -- Patterns like `/KEY/i` and `/FILE/i` match nearly any extension
- `KEY` matches "keyboard", "monkey", etc.
- `FILE` matches any file operation capability
- These generate noise that makes triage harder

## Proposed Solutions

### Option 1: Require word boundaries or more specific patterns

**Approach:** Change `/KEY/i` to `/\bapi[_-]?key\b/i` or similar targeted patterns. Require context like "secret", "token", "credential" nearby.

**Pros:** Fewer false positives, better signal-to-noise ratio

**Risk:** Low-Medium (might miss creative obfuscation)

## Recommended Action

Use Option 1: Add word boundaries and require more specific patterns. Test against known malicious samples in vsix-zoo to verify no regression before merging.

## Acceptance Criteria

- [ ] Broad patterns narrowed with word boundaries or context
- [ ] False positive rate reduced on common extensions
- [ ] No regression on known malicious samples
- [ ] Existing tests pass

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (code-simplicity-reviewer agent)

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
