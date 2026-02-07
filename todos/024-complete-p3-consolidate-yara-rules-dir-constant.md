---
status: complete
priority: p3
issue_id: "024"
tags: [cleanup, yara, constants]
dependencies: []
---

# Consolidate DEFAULT_YARA_RULES_DIR with async getter

## Problem Statement

`DEFAULT_YARA_RULES_DIR` is exported as a constant alongside `getYaraRulesDir()` which computes the same value asynchronously. Two sources of truth for the same concept.

## Findings

- `src/scanner/checks/yara.ts` -- Both `DEFAULT_YARA_RULES_DIR` constant and `getYaraRulesDir()` async function exist
- The constant is a simple path join; the async version may do validation
- Callers use one or the other inconsistently

## Proposed Solutions

### Option 1: Single source of truth

**Approach:** Keep only the async getter (which can validate the directory exists). Remove the constant or make it private.

**Pros:** Single source of truth, can validate at runtime

**Risk:** Low

## Recommended Action

Use Option 1: Keep only the async getter, make the constant private. Callers should always go through the validated path.

## Acceptance Criteria

- [ ] Single way to get YARA rules directory
- [ ] All callers use the same mechanism
- [ ] Validation happens consistently

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (code-simplicity-reviewer agent)

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
