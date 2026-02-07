---
status: complete
priority: p1
issue_id: "007"
tags: [sarif, correctness]
dependencies: []
---

# Fix SARIF severity mapping and add rules array

## Problem Statement

SARIF output maps `low` severity to `warning` instead of `note`, and is missing the `tool.driver.rules` array that SARIF viewers need for rule descriptions.

## Findings

- `src/cli.ts:732` -- `low` and `medium` both map to `"warning"`; SARIF 2.1.0 spec says `low` should be `note`
- No `rules` array in SARIF output -- viewers can't display rule descriptions or help URIs
- `SarifReport.runs` typed as `object[]` -- no compile-time validation of SARIF structure

## Proposed Solutions

### Option 1: Fix mapping + add rules array

**Approach:**

1. Map `low` to `"note"`, `medium` to `"warning"`, `high`/`critical` to `"error"`
2. Add `tool.driver.rules` array with rule IDs and descriptions
3. Type the SARIF run structure properly

**Pros:**

- Spec-compliant output
- Better viewer integration

**Cons:**

- Rules array requires enumerating all possible finding IDs

**Risk:** Low

## Recommended Action

Use Option 1: Fix severity mapping, add rules array, and type the SARIF run. The rules array can be built dynamically from the findings in each scan result rather than enumerating all possible IDs upfront.

## Acceptance Criteria

- [ ] `low` findings map to SARIF level `note`
- [ ] `medium` findings map to `warning`
- [ ] `high`/`critical` map to `error`
- [ ] SARIF output includes `tool.driver.rules` array
- [ ] SARIF structure is properly typed (not `object[]`)

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (architecture-strategist agent)

**Actions:**

- Identified incomplete SARIF level mapping
- Identified missing rules array

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
