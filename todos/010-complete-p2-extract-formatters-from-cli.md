---
status: complete
priority: p2
issue_id: "010"
tags: [refactor, cli, srp]
dependencies: []
---

# Extract formatters from cli.ts into separate modules

## Problem Statement

`cli.ts` at 824 lines mixes command definitions, output formatting (text/JSON/SARIF), and utilities. The output formatting switch is duplicated across 3 scan modes.

## Findings

- `src/cli.ts` -- 824 lines, violates SRP
- `toSarif()` (lines 716-748), `printTextReport()` (lines 653-708), `printBatchSummary()` (lines 763-824) are pure formatting functions
- Output format switch (`json`/`sarif`/`text`) duplicated 3 times (lines 161-179, 257-269, 300-306)
- `severityColor` mapping defined identically in two places (lines 692, 798)
- Error handling pattern repeated 6 times

## Proposed Solutions

### Option 1: Extract to src/formatters/

**Approach:** Move SARIF, text, and batch formatters to `src/formatters/{sarif,text}.ts`. Create shared `outputResult(result, format)` dispatch function.

**Pros:**

- Reduces cli.ts to ~400 lines
- Formatters become independently testable
- Single output dispatch eliminates 3x duplication

**Cons:**

- New module boundary

**Risk:** Low

## Recommended Action

Use Option 1: Extract to `src/formatters/`. Do this after issue 007 (SARIF fix) to avoid merge conflicts -- the SARIF formatter will be extracted in its corrected form.

## Acceptance Criteria

- [ ] Formatters extracted to separate modules
- [ ] Single output dispatch function
- [ ] cli.ts under 500 lines
- [ ] All output formats produce identical results
- [ ] Existing tests pass

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (multi-agent review)

**Actions:**

- Identified cli.ts as monolith with extractable formatting logic

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
