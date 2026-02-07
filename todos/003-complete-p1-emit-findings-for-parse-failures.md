---
status: complete
priority: p1
issue_id: "003"
tags: [security, error-handling, coverage-degradation]
dependencies: []
---

# Emit findings for parse/scan failures instead of silently skipping

## Problem Statement

19 bare `catch {}` blocks exist across the codebase. Several are in security-critical paths where silent failure means a malicious extension could evade detection. For a security scanner, unparseable files and scan failures are signals, not non-events.

## Findings

**Security-critical silent failures:**

- `src/scanner/checks/ast.ts:441` -- AST parse failure silently returns empty findings. A file crafted to crash the parser is never analyzed.
- `src/scanner/checks/package.ts:485` -- Malformed package.json silently skips all dependency analysis (typosquatting, lifecycle scripts, blocklist).
- `src/scanner/checks/yara.ts:250` -- YARA rule file parse failure silently ignored. Corrupted rules degrade signature coverage with no warning.
- `src/scanner/checks/yara.ts:393-399` -- YARA scan errors have a no-op catch block. The comment says "silently ignore scan errors."
- `src/scanner/checks/yara.ts:405` -- Temp cleanup failure could leak extension data to /tmp.

**Acceptable silent catches (filesystem existence checks):**

- `src/scanner/cache.ts:87,107,134,174` -- TOCTOU avoidance
- `src/scanner/loaders/zoo.ts:27,36` -- Path probing fallback
- `src/scanner/checks/yara.ts:100,109` -- Same pattern
- `src/scanner/checks/telemetry.ts:147,198,215` -- URL parsing

**Consensus:** Identified by Security, Architecture, Pattern, and TypeScript agents (4/6).

## Proposed Solutions

### Option 1: Emit low-severity informational findings

**Approach:** In security-critical catch blocks, push a `Finding` with severity `low` and category `"pattern"` indicating the file could not be analyzed. Include the error message.

**Pros:**

- Users see degraded coverage in scan results
- Suspicious files that crash parsers become visible
- No architecture change needed

**Cons:**

- Adds noise for legitimate parse failures (e.g., binary files misdetected as JS)

**Risk:** Low

### Option 2: Add error aggregation to CheckSummary

**Approach:** Extend `CheckSummary` type to include an `errors` array. Each catch block appends to it. The CLI displays a "degraded coverage" warning.

**Pros:**

- Separates scan errors from findings
- Cleaner reporting

**Cons:**

- Requires type changes and CLI output changes

**Risk:** Medium

## Recommended Action

Use Option 1: Emit low-severity informational findings for the 5 security-critical catch blocks. Leave the acceptable silent catches (TOCTOU, path probing, URL parsing) as-is. Focus on ast.ts, package.ts, and yara.ts.

## Acceptance Criteria

- [ ] AST parse failures emit a finding or warning
- [ ] Malformed package.json emits a finding
- [ ] YARA scan errors are surfaced (at minimum logged)
- [ ] YARA rule file read errors are surfaced
- [ ] Existing tests still pass
- [ ] New tests verify findings are emitted on parse failure

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (multi-agent review)

**Actions:**

- Catalogued all 19 bare catch blocks
- Categorized as acceptable vs concerning
- Identified 5 security-critical silent failures

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
