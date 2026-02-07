---
status: complete
priority: p2
issue_id: "014"
tags: [performance, yara, optimization]
dependencies: []
---

# Combine YARA rule files into single scan invocation

## Problem Statement

Each YARA rule file triggers a separate `yr scan` subprocess. With N rule files, this spawns N processes sequentially, each re-traversing the temp directory and recompiling rules from source.

## Findings

- `src/scanner/checks/yara.ts:348-399` -- Sequential loop over rule files, each spawning `execFile("yr", ...)`
- Each process: fork+exec (~5-15ms) + rule compilation + directory traversal
- With 20+ rule files: 100-300ms of pure process overhead
- YARA-X supports multiple `-r` flags or compiled rulesets (`.yarc`)

## Proposed Solutions

### Option 1: Single invocation with multiple -r flags

**Approach:** Build one `yr scan` command with all rule files: `yr scan -r rule1.yar -r rule2.yar ... tempDir`

**Pros:**

- N process spawns reduced to 1
- Single directory traversal

**Cons:**

- Need to parse combined output to attribute findings to specific rules
- Need to verify yr supports multiple -r flags

**Risk:** Low-Medium

### Option 2: Pre-compiled ruleset (.yarc)

**Approach:** At build/install time, compile all rules into a single `.yarc` file.

**Pros:**

- Eliminates per-scan compilation
- Single file to manage

**Cons:**

- Build step required
- Stale compiled rules if source changes

**Risk:** Medium

## Recommended Action

Start with Option 1: Multiple `-r` flags. Verify `yr scan` supports this first, then implement. Option 2 (.yarc) can be a follow-up optimization if compilation time is still significant.

## Acceptance Criteria

- [ ] Single yr process invocation per scan (or compiled ruleset)
- [ ] All rule matches still correctly attributed
- [ ] Measurable reduction in YARA scan time
- [ ] Existing tests pass

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (performance-oracle agent)

**Actions:**

- Identified sequential YARA rule execution as performance bottleneck

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
