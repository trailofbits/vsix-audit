---
status: complete
priority: p2
issue_id: "013"
tags: [performance, memory, optimization]
dependencies: []
---

# Pre-compute string contents once per scan to eliminate redundant conversions

## Problem Statement

Each check module independently calls `buffer.toString("utf8")` on the same files. For a 5MB JS file, this creates ~10MB strings (UTF-16) per module -- 5 modules = 50MB of transient allocations for one file.

## Findings

- `src/scanner/checks/obfuscation.ts:127,470` -- `buffer.toString("utf8")`
- `src/scanner/checks/ioc.ts:83,113,211` -- same
- `src/scanner/checks/telemetry.ts:562` -- same + builds separate `allFileContents` Map
- `src/scanner/checks/ast.ts:542` -- same
- Performance agent estimates 40-60% reduction in string allocation overhead

## Proposed Solutions

### Option 1: Convert once in scanExtension, pass string map

**Approach:** In `src/scanner/index.ts`, convert each Buffer to string once, store in `Map<string, string>`, pass to check modules alongside the Buffer map.

**Pros:**

- Eliminates 4-5x redundant conversions per file
- Saves 200MB+ transient allocations for typical extension

**Cons:**

- Requires changing check function signatures or extending VsixContents

**Risk:** Low

## Recommended Action

Use Option 1: Convert once in `scanExtension`, pass string map. Best done alongside issue 012 (CheckModule interface) -- the `ScanContext` object naturally carries the string cache.

## Acceptance Criteria

- [ ] Each file converted to string at most once per scan
- [ ] Telemetry module's `allFileContents` uses shared cache
- [ ] Memory profiling confirms reduced allocations
- [ ] Existing tests pass

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (performance-oracle agent)

**Actions:**

- Identified redundant Buffer-to-string conversions across 5 modules

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
