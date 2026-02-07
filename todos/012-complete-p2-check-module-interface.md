---
status: complete
priority: p2
issue_id: "012"
tags: [architecture, extensibility, refactor]
dependencies: []
---

# Define formal CheckModule interface for scanner modules

## Problem Statement

Check modules have inconsistent signatures (some take ZooData, some don't; one is async). The orchestrator manually wires each with ~15 lines of boilerplate. `ModuleTimings` hardcodes module names.

## Findings

- `src/scanner/index.ts:96-232` -- 6 blocks of ~15 lines of identical boilerplate
- Module signatures vary: `(VsixContents)`, `(VsixContents, ZooData)`, `(VsixContents) => Promise<Finding[]>`
- `src/scanner/types.ts:5-14` -- `ModuleTimings` hardcodes module names as optional properties
- Adding a new module requires changes in 3 files

## Proposed Solutions

### Option 1: Uniform ScanModule interface with context object

**Approach:** Define a `ScanContext` containing `VsixContents` and `ZooData`. Each module conforms to `(context: ScanContext) => Promise<Finding[]>`. Replace `ModuleTimings` with `Record<string, number>`.

**Pros:**

- Loop-based orchestration
- Adding a module = one file + one array entry

**Cons:**

- Modules that don't need ZooData still receive it

**Risk:** Low

## Recommended Action

Use Option 1: Uniform `ScanModule` interface with `ScanContext`. Pairs naturally with issue 013 (pre-computed string contents) -- the shared context object carries both buffers and string cache.

## Acceptance Criteria

- [ ] Common CheckModule interface defined
- [ ] Orchestrator uses loop instead of 6 manual blocks
- [ ] ModuleTimings uses dynamic keys
- [ ] Adding a module requires changes in 1-2 files (not 3)

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (architecture + pattern agents)

**Actions:**

- Identified inconsistent module signatures
- Identified hardcoded ModuleTimings type

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
