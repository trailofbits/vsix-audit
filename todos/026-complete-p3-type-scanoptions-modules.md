---
status: complete
priority: p3
issue_id: "026"
tags: [typescript, types, safety]
dependencies: ["012"]
---

# Type ScanOptions.modules as ModuleName[] instead of string[]

## Problem Statement

`ScanOptions.modules` is typed as `string[]` instead of a union of known module names, allowing typos and invalid module names to pass type checking.

## Findings

- `src/scanner/types.ts` -- `modules?: string[]` in ScanOptions
- Known modules are a fixed set: obfuscation, ioc, telemetry, yara, ast, package, manifest
- A `ModuleName` type would catch invalid values at compile time

## Proposed Solutions

### Option 1: Define ModuleName union type

**Approach:** Create `type ModuleName = "obfuscation" | "ioc" | "telemetry" | "yara" | "ast" | "package" | "manifest"` and use it for `modules`.

**Pros:**

- Compile-time validation of module names
- Autocomplete in editors

**Risk:** Low

## Recommended Action

Use Option 1: Define `ModuleName` union type. Best done after issue 012 (CheckModule interface) which will formalize the module registry -- derive `ModuleName` from the module definitions.

## Acceptance Criteria

- [ ] `ModuleName` type defined
- [ ] `ScanOptions.modules` uses `ModuleName[]`
- [ ] CLI validation maps user input to typed values
- [ ] Existing tests pass

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (kieran-typescript-reviewer agent)

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Blocked by issue 012 (CheckModule interface)
