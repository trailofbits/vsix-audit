---
status: complete
priority: p3
issue_id: "023"
tags: [feature, obfuscation, bundler]
dependencies: []
---

# Add Vite bundler detection

## Problem Statement

`BundlerType` union includes `"vite"` as a possible value, but `detectBundler()` has no logic to identify Vite-bundled output.

## Findings

- `src/scanner/types.ts` -- `BundlerType` includes `"vite"`
- `src/scanner/checks/obfuscation.ts` -- `detectBundler` handles webpack, esbuild, rollup, parcel but not vite
- Vite uses Rollup under the hood for production builds, so some Vite output may be caught by Rollup detection

## Proposed Solutions

### Option 1: Add Vite detection heuristics

**Approach:** Add detection for Vite-specific patterns (e.g., `__vite_ssr_import__`, `import.meta.hot`, Vite manifest comments).

**Pros:** Complete coverage matching the type definition

**Risk:** Low

### Option 2: Remove vite from BundlerType

**Approach:** If Rollup detection covers Vite output sufficiently, remove the separate type.

**Pros:** Types match implementation

**Risk:** Low

## Recommended Action

Use Option 1: Add Vite detection. Vite-specific patterns (`__vite_ssr_import__`, `import.meta.hot`) are distinct from Rollup output. Keeps the type honest and improves bundler attribution.

## Acceptance Criteria

- [ ] Either Vite detection added or type updated to match reality
- [ ] No phantom types without corresponding logic

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (pattern-recognition-specialist agent)

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
