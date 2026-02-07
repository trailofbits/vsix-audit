# P1: Deduplicate YARA finding-creation code

## Problem

The YARA scanner has duplicated finding-creation logic in `src/scanner/checks/yara.ts`. Lines 365-389 (happy path) and lines 400-424 (error recovery path) contain nearly identical code that constructs `Finding` objects from YARA match metadata.

This violates DRY and means any future changes to finding structure must be made in two places.

## Location

- `src/scanner/checks/yara.ts:365-389` (happy path)
- `src/scanner/checks/yara.ts:400-424` (error recovery path)

## Fix

Extract a helper function like `buildYaraFinding(match, meta, filename)` that both code paths call. This function should handle:

- Severity casting with validation
- Finding object construction
- Default severity fallback

## Severity

P1 - Code duplication in a security-critical path increases risk of inconsistent behavior.
