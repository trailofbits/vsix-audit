# P2: Unsafe `as` cast for YARA severity type

## Problem

In `src/scanner/checks/yara.ts`, the severity from YARA rule metadata is cast with:

```typescript
(meta.severity as "low" | "medium" | "high" | "critical") ?? "medium";
```

This appears at both lines ~375 and ~410 (in the duplicated finding-creation code). The `as` cast bypasses TypeScript's type checking - if a YARA rule has `severity = "extreme"` or any other unexpected value, it would pass through unchecked and potentially cause issues downstream.

## Location

- `src/scanner/checks/yara.ts:375` (happy path)
- `src/scanner/checks/yara.ts:410` (error recovery path)

## Fix

Add runtime validation:

```typescript
const VALID_SEVERITIES = new Set(["low", "medium", "high", "critical"]);
const severity = VALID_SEVERITIES.has(meta.severity)
  ? (meta.severity as Finding["severity"])
  : "medium";
```

This should be part of the extracted `buildYaraFinding` helper (see todo #032).

## Severity

P2 - Type safety gap in security-critical code.
