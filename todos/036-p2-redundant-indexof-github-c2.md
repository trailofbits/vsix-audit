# P2: Redundant indexOf in checkGithubC2

## Problem

In `src/scanner/checks/ioc.ts:295-300`, the code calls `content.indexOf(pattern)` to check if the pattern exists, but then calls `findLineNumberByString(content, pattern, lineStarts)` which internally also searches for the pattern. This results in scanning the content twice for each pattern match.

## Location

- `src/scanner/checks/ioc.ts:295-300`

## Fix

Use the `idx` from `indexOf` to compute the line number directly from `lineStarts` (binary search on the offset), avoiding the redundant search in `findLineNumberByString`. Alternatively, use a variant of `findLineNumberByString` that accepts an offset.

Check how other check functions handle this pattern for consistency.

## Severity

P2 - Minor performance inefficiency, but more importantly a code quality issue.
