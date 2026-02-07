# P2: Case-insensitive matching gap in checkGithubC2

## Problem

`checkGithubC2` in `src/scanner/checks/ioc.ts:279-323` uses case-sensitive `content.indexOf(pattern)` to match GitHub URLs. GitHub usernames are case-insensitive, so a C2 account `AykhanMV` would not match `github.com/aykhanmv/` in extension code.

The zoo loader lowercases accounts via `parseIOCFile(githubC2Content, (username) => username.toLowerCase())` in `zoo.ts`, but the file content being searched is not lowercased.

## Location

- `src/scanner/checks/ioc.ts:295` (`content.indexOf(pattern)`)

## Fix

Either:

1. Convert `content` to lowercase before matching (preferred - simpler), or
2. Use a case-insensitive search utility

Ensure the fix does not break line number computation (if lowercasing, compute `lineStarts` before or use original content for line lookup).

## Severity

P2 - Detection bypass through case variation.
