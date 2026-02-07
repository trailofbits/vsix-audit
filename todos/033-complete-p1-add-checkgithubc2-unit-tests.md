# P1: Add unit tests for checkGithubC2

## Problem

The new `checkGithubC2` function in `src/scanner/checks/ioc.ts:279-323` has no dedicated unit tests. The only test coverage is indirect through `checkIocs` integration. The existing test fixtures add `githubC2Accounts: new Set()` but never test with actual accounts.

## Location

- `src/scanner/checks/ioc.ts:279-323` (function under test)
- `src/scanner/checks/ioc.test.ts` (test file to add tests to)

## Required Tests

1. Returns empty array when `githubC2Accounts` is empty
2. Detects `github.com/{account}/` pattern
3. Detects `api.github.com/repos/{account}/` pattern
4. Detects `raw.githubusercontent.com/{account}/` pattern
5. Does not match partial account names (e.g., account "foo" should not match "foobar")
6. Skips non-scannable files (binary files)
7. Reports correct line number in finding
8. Breaks after first pattern match per account per file (no duplicate findings)

## Severity

P1 - New detection capability with zero test coverage.
