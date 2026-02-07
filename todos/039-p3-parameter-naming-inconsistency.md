# P3: Parameter naming inconsistency in checkGithubC2

## Problem

The `checkGithubC2` function uses `githubC2Accounts: Set<string>` as its parameter name, while other similar check functions use shorter, more consistent names. For example, `checkKnownC2Domains` uses `c2Domains`, `checkKnownC2Ips` uses `c2Ips`.

## Location

- `src/scanner/checks/ioc.ts:279` (function signature)

## Fix

Consider renaming to `c2Accounts` or `githubAccounts` for consistency with sibling functions. This is a minor style issue.

## Severity

P3 - Naming convention, no functional impact.
