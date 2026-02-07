# P3: IOC file header convention

## Problem

The new `zoo/iocs/github-c2.txt` file lacks the standardized header format used by other IOC files. Other files like `hashes.txt`, `c2-domains.txt`, and `c2-ips.txt` include:

- Title comment
- Format description comment
- Submission instructions comment
- Blank line before entries

## Location

- `zoo/iocs/github-c2.txt`

## Fix

Add a header matching the convention:

```
# VS Code Extension Malware GitHub C2 Accounts
# Format: username  # Campaign - Notes
#
# Submit new accounts via PR or issue

aykhanmv  # TheseVibesAreOff - ScreenConnect RAT delivery via GitHub releases
```

## Severity

P3 - Documentation convention, no functional impact.
