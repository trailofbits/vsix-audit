---
status: complete
priority: p3
issue_id: "027"
tags: [security, download, resource-limits]
dependencies: []
---

# Add download size limit to downloadVsixFromUrl

## Problem Statement

`downloadVsixFromUrl` fetches the entire response body into memory with no size limit, making it vulnerable to resource exhaustion from unexpectedly large files.

## Findings

- `src/scanner/download.ts` -- `downloadVsixFromUrl` uses `arrayBuffer()` on response with no Content-Length check
- Typical VSIX files are 1-50MB; a malicious or corrupt URL could serve gigabytes
- Complements issue 002 (decompression bomb) -- this is the download-phase equivalent

## Proposed Solutions

### Option 1: Check Content-Length and stream with limit

**Approach:** Check `Content-Length` header against a configurable max (default 500MB). Use streaming download with running byte count to enforce even when Content-Length is missing or lies.

**Pros:** Protects against both honest and dishonest servers

**Risk:** Low

## Recommended Action

Use Option 1: Check Content-Length + streaming byte counter. Pairs with issue 002 (decompression bomb) for defense-in-depth at both download and extraction phases.

## Acceptance Criteria

- [ ] Downloads abort above size limit
- [ ] Clear error message with actual vs allowed size
- [ ] Configurable limit via ScanOptions or CLI flag
- [ ] Existing tests pass

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (security-sentinel agent)

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
