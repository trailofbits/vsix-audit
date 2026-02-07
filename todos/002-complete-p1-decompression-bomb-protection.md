---
status: complete
priority: p1
issue_id: "002"
tags: [security, zip, dos]
dependencies: []
---

# Add decompression bomb protection to ZIP extraction

## Problem Statement

`extractEntry()` in `vsix.ts` has no validation of decompression ratio or total uncompressed size. A malicious VSIX could contain a zip bomb that expands to gigabytes, causing OOM.

## Findings

- `src/scanner/vsix.ts:141-151` -- `inflateRawSync(compressedData)` has no size limit
- `src/scanner/vsix.ts:153-154` -- `readFile(vsixPath)` loads entire ZIP into memory
- The 10MB skip in YARA (`yara.ts:337`) only applies to YARA scanning, not extraction
- Every file is extracted into the `files` Map regardless of size
- PoC: A 1KB compressed entry decompressing to 4GB would crash the process

## Proposed Solutions

### Option 1: Validate uncompressedSize from central directory

**Approach:** Before decompressing, check `entry.uncompressedSize` against a maximum (e.g., 500MB) and check compression ratio (`uncompressedSize / compressedSize > 100`).

**Pros:**

- Simple to implement
- Catches most zip bombs
- Central directory already parsed

**Cons:**

- Declared size could be spoofed (but then inflateRawSync output won't match)

**Risk:** Low

### Option 2: Streaming decompression with byte counter

**Approach:** Use streaming inflate that aborts if output exceeds declared size or absolute maximum.

**Pros:**

- Catches bombs even with spoofed headers
- Memory-safe

**Cons:**

- More complex than sync inflate
- Requires architecture change from `inflateRawSync`

**Risk:** Medium

## Recommended Action

Use Option 1: Validate uncompressedSize from central directory header before decompressing. Simple, low-risk, catches the common case. Option 2 can be a follow-up if spoofed headers are a concern.

## Acceptance Criteria

- [ ] Entries with unreasonable uncompressedSize (>500MB) are rejected
- [ ] Compression ratio >100:1 triggers a warning/rejection
- [ ] Total extracted size is bounded
- [ ] Test with crafted zip bomb input
- [ ] Existing tests still pass

## Work Log

### 2026-02-06 - Review Finding

**By:** Claude Code (security-sentinel agent)

**Actions:**

- Identified missing decompression bomb protection
- Assessed as HIGH severity -- only finding above MEDIUM from security review

### 2026-02-06 - Approved for Work

**By:** Claude Triage System

**Actions:**

- Issue approved during triage session
- Status changed from pending to ready
- Ready to be picked up and worked on
