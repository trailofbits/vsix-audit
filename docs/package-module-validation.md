# Package Module Validation Results

**Date**: 2026-01-29
**Module**: `package`
**Test corpus**: 456 extensions (438 in test-corpus/, 10 in test-corpus/malicious/, ~8 bundled)

## Summary

| Severity  | Count   |
| --------- | ------- |
| Critical  | 15      |
| High      | 142     |
| Medium    | 141     |
| **Total** | **298** |

**Scan Status**: Completed successfully with no crashes.

## Finding Breakdown by Type

| Finding Type                         | Count | Category |
| ------------------------------------ | ----- | -------- |
| Potential typosquatting package      | 108   | HIGH     |
| Extension activates on startup       | 78    | MEDIUM   |
| Has postinstall script               | 53    | MEDIUM   |
| Extension activates on all events    | 23    | HIGH     |
| Known malicious npm package          | 14    | CRITICAL |
| Theme extension has code entry point | 11    | HIGH     |
| Has preinstall script                | 7     | MEDIUM   |
| Has postpublish script               | 2     | MEDIUM   |
| Has prepublish script                | 1     | MEDIUM   |
| Extension on malware blocklist       | 1     | CRITICAL |

## True Positives

### 1. Blocklist Hit - priskinski.Theme-AllHallowsEve-remake

**Extension**: `test-corpus/malicious/priskinski.theme-allhallowseve-remake-1.0.0.vsix`
**Finding**: `BLOCKLIST_MATCH` - matches `priskinski.*` blocklist pattern
**Verdict**: TRUE POSITIVE - This is a known ReversingLabs-Dec2025 campaign sample

The extension correctly triggered:

- `BLOCKLIST_MATCH` (critical)
- `ACTIVATION_WILDCARD` (high) - uses `"activationEvents": ["*"]`
- `THEME_WITH_CODE` (high) - theme with executable code

### 2. Activation Warnings

Extensions flagged for `onStartupFinished` or `*` activation events are informational. Examples of legitimate use:

- GitLens - needs startup for status bar integration
- Continue - AI assistant needs early initialization
- Language servers - need startup for file watching

## Malware Sample Detection Results

Tested 10 known malicious samples from vsix-zoo:

| Sample                               | Extension ID                            | Detection              | Notes                |
| ------------------------------------ | --------------------------------------- | ---------------------- | -------------------- |
| priskinski (ReversingLabs-Dec2025)   | `priskinski.Theme-AllHallowsEve-remake` | ✅ BLOCKLIST           | True positive        |
| react-native-vscode (malwarebazaar)  | `msjsdreact.react-native-vscode`        | ⚠️ event-stream        | Weak signal only     |
| **icon-theme-materiall (GlassWorm)** | `Iconkieftwo.icon-theme-materiall`      | ❌ MISSED              | Case sensitivity bug |
| latex-workshop (kirill89)            | `James-Yu.latex-workshop`               | ❌ Not detected        | Backdoored clone     |
| rainbow-fart (kirill89)              | `saekiraku.rainbow-fart`                | ❌ Not detected        | Backdoored clone     |
| vscode-instant-markdown (kirill89)   | `dbankier.vscode-instant-markdown`      | ❌ Not detected        | Backdoored clone     |
| open-html-in-browser (kirill89)      | `peakchen90.open-html-in-browser`       | ❌ Not detected        | Backdoored clone     |
| extension-attack-suite (ecm3401)     | `ecm3401.extension-attack-suite`        | ❌ Not detected        | Educational sample   |
| malicious-api-extension (ecm3401)    | `ecm3401.malicious-api-extension`       | ⚠️ Wildcard activation | Weak signal only     |
| example-api-extension (ecm3401)      | `ecm3401.example-api-extension`         | ❌ Not detected        | Educational sample   |

### Analysis

1. **GlassWorm missed due to case sensitivity bug** - Blocklist has `iconkieftwo.*` but extension uses `Iconkieftwo.*`
2. **kirill89 samples use legitimate publisher IDs** - These are backdoored clones of real extensions, not detectable via blocklist
3. **ecm3401 samples are educational** - Research samples not in threat intel

## False Negatives (Bugs)

### 1. Case-Sensitive Blocklist Matching

**Bug**: Extension ID matching is case-sensitive
**Impact**: GlassWorm sample `Iconkieftwo.icon-theme-materiall` not matched against `iconkieftwo.*`
**Location**: `src/scanner/checks/package.ts:126-132`
**Fix**: Use case-insensitive comparison for extension IDs

```typescript
// Current (broken)
return extensionId === pattern;

// Should be
return extensionId.toLowerCase() === pattern.toLowerCase();
```

## False Positives

### 1. Typosquatting: `chai` flagged as typosquat of `chalk`

**Impact**: 20+ extensions affected (Microsoft, GitLens, etc.)
**Issue**: Edit distance of 2 between `chai` and `chalk`
**Reality**: `chai` is a famous testing library with 9M+ weekly downloads
**Recommendation**: Add `chai` to a whitelist of known-good packages

Affected extensions:

- ms-vscode.cpptools (Microsoft C/C++)
- IntelliCode
- Java extension
- GitHub Copilot for Azure
- Many others

### 2. Typosquatting: `open` flagged as typosquat of `openai`

**Impact**: 10+ extensions affected
**Issue**: Edit distance of 2 between `open` and `openai`
**Reality**: `open` is a legitimate package for opening URLs in browsers (5M+ downloads)
**Recommendation**: Add `open` to whitelist

Affected extensions:

- Azure Storage
- Solidity (Wake)
- Various file-opening utilities

### 3. Typosquatting: `core` flagged as typosquat of `cors`

**Impact**: 5+ extensions affected
**Issue**: Edit distance of 1 between `core` and `cors`
**Reality**: `core` is commonly used as a package name
**Recommendation**: Increase minimum length for edit-distance checks or add to whitelist

### 4. Typosquatting: `uuid4` flagged as typosquat of `uuid`

**Impact**: 5+ extensions
**Issue**: Edit distance of 1
**Reality**: `uuid4` is a legitimate UUID generation package
**Recommendation**: Add to whitelist

### 5. Malicious npm package: `event-stream` in devDependencies

**Impact**: 14 major Microsoft extensions flagged
**Issue**: `event-stream` is in the malicious package list due to the 2018 flatmap-stream attack
**Reality**: The malicious version was 3.3.6. Current version (4.0.1) is safe. Additionally, it's in devDependencies (not bundled).
**Recommendation**:

1. Consider version-aware checks (only flag 3.3.6)
2. Optionally skip devDependencies in bundled extensions (they aren't included in the vsix)
3. At minimum, note in the finding description that version/context matters

Affected extensions:

- ms-vscode.cpptools (C/C++)
- VSCodeVim.vim
- ms-vscode.coder
- ms-python.python
- ms-toolsai.jupyter
- React Native Tools
- CMake Tools
- Many others

## Recommendations

### Critical Fixes

0. **Fix case-sensitive blocklist matching**
   - Extension IDs should match case-insensitively
   - Currently missing GlassWorm sample due to `Iconkieftwo` vs `iconkieftwo`
   - Simple fix in `matchesWildcard()` function

### High Priority Fixes

1. **Add whitelist for known-good packages**
   - `chai` - testing library
   - `open` - URL opener
   - `uuid4` - UUID generation
   - `core` - generic name
   - `acorn` - JavaScript parser (flagged as typosquat of `cors`)

2. **Make malicious npm check version-aware**
   - `event-stream@3.3.6` was malicious
   - `event-stream@4.0.1` is clean
   - Consider flagging only known-bad versions

3. **Consider skipping devDependencies**
   - devDependencies aren't bundled in vsix files
   - They're only used during development
   - Option: Add flag to skip or lower severity

### Medium Priority

4. **Increase edit distance threshold or minimum package name length**
   - Short package names (3-4 chars) create many false positives
   - Consider requiring length >= 6 for edit distance checks

5. **Add context to lifecycle script findings**
   - Many legitimate extensions have postinstall scripts
   - Consider noting common legitimate uses (downloading language servers, etc.)

### Low Priority

6. **Theme with code warnings**
   - Many legitimate theme packs include settings sync or preview features
   - Consider lowering severity or adding known-good publishers

## Test Coverage

- [x] Scanner completes without crashes
- [x] All 456 extensions processed
- [x] True positive: Blocklist hit on known malware (priskinski)
- [x] True positive: Activation event warnings are useful context
- [x] False positives identified and documented
- [x] False negative: Case-sensitivity bug found (GlassWorm missed)
- [x] Known limitation: Backdoored clones with legitimate IDs not detectable via package module

## Next Steps

1. **CRITICAL**: Fix case-insensitive blocklist matching
2. Create issue to implement whitelist for legitimate packages
3. Create issue to add version-aware checking for npm packages
4. Consider adding "confidence" field to findings to distinguish strong vs weak signals
5. Note: kirill89-style backdoors need detection via other modules (YARA, code patterns)
