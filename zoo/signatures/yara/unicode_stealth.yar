/*
    GlassWorm Unicode Stealth Detection
    Detects invisible Unicode variation selectors used to hide malicious code

    IMPORTANT: This rule requires MANY variation selectors plus eval/Function.
    A few zero-width characters are normal in i18n bundles.
*/

rule GlassWorm_Unicode_Stealth {
    meta:
        description = "Detects GlassWorm-style invisible Unicode code hiding"
        severity = "critical"
        score = "95"
        author = "vsix-audit"
        date = "2025-01-29"

    strings:
        // UTF-8 encoded variation selectors (U+FE00-U+FE0F)
        // Note: These are 3-byte UTF-8 sequences EF B8 80 through EF B8 8F
        $vs_utf8 = { EF B8 (80 | 81 | 82 | 83 | 84 | 85 | 86 | 87 | 88 | 89 | 8A | 8B | 8C | 8D | 8E | 8F) }

        // Code execution patterns - must have eval or Function
        $eval = "eval(" ascii wide
        $function = "new Function(" ascii wide

        // Decode patterns that are used to extract the hidden code
        $decode1 = "String.fromCharCode" ascii wide
        $decode2 = "charCodeAt" ascii wide

    condition:
        // Require MANY variation selectors (10+) to avoid i18n false positives
        #vs_utf8 > 10 and any of ($eval, $function) and any of ($decode*)
}

// REMOVED: GlassWorm_Suspicious_Code_Gaps
// This rule was removed earlier - it matched any code with whitespace.
