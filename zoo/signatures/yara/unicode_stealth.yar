/*
    GlassWorm Unicode Stealth Detection
    Detects invisible Unicode variation selectors used to hide malicious code

    IMPORTANT: This rule requires MANY variation selectors plus eval/Function.
    A few zero-width characters are normal in i18n bundles.
*/

rule MAL_JS_GlassWorm_Unicode_Stealth_Jan25 {
  meta:
    description = "Detects GlassWorm-style invisible Unicode variation selectors used to hide malicious code"
    severity    = "critical"
    score       = "95"
    author      = "vsix-audit"
    date        = "2025-01-29"
    reference   = "https://www.koi.security/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace"

  strings:
    // UTF-8 encoded variation selectors (U+FE00-U+FE0F)
    // Note: These are 3-byte UTF-8 sequences EF B8 80 through EF B8 8F
    $vs_utf8 = { EF B8 (80 | 81 | 82 | 83 | 84 | 85 | 86 | 87 | 88 | 89 | 8A | 8B | 8C | 8D | 8E | 8F) }

    // Code execution patterns - must have eval or Function
    $eval     = "eval(" ascii wide
    $function = "new Function(" ascii wide

    // Decode patterns that are used to extract the hidden code
    $decode1 = "String.fromCharCode" ascii wide
    $decode2 = "charCodeAt" ascii wide

    // Zero-width space (U+200B) - used in obfuscation
    $zws = { E2 80 8B }

    // Zero-width non-joiner (U+200C) and joiner (U+200D)
    $zwc = { E2 80 (8C | 8D) }

  condition:
    // Require VERY MANY variation selectors (50+) for standalone detection
    // Normal i18n/emoji bundles have < 30, malware has hundreds
    (#vs_utf8 > 50 and any of ($eval, $function)) or
    // Or: moderate VS count + both eval AND decode (full chain)
    (#vs_utf8 > 20 and any of ($eval, $function) and any of ($decode*)) or
    // Or: many zero-width chars + eval (different obfuscation style)
    ((#zws + #zwc) > 30 and any of ($eval, $function))
}

// REMOVED: GlassWorm_Suspicious_Code_Gaps
// This rule was removed earlier - it matched any code with whitespace.
