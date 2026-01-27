/*
    GlassWorm Unicode Stealth Detection
    Detects invisible Unicode variation selectors used to hide malicious code
    Based on GlassWorm attack using U+FE00-U+FE0F and U+E0100-U+E01EF ranges
*/

rule GlassWorm_Unicode_Stealth {
    meta:
        description = "Detects GlassWorm-style invisible Unicode code hiding"
        severity = "high"
        score = "90"
        author = "Kirin Scanner (by Knostic)  - GlassWorm Detection Suite"
        date = "2025-10-18"
        reference = "https://www.koi.ai/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace"
    
    strings:
        // Unicode Variation Selectors (U+FE00-U+FE0F) - most common for code hiding
        $vs1 = { FE 00 } // Variation Selector-1
        $vs2 = { FE 01 } // Variation Selector-2
        $vs3 = { FE 02 } // Variation Selector-3
        $vs4 = { FE 03 } // Variation Selector-4
        $vs5 = { FE 04 } // Variation Selector-5
        $vs6 = { FE 05 } // Variation Selector-6
        $vs7 = { FE 06 } // Variation Selector-7
        $vs8 = { FE 07 } // Variation Selector-8
        $vs9 = { FE 08 } // Variation Selector-9
        $vs10 = { FE 09 } // Variation Selector-10
        $vs11 = { FE 0A } // Variation Selector-11
        $vs12 = { FE 0B } // Variation Selector-12
        $vs13 = { FE 0C } // Variation Selector-13
        $vs14 = { FE 0D } // Variation Selector-14
        $vs15 = { FE 0E } // Variation Selector-15
        $vs16 = { FE 0F } // Variation Selector-16
        
        // Variation Selectors Supplement (U+E0100-U+E01EF)
        $vss1 = { F3 A0 84 80 } // Variation Selector-17 (UTF-8 encoded)
        $vss2 = { F3 A0 84 81 } // Variation Selector-18
        $vss3 = { F3 A0 84 82 } // Variation Selector-19
        $vss4 = { F3 A0 84 83 } // Variation Selector-20
        $vss5 = { F3 A0 84 84 } // Variation Selector-21
        
        // Zero Width Characters commonly used for steganography
        $zwsp = { E2 80 8B } // Zero Width Space (U+200B)
        $zwnj = { E2 80 8C } // Zero Width Non-Joiner (U+200C)
        $zwj = { E2 80 8D } // Zero Width Joiner (U+200D)
        $zwnb = { E2 80 8E } // Zero Width No-Break Space (U+200E)
        $zwl = { E2 80 8F } // Zero Width Left-to-Right Mark (U+200F)
        
        // Suspicious patterns that might indicate hidden code
        $eval = "eval(" ascii wide
        $function = "Function(" ascii wide
        $atob = "atob(" ascii wide
        $btoa = "btoa(" ascii wide
        $buffer = "Buffer.from" ascii wide
        $base64 = "base64" nocase ascii wide
        
    condition:
        // High confidence: Multiple variation selectors + suspicious code patterns
        (2 of ($vs*) or 2 of ($vss*) or 3 of ($zwsp, $zwnj, $zwj, $zwnb, $zwl)) and 
        (any of ($eval, $function, $atob, $btoa, $buffer, $base64))
}

rule GlassWorm_Suspicious_Code_Gaps {
    meta:
        description = "Detects suspicious gaps in code that might hide invisible characters"
        severity = "medium"
        score = "60"
        author = "Kirin Scanner (by Knostic)  - GlassWorm Detection Suite"
        date = "2025-10-18"
    
    strings:
        // Patterns that suggest code gaps or unusual spacing
        $empty_line = /\n\s*\n\s*\n/ ascii wide
        $large_gap = /\n\s{10,}\n/ ascii wide
        $invisible_chars = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/ ascii wide
        
        // Common JavaScript patterns that might be hiding code
        $js_patterns = /function\s*\(|var\s+\w+|let\s+\w+|const\s+\w+/ ascii wide
        
    condition:
        // Detect suspicious gaps combined with JavaScript patterns
        ($empty_line or $large_gap or $invisible_chars) and $js_patterns
}
