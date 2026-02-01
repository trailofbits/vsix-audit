/*
    JavaScript Obfuscation Pattern Detection
    Detects common obfuscation techniques used to hide malicious code
*/

rule SUSP_JS_Obfuscator_Hex_Vars_Jan25 {
  meta:
    description = "Detects javascript-obfuscator tool signature with _0x prefixed hexadecimal variable names"
    severity    = "high"
    score       = 80
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    // _0x followed by 4+ hex chars - signature of javascript-obfuscator
    $hex_var = /_0x[a-fA-F0-9]{4,}/ ascii wide

  condition:
    #hex_var >= 5
}

rule SUSP_JS_FromCharCode_Chain_Jan25 {
  meta:
    description = "Detects String.fromCharCode with many arguments used to hide string content from static analysis"
    severity    = "high"
    score       = 75
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    // fromCharCode with 5+ comma-separated numbers
    $charcode = /String\.fromCharCode\s*\(\s*(\d+\s*,\s*){5,}/ ascii wide

  condition:
    $charcode
}

rule SUSP_JS_Hex_Escape_Chain_Jan25 {
  meta:
    description = "Detects 10+ consecutive hex escape sequences (\\xNN) indicating obfuscated string content"
    severity    = "medium"
    score       = 60
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    // Consecutive hex escape pairs - provides 8-byte atoms for Aho-Corasick
    // Each matches 2 consecutive \xNN patterns, requiring 5+ matches = 10+ escapes
    $h1 = /\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}/ ascii wide

  condition:
    #h1 >= 5
}

rule SUSP_JS_Decimal_Byte_Array_Jan25 {
  meta:
    description = "Detects large array of 20+ decimal byte values likely containing encoded payload data"
    severity    = "medium"
    score       = 55
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    // Comma-separated number patterns (4-byte atoms)
    // Matches ", NN," patterns - 20+ of these indicates byte array
    $num = /,\s?\d{1,3},/ ascii wide

    // Array opener with number
    $arr_open = /\[\d{1,3},/ ascii wide

  condition:
    $arr_open and #num >= 19
}

rule SUSP_JS_Bracket_Notation_Chain_Jan25 {
  meta:
    description = "Detects long bracket notation property chains used to hide method calls from static analysis"
    severity    = "medium"
    score       = 65
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    // 4+ consecutive bracket notation accesses
    $bracket_chain = /\[\s*['"][a-zA-Z]+['"]\s*\](\s*\[\s*['"][a-zA-Z]+['"]\s*\]){3,}/ ascii wide

  condition:
    $bracket_chain
}

rule SUSP_JS_String_Array_Rotation_Jan25 {
  meta:
    description = "Detects javascript-obfuscator string table pattern with large array and hex variable names"
    severity    = "medium"
    score       = 55
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    // Literal anchors for string array separators (4-byte atoms)
    $sep1 = "','" ascii wide
    $sep2 = "\",\"" ascii wide
    $sep3 = "', '" ascii wide
    $sep4 = "\", \"" ascii wide

    // Array assignment patterns
    $arr1 = "=['" ascii wide
    $arr2 = "=[\"" ascii wide
    $arr3 = "= ['" ascii wide
    $arr4 = "= [\"" ascii wide

    // javascript-obfuscator hex variable (bounded to reduce backtracking)
    $obf_hex_var = /_0x[a-fA-F0-9]{4,8}/ ascii wide

  condition:
    // Require separators + array assignment + multiple hex vars
    (2 of ($sep*)) and (1 of ($arr*)) and #obf_hex_var >= 3
}

rule SUSP_JS_Obfuscation_Eval_Jan25 {
  meta:
    description = "Detects obfuscation patterns like hex vars or fromCharCode combined with eval execution"
    severity    = "critical"
    score       = 95
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    // Obfuscation indicators
    $obf1 = /_0x[a-fA-F0-9]{4,}/ ascii wide
    $obf2 = /\\x[a-fA-F0-9]{2}/ ascii wide
    $obf3 = "String.fromCharCode" ascii wide

    // Eval patterns
    $eval1 = "eval(" ascii wide
    $eval2 = "new Function(" ascii wide

  condition:
    any of ($obf*) and any of ($eval*)
}

rule SUSP_JS_Packer_Dean_Edwards_Jan25 {
  meta:
    description = "Detects Dean Edwards style JavaScript packer using eval(function(p,a,c,k,e pattern"
    severity    = "high"
    score       = 85
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    // Common packer patterns
    $packer1 = "eval(function(p,a,c,k,e," ascii wide
    $packer2 = /}\s*\(\s*['"][^'"]{100,}['"]/ ascii wide
    $packer3 = ".split('|')" ascii wide

  condition:
    $packer1 or ($packer2 and $packer3)
}

rule SUSP_JS_JJEncode_Jan25 {
  meta:
    description = "Detects JJEncode JavaScript obfuscation using $=~[] and $$$ patterns to hide code"
    severity    = "high"
    score       = 90
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    $jj1 = "$=~[]" ascii wide
    $jj2 = "_=~[]" ascii wide
    $jj3 = "$$$$" ascii wide

  condition:
    // Require 2+ patterns to avoid FPs on bundled code with isolated patterns
    2 of them
}

rule SUSP_JS_AAEncode_Jan25 {
  meta:
    description = "Detects AAEncode JavaScript obfuscation using emoticon-based encoding patterns"
    severity    = "high"
    score       = 85
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    $aa1 = /\(\s*!\s*\[\s*\]\s*\+\s*""\s*\)/ ascii wide
    $aa2 = /\[\s*\+\s*!\s*\+\s*\[\s*\]\s*\]/ ascii wide

  condition:
    #aa1 > 3 or #aa2 > 3
}

rule SUSP_JS_JSFuck_Jan25 {
  meta:
    description = "Detects JSFuck obfuscation encoding JavaScript using only []()!+ characters"
    severity    = "critical"
    score       = 95
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    // Long sequences of only these characters
    $jsfuck = /[\[\]\(\)!\+]{50,}/ ascii wide

  condition:
    $jsfuck
}
