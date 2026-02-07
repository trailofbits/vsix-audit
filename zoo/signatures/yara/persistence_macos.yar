/*
    macOS Persistence Detection
    Detects LaunchAgent/LaunchDaemon persistence mechanisms
    used by malware to survive reboots on macOS.

    GlassWorm Wave 3 Rust implants write LaunchAgent plists
    to ~/Library/LaunchAgents/ with com.apple.* naming to
    blend in with legitimate Apple services.

    Target: JavaScript files (no `wide` needed)
*/

rule SUSP_Mac_LaunchAgent_Feb26 {
  meta:
    description = "Detects LaunchAgent plist creation for macOS persistence, used by GlassWorm Rust implants"
    severity    = "high"
    score       = 85
    author      = "vsix-audit"
    date        = "2026-02-06"
    reference   = "https://www.secureannex.com/blog/the-glass-is-half-empty"

  strings:
    // LaunchAgent/LaunchDaemon paths
    $la_path1 = "LaunchAgents" ascii
    $la_path2 = "LaunchDaemons" ascii
    $la_path3 = "Library/LaunchAgents" ascii
    $la_path4 = "Library/LaunchDaemons" ascii

    // Plist content patterns
    $plist1 = "ProgramArguments" ascii
    $plist2 = "RunAtLoad" ascii
    $plist3 = "KeepAlive" ascii
    $plist4 = "StartInterval" ascii

    // File write operations
    $write1 = "writeFile" ascii
    $write2 = "writeFileSync" ascii
    $write3 = "createWriteStream" ascii

    // Or plist XML format
    $xml1 = "<!DOCTYPE plist" ascii
    $xml2 = "<plist version" ascii

  condition:
    any of ($la_path*) and
    (2 of ($plist*) or any of ($xml*)) and
    any of ($write*)
}

rule SUSP_Mac_AppleDisguise_Feb26 {
  meta:
    description = "Detects use of com.apple.* naming for non-Apple LaunchAgent persistence (masquerading)"
    severity    = "critical"
    score       = 90
    author      = "vsix-audit"
    date        = "2026-02-06"
    reference   = "https://www.secureannex.com/blog/the-glass-is-half-empty"

  strings:
    // Apple-disguised plist labels
    $apple_label = /com\.apple\.[a-zA-Z0-9._-]+\.plist/ ascii

    // LaunchAgent context
    $la1 = "LaunchAgents" ascii
    $la2 = "LaunchDaemons" ascii

    // Non-Apple origin evidence (JS/Node context)
    $js1 = "require(" ascii
    $js2 = "child_process" ascii
    $js3 = "execSync(" ascii
    $js4 = "writeFile" ascii

  condition:
    $apple_label and
    any of ($la*) and
    any of ($js*)
}

rule SUSP_Mac_LoginItem_Feb26 {
  meta:
    description = "Detects programmatic addition of macOS Login Items for persistence"
    severity    = "medium"
    score       = 75
    author      = "vsix-audit"
    date        = "2026-02-06"
    reference   = "https://www.secureannex.com/blog/the-glass-is-half-empty"

  strings:
    // Login Items manipulation via osascript
    $login1 = "login item" ascii nocase
    $login2 = "LoginItems" ascii
    $login3 = "LSSharedFileList" ascii

    // osascript for AppleScript execution
    $osa1 = "osascript" ascii
    $osa2 = "tell application" ascii

    // Open at Login
    $open1 = "LSRegisterURL" ascii
    $open2 = "open at login" ascii nocase

    // Code execution context
    $exec1 = "exec(" ascii
    $exec2 = "execSync(" ascii
    $exec3 = "child_process" ascii
    $exec4 = "spawn(" ascii

    // Exclude TextMate grammar/syntax files
    // (contain AppleScript keywords as language tokens)
    $fp_grammar1 = "tmLanguage" ascii
    $fp_grammar2 = "scopeName" ascii
    $fp_grammar3 = "repository" ascii

  condition:
    any of ($login*, $open*) and
    (any of ($osa*) or any of ($exec*)) and
    not 2 of ($fp_grammar*)
}
