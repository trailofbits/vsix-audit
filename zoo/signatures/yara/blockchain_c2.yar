/*
    GlassWorm Blockchain C2 Detection
    Detects Solana blockchain-based command and control infrastructure

    IMPORTANT: These rules require SPECIFIC GlassWorm patterns, not just
    Solana SDK usage. Many legitimate extensions use Solana.
*/

rule C2_JS_GlassWorm_Solana_Jan25 {
  meta:
    description = "Detects GlassWorm-style Solana blockchain C2 using transaction memos to receive and execute commands"
    severity    = "critical"
    score       = "90"
    author      = "vsix-audit"
    date        = "2025-01-29"
    reference   = "https://www.koi.security/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace"

  strings:
    // Must use Solana SDK
    $solana_import = "@solana/web3.js" ascii wide

    // Must parse transaction memos (the C2 channel)
    $memo_parse1 = "instructionData" ascii wide
    $memo_parse2 = "transaction.memo" ascii wide
    $memo_parse3 = "memoData" ascii wide

    // Must decode hidden payload from memo
    $decode1 = "atob" ascii wide
    $decode2 = /Buffer\.from\([^,]+,\s*["']base64["']\)/ ascii wide

    // Must fetch the decoded URL
    $fetch = /fetch\s*\(/ ascii wide

    // Code execution from fetched payload
    $exec1 = "eval(" ascii wide
    $exec2 = "new Function(" ascii wide

  condition:
    $solana_import and any of ($memo_parse*) and
    any of ($decode*) and $fetch and any of ($exec*)
}

// REMOVED: GlassWorm_Blockchain_Memo_Parsing
// Too broad - legitimate Solana apps parse memos.

// REMOVED: GlassWorm_Dynamic_C2_Resolution
// Way too broad - matched "history" + "setInterval" + "fetch"
// which is virtually all web apps with periodic updates.
