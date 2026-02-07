/*
    Suspicious Native Addon Loading Detection
    Detects platform-conditional loading of .node native addons,
    a pattern used by GlassWorm Wave 3 to load Rust implants
    (darwin.node, os.node) that establish persistence.

    Legitimate native addons exist (e.g., node-sass, sharp) but
    they load via npm packages, not inline require with
    platform checks and custom-named .node files.

    Target: JavaScript files (no `wide` needed)
*/

rule SUSP_NativeAddon_Platform_Loader_Feb26 {
  meta:
    description = "Detects platform-conditional loading of .node native addons, a pattern used by GlassWorm for Rust implant delivery"
    severity    = "high"
    score       = 85
    author      = "vsix-audit"
    date        = "2026-02-06"
    reference   = "https://www.secureannex.com/blog/the-glass-is-half-empty"

  strings:
    // Platform detection
    $platform1 = "os.platform()" ascii
    $platform2 = "process.platform" ascii

    // Platform value used in comparisons
    // (must be full quoted strings to avoid short-atom issues)
    $win = "'win32'" ascii
    $mac = "'darwin'" ascii

    // Native addon loading with relative path
    $node_load1 = /require\s*\(\s*['"][^'"]*\.node['"]\s*\)/ ascii
    $node_load2 = "darwin.node" ascii
    $node_load3 = "os.node" ascii
    $node_load4 = "win.node" ascii
    $node_load5 = "linux.node" ascii

    // The loaded addon is called with .run()
    $run_call = ".run(" ascii

  condition:
    any of ($platform*) and
    ($win or $mac) and
    any of ($node_load*) and
    $run_call
}

rule SUSP_NativeAddon_Bundled_Binary_Feb26 {
  meta:
    description = "Detects custom-named .node file loading outside of node_modules, suggesting a bundled native binary"
    severity    = "medium"
    score       = 70
    author      = "vsix-audit"
    date        = "2026-02-06"
    reference   = "https://www.secureannex.com/blog/the-glass-is-half-empty"

  strings:
    // Require of .node files with relative paths (not from node_modules)
    $rel_node1 = /require\s*\(\s*['"]\.\/[^'"]+\.node['"]\s*\)/ ascii
    $rel_node2 = /require\s*\(\s*['"]\.\.\/[^'"]+\.node['"]\s*\)/ ascii

    // VS Code extension activation context
    $activate = "activate" ascii
    $vscode   = "vscode" ascii

  condition:
    any of ($rel_node*) and
    ($activate and $vscode)
}
