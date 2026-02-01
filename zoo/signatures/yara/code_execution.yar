/*
    Dynamic Code Execution Detection
    Detects patterns for executing code from strings/encoded content
*/

rule SUSP_JS_Eval_Base64_Jan25 {
  meta:
    description = "Detects eval() used with base64 decoding to execute hidden or obfuscated code"
    severity    = "critical"
    score       = 90
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    $eval = "eval(" ascii wide

    // Base64 decode patterns
    $decode1 = "atob(" ascii wide
    $decode2 = /Buffer\.from\([^,]+,\s*["']base64["']\)/ ascii wide
    $decode3 = "base64" ascii wide

  condition:
    $eval and any of ($decode*)
}

rule SUSP_JS_Function_Constructor_Jan25 {
  meta:
    description = "Detects new Function() constructor that creates executable code from strings, equivalent to eval"
    severity    = "high"
    score       = 75
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    $func1 = /new\s+Function\s*\(\s*["'`]/ ascii wide
    $func2 = /new\s+Function\s*\(\s*[a-zA-Z_]/ ascii wide

  condition:
    any of them
}

rule SUSP_JS_Eval_Charcode_Jan25 {
  meta:
    description = "Detects eval() combined with String.fromCharCode or hex escapes to hide malicious code"
    severity    = "critical"
    score       = 90
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    $eval = "eval(" ascii wide

    // String construction
    $build1 = "String.fromCharCode" ascii wide
    $build2 = "charCodeAt" ascii wide
    $build3 = /\\x[0-9a-fA-F]{2}/ ascii wide

  condition:
    $eval and any of ($build*)
}

rule SUSP_JS_Indirect_Eval_Jan25 {
  meta:
    description = "Detects indirect eval access through global object like globalThis['eval'] to evade detection"
    severity    = "high"
    score       = 80
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    $indirect1  = "globalThis.eval" ascii wide
    $indirect2  = "globalThis['eval']" ascii wide
    $indirect3  = "global.eval" ascii wide
    $indirect4  = "global['eval']" ascii wide
    $indirect5  = "window.eval" ascii wide
    $indirect6  = "window['eval']" ascii wide
    $indirect7  = "this.eval" ascii wide
    $indirect8  = "self.eval" ascii wide
    $indirect9  = "(0,eval)" ascii wide
    $indirect10 = "(1,eval)" ascii wide

  condition:
    any of them
}

rule SUSP_JS_Child_Process_Variable_Jan25 {
  meta:
    description = "Detects child_process execution with variable command input instead of static string literal"
    severity    = "medium"
    score       = 60
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    $cp1 = "child_process" ascii wide
    $cp2 = "require('child_process')" ascii wide
    $cp3 = "require(\"child_process\")" ascii wide

    // Execution with template literal or variable
    $exec1 = /\.exec\s*\(\s*`/ ascii wide
    $exec2 = /\.execSync\s*\(\s*`/ ascii wide
    $exec3 = /\.spawn\s*\(\s*[a-zA-Z_]/ ascii wide
    $exec4 = /\.exec\s*\(\s*[a-zA-Z_]/ ascii wide

  condition:
    any of ($cp*) and any of ($exec*)
}

rule SUSP_JS_Process_Binding_Jan25 {
  meta:
    description = "Detects access to Node.js internal process bindings that can bypass security restrictions"
    severity    = "high"
    score       = 85
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    $binding1 = "process.binding(" ascii wide
    $binding2 = "process._linkedBinding(" ascii wide
    $binding3 = "process.dlopen(" ascii wide

  condition:
    any of them
}

rule SUSP_JS_VM_Module_Jan25 {
  meta:
    description = "Detects Node.js vm module usage for code execution in sandboxes that can potentially be escaped"
    severity    = "medium"
    score       = 55
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    $vm1 = "require('vm')" ascii wide
    $vm2 = "require(\"vm\")" ascii wide
    $vm3 = "vm.runInThisContext" ascii wide
    $vm4 = "vm.runInNewContext" ascii wide
    $vm5 = "vm.Script" ascii wide

  condition:
    any of them
}

rule SUSP_JS_WebAssembly_Remote_Jan25 {
  meta:
    description = "Detects WebAssembly instantiation with remote or base64 source that could execute arbitrary code"
    severity    = "low"
    score       = 40
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    $wasm1 = "WebAssembly.instantiate" ascii wide
    $wasm2 = "WebAssembly.compile" ascii wide
    $wasm3 = "WebAssembly.Instance" ascii wide

    // From network or encoded source
    $source1 = "fetch(" ascii wide
    $source2 = "atob(" ascii wide
    $source3 = "base64" ascii wide

  condition:
    any of ($wasm*) and any of ($source*)
}
