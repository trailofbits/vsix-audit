/*
    WebSocket C2 Detection
    Detects WebSocket-based command and control patterns
*/

rule C2_JS_WebSocket_Command_Exec_Jan25 {
  meta:
    description = "Detects WebSocket C2 pattern with message handler triggering child_process command execution"
    severity    = "high"
    score       = 80
    author      = "vsix-audit"
    date        = "2025-01-30"

  strings:
    // WebSocket creation
    $ws1 = "new WebSocket(" ascii wide
    $ws2 = "WebSocket(" ascii wide
    $ws3 = "ws://" ascii wide
    $ws4 = "wss://" ascii wide

    // Message handling (specific patterns)
    $msg1 = ".onmessage" ascii wide
    $msg2 = ".on('message'" ascii wide
    $msg3 = ".on(\"message\"" ascii wide

    // Command execution via child_process (not just setTimeout)
    $exec_cp      = "child_process" ascii wide
    $exec_method1 = ".exec(" ascii wide
    $exec_method2 = ".spawn(" ascii wide
    $exec_sync1   = "execSync" ascii wide
    $exec_sync2   = "spawnSync" ascii wide

    // Eval from message (dangerous pattern)
    $eval_msg = "eval(" ascii wide

    // C2-specific patterns
    $c2_cmd   = "command" ascii wide
    $c2_shell = "shell" ascii wide nocase
    $c2_run   = "runCommand" ascii wide

  condition:
    // WebSocket + message handler + child_process execution
    any of ($ws*) and any of ($msg*) and
    (
      // Direct child_process usage with exec/spawn method
      ($exec_cp and any of ($exec_method*, $exec_sync*)) or
      // Eval from WebSocket (rare in legit code)
      ($eval_msg and any of ($c2_cmd, $c2_shell, $c2_run))
    )
}

rule RAT_JS_WebSocket_Reverse_Shell_Jan25 {
  meta:
    description = "Detects WebSocket reverse shell with shell process stdin/stdout piped through socket"
    severity    = "critical"
    score       = 95
    author      = "vsix-audit"
    date        = "2025-01-30"

  strings:
    // WebSocket creation
    $ws1 = "new WebSocket(" ascii wide
    $ws2 = "WebSocket(" ascii wide
    $ws3 = "ws://" ascii wide
    $ws4 = "wss://" ascii wide

    // Shell paths
    $shell1 = "/bin/sh" ascii wide
    $shell2 = "/bin/bash" ascii wide
    $shell3 = "/bin/zsh" ascii wide
    $shell4 = "cmd.exe" ascii wide
    $shell5 = "powershell" ascii wide nocase

    // Stream piping (connecting shell to socket)
    $pipe1 = ".pipe(" ascii wide
    $pipe2 = "stdin" ascii wide
    $pipe3 = "stdout" ascii wide
    $pipe4 = "stderr" ascii wide
    $pipe5 = ".send(" ascii wide

  condition:
    any of ($ws*) and any of ($shell*) and 2 of ($pipe*)
}
