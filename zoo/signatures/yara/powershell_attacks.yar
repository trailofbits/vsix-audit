/*
    PowerShell Attack Detection
    Detects malicious PowerShell patterns commonly used in VS Code extension malware
*/

rule SUSP_PS_Hidden_Window_Jan25 {
  meta:
    description = "Detects PowerShell execution with hidden window flag to avoid user detection"
    severity    = "critical"
    score       = 90
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    $hidden1 = "-WindowStyle Hidden" ascii wide nocase
    $hidden2 = "-w hidden" ascii wide nocase
    $hidden3 = "-windowstyle h" ascii wide nocase

    $ps1 = "powershell" ascii wide nocase
    $ps2 = "pwsh" ascii wide nocase

  condition:
    any of ($ps*) and any of ($hidden*)
}

rule LOADER_PS_Download_Execute_Jan25 {
  meta:
    description = "Detects PowerShell download and execute cradle using IEX with Invoke-WebRequest or WebClient"
    severity    = "critical"
    score       = 95
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    // Require PowerShell context
    $ps1 = "powershell" ascii wide nocase
    $ps2 = "pwsh" ascii wide nocase

    // Direct piped IEX patterns (most malicious pattern)
    // These match actual PowerShell IEX cradles, not random JS with curl/iex strings
    $iex_pipe1 = /\|\s*(iex|Invoke-Expression)/i ascii wide
    $iex_pipe2 = /(irm|iwr|Invoke-RestMethod|Invoke-WebRequest)[^;]{0,80}\|\s*(iex|Invoke-Expression)/i ascii wide

    // .NET WebClient download+execute (classic PowerShell dropper)
    $webclient1 = "Net.WebClient" ascii wide nocase
    $webclient2 = "DownloadString" ascii wide nocase
    $webclient3 = "DownloadFile" ascii wide nocase

    // Full form Invoke-Expression
    $iex_full = "Invoke-Expression" ascii wide nocase

  condition:
    // Either: PowerShell context with IEX pipe patterns
    (any of ($ps*) and any of ($iex_pipe*)) or
    // Or: .NET WebClient patterns with Invoke-Expression (no PS context needed)
    (any of ($webclient*) and $iex_full)
}

rule SUSP_PS_Encoded_Command_Jan25 {
  meta:
    description = "Detects PowerShell with base64 encoded command flag used to hide malicious payload"
    severity    = "high"
    score       = 85
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    $enc1 = "-enc " ascii wide nocase
    $enc2 = "-EncodedCommand" ascii wide nocase
    $enc3 = "-ec " ascii wide nocase

    $ps1 = "powershell" ascii wide nocase
    $ps2 = "pwsh" ascii wide nocase

  condition:
    any of ($ps*) and any of ($enc*)
}

rule SUSP_PS_Bypass_Policy_Jan25 {
  meta:
    description = "Detects PowerShell execution policy bypass used to run unsigned or restricted scripts"
    severity    = "high"
    score       = 80
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    $bypass1 = "-ExecutionPolicy Bypass" ascii wide nocase
    $bypass2 = "-ep bypass" ascii wide nocase
    $bypass3 = "-exec bypass" ascii wide nocase
    $bypass4 = "Set-ExecutionPolicy" ascii wide nocase

    $ps1 = "powershell" ascii wide nocase
    $ps2 = "pwsh" ascii wide nocase

  condition:
    any of ($ps*) and any of ($bypass*)
}

rule SUSP_PS_AMSI_Bypass_Jan25 {
  meta:
    description = "Detects attempt to bypass Windows AMSI (Anti-Malware Scan Interface) for evasion"
    severity    = "critical"
    score       = 95
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    $amsi1 = "AmsiUtils" ascii wide nocase
    $amsi2 = "amsiInitFailed" ascii wide nocase
    $amsi3 = "AmsiScanBuffer" ascii wide nocase
    $amsi4 = "[Ref].Assembly.GetType" ascii wide

  condition:
    any of them
}
