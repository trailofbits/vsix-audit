/*
    RMM/RAT Tool Delivery Detection
    Detects delivery of Remote Monitoring & Management tools
    (ScreenConnect, AnyDesk, TeamViewer) via scripted installers.

    Covers the "These Vibes Are Off" campaign pattern where
    extensions use PowerShell IEX cradles to silently install
    ScreenConnect for persistent remote access.

    Target: JavaScript files in VS Code extensions (no `wide` needed)
*/

rule LOADER_RMM_ScreenConnect_Delivery_Feb26 {
  meta:
    description = "Detects ScreenConnect (ConnectWise Control) delivery or silent installation patterns in extension code"
    severity    = "critical"
    score       = 95
    author      = "vsix-audit"
    date        = "2026-02-06"
    reference   = "https://www.secureannex.com/blog/these-vibes-are-off"

  strings:
    // ScreenConnect / ConnectWise Control identifiers
    $sc1 = "screenconnect" ascii nocase
    $sc2 = "ScreenConnect.Client" ascii
    $sc3 = "ScreenConnect.WindowsClient" ascii
    $sc4 = "connectwise" ascii nocase

    // ScreenConnect relay/session URLs
    $relay1 = /instance-[a-z0-9]+-relay\.screenconnect\.com/ ascii
    $relay2 = /[a-z0-9]{4,30}\.screenconnect\.com/ ascii

    // Script-based delivery context
    $deliver1 = "child_process" ascii
    $deliver2 = "exec(" ascii
    $deliver3 = "execSync(" ascii
    $deliver4 = "spawn(" ascii
    $deliver5 = "powershell" ascii nocase

  condition:
    (any of ($sc*) or any of ($relay*)) and
    any of ($deliver*)
}

rule LOADER_RMM_AnyDesk_Delivery_Feb26 {
  meta:
    description = "Detects AnyDesk silent installation or deployment patterns in extension code"
    severity    = "critical"
    score       = 90
    author      = "vsix-audit"
    date        = "2026-02-06"
    reference   = "https://www.secureannex.com/blog/these-vibes-are-off"

  strings:
    $ad1 = "anydesk" ascii nocase
    $ad2 = "AnyDesk.exe" ascii

    // AnyDesk silent install flags
    $install1 = "--install" ascii
    $install2 = "--silent" ascii
    $install3 = "--start-with-win" ascii

    // AnyDesk password setting (unattended access)
    $pwd1 = "--set-password" ascii
    $pwd2 = "ad.anynet.pwd" ascii

    // Delivery context
    $deliver1 = "child_process" ascii
    $deliver2 = "exec(" ascii
    $deliver3 = "powershell" ascii nocase
    $deliver4 = "spawn(" ascii

  condition:
    any of ($ad*) and
    (any of ($install*) or any of ($pwd*)) and
    any of ($deliver*)
}

rule LOADER_RMM_TeamViewer_Delivery_Feb26 {
  meta:
    description = "Detects TeamViewer silent installation or deployment patterns in extension code"
    severity    = "critical"
    score       = 90
    author      = "vsix-audit"
    date        = "2026-02-06"
    reference   = "https://www.secureannex.com/blog/these-vibes-are-off"

  strings:
    $tv1 = "teamviewer" ascii nocase
    $tv2 = "TeamViewer.exe" ascii
    $tv3 = "TeamViewer_Setup" ascii

    // Silent/unattended install
    $install1 = "CUSTOMCONFIGID" ascii nocase
    $install2 = "APITOKEN" ascii nocase

    // Delivery context
    $deliver1 = "child_process" ascii
    $deliver2 = "exec(" ascii
    $deliver3 = "powershell" ascii nocase
    $deliver4 = "spawn(" ascii

  condition:
    any of ($tv*) and any of ($install*) and
    any of ($deliver*)
}
