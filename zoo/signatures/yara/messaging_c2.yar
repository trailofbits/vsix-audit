/*
    Messaging Platform C2 Detection
    Detects use of messaging platforms (Telegram, Slack) for C2 and exfiltration
*/

rule C2_JS_Telegram_Bot_Jan25 {
  meta:
    description = "Detects Telegram bot API used for C2 communication with command execution or system info gathering"
    severity    = "high"
    score       = 85
    author      = "vsix-audit"
    date        = "2025-01-30"

  strings:
    // Telegram API
    $tg1 = "api.telegram.org" ascii wide
    $tg2 = "/bot" ascii wide
    $tg3 = "telegram" ascii wide nocase

    // Bot methods
    $method1 = "sendMessage" ascii wide
    $method2 = "getUpdates" ascii wide
    $method3 = "sendDocument" ascii wide
    $method4 = "sendPhoto" ascii wide

    // Command execution or system info (C2 indicators)
    $exec1 = "child_process" ascii wide
    $exec2 = ".exec(" ascii wide
    $exec3 = ".spawn(" ascii wide
    $exec4 = "execSync" ascii wide
    $sys1  = "os.hostname" ascii wide
    $sys2  = "os.userInfo" ascii wide
    $sys3  = "os.platform" ascii wide
    $sys4  = "process.env" ascii wide

  condition:
    any of ($tg*) and any of ($method*) and any of ($exec*, $sys*)
}

rule STEALER_JS_Telegram_Exfil_Jan25 {
  meta:
    description = "Detects Telegram API used for file exfiltration targeting sensitive credential paths like .ssh"
    severity    = "high"
    score       = 80
    author      = "vsix-audit"
    date        = "2025-01-30"

  strings:
    // Telegram API
    $tg1 = "api.telegram.org" ascii wide
    $tg2 = "/bot" ascii wide

    // Document sending
    $send1 = "sendDocument" ascii wide
    $send2 = "sendFile" ascii wide
    $send3 = "multipart/form-data" ascii wide

    // File reading
    $read1 = "readFileSync" ascii wide
    $read2 = "readFile" ascii wide
    $read3 = "createReadStream" ascii wide

    // Sensitive paths
    $path1 = ".ssh" ascii wide
    $path2 = ".npmrc" ascii wide
    $path3 = ".env" ascii wide
    $path4 = "credentials" ascii wide
    $path5 = ".aws" ascii wide
    $path6 = ".git-credentials" ascii wide

  condition:
    any of ($tg*) and any of ($send*) and any of ($read*) and any of ($path*)
}

rule C2_JS_Slack_Webhook_Jan25 {
  meta:
    description = "Detects Slack webhook URL used for data exfiltration with system info or file access patterns"
    severity    = "high"
    score       = 75
    author      = "vsix-audit"
    date        = "2025-01-30"

  strings:
    // Slack webhook URL pattern
    $slack1 = "hooks.slack.com/services" ascii wide
    $slack2 = "hooks.slack.com" ascii wide
    $slack3 = /T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[a-zA-Z0-9]{20,}/ ascii wide

    // Data transmission
    $send1 = "fetch(" ascii wide
    $send2 = "axios" ascii wide
    $send3 = ".post(" ascii wide
    $send4 = "request(" ascii wide

    // Data collection indicators
    $data1 = "JSON.stringify" ascii wide
    $data2 = "process.env" ascii wide
    $data3 = "os.hostname" ascii wide
    $data4 = "readFileSync" ascii wide

  condition:
    any of ($slack*) and any of ($send*) and any of ($data*)
}
