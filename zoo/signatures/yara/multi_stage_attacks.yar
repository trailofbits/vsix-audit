/*
    Multi-Stage Attack Pattern Detection
    Detects attack chains that combine multiple stages (download->write->execute, etc.)
*/

rule LOADER_JS_Download_Write_Execute_Jan25 {
  meta:
    description = "Detects dropper pattern that downloads content, writes to temp directory, and executes"
    severity    = "critical"
    score       = 90
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    // Download stage
    $dl1 = "fetch(" ascii wide
    $dl2 = "axios.get" ascii wide
    $dl3 = "https.get" ascii wide
    $dl4 = "http.get" ascii wide
    $dl5 = "request(" ascii wide
    $dl6 = "got(" ascii wide

    // Write stage
    $write1 = "writeFileSync" ascii wide
    $write2 = "writeFile" ascii wide
    $write3 = "createWriteStream" ascii wide

    // Execute stage
    $exec1 = "child_process" ascii wide
    $exec2 = ".exec(" ascii wide
    $exec3 = ".spawn(" ascii wide
    $exec4 = "execSync" ascii wide
    $exec5 = "spawnSync" ascii wide

    // Temp/hidden location indicators (require these for dropper pattern)
    $temp1 = "/tmp/" ascii wide
    $temp2 = "\\Temp\\" ascii wide
    $temp3 = "os.tmpdir" ascii wide
    $temp4 = "TEMP" ascii wide

    // Base64 decode before write (payload decoding)
    $decode1 = "atob(" ascii wide
    $decode2 = "Buffer.from" ascii wide
    $decode3 = "base64" ascii wide nocase

    // Make executable before exec (chmod)
    $chmod1 = "chmodSync" ascii wide
    $chmod2 = "fs.chmod" ascii wide
    $chmod3 = "chmod(" ascii wide

    // Hidden file indicators (require 4+ bytes for good YARA atoms)
    $hidden1 = "/tmp/." ascii wide  // Unix hidden files in /tmp
    $hidden2 = "\\AppData\\Local\\Temp\\." ascii wide  // Windows hidden files in temp

  condition:
    // Require all three stages PLUS dropper indicator
    any of ($dl*) and any of ($write*) and any of ($exec*) and
    (
      any of ($temp*) or  // Writing to temp directory
      any of ($decode*) or  // Decoding payload before write
      any of ($chmod*) or  // Making file executable
      any of ($hidden*)  // Writing to hidden location
    )
}

rule RAT_JS_Reverse_Shell_Jan25 {
  meta:
    description = "Detects reverse shell pattern where network socket is piped to shell for remote command execution"
    severity    = "high"
    score       = 85
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    // Network socket creation (raw TCP, not HTTP)
    $net1 = "net.Socket" ascii wide
    $net2 = "net.connect" ascii wide
    $net3 = "net.createConnection" ascii wide
    $net4 = "socket.connect" ascii wide

    // Shell execution (specific paths, not just "child_process")
    $shell1 = "/bin/sh" ascii wide
    $shell2 = "/bin/bash" ascii wide
    $shell3 = "/bin/zsh" ascii wide
    $shell4 = "cmd.exe" ascii wide
    $shell5 = "powershell.exe" ascii wide nocase

    // Piping stdin/stdout (require both for reverse shell)
    $pipe_stdin  = "stdin" ascii wide
    $pipe_stdout = "stdout" ascii wide
    $pipe_method = ".pipe(" ascii wide

    // Spawn with shell option (classic reverse shell pattern)
    $spawn_shell = /spawn\s*\([^)]*shell\s*:\s*true/i ascii wide

  condition:
    // Classic reverse shell: socket + shell path + stdin/stdout piping
    (any of ($net*) and any of ($shell*) and $pipe_stdin and $pipe_stdout) or
    // Or: socket + shell path + pipe method
    (any of ($net*) and any of ($shell*) and $pipe_method) or
    // Or: spawn with shell option + socket
    ($spawn_shell and any of ($net*))
}

rule STEALER_JS_Keylogger_Jan25 {
  meta:
    description = "Detects keylogger pattern that captures keyboard or clipboard input and exfiltrates data"
    severity    = "high"
    score       = 85
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    // High-confidence capture patterns (actual keylogging, not text document events)
    $capture_key1 = "keydown" ascii wide
    $capture_key2 = "keypress" ascii wide
    $capture_key3 = "keyup" ascii wide
    $capture_clip = "clipboard.readText" ascii wide

    // Low-confidence capture (VS Code API - needs additional indicators)
    $capture_vsc = "onDidChangeTextDocument" ascii wide

    // Storage with suspicious naming
    $store_suspicious1 = "keylog" ascii wide nocase
    $store_suspicious2 = "keystroke" ascii wide nocase
    $store_suspicious3 = "inputBuffer" ascii wide
    $store_suspicious4 = "capturedKeys" ascii wide

    // Generic storage (needs other indicators)
    $store_generic1 = "globalState" ascii wide
    $store_generic2 = "appendFile" ascii wide

    // High-confidence exfil (known bad destinations)
    $exfil_discord  = "discord.com/api/webhooks" ascii wide
    $exfil_telegram = "api.telegram.org" ascii wide

    // Generic exfil (needs other indicators)
    $exfil_generic1 = "axios.post" ascii wide
    $exfil_generic2 = ".post(" ascii wide

  condition:
    // High confidence: keyboard events + storage + exfil
    (any of ($capture_key*) and any of ($store_suspicious*, $store_generic*) and any of ($exfil_discord, $exfil_telegram, $exfil_generic*)) or
    // High confidence: clipboard read + known bad destination
    ($capture_clip and any of ($exfil_discord, $exfil_telegram)) or
    // Medium confidence: VS Code API + suspicious storage names + exfil
    ($capture_vsc and any of ($store_suspicious*) and any of ($exfil_discord, $exfil_telegram, $exfil_generic*))
}

rule RAT_JS_Persistence_Startup_Jan25 {
  meta:
    description = "Detects persistence mechanism that modifies startup files, registry keys, or scheduled tasks"
    severity    = "high"
    score       = 80
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    // Unix startup file paths (require path context, not just filename)
    $unix_path1 = /\$HOME\/\.bashrc/ ascii wide
    $unix_path2 = /\$HOME\/\.zshrc/ ascii wide
    $unix_path3 = /\$HOME\/\.profile/ ascii wide
    $unix_path4 = /\$HOME\/\.bash_profile/ ascii wide
    $unix_path5 = "process.env.HOME" ascii wide
    $unix_path6 = "os.homedir()" ascii wide

    // macOS Launch services (specific paths)
    $mac1 = "/Library/LaunchAgents" ascii wide
    $mac2 = "/Library/LaunchDaemons" ascii wide
    $mac3 = "~/Library/LaunchAgents" ascii wide

    // Crontab manipulation (require command)
    $cron1 = "crontab -" ascii wide
    $cron2 = /crontab\s+(--|-e|-l|-r)/ ascii wide

    // Windows registry persistence (require full path)
    $win_reg1 = "CurrentVersion\\Run" ascii wide
    $win_reg2 = "CurrentVersion\\RunOnce" ascii wide
    $win_reg3 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $win_reg4 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase

    // Windows scheduled tasks (require schtasks command)
    $win_sched1 = /schtasks\s+\/create/i ascii wide
    $win_sched2 = /schtasks\s+\/change/i ascii wide

    // Write operations with shell config context
    $write_shell = /write(File|FileSync)\s*\([^)]*\.(bashrc|zshrc|profile|bash_profile)/ ascii wide

  condition:
    // Unix: home path + shell config reference
    ((any of ($unix_path*)) and any of ($unix_path1, $unix_path2, $unix_path3, $unix_path4)) or
    // macOS Launch services
    any of ($mac*) or
    // Crontab commands
    any of ($cron*) or
    // Windows registry persistence paths
    any of ($win_reg*) or
    // Windows scheduled task creation
    any of ($win_sched*) or
    // Direct write to shell config
    $write_shell
}

rule MAL_JS_Self_Propagation_Publish_Jan25 {
  meta:
    description = "Detects self-propagation worm pattern that accesses publish tokens and runs publish commands"
    severity    = "critical"
    score       = 95
    author      = "vsix-audit"
    date        = "2025-01-29"
    reference   = "https://www.koi.security/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace"

  strings:
    // Credential access
    $cred1 = ".npmrc" ascii wide
    $cred2 = "NPM_TOKEN" ascii wide
    $cred3 = "OPENVSX_TOKEN" ascii wide
    $cred4 = "VSCE_PAT" ascii wide

    // Publish commands
    $pub1 = "npm publish" ascii wide
    $pub2 = "vsce publish" ascii wide
    $pub3 = "ovsx publish" ascii wide
    $pub4 = "yarn publish" ascii wide

  condition:
    any of ($cred*) and any of ($pub*)
}

rule MAL_JS_Supply_Chain_Install_Jan25 {
  meta:
    description = "Detects supply chain attack that runs malicious commands during npm package lifecycle hooks"
    severity    = "high"
    score       = 85
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    // Lifecycle script indicators (in package.json context)
    $script1 = "preinstall" ascii wide
    $script2 = "postinstall" ascii wide
    $script3 = "prepublish" ascii wide

    // System info gathering
    $sys1 = "os.homedir" ascii wide
    $sys2 = "os.userInfo" ascii wide
    $sys3 = "os.hostname" ascii wide
    $sys4 = "process.env.HOME" ascii wide
    $sys5 = "process.env.USER" ascii wide

    // Network beacon
    $net1 = "fetch(" ascii wide
    $net2 = "axios" ascii wide
    $net3 = "https.request" ascii wide

  condition:
    any of ($script*) and any of ($sys*) and any of ($net*)
}

rule STEALER_JS_Crypto_Wallet_Jan25 {
  meta:
    description = "Detects cryptocurrency stealer that accesses wallet directories, keys, or seed phrases and exfiltrates"
    severity    = "high"
    score       = 85
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    // Wallet directory paths (more specific than just wallet names)
    $wallet_path1 = ".config/solana" ascii wide
    $wallet_path2 = "AppData\\Roaming\\Ethereum" ascii wide
    $wallet_path3 = "AppData\\Local\\Exodus" ascii wide
    $wallet_path4 = "AppData\\Local\\Phantom" ascii wide
    $wallet_path5 = "Library/Application Support/Exodus" ascii wide
    $wallet_path6 = ".ethereum/keystore" ascii wide
    $wallet_path7 = "wallet.dat" ascii wide

    // Browser extension wallet paths
    $ext_metamask = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide  // MetaMask extension ID
    $ext_phantom  = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii wide  // Phantom extension ID

    // Seed phrase / key extraction patterns (specific to crypto)
    $key_mnemonic   = "mnemonic" ascii wide nocase
    $key_seedphrase = "seedPhrase" ascii wide
    $key_privatekey = "privateKey" ascii wide
    $key_secretkey  = "secretKey" ascii wide

    // File read patterns targeting wallet files
    $read_wallet   = /readFile[^)]*wallet/i ascii wide
    $read_keystore = /readFile[^)]*keystore/i ascii wide

    // High-confidence exfil (known bad destinations)
    $exfil_discord  = "discord.com/api/webhooks" ascii wide
    $exfil_telegram = "api.telegram.org" ascii wide

  condition:
    // Wallet paths + seed/key extraction
    (any of ($wallet_path*, $ext_*) and any of ($key_*)) or
    // Wallet file reads + known bad exfil
    (any of ($read_wallet, $read_keystore) and any of ($exfil_discord, $exfil_telegram)) or
    // Wallet paths + known bad exfil
    (any of ($wallet_path*, $ext_*) and any of ($exfil_discord, $exfil_telegram))
}

rule MAL_JS_GlassWorm_Extension_Modification_Jan25 {
  meta:
    description = "Detects GlassWorm-style attack that modifies other VS Code extensions to inject malicious code"
    severity    = "critical"
    score       = 95
    author      = "vsix-audit"
    date        = "2025-01-29"
    reference   = "https://www.koi.security/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace"

  strings:
    // Extension paths
    $path1 = ".vscode/extensions" ascii wide
    $path2 = ".vscode-server/extensions" ascii wide
    $path3 = "extensions/" ascii wide

    // File modification
    $mod1 = "writeFileSync" ascii wide
    $mod2 = "writeFile" ascii wide

    // Extension files
    $file1 = "extension.js" ascii wide
    $file2 = "package.json" ascii wide
    $file3 = ".vsix" ascii wide

  condition:
    any of ($path*) and any of ($mod*) and any of ($file*)
}
