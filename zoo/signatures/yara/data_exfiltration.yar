/*
    Data Exfiltration Detection
    Detects patterns for stealing and transmitting sensitive data
*/

rule C2_JS_Discord_Webhook_Jan25 {
  meta:
    description = "Detects Discord webhook URL patterns commonly used for data exfiltration and C2 communication"
    severity    = "high"
    score       = 75
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    $webhook1 = /discord\.com\/api\/webhooks\/\d+\/[a-zA-Z0-9_-]+/ ascii wide
    $webhook2 = /discordapp\.com\/api\/webhooks\/\d+\/[a-zA-Z0-9_-]+/ ascii wide
    $webhook3 = "discord.com/api/webhooks" ascii wide
    $webhook4 = "discordapp.com/api/webhooks" ascii wide

  condition:
    any of them
}

rule C2_JS_Free_Hosting_Jan25 {
  meta:
    description = "Detects free hosting service domains commonly abused for C2 infrastructure and data exfiltration"
    severity    = "medium"
    score       = 60
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    // Vercel - commonly abused
    $vercel = /[a-z0-9-]+\.vercel\.app/ ascii wide

    // PythonAnywhere - commonly abused for exfil
    $pythonanywhere = /[a-z0-9-]+\.pythonanywhere\.com/ ascii wide

    // Netlify
    $netlify = /[a-z0-9-]+\.netlify\.app/ ascii wide

    // Glitch
    $glitch = /[a-z0-9-]+\.glitch\.me/ ascii wide

    // Replit
    $replit = /[a-z0-9-]+\.repl\.co/ ascii wide

    // Railway
    $railway = /[a-z0-9-]+\.railway\.app/ ascii wide

    // Render
    $render = /[a-z0-9-]+\.onrender\.com/ ascii wide

    // Cloudflare Pages
    $cf_pages = /[a-z0-9-]+\.pages\.dev/ ascii wide

    // Cloudflare Workers
    $cf_workers = /[a-z0-9-]+\.workers\.dev/ ascii wide

    // Firebase Hosting
    $firebase1 = /[a-z0-9-]+\.web\.app/ ascii wide
    $firebase2 = /[a-z0-9-]+\.firebaseapp\.com/ ascii wide

    // AWS Amplify
    $amplify = /[a-z0-9-]+\.amplifyapp\.com/ ascii wide

    // Heroku
    $heroku = /[a-z0-9-]+\.herokuapp\.com/ ascii wide

    // Deno Deploy
    $deno = /[a-z0-9-]+\.deno\.dev/ ascii wide

    // Fly.io
    $fly = /[a-z0-9-]+\.fly\.dev/ ascii wide

    // Ngrok tunnels
    $ngrok1 = /[a-z0-9-]+\.ngrok\.io/ ascii wide
    $ngrok2 = /[a-z0-9-]+\.ngrok-free\.app/ ascii wide

  condition:
    any of them
}

rule STEALER_JS_SSH_Key_Exfil_Jan25 {
  meta:
    description = "Detects SSH private key file access combined with network transmission for credential theft"
    severity    = "critical"
    score       = 90
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    // SSH key paths
    $ssh1 = ".ssh/id_rsa" ascii wide
    $ssh2 = ".ssh/id_ed25519" ascii wide
    $ssh3 = ".ssh/id_ecdsa" ascii wide
    $ssh4 = ".ssh/id_dsa" ascii wide

    // File reading
    $read1 = "readFileSync" ascii wide
    $read2 = "readFile" ascii wide
    $read3 = "createReadStream" ascii wide

    // Network transmission
    $net1 = "fetch(" ascii wide
    $net2 = "axios" ascii wide
    $net3 = "request(" ascii wide
    $net4 = "https.request" ascii wide
    $net5 = "http.request" ascii wide
    $net6 = ".post(" ascii wide
    $net7 = ".put(" ascii wide

  condition:
    any of ($ssh*) and any of ($read*) and any of ($net*)
}

rule STEALER_JS_Credential_File_Exfil_Jan25 {
  meta:
    description = "Detects credential file access (.npmrc, .env, .aws/credentials) combined with network exfiltration"
    severity    = "critical"
    score       = 90
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    // Credential files
    $cred1 = ".npmrc" ascii wide
    $cred2 = ".netrc" ascii wide
    $cred3 = ".git-credentials" ascii wide
    $cred4 = ".env" ascii wide
    $cred5 = "credentials.json" ascii wide
    $cred6 = ".aws/credentials" ascii wide

    // File reading
    $read1 = "readFileSync" ascii wide
    $read2 = "readFile" ascii wide

    // Network transmission
    $net1 = "fetch(" ascii wide
    $net2 = "axios" ascii wide
    $net3 = ".post(" ascii wide
    $net4 = "discord.com/api/webhooks" ascii wide

  condition:
    any of ($cred*) and any of ($read*) and any of ($net*)
}

rule STEALER_JS_Browser_Data_Theft_Jan25 {
  meta:
    description = "Detects browser credential and cookie theft pattern targeting Chrome/Firefox/Edge storage files"
    severity    = "critical"
    score       = 95
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    // Browser data paths
    $chrome1  = "Chrome" ascii wide nocase
    $chrome2  = "User Data" ascii wide nocase
    $chrome3  = "Login Data" ascii wide nocase
    $chrome4  = "Cookies" ascii wide nocase
    $firefox1 = "Firefox" ascii wide nocase
    $firefox2 = "logins.json" ascii wide nocase
    $edge1    = "Edge" ascii wide nocase
    $brave1   = "BraveSoftware" ascii wide nocase

    // Storage paths
    $storage1 = "Local Storage" ascii wide nocase
    $storage2 = "leveldb" ascii wide nocase
    $storage3 = "IndexedDB" ascii wide nocase

    // File operations
    $read1 = "readFileSync" ascii wide
    $read2 = "copyFileSync" ascii wide
    $read3 = "createReadStream" ascii wide

  condition:
    (2 of ($chrome*) or any of ($firefox*) or ($edge1 and $chrome3) or $brave1) and
    any of ($storage*) and any of ($read*)
}

rule STEALER_JS_Env_Token_Exfil_Jan25 {
  meta:
    description = "Detects API token access from process.env variables combined with network transmission"
    severity    = "high"
    score       = 80
    author      = "vsix-audit"
    date        = "2025-01-29"

  strings:
    // Token environment variables
    $env1 = "process.env.GITHUB_TOKEN" ascii wide
    $env2 = "process.env.NPM_TOKEN" ascii wide
    $env3 = "process.env.OPENAI_API_KEY" ascii wide
    $env4 = "process.env.ANTHROPIC_API_KEY" ascii wide
    $env5 = "process.env.AWS_SECRET" ascii wide
    $env6 = "process.env.AZURE" ascii wide
    $env7 = /process\.env\.[A-Z_]*(TOKEN|KEY|SECRET|PASSWORD)/ ascii wide

    // Network transmission
    $net1 = "fetch(" ascii wide
    $net2 = "axios" ascii wide
    $net3 = ".post(" ascii wide

  condition:
    any of ($env*) and any of ($net*)
}
