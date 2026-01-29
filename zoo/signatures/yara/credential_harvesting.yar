/*
    GlassWorm Credential Harvesting Detection
    Detects patterns for harvesting NPM, GitHub, OpenVSX, Git, and SSH credentials

    IMPORTANT: These rules are tuned to avoid false positives on legitimate code.
    Legitimate SSH tools, Git integrations, and package managers will use these
    APIs. We require MULTIPLE strong indicators to fire.
*/

rule GlassWorm_NPM_Token_Theft {
    meta:
        description = "Detects NPM token theft specifically targeting .npmrc"
        severity = "high"
        score = "85"
        author = "vsix-audit"
        date = "2025-01-29"

    strings:
        // Must specifically target .npmrc file
        $npmrc_path = /\.npmrc/ ascii wide
        $homedir = "os.homedir" ascii wide

        // Must read the file
        $read = "readFile" ascii wide

        // Must do something suspicious with the token
        $exfil1 = /fetch\s*\(\s*["'][^"']*["']\s*,\s*\{[^}]*body/ ascii wide
        $exfil2 = "axios.post" ascii wide
        $exfil3 = "discord.com/api/webhooks" ascii wide
        $exfil4 = "discordapp.com/api/webhooks" ascii wide

    condition:
        $npmrc_path and $homedir and $read and any of ($exfil*)
}

rule GlassWorm_SSH_Key_Theft {
    meta:
        description = "Detects SSH private key theft"
        severity = "critical"
        score = "90"
        author = "vsix-audit"
        date = "2025-01-29"

    strings:
        // Must target SSH private key paths specifically
        $ssh_key1 = "id_rsa" ascii wide
        $ssh_key2 = "id_ed25519" ascii wide
        $ssh_key3 = "id_ecdsa" ascii wide

        // Must access home directory
        $homedir = "os.homedir" ascii wide

        // Must read the file
        $read1 = "readFileSync" ascii wide
        $read2 = "readFile" ascii wide

        // Must have network exfiltration
        $exfil1 = /fetch\s*\(\s*["'][^"']*["']\s*,\s*\{[^}]*body/ ascii wide
        $exfil2 = "axios.post" ascii wide
        $exfil3 = "discord.com/api/webhooks" ascii wide
        $exfil4 = "https.request" ascii wide

        // Encoding before exfil
        $encode1 = "base64" ascii wide
        $encode2 = "btoa" ascii wide

    condition:
        any of ($ssh_key*) and $homedir and any of ($read*) and
        any of ($exfil*) and any of ($encode*)
}

rule GlassWorm_Browser_Credential_Theft {
    meta:
        description = "Detects browser credential database theft"
        severity = "critical"
        score = "95"
        author = "vsix-audit"
        date = "2025-01-29"

    strings:
        // Browser credential paths - very specific
        $chrome_login = "Chrome/User Data/Default/Login Data" ascii wide nocase
        $firefox_login = "Firefox/Profiles" ascii wide nocase
        $edge_login = "Edge/User Data/Default/Login Data" ascii wide nocase
        $brave_login = "BraveSoftware" ascii wide nocase

        // Must copy or read these files
        $copy1 = "copyFileSync" ascii wide
        $copy2 = "createReadStream" ascii wide
        $read = "readFileSync" ascii wide

        // Network exfil
        $exfil = /(?:fetch|axios|request)\s*\(/ ascii wide

    condition:
        any of ($chrome_login, $firefox_login, $edge_login, $brave_login) and
        any of ($copy*, $read) and $exfil
}

// REMOVED: GlassWorm_Credential_Exfiltration
// This rule was too broad - it matched any code with POST + JSON.stringify + "token"
// which is virtually all web applications.

// REMOVED: GlassWorm_SSH_Credential_Harvesting
// Too broad - matched any SSH tooling. Replaced with GlassWorm_SSH_Key_Theft above.

// REMOVED: GlassWorm_GitHub_Credential_Harvesting
// Too broad for GitHub integrations.

// REMOVED: GlassWorm_OpenVSX_Credential_Harvesting
// Extensions that publish need these patterns legitimately.
