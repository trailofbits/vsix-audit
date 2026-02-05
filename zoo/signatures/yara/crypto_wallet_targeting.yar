/*
    GlassWorm Cryptocurrency Wallet Targeting Detection
    Detects patterns for targeting cryptocurrency wallet extensions

    IMPORTANT: These rules require CLEAR malicious intent indicators.
    Many legitimate tools interact with crypto wallets.
*/

rule MAL_JS_GlassWorm_Wallet_Seed_Extraction_Jan25 {
  meta:
    description = "Detects GlassWorm-style wallet seed phrase extraction from storage combined with network exfil"
    severity    = "critical"
    score       = "95"
    author      = "vsix-audit"
    date        = "2025-01-29"
    reference   = "https://www.koi.security/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace"

  strings:
    // Seed phrase patterns (very specific)
    $seed1 = "seedPhrase" ascii wide
    $seed2 = "mnemonic" ascii wide
    $seed3 = "recoveryPhrase" ascii wide

    // Private key extraction
    $privkey = "privateKey" ascii wide

    // Storage access
    $storage1 = "localStorage.getItem" ascii wide
    $storage2 = "chrome.storage" ascii wide

    // Exfiltration - must send somewhere
    $exfil1 = "discord.com/api/webhooks" ascii wide
    $exfil2 = "discordapp.com/api/webhooks" ascii wide
    $exfil3 = /fetch\s*\(\s*["'][^"']*["']\s*,\s*\{[^}]*body/ ascii wide
    $exfil4 = "axios.post" ascii wide

  condition:
    any of ($seed*, $privkey) and any of ($storage*) and any of ($exfil*)
}

rule MAL_JS_GlassWorm_Multi_Wallet_Enum_Jan25 {
  meta:
    description = "Detects GlassWorm-style enumeration of 3+ crypto wallet browser extension IDs for targeting"
    severity    = "high"
    score       = "85"
    author      = "vsix-audit"
    date        = "2025-01-29"
    reference   = "https://www.koi.security/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace"

  strings:
    // MetaMask extension ID
    $metamask_id = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide

    // Phantom extension ID
    $phantom_id = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii wide

    // Coinbase Wallet extension ID
    $coinbase_id = "hnfanknocfeofbddgcijnmhnfnkdnaad" ascii wide

    // Other wallet extension IDs
    $trust_id  = "egjidjbpglichdcondbcbdnbeeppgdph" ascii wide
    $exodus_id = "aholpfdialjgjfhomihkjbmgjidlcdno" ascii wide

    // Additional wallet extension IDs
    $rabby_id    = "acmacodkjbdgmoleebolmdjonilkdbch" ascii wide
    $keplr_id    = "dmkamcknogkgcdfhhbddcghachkejeap" ascii wide
    $okx_id      = "mcohilncbfahbmgdjkbpemcciiolgcge" ascii wide
    $bitget_id   = "jiidiaalihmmhddjgbnbgdfflelocpak" ascii wide
    $rainbow_id  = "opfgelmcmbiajamepnmloijbpoleiama" ascii wide
    $zerion_id   = "klghhnkeealcohjjanjjdaeeggmfmlpl" ascii wide
    $backpack_id = "aflkmfhebedbjioipglgcbcmnbpgliof" ascii wide
    $solflare_id = "bhhhlbepdkbapadjdnnojkbgioiodbic" ascii wide

    // Must be checking for multiple
    $check = /chrome\.runtime\.sendMessage|chrome\.management\.get/ ascii wide

  condition:
    3 of ($metamask_id, $phantom_id, $coinbase_id, $trust_id, $exodus_id,
      $rabby_id, $keplr_id, $okx_id, $bitget_id, $rainbow_id,
      $zerion_id, $backpack_id, $solflare_id) and $check
}

// REMOVED: GlassWorm_Crypto_Wallet_Targeting
// Too broad - matched "metamask" + "phantom" + "address"
// which appears in many legitimate dApp extensions.

// REMOVED: GlassWorm_Wallet_Transaction_Interception
// Too broad - "transaction" + "hook" + "to/from/value" matches
// virtually all web3 applications.

// REMOVED: GlassWorm_Wallet_Extension_Enumeration
// Too broad - wallet detection is legitimate for dApps.
