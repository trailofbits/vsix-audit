/*
    GlassWorm Cryptocurrency Wallet Targeting Detection
    Detects patterns for targeting 49+ cryptocurrency wallet extensions
    Based on GlassWorm targeting MetaMask, Phantom, Coinbase Wallet, etc.
*/

rule GlassWorm_Crypto_Wallet_Targeting {
    meta:
        description = "Detects cryptocurrency wallet targeting patterns"
        severity = "high"
        score = "90"
        author = "Kirin Scanner (by Knostic)  - GlassWorm Detection Suite"
        date = "2025-10-18"
        reference = "https://www.koi.ai/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace"
    
    strings:
        // Major wallet extensions
        $metamask = "metamask" nocase ascii wide
        $phantom = "phantom" nocase ascii wide
        $coinbase = "coinbase" nocase ascii wide
        $trust_wallet = "trust wallet" nocase ascii wide
        $rainbow = "rainbow" nocase ascii wide
        $argent = "argent" nocase ascii wide
        $imtoken = "imtoken" nocase ascii wide
        $tokenpocket = "tokenpocket" nocase ascii wide
        
        // Wallet extension IDs and manifests
        $wallet_extension = "wallet" ascii wide
        $crypto_extension = "crypto" ascii wide
        $blockchain_extension = "blockchain" ascii wide
        $defi_extension = "defi" ascii wide
        
        // Browser extension manifest queries
        $chrome_extensions = "chrome://extensions" ascii wide
        $extension_manifest = "manifest.json" ascii wide
        $extension_id = "extensionId" ascii wide
        $extension_name = "extensionName" ascii wide
        
        // Wallet API access
        $ethereum_provider = "ethereum" ascii wide
        $web3_provider = "web3" ascii wide
        $wallet_provider = "provider" ascii wide
        $wallet_connect = "walletconnect" ascii wide
        
        // Wallet data access
        $wallet_address = "address" ascii wide
        $private_key = "privateKey" ascii wide
        $seed_phrase = "seedPhrase" ascii wide
        $mnemonic = "mnemonic" ascii wide
        $wallet_balance = "balance" ascii wide
        
    condition:
        // High confidence: Multiple wallet targets + wallet API access
        (3 of ($metamask, $phantom, $coinbase, $trust_wallet, $rainbow, $argent, $imtoken, $tokenpocket)) and
        (any of ($wallet_extension, $crypto_extension, $blockchain_extension, $defi_extension)) and
        (any of ($ethereum_provider, $web3_provider, $wallet_provider, $wallet_connect, $chrome_extensions, $extension_manifest, $extension_id, $extension_name, $wallet_address, $private_key, $seed_phrase, $mnemonic, $wallet_balance))
}

rule GlassWorm_Wallet_Seed_Extraction {
    meta:
        description = "Detects wallet seed phrase extraction patterns"
        severity = "critical"
        score = "95"
        author = "Kirin Scanner (by Knostic)  - GlassWorm Detection Suite"
        date = "2025-10-18"
    
    strings:
        // Seed phrase patterns
        $seed_phrase = "seedPhrase" ascii wide
        $mnemonic = "mnemonic" ascii wide
        $seed_words = "seedWords" ascii wide
        $recovery_phrase = "recoveryPhrase" ascii wide
        $backup_phrase = "backupPhrase" ascii wide
        
        // Private key patterns
        $private_key = "privateKey" ascii wide
        $private_key_hex = "privateKeyHex" ascii wide
        $wallet_key = "walletKey" ascii wide
        $master_key = "masterKey" ascii wide
        
        // Wallet storage access
        $local_storage = "localStorage" ascii wide
        $session_storage = "sessionStorage" ascii wide
        $chrome_storage = "chrome.storage" ascii wide
        $browser_storage = "browser.storage" ascii wide
        
        // Data extraction methods
        $get_item = "getItem" ascii wide
        $get_storage = "getStorage" ascii wide
        $read_storage = "readStorage" ascii wide
        $extract_data = "extract" ascii wide
        
        // Encryption/decryption
        $decrypt = "decrypt" ascii wide
        $unlock = "unlock" ascii wide
        $derive_key = "deriveKey" ascii wide
        $crypto_decrypt = "crypto.decrypt" ascii wide
        
    condition:
        // Critical: Seed phrase access + storage reading + decryption
        (any of ($seed_phrase, $mnemonic, $seed_words, $recovery_phrase, $backup_phrase, $private_key, $private_key_hex, $wallet_key, $master_key)) and
        (any of ($local_storage, $session_storage, $chrome_storage, $browser_storage)) and
        (any of ($get_item, $get_storage, $read_storage, $extract_data)) and
        (any of ($decrypt, $unlock, $derive_key, $crypto_decrypt))
}

rule GlassWorm_Wallet_Transaction_Interception {
    meta:
        description = "Detects wallet transaction interception patterns"
        severity = "high"
        score = "85"
        author = "Kirin Scanner (by Knostic)  - GlassWorm Detection Suite"
        date = "2025-10-18"
    
    strings:
        // Transaction patterns
        $transaction = "transaction" ascii wide
        $tx_hash = "txHash" ascii wide
        $transaction_hash = "transactionHash" ascii wide
        $tx_data = "txData" ascii wide
        
        // Transaction interception
        $intercept = "intercept" ascii wide
        $hook = "hook" ascii wide
        $override = "override" ascii wide
        $monitor = "monitor" ascii wide
        
        // Wallet API hooks
        $send_transaction = "sendTransaction" ascii wide
        $sign_transaction = "signTransaction" ascii wide
        $request_accounts = "requestAccounts" ascii wide
        $get_accounts = "getAccounts" ascii wide
        
        // Transaction data access
        $to_address = "to" ascii wide
        $from_address = "from" ascii wide
        $value = "value" ascii wide
        $gas_price = "gasPrice" ascii wide
        $gas_limit = "gasLimit" ascii wide
        
    condition:
        // Detect transaction interception with wallet API hooks
        (any of ($transaction, $tx_hash, $transaction_hash, $tx_data)) and
        (any of ($intercept, $hook, $override, $monitor)) and
        (any of ($send_transaction, $sign_transaction, $request_accounts, $get_accounts, $to_address, $from_address, $value, $gas_price, $gas_limit))
}

rule GlassWorm_Wallet_Extension_Enumeration {
    meta:
        description = "Detects wallet extension enumeration patterns"
        severity = "medium"
        score = "70"
        author = "Kirin Scanner (by Knostic)  - GlassWorm Detection Suite"
        date = "2025-10-18"
    
    strings:
        // Extension enumeration
        $enumerate = "enumerate" ascii wide
        $list_extensions = "listExtensions" ascii wide
        $get_extensions = "getExtensions" ascii wide
        $scan_extensions = "scanExtensions" ascii wide
        
        // Wallet detection
        $detect_wallet = "detectWallet" ascii wide
        $find_wallet = "findWallet" ascii wide
        $check_wallet = "checkWallet" ascii wide
        $wallet_detection = "walletDetection" ascii wide
        
        // Extension manifest queries
        $manifest_query = "manifest" ascii wide
        $extension_info = "extensionInfo" ascii wide
        $extension_details = "extensionDetails" ascii wide
        
        // Wallet-specific queries
        $metamask_detect = "metamask" nocase ascii wide
        $phantom_detect = "phantom" nocase ascii wide
        $coinbase_detect = "coinbase" nocase ascii wide
        
    condition:
        // Detect extension enumeration with wallet-specific detection
        (any of ($enumerate, $list_extensions, $get_extensions, $scan_extensions)) and
        (any of ($detect_wallet, $find_wallet, $check_wallet, $wallet_detection)) and
        (any of ($manifest_query, $extension_info, $extension_details, $metamask_detect, $phantom_detect, $coinbase_detect))
}
