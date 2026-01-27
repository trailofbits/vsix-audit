/*
    GlassWorm Blockchain C2 Detection
    Detects Solana blockchain-based command and control infrastructure
    Based on GlassWorm using Solana transactions for C2 communication
*/

rule GlassWorm_Solana_C2 {
    meta:
        description = "Detects Solana blockchain C2 infrastructure patterns"
        severity = "high"
        score = "85"
        author = "Kirin Scanner (by Knostic)  - GlassWorm Detection Suite"
        date = "2025-10-18"
        reference = "https://www.koi.ai/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace"

    strings:
        // Solana RPC endpoints
        $solana_mainnet = "api.mainnet-beta.solana.com" ascii wide
        $solana_devnet = "api.devnet.solana.com" ascii wide
        $solana_testnet = "api.testnet.solana.com" ascii wide
        $solana_rpc = "solana.com" ascii wide
        $solana_api = "solana-api" ascii wide

        // Solana SDK imports and usage
        $solana_web3 = "@solana/web3.js" ascii wide
        $solana_connection = "Connection" ascii wide
        $solana_publickey = "PublicKey" ascii wide
        $solana_transaction = "Transaction" ascii wide
        $solana_gettransaction = "getTransaction" ascii wide
        $solana_getsignatures = "getSignaturesForAddress" ascii wide

        // Blockchain transaction patterns (optimized - removed redundant strings)
        $instruction_data = "instructionData" ascii wide
        $transaction_memo = "transaction.memo" ascii wide
        $base64_decode = "base64decode" ascii wide
        $base64_encode = "base64encode" ascii wide

        // C2 communication patterns (optimized - removed heavy regex and redundant strings)
        $solana_url = /https?:\/\/[a-z0-9\-\.]*solana[a-z0-9\-\.]*\.com/ ascii wide
        $json_rpc = "jsonrpc" ascii wide

        // Dynamic payload fetching
        $fetch_payload = "fetch" ascii wide
        $http_request = "http.request" ascii wide
        $https_request = "https.request" ascii wide
        $axios = "axios" ascii wide

    condition:
        // High confidence: Solana RPC + transaction parsing + payload fetching
        (any of ($solana_mainnet, $solana_devnet, $solana_testnet, $solana_rpc, $solana_api)) and
        (any of ($solana_web3, $solana_connection, $solana_publickey, $solana_transaction, $solana_gettransaction, $solana_getsignatures)) and
        (any of ($instruction_data, $transaction_memo, $base64_decode, $base64_encode)) and
        (any of ($fetch_payload, $http_request, $https_request, $axios, $solana_url, $json_rpc))
}

rule GlassWorm_Blockchain_Memo_Parsing {
    meta:
        description = "Detects blockchain memo field parsing for C2 commands"
        severity = "high"
        score = "80"
        author = "Kirin Scanner (by Knostic)  - GlassWorm Detection Suite"
        date = "2025-10-18"

    strings:
        // Memo parsing patterns (optimized - removed redundant memo_parse)
        $json_parse = "JSON.parse" ascii wide
        $json_stringify = "JSON.stringify" ascii wide
        $memo_data = "memoData" ascii wide
        $instruction_data = "instructionData" ascii wide

        // Base64 encoding/decoding for payload URLs
        $atob = "atob(" ascii wide
        $btoa = "btoa(" ascii wide
        $buffer_from = "Buffer.from" ascii wide
        $base64 = "base64" ascii wide

        // URL extraction from memo
        $url_pattern = /https?:\/\/[^\s"']+/ ascii wide
        $link_extract = "link" ascii wide
        $payload_url = "payload" ascii wide

        // Command parsing
        $command_parse = "command" ascii wide
        $cmd_exec = "exec" ascii wide
        $eval_cmd = "eval" ascii wide

    condition:
        // Detect memo parsing with base64 decoding and URL extraction
        ($memo_data or $instruction_data) and
        (any of ($json_parse, $json_stringify)) and
        (any of ($atob, $btoa, $buffer_from, $base64)) and
        (any of ($url_pattern, $link_extract, $payload_url, $command_parse, $cmd_exec, $eval_cmd))
}

rule GlassWorm_Dynamic_C2_Resolution {
    meta:
        description = "Detects dynamic C2 resolution via blockchain queries"
        severity = "medium"
        score = "70"
        author = "Kirin Scanner (by Knostic)  - GlassWorm Detection Suite"
        date = "2025-10-18"

    strings:
        // Dynamic C2 patterns
        $wallet_query = "getSignaturesForAddress" ascii wide
        $transaction_query = "getTransaction" ascii wide
        $recent_transactions = "recent" ascii wide
        $transaction_history = "history" ascii wide

        // Polling behavior
        $setInterval = "setInterval" ascii wide
        $setTimeout = "setTimeout" ascii wide
        $polling = "poll" ascii wide

        // C2 rotation
        $c2_rotation = "rotation" ascii wide
        $backup_c2 = "backup" ascii wide
        $fallback = "fallback" ascii wide

        // Network requests to resolved C2
        $fetch = "fetch(" ascii wide
        $request = "request(" ascii wide
        $http = "http" ascii wide

    condition:
        // Detect blockchain querying with polling and network requests
        (any of ($wallet_query, $transaction_query, $recent_transactions, $transaction_history)) and
        (any of ($setInterval, $setTimeout, $polling)) and
        (any of ($fetch, $request, $http, $c2_rotation, $backup_c2, $fallback))
}
