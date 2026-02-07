/*
    Extended Blockchain C2 Detection
    Detects Ethereum smart contract interaction patterns used
    for command-and-control, extending the Solana-focused
    blockchain_c2.yar rules.

    SleepyDuck campaign uses Ethereum contracts to store C2
    server addresses, queried via ethers.js/web3.js ABI calls.
    The contract stores the current C2 URL which the malware
    reads to get instructions, then executes the result.

    Target: JavaScript files (no `wide` needed)
*/

rule C2_JS_Ethereum_Contract_C2_Feb26 {
  meta:
    description = "Detects Ethereum contract queries combined with dynamic code execution (SleepyDuck C2 pattern)"
    severity    = "high"
    score       = 80
    author      = "vsix-audit"
    date        = "2026-02-06"
    reference   = "https://www.secureannex.com/blog/can-you-trust-your-vscode-extensions"

  strings:
    // Ethereum library imports
    $lib1 = "ethers" ascii
    $lib2 = "@ethersproject" ascii

    // Contract interaction
    $contract1 = "new Contract(" ascii
    $contract2 = "getContract(" ascii

    // RPC provider connection
    $rpc1 = "JsonRpcProvider" ascii
    $rpc2 = "InfuraProvider" ascii
    $rpc3 = "AlchemyProvider" ascii
    $rpc4 = "Web3Provider" ascii

    // Dynamic code execution — the C2 signal
    // child_process and new Function("return this") are too
    // common in bundled Ethereum dev tools (webpack polyfills,
    // compiler toolchains). Only eval() is a strong C2 signal
    // when combined with contract interaction.
    $exec1 = "eval(" ascii

  condition:
    any of ($lib*) and
    any of ($contract*) and
    any of ($rpc*) and
    $exec1
}

// REMOVED: C2_JS_Blockchain_Address_Resolution_Feb26
// 87 FPs across 440-extension corpus. The getter patterns
// (.getServer, .getConfig, .getAddress) combined with
// Provider() + fetch() + child_process were far too generic —
// matched virtually any large bundled extension.
