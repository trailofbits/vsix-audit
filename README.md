# vsix-audit

Security scanner for VS Code extensions. Detects malicious extensions before installation by analyzing code patterns, indicators of compromise, and known malware signatures.

## The Problem

VS Code extensions run with full trust and the same permissions as the editor itself. Malicious extensions have been found in both the official Microsoft marketplace and OpenVSX:

- **Credential theft** - SSH keys, browser cookies, password manager databases
- **Cryptocurrency theft** - Wallet files, clipboard hijacking for addresses
- **Source code exfiltration** - Stealing proprietary code via Discord webhooks
- **Cryptominers and RATs** - CoinIMP miners, ScreenConnect RATs, multi-stage loaders
- **Self-propagation** - GlassWorm spread by modifying installed extensions

## Detection Modules

The scanner runs 6 detection modules against each extension:

### Package Analysis (`package.ts`)

Examines `package.json` and extension manifest for suspicious configurations.

| Check                  | What It Detects                                                                 | Severity        |
| ---------------------- | ------------------------------------------------------------------------------- | --------------- |
| Blocklist              | Extension ID matches known malicious extensions                                 | Critical        |
| Wildcard activation    | `activationEvents: ["*"]` - runs on every action                                | High            |
| Startup activation     | `onStartupFinished` - runs at VS Code launch                                    | Medium          |
| Theme with code        | Theme extension that has a `main` entry point                                   | High            |
| Malicious npm packages | Dependencies matching known malware packages                                    | Critical        |
| Typosquatting          | Dependencies within edit distance 1-2 of popular packages (lodash, axios, etc.) | High            |
| Lifecycle scripts      | `preinstall`/`postinstall` scripts with suspicious patterns                     | Critical/Medium |

### Indicators of Compromise (`ioc.ts`)

Matches against curated threat intelligence from `zoo/iocs/`.

| Check          | Detection Method                                                    | Severity |
| -------------- | ------------------------------------------------------------------- | -------- |
| Malware hashes | SHA256 hash of files matches known samples                          | Critical |
| C2 domains     | Domain extraction matched against blocklist                         | Critical |
| C2 IPs         | IPv4 extraction (excludes private ranges) matched against blocklist | Critical |
| Crypto wallets | BTC (legacy/SegWit/Bech32), ETH, Monero, Solana address patterns    | High     |

### AST Analysis (`ast.ts`)

OXC-based parsing to detect structural patterns that regex can't catch.

| Rule                       | What It Detects                                  | Severity |
| -------------------------- | ------------------------------------------------ | -------- |
| `AST_EVAL_DYNAMIC`         | `eval(variable)` - non-literal argument          | High     |
| `AST_FUNCTION_CONSTRUCTOR` | `new Function(string)` - runtime code generation | High     |
| `AST_DYNAMIC_REQUIRE`      | `require(variable)` - computed module loads      | Medium   |
| `AST_DYNAMIC_IMPORT`       | `import(variable)` - computed dynamic imports    | Medium   |
| `AST_PROCESS_BINDING`      | `process.binding()` - Node.js internals access   | High     |
| `AST_GLOBAL_THIS_EVAL`     | `globalThis.eval` - indirect eval access         | High     |

### Obfuscation Detection (`obfuscation.ts`)

Detects obfuscation techniques used to hide malicious intent.

| Rule                       | Detection Method                                                  | Severity |
| -------------------------- | ----------------------------------------------------------------- | -------- |
| `OBFUSCATION_HIGH_ENTROPY` | Shannon entropy >5.5 bits/char (200-char windows)                 | Medium   |
| `ZERO_WIDTH_CHARS`         | Zero-width spaces/joiners hiding code (U+200B-200D)               | High     |
| `VARIATION_SELECTOR`       | GlassWorm-style hidden data in variation selectors (U+FE00-FE0F)  | Critical |
| `BIDI_OVERRIDE`            | Trojan Source attacks using bidirectional overrides (U+202A-202E) | Critical |
| `UNICODE_ASCII_ESCAPE`     | `\u00XX` escapes for normal ASCII chars (obfuscation)             | Medium   |
| `CYRILLIC_HOMOGLYPH`       | Cyrillic letters that look like Latin (а/a, е/e, с/c)             | High     |
| `OTHER_INVISIBLE_CHARS`    | Soft hyphens, combining marks, format controls                    | Medium   |
| `INVISIBLE_CODE_EXECUTION` | Invisible chars near `eval`/`Function`/`exec`                     | Critical |

JavaScript obfuscation patterns (hex variables, `fromCharCode` arrays, eval+decode, packers) are now detected via YARA rules for better accuracy.

### YARA Rules (`yara.ts`)

External YARA-X engine for complex pattern matching. Rules loaded from `zoo/signatures/yara/`. Requires `yr` CLI (`brew install yara-x`).

| Rule File                     | Detects                                                        |
| ----------------------------- | -------------------------------------------------------------- |
| `blockchain_c2.yar`           | Solana RPC C2, memo parsing, blockchain-based command channels |
| `code_execution.yar`          | `eval`, `Function` constructor, `child_process` patterns       |
| `credential_harvesting.yar`   | NPM/GitHub/SSH credential theft, `.npmrc` access               |
| `crypto_wallet_targeting.yar` | MetaMask, Phantom, Exodus wallet extension targeting           |
| `data_exfiltration.yar`       | Discord webhooks, SSH key theft, browser data exfil            |
| `google_calendar_c2.yar`      | Google Calendar API abuse for C2 communication                 |
| `multi_stage_attacks.yar`     | Dropper chains, reverse shells, keylogger patterns             |
| `obfuscation_patterns.yar`    | Hex variables, `fromCharCode`, packed/encoded code             |
| `powershell_attacks.yar`      | Hidden windows, `-ExecutionPolicy Bypass`, AMSI evasion        |
| `rat_capabilities.yar`        | SOCKS proxy, VNC, remote command execution                     |
| `self_propagation.yar`        | GlassWorm-style worm propagation via extension modification    |
| `unicode_stealth.yar`         | Invisible Unicode, variation selectors, homoglyphs             |

### Telemetry Detection (`telemetry.ts`)

Detects when extensions send data to external analytics, crash-reporting, or APM services.

| Check           | What It Detects                                                   | Severity      |
| --------------- | ----------------------------------------------------------------- | ------------- |
| SDK imports     | Known telemetry packages (Sentry, Mixpanel, PostHog, AppInsights) | High/Medium   |
| Endpoint URLs   | URLs matching known telemetry services from `zoo/telemetry/`      | High/Medium   |
| Telemetry paths | API paths like `/collect`, `/track`, `/ingest`, `/metrics`        | High/Medium   |
| Data collection | Patterns near telemetry code (machine_id, user_id, file_paths)    | Informational |

**Opt-out detection:** Severity is reduced from High to Medium when extensions respect user preferences:

- `vscode.env.isTelemetryEnabled` - VS Code's global telemetry setting
- Manifest configuration - Extension exposes a telemetry toggle setting
- Code conditional - Checks a user preference before sending

### Triage-Friendly Output

Every finding includes context to help quickly determine if it's a real threat:

- **Legitimate uses** - Why this pattern exists in benign extensions
- **Red flags** - What makes the same pattern suspicious in context
- **Severity** - Critical/high/medium/low based on risk and intent signals
- **Location** - File path and line number for the match

The goal is rich context for human/agent review, not just pass/fail.

## Installation

```sh
npm install -g @trailofbits/vsix-audit
```

Requires Node.js 22 or later.

## Usage

### Commands

**Scan an extension for security issues:**

```sh
vsix-audit scan ./extension.vsix
vsix-audit scan publisher.extension-name
vsix-audit scan openvsx:publisher.extension-name
```

**Download an extension for offline analysis:**

```sh
vsix-audit download ms-python.python
vsix-audit download ms-python.python@2024.1.0 -o ./downloads
vsix-audit download openvsx:redhat.java
```

**Show extension metadata:**

```sh
vsix-audit info ./extension.vsix
vsix-audit info ./extension-folder
```

Displays: name, publisher, version, activation events, entry points, contributions, dependencies, file count, and size.

### Registry Prefixes

| Prefix         | Registry                       |
| -------------- | ------------------------------ |
| (none)         | VS Code Marketplace (default)  |
| `marketplace:` | VS Code Marketplace (explicit) |
| `openvsx:`     | Open VSX Registry              |
| `cursor:`      | Cursor Extension Marketplace   |

### Scan Options

| Option                   | Description                                                                      |
| ------------------------ | -------------------------------------------------------------------------------- |
| `-o, --output <format>`  | Output format: `text`, `json`, or `sarif` (default: `text`)                      |
| `-s, --severity <level>` | Minimum severity to report: `low`, `medium`, `high`, `critical` (default: `low`) |
| `-r, --recursive`        | Recursively scan all .vsix files in a directory                                  |
| `-j, --jobs <n>`         | Number of parallel scans (default: 4, used with --recursive)                     |
| `--no-network`           | Disable network-based checks                                                     |
| `--no-cache`             | Bypass cache, download fresh                                                     |
| `--force`                | Re-download even if cached                                                       |
| `--all-registries`       | Scan from all registries (Marketplace + OpenVSX + Cursor)                        |

### Extension Cache

Downloaded extensions are cached for faster subsequent scans:

| Platform | Cache Location                                          |
| -------- | ------------------------------------------------------- |
| macOS    | `~/Library/Caches/vsix-audit/`                          |
| Linux    | `$XDG_CACHE_HOME/vsix-audit/` or `~/.cache/vsix-audit/` |

Extensions are organized by registry (`marketplace/`, `openvsx/`, `cursor/`).

**Cache management commands:**

```sh
vsix-audit cache path              # Print cache directory
vsix-audit cache list [--json]     # List cached extensions
vsix-audit cache clear [pattern]   # Clear cache (optional glob pattern)
vsix-audit cache info <ext-id>     # Show cached versions
```

**Examples:**

```sh
# First scan downloads to cache
vsix-audit scan ms-python.python
# → Downloaded ~/.cache/vsix-audit/marketplace/ms-python.python-2024.1.0.vsix

# Second scan uses cache
vsix-audit scan ms-python.python
# → Using cached ~/.cache/vsix-audit/marketplace/ms-python.python-2024.1.0.vsix

# Force re-download
vsix-audit scan --force ms-python.python

# Bypass cache entirely
vsix-audit scan --no-cache ms-python.python

# Clear specific extensions
vsix-audit cache clear ms-python.*
```

### Output Formats

**Text** (default) - Human-readable report for terminal output.

**JSON** - Machine-readable results for integration with other tools.

**SARIF** - Static Analysis Results Interchange Format for CI/CD integration.

### Exit Codes

| Code | Meaning           |
| ---- | ----------------- |
| 0    | No findings       |
| 1    | Findings detected |
| 2    | Error during scan |

## Threat Intelligence

The `zoo/` directory contains threat intelligence for detection:

| Directory         | Contents                                                              |
| ----------------- | --------------------------------------------------------------------- |
| `zoo/blocklist/`  | Known malicious extension IDs with campaign attribution               |
| `zoo/iocs/`       | SHA256 hashes, C2 domains/IPs, crypto wallets, malicious npm packages |
| `zoo/signatures/` | YARA rules for credential harvesting, RAT behavior, self-propagation  |
| `zoo/telemetry/`  | Known telemetry service domains (analytics, crash-reporting, APM)     |

**IOCs sourced from:** GlassWorm, Evelyn, TigerJack, OctoRAT, WhiteCobra, Shiba, MUT-9332, FAMOUS CHOLLIMA, ReversingLabs-Dec2025

### Malware Samples (for development)

Malware samples are in a separate private repository ([trailofbits/vsix-zoo](https://github.com/trailofbits/vsix-zoo)) to avoid Dependabot alerts and AV triggers.

```bash
# Clone the samples repo (requires access)
git clone git@github.com:trailofbits/vsix-zoo.git ../vsix-zoo

# Run tests with samples
VSIX_ZOO_PATH=../vsix-zoo/samples npm test
```

## Development

```sh
git clone https://github.com/trailofbits/vsix-audit.git
cd vsix-audit
npm install
prek install   # pre-commit hooks
npm run check  # typecheck + lint + test
```

## License

AGPL-3.0
