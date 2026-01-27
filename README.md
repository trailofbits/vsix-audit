# vsix-audit

Security scanner for VS Code extensions. Detects malicious extensions before installation by analyzing code patterns, indicators of compromise, and known malware signatures.

## The Problem

VS Code extensions run with full trust and the same permissions as the editor itself. Malicious extensions have been found in both the official Microsoft marketplace and OpenVSX:

- **Credential theft** - SSH keys, browser cookies, password manager databases
- **Cryptocurrency theft** - Wallet files, clipboard hijacking for addresses
- **Source code exfiltration** - Stealing proprietary code via Discord webhooks
- **Cryptominers and RATs** - CoinIMP miners, ScreenConnect RATs, multi-stage loaders
- **Self-propagation** - GlassWorm spread by modifying installed extensions

**Real campaigns we track:** GlassWorm, TigerJack, Evelyn, WhiteCobra, OctoRAT, Shiba, MUT-9332

## Detection Capabilities

| Category | What It Detects |
|----------|-----------------|
| **Blocklist** | Known malicious extension IDs from tracked campaigns |
| **IOCs** | SHA256 hashes, C2 domains, C2 IPs, crypto wallet addresses |
| **Patterns** | PowerShell attacks, Discord webhooks, SSH key theft, crypto wallet access, eval/atob obfuscation |
| **Unicode** | GlassWorm variation selectors, Trojan Source bidi overrides, Cyrillic homoglyphs, zero-width characters |
| **YARA** | Credential harvesting, RAT capabilities, self-propagation, crypto targeting, blockchain C2 |
| **Dependencies** | Known malicious npm packages |
| **Manifest** | Wildcard activation events, themes with code (common malware disguise) |

### Triage-Friendly Design

Every finding includes context to help you quickly determine if it's a real threat or expected behavior:

- **Legitimate uses** - Why this pattern exists in benign extensions
- **Red flags** - What makes the same pattern suspicious in context
- **Severity ratings** - Critical/high/medium/low based on risk and intent signals

The goal is rich context for human/agent review, not just pass/fail.

## Installation

```sh
npm install -g vsix-audit
```

Requires Node.js 22 or later.

## Usage

### Commands

**Scan an extension for security issues:**

```sh
vsix-audit scan ./extension.vsix
vsix-audit scan publisher.extension-name
```

**Download an extension for offline analysis:**

```sh
vsix-audit download ms-python.python
vsix-audit download ms-python.python@2024.1.0 -o ./downloads
```

**Show extension metadata:**

```sh
vsix-audit info ./extension.vsix
vsix-audit info ./extension-folder
```

Displays: name, publisher, version, activation events, entry points, contributions, dependencies, file count, and size.

### Scan Options

| Option | Description |
|--------|-------------|
| `-o, --output <format>` | Output format: `text`, `json`, or `sarif` (default: `text`) |
| `-s, --severity <level>` | Minimum severity to report: `low`, `medium`, `high`, `critical` (default: `low`) |
| `--no-network` | Disable network-based checks |

### Output Formats

**Text** (default) - Human-readable report for terminal output.

**JSON** - Machine-readable results for integration with other tools.

**SARIF** - Static Analysis Results Interchange Format for CI/CD integration.

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings |
| 1 | Findings detected |
| 2 | Error during scan |

## Threat Intelligence

The `zoo/` directory contains threat intelligence for detection:

| Directory | Contents |
|-----------|----------|
| `zoo/blocklist/` | Known malicious extension IDs with campaign attribution |
| `zoo/iocs/` | SHA256 hashes, C2 domains/IPs, crypto wallets, malicious npm packages |
| `zoo/signatures/` | YARA rules for credential harvesting, RAT behavior, self-propagation |

**Campaigns covered:** GlassWorm, Evelyn, TigerJack, OctoRAT, WhiteCobra, Shiba, MUT-9332, ReversingLabs-Dec2025

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
npm run build
```

Run tests:

```sh
npm test
```

Type check and lint:

```sh
npm run check
```

## License

AGPL-3.0
