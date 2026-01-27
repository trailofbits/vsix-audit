# vsix-audit

> **WARNING: This repository contains live malware samples in the `zoo/` directory for security research purposes. Do not execute, install, or open these files outside of an isolated analysis environment. Handle with extreme caution.**

Security scanner for VS Code extensions. Analyze extensions before approving them for installation in your organization.

## Installation

```sh
npm install -g vsix-audit
```

Requires Node.js 22 or later.

## Usage

Scan a local `.vsix` file:

```sh
vsix-audit scan ./extension.vsix
```

Scan by extension ID (downloads from marketplace):

```sh
vsix-audit scan publisher.extension-name
```

### Options

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

## Security Checks

The scanner analyzes extensions for:

- **Permissions** - Excessive or dangerous permission requests
- **Code patterns** - Obfuscated code, eval usage, dynamic imports
- **Network activity** - Suspicious URLs, data exfiltration patterns
- **Dependencies** - Known vulnerable packages
- **Manifest issues** - Misconfigured activation events, overly broad file associations

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

## Malware Zoo

The `zoo/` directory contains malware samples and threat intelligence for testing detection capabilities:

| Directory | Contents |
|-----------|----------|
| `zoo/samples/` | 833 files including .vsix extensions, native binaries, JS payloads |
| `zoo/blocklist/` | 24 known malicious extension IDs |
| `zoo/iocs/` | Hashes, C2 domains/IPs, crypto wallets |
| `zoo/signatures/` | 7 YARA detection rules |

**Campaigns covered:** GlassWorm, Evelyn, TigerJack, OctoRAT, WhiteCobra, SnowShoNo, Shiba, FAMOUS CHOLLIMA

Sources: MalwareBazaar, VirusTotal, Knostic, ReversingLabs, Koi Security, educational PoCs from GitHub.

## License

AGPL-3.0
