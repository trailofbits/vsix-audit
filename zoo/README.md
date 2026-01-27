# VS Code Extension Malware Zoo

A community-maintained collection of malicious VS Code extension samples, IOCs, and detection signatures.

**Purpose:**
- Validate scanner detection capabilities
- Share threat intelligence with the security community
- Track emerging threats targeting developers

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to submit samples and IOCs.

## Directory Structure

```
zoo/
├── manifest.json          # Index of all samples with metadata
├── samples/               # Malicious extensions (VSIX files or extracted folders)
│   └── {campaign}/        # Organized by threat actor/campaign
├── iocs/                  # Indicators of compromise
│   ├── hashes.txt         # SHA256 hashes (one per line)
│   ├── c2-domains.txt     # Command & control domains
│   ├── c2-ips.txt         # Command & control IPs
│   └── wallets.txt        # Cryptocurrency wallets
├── signatures/            # Detection rules
│   └── yara/              # YARA rules
├── blocklist/             # Known malicious extensions
│   └── extensions.json    # Extension IDs to block
└── watchlist/             # Suspicious but unconfirmed
    └── suspicious.json    # Extensions exhibiting anomalies
```

## Quick Stats

| Metric | Count |
|--------|-------|
| Samples tracked | 10+ |
| Threat actors | 5 |
| YARA rules | 24+ |
| Blocked extensions | 15+ |

## Threat Actors Tracked

| Actor | Campaign | Targets | Active |
|-------|----------|---------|--------|
| GlassWorm | Supply chain | All developers | Yes |
| WhiteCobra | Crypto theft | Crypto developers | Yes |
| TigerJack | Code theft, mining | All developers | Yes |
| FAMOUS CHOLLIMA | Interview scams | Job seekers | Yes |
| Unknown | Evelyn Stealer | Crypto developers | Yes |

## Usage with vsix-audit

```bash
# Scan against all samples
vsix-audit scan zoo/samples/ --recursive

# Check extension against blocklist
vsix-audit check <extension-id> --blocklist zoo/blocklist/extensions.json

# Run with custom YARA rules
vsix-audit scan <extension> --yara zoo/signatures/yara/
```

## Manifest Schema

Each entry in `manifest.json`:

```json
{
  "id": "unique-sample-id",
  "name": "Extension Name",
  "publisher": "publisher-name",
  "version": "1.0.0",
  "platform": "vscode|openvsx|cursor",
  "campaign": "GlassWorm|TigerJack|WhiteCobra|...",
  "malwareFamily": "ScreenConnect|OctoRAT|Ransomware|...",
  "sha256": "hash-of-vsix-or-main-file",
  "source": "github|virustotal|community",
  "sourceUrl": "https://...",
  "discoveryDate": "2025-11-28",
  "capabilities": ["credential-theft", "crypto-wallet", "keylogger", "ransomware"],
  "localPath": "samples/glassworm/material-icon-fake.vsix",
  "notes": "Description of the threat"
}
```

## Sample Sources

We track samples from:

### GitHub Repositories

| Repository | Contents |
|------------|----------|
| [b4ba/ECM3401-VSCode-Extensions](https://github.com/b4ba/ECM3401-VSCode-Extensions) | Pre-built .vsix files (educational) |
| [KagemaNjoroge/malicious-vscode-extensions](https://github.com/KagemaNjoroge/malicious-vscode-extensions) | Community tracker with extension folders |
| [0x-Apollyon/Malicious-VScode-Extension](https://github.com/0x-Apollyon/Malicious-VScode-Extension) | PoC samples |

### VirusTotal Hashes

| Sample | SHA256 | Campaign |
|--------|--------|----------|
| os.node (Windows) | `6ebeb188f3cc3b647c4460c0b8e41b75d057747c662f4cd7912d77deaccfd2f2` | GlassWorm |
| darwin.node (macOS) | `fb07743d139f72fca4616b01308f1f705f02fda72988027bc68e9316655eadda` | GlassWorm |
| extension.js | `9212a99a7730b9ee306e804af358955c3104e5afce23f7d5a207374482ab2f8f` | GlassWorm |

## Legal Notice

This collection is for **security research and defensive tool development only**.

- Do NOT execute samples outside isolated/sandboxed environments
- Do NOT use samples for malicious purposes
- Samples may be subject to takedown requests

## Related Projects

- [Knostic GlassWorm YARA](https://github.com/knostic/open-tools/tree/main/glassworm_yara) - Detection rules
- [Koi Security](https://dex.koi.security/) - Extension threat intelligence
- [Socket.dev](https://socket.dev/) - npm package security
