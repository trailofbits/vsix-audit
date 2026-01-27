# Contributing to the Zoo

We welcome contributions of malicious extension samples, IOCs, and detection signatures.

## What We Accept

### Samples
- Malicious VS Code extensions (.vsix files or extracted folders)
- Extensions from any platform: VS Code Marketplace, Open VSX, Cursor, Windsurf
- PoC/educational samples (clearly labeled)

### IOCs
- SHA256 hashes of malicious files
- C2 domains and IP addresses
- Cryptocurrency wallet addresses used by attackers
- Extension IDs confirmed malicious

### Signatures
- YARA rules for detection
- Code patterns and regex for scanning

## How to Submit

### Option 1: Pull Request (Preferred)

1. Fork the repository
2. Add your sample/IOC following the structure below
3. Submit a PR with description of the threat

### Option 2: Issue

Open an issue with:
- Sample hash (SHA256)
- Source (where you found it)
- Brief description of malicious behavior
- Any references (blog posts, research)

### Option 3: Email

For sensitive submissions, contact the maintainers directly.

## Sample Submission Format

### Adding a Sample

1. Place the file in `samples/{campaign}/`
2. Add an entry to `manifest.json`:

```json
{
  "id": "unique-id",
  "name": "Extension Name",
  "publisher": "publisher-name",
  "version": "1.0.0",
  "platform": "vscode|openvsx|cursor",
  "campaign": "CampaignName",
  "malwareFamily": "MalwareType",
  "sha256": "hash-of-main-file",
  "source": "github|virustotal|community|your-name",
  "sourceUrl": "https://reference-link",
  "discoveryDate": "YYYY-MM-DD",
  "capabilities": ["list", "of", "capabilities"],
  "localPath": "samples/campaign/filename.vsix",
  "notes": "Brief description"
}
```

### Adding IOCs

Append to the appropriate file in `iocs/`:

- `hashes.txt` - One SHA256 per line, with comment
- `c2-domains.txt` - One domain per line (defanged: `example[.]com`)
- `c2-ips.txt` - One IP per line
- `wallets.txt` - Wallet address with currency type

### Adding to Blocklist

Add to `blocklist/extensions.json`:

```json
{
  "id": "publisher.extension-name",
  "reason": "Brief reason",
  "campaign": "CampaignName",
  "addedDate": "YYYY-MM-DD"
}
```

## Capabilities Tags

Use these standard tags in the `capabilities` field:

| Tag | Description |
|-----|-------------|
| `credential-theft` | Steals passwords, tokens, API keys |
| `crypto-wallet` | Targets cryptocurrency wallets |
| `keylogger` | Records keystrokes |
| `screenshot` | Captures screenshots |
| `ransomware` | Encrypts files for ransom |
| `cryptominer` | Mines cryptocurrency |
| `backdoor` | Provides remote access |
| `rat` | Full remote access trojan |
| `data-exfiltration` | Sends data to attacker |
| `self-propagation` | Spreads to other systems |
| `persistence` | Survives reboots |

## Quality Standards

- **Verify before submitting** - Confirm the sample is actually malicious
- **Include sources** - Link to research, blog posts, or VirusTotal
- **Defang URLs/IPs** - Use `[.]` in domains, don't include live C2 links
- **No duplicates** - Check `manifest.json` first

## Attribution

Contributors will be credited in the manifest entry (`source` field) unless they prefer anonymity.

## Questions?

Open an issue or reach out to maintainers.
