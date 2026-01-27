# vsix-audit Project Instructions

## Project Overview

A security scanner for VS Code extensions. Detects malicious extensions before installation.

## API Keys Available

### VirusTotal
- **Location**: `.env` file (`VIRUSTOTAL_API_KEY`)
- **Usage**: Download malware samples, query file hashes, get threat intelligence
- **API Docs**: https://docs.virustotal.com/reference/overview
- **Rate Limits**: 4 requests/minute (free tier)

```bash
# Example: Download a file by hash
curl -s "https://www.virustotal.com/api/v3/files/{hash}/download" \
  -H "x-apikey: $VIRUSTOTAL_API_KEY" -o sample.bin

# Example: Get file report
curl -s "https://www.virustotal.com/api/v3/files/{hash}" \
  -H "x-apikey: $VIRUSTOTAL_API_KEY"
```

### MalwareBazaar (abuse.ch)
- **Location**: `.env` file (`MALWAREBAZAAR_API_KEY`)
- **Usage**: Download malware samples, query threat intel, similarity searches
- **API Docs**: [docs/apis/malwarebazaar.md](docs/apis/malwarebazaar.md) ← **Read before using**
- **Rate Limits**: Fair use (commercial use requires paid tier)

```bash
# Example: Download sample by hash (returns AES-encrypted ZIP, password: infected)
curl -X POST "https://mb-api.abuse.ch/api/v1/" \
  -H "Auth-Key: $MALWAREBAZAAR_API_KEY" \
  -d "query=get_file&sha256_hash=HASH" -o sample.zip

# Example: Query sample info
curl -X POST "https://mb-api.abuse.ch/api/v1/" \
  -H "Auth-Key: $MALWAREBAZAAR_API_KEY" \
  -d "query=get_info&hash=HASH"
```

### Exa AI (MCP Server)
- **Location**: `.mcp.json` (project scope)
- **Usage**: Web search for threat intelligence, malware research
- **Tools**: `mcp__exa-ai__web_search_exa`, `mcp__exa-ai__get_code_context_exa`

## Project Structure

```
vsix-audit/
├── src/                    # Scanner source code (TypeScript)
├── zoo/                    # Malware sample collection
│   ├── manifest.json       # Sample index
│   ├── samples/            # Actual malware files
│   ├── iocs/               # Hashes, C2 domains, IPs, wallets
│   ├── signatures/yara/    # Detection rules
│   ├── blocklist/          # Extension IDs to block
│   └── watchlist/          # Suspicious extensions to monitor
├── docs/apis/              # API reference (read before using)
│   └── malwarebazaar.md    # MalwareBazaar API usage
└── docs/research/          # Threat intelligence notes
    ├── vscode-extension-security.md    # Extension-specific threats
    └── vscode-workspace-security.md    # tasks.json, npm attacks
```

## Key Commands

```bash
# Run tests
npm test

# Build
npm run build

# Lint
npm run lint
```

## Zoo Management

When adding samples to the zoo:
1. Download by hash from VirusTotal or MalwareBazaar (see `docs/apis/`)
2. Add entry to `zoo/manifest.json`
3. Update IOC files in `zoo/iocs/`
4. Large files (.vsix, .node, .exe) are gitignored - samples stay local

## Research Sources

- **MalwareBazaar**: https://bazaar.abuse.ch/ - Malware sample repository (we have API key)
- **Koi Security**: https://dex.koi.security/ - Real-time extension threat feed
- **Knostic YARA**: https://github.com/knostic/open-tools/tree/main/glassworm_yara
- **Socket.dev**: https://socket.dev/blog - npm malware tracking
- **ops-trust**: Internal threat intel (check docs/research/ for archived intel)

## Threat Actors We Track

| Actor | Focus |
|-------|-------|
| GlassWorm | Supply chain, self-propagation |
| WhiteCobra | Crypto theft |
| TigerJack | Keylogging, cryptomining |
| FAMOUS CHOLLIMA | Fake job interviews (North Korea) |
