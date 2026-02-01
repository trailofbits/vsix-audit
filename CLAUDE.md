# vsix-audit Project Instructions

## Project Overview

A security scanner for VS Code extensions. Detects malicious extensions before installation.

## Scanner Design Philosophy

**Core principle:** Flag suspicious patterns for human/agent review with rich context, rather than trying to eliminate false positives.

### Design Decisions

1. **Prefer sensitivity over specificity**
   - Better to flag a legitimate extension for review than miss a malicious one
   - The cost of a false negative (missed malware) far exceeds a false positive (extra review)

2. **Findings must facilitate triage**
   - Every finding needs enough context for a reviewer to quickly determine: real threat or expected behavior?
   - Include: matched text, file location, line number when possible
   - Describe legitimate uses alongside the risk

3. **Finding structure**

   ```typescript
   {
     id: "CHILD_PROCESS_EXEC",           // Unique rule identifier
     title: "Command execution via child_process",
     description: "...",                  // Explain risk AND legitimate uses
     severity: "medium",                  // low/medium/high/critical
     category: "pattern",                 // pattern/manifest/unicode/yara/ioc
     location: { file: "...", line: 42 }, // Where it was found
     metadata: {
       matched: "exec('git pull')",       // Actual matched content
       legitimateUses: ["Git", "Build tools", "Linters"],
       redFlags: ["Combined with obfuscation", "Network exfiltration nearby"]
     }
   }
   ```

4. **Severity guidelines**
   - **critical**: Known malware signatures, C2 domains, credential exfiltration patterns
   - **high**: Suspicious combinations (invisible chars + eval), wallet access, SSH key reads
   - **medium**: Single suspicious patterns that have legitimate uses (child_process, lifecycle scripts)
   - **low**: Informational (module imports, activation events)

5. **Edge cases are expected**
   - Extensions like `remote-ssh` will trigger SSH-related findings - that's correct behavior
   - Security audit tools may reference wallets/crypto - document this in the finding
   - The goal is contextual findings, not zero findings

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
├── zoo/                    # Threat intelligence (no samples)
│   ├── iocs/               # Hashes, C2 domains, IPs, wallets, malicious npm packages
│   ├── signatures/yara/    # Detection rules
│   └── blocklist/          # Extension IDs to block
└── docs/apis/              # API reference (read before using)
    └── malwarebazaar.md    # MalwareBazaar API usage
```

### vsix-zoo (Separate Private Repository)

Malware samples are stored in a separate private repository (`trailofbits/vsix-zoo`) to:

- Eliminate Dependabot security alert noise
- Prevent AV triggers when users install the scanner
- Keep the main repo lightweight

```
vsix-zoo/
├── samples/                # Malware samples (94MB+)
│   ├── apollyon/           # Discord webhook exfil PoC
│   ├── ecm3401/            # Educational attack suite
│   ├── glassworm/          # Supply chain malware
│   ├── kagema/             # SnowShoNo samples
│   └── ...
├── manifest.json           # Sample metadata/index
├── watchlist/              # Suspicious extensions to monitor
└── research/               # Threat intelligence notes
```

**To run sample-based tests:**

```bash
git clone git@github.com:trailofbits/vsix-zoo.git ../vsix-zoo
VSIX_ZOO_PATH=../vsix-zoo/samples npm test
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

## Pre-commit Hooks

This project uses prek for pre-commit hooks. Hooks are **mandatory** - do not bypass them.

### Setup

```bash
prek install
```

### What runs on commit

1. **Hygiene**: trailing whitespace, EOF newlines, YAML/JSON validation
2. **Security**: private key detection, large file blocking
3. **Quality**: TypeScript type checking, oxlint, oxfmt formatting
4. **Tests**: Full vitest suite

### Commands

```bash
prek run --all-files  # Run all hooks on entire codebase
prek run              # Run hooks on staged files only
```

### Do not bypass

Never use `--no-verify` to skip hooks. If hooks fail, fix the issues.

## Zoo Management

### IOCs and Signatures (in vsix-audit)

- Update IOC files in `zoo/iocs/` (hashes, C2 domains, IPs, wallets)
- Add YARA rules to `zoo/signatures/yara/`
- Update blocklist in `zoo/blocklist/`

### Samples (in vsix-zoo)

When adding samples to the zoo:

1. Clone `vsix-zoo` repo locally
2. Download by hash from VirusTotal or MalwareBazaar (see `docs/apis/`)
3. Add sample to `vsix-zoo/samples/{campaign}/`
4. Update `vsix-zoo/manifest.json`

## Research Sources

- **MalwareBazaar**: https://bazaar.abuse.ch/ - Malware sample repository (we have API key)
- **Koi Security**: https://dex.koi.security/ - Real-time extension threat feed
- **Knostic YARA**: https://github.com/knostic/open-tools/tree/main/glassworm_yara
- **Socket.dev**: https://socket.dev/blog - npm malware tracking
- **ops-trust**: Internal threat intel (check docs/research/ for archived intel)

## Threat Actors We Track

| Actor                 | Focus                             |
| --------------------- | --------------------------------- |
| GlassWorm             | Supply chain, self-propagation    |
| TigerJack             | Keylogging, cryptomining          |
| Evelyn                | Credential theft                  |
| WhiteCobra            | Crypto theft                      |
| OctoRAT               | Remote access trojan              |
| Shiba                 | Data exfiltration                 |
| MUT-9332              | Malicious updates                 |
| FAMOUS CHOLLIMA       | Fake job interviews (North Korea) |
| ReversingLabs-Dec2025 | Mass marketplace compromise       |
