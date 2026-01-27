# VS Code Extension Security Research

Research notes for building vsix-audit - a security scanner for VS Code extensions.

## Agent-Native Design Principles

Reference: https://every.to/guides/agent-native

### Core Principles Applied to vsix-audit

1. **Parity** - Whatever users can do through UI, agents should achieve through tools
   - CLI must be fully scriptable for automated security workflows
   - Machine-readable output (JSON/SARIF) is the agent interface
   - All analysis capabilities exposed programmatically

2. **Granularity** - Tools should be atomic primitives
   - Consider decomposing into: `download`, `extract`, `analyze-manifest`, `analyze-code`, `analyze-deps`, `report`
   - Agents compose primitives for workflows we didn't anticipate

3. **Composability** - New features via prompts, not code
   - With atomic tools, an agent could: "Scan all extensions requesting file system access, compare download counts to detect impersonation"

4. **Emergent Capability** - Handle open-ended requests
   - Correlate findings across extensions
   - Suggest safer alternatives
   - Track approval history over time

### Product Ideas from Agent-Native Thinking

- **MCP Server** - Expose vsix-audit as MCP tool for direct agent invocation
- **Structured output first** - JSON/SARIF primary, text derived
- **Approval workflow** - Store decisions so agents can reference past approvals
- **Batch operations** - Process multiple extensions in one invocation
- **Diff mode** - Compare extension versions to detect changes
- **Watch mode** - Monitor extensions for updates and auto-scan
- **Extension alternatives** - Suggest safer alternatives when flagging an extension

---

## Attack Patterns & Vulnerabilities

### 1. Verified Badge Bypass (OX Security Research)

Reference: https://www.ox.security/blog/can-you-trust-that-verified-symbol-exploiting-ide-extensions-is-easier-than-it-should-be/

**Summary:** Attackers can create malicious extensions that maintain the "verified" badge by modifying values in the extension files that are used for marketplace verification.

**Technical Details:**
- VS Code checks verification via `marketplace.visualstudio.com/_apis/public/gallery/extensionquery`
- The verification request uses values stored within the extension package itself
- Attackers can copy verified publisher values into malicious extensions
- The malicious VSIX can be distributed via GitHub or other channels
- Side-loaded extensions bypass marketplace security entirely

**Affected Platforms:** VS Code, Visual Studio, IntelliJ IDEA, Cursor

**Vendor Responses:**
- Microsoft: "By design" - signature verification now enabled by default, but still exploitable as of June 2025
- JetBrains: Warning displayed for manually installed plugins
- Cursor: Does not verify extension signatures at all

**Detection Opportunity:** Compare extension metadata against official marketplace records, validate per-file hashes

### 2. Impersonation with Fake Download Counts

Reference: https://x.com/juanfranblanco/status/1914225236809044029

**Real-world case:** Fake "solidity" extension impersonating Juan Blanco's legitimate extension
- Fake publisher: "Juan Fran Blanco" (vs real "Juan Blanco")
- Fake downloads: 20.8M (vs real 1.5M)
- Published same day, impossible download count
- Similar icon, name, and description

**Detection Signals:**
- New extension with impossibly high download count
- Publisher name similar to legitimate publisher (typosquatting)
- Download count exceeds legitimate extension
- Recent publish date + high downloads = impossible

### 3. Crypto-Targeting Malware Campaign (Real Incident)

Reference: https://x.com/0xzak/status/1955655184522371361

**Timeline:**
- Aug 7: Installed Solidity extension via Cursor/Open VSX
- Aug 10: Wallet drained
- Aug 11: Detected compromise
- Aug 12: Forensic evidence collected, machine wiped

**Attack Characteristics:**
- Part of documented campaign targeting crypto developers
- $500k+ stolen from others using similar extensions
- Windows variant: Quasar RAT, PureLogs stealer, ScreenConnect
- macOS: Different payload

**Scope of Exposure (extensions run with user permissions):**
- `~/.ssh/`, `~/.aws/` directories
- Browser password stores and cookies
- macOS Keychain (if unlocked)
- Local project files and `.env` files

**Persistence Mechanisms:**
- Second-stage payload in `/Users/Shared/` (world-writable)
- Background run permissions
- Launch agents and daemons

**Key Detection Insights:**
- **Lindy Effect:** CHECK THE RELEASE DATE - time can't be spoofed
- Malicious extension was days old with 54K downloads
- High downloads + no reviews = MAJOR RED FLAG
- Open VSX has weaker security than Microsoft Marketplace

**Forensic Artifacts to Check:**
- `~/.cursor/extensions/`
- `~/.vscode/extensions/`
- `~/.cursor/logs/` (includes install timestamps)
- Browser history around install time
- Network logs, system process lists
- Launch agents, modified file timestamps

### 4. Code Patterns in Malicious Extensions

**Dangerous capabilities:**
- `child_process.exec()` / `spawn()` - arbitrary command execution
- `eval()` - dynamic code execution
- Dynamic `import()` - load remote code
- `fetch()` / `http.request()` to suspicious domains
- File system access to sensitive paths (`~/.ssh`, `~/.aws`, `~/.env`)
- Keychain/credential store access

**Obfuscation techniques:**
- Base64 encoded payloads
- String concatenation to hide URLs
- Minified/uglified code
- Encrypted payloads decrypted at runtime

---

## Existing Tools & Competitors

### VSDeer
Reference: https://vsdeer.soldeer.xyz/

- Web-based scanner for VS Code (Microsoft Marketplace) and Cursor/Windsurf (Open VSX)
- Features: Detect malicious extensions, compare publishers, verify authenticity
- Emphasis on sandboxing extensions before installation

### Secure Annex
Reference: https://secureannex.com/

- Enterprise product for Chrome, Edge, Firefox, VS Code
- Key features:
  - **YARA rules** for pattern matching
  - **Vulnerability detection**
  - **Ownership monitoring** (detect when extension changes hands)
  - **Review sentiment analysis** (detect fake reviews)
  - **AI analysis**
  - Proactive alerts

### Koidex
Reference: https://dex.koi.security/

- Most comprehensive - supports many platforms:
  - VS Code, JetBrains, Chrome, Edge, Firefox
  - Cursor, Windsurf
  - npm, PyPi (Enterprise)
  - Hugging Face, MCP servers (Enterprise)
  - Office Add-ins, Homebrew (Enterprise)
- "Catch of the Day" - real-time malware feed
- Recent catches (all VS Code, Critical, 0.0 stars):
  - Discord RPC (6.9K installs)
  - ChatGPT - Co... by GPTOnce (2.2K installs)
  - Sysl (1.6K installs)
  - Solidity - Ethereum Language by Mark Wood (9.1K installs)

### crxaminer
Reference: https://github.com/markkcc/crxaminer

- Chrome extension scanner (concepts apply to VS Code)
- Analyzes manifest.json permissions
- Risk scoring based on permission scope
- CRX3 format: ZIP archive with prepended header (similar to VSIX)

### Open VSX Registry API
Reference: https://open-vsx.org/swagger-ui/

- Programmatic access to extension metadata
- Key endpoints:
  - `GET /api/-/query` - Query extension metadata
  - `GET /api/-/search` - Search extensions
  - `GET /api/{namespace}/{extension}` - Get extension details
  - `GET /api/{namespace}/{extension}/{version}/file/**` - Download extension files

---

## Detection Techniques

### Metadata Analysis (No Code Inspection Required)

| Signal | What to Check | Red Flag |
|--------|---------------|----------|
| Age vs Downloads | Publish date, download count | New extension with high downloads |
| Reviews | Star rating, review count | High downloads + 0 reviews |
| Publisher | Name similarity to known publishers | Typosquatting |
| Verified Status | Compare against marketplace API | Mismatch with official records |
| Version History | Number of versions, update frequency | Single version, no history |

### Manifest Analysis (package.json)

| Field | Risk Indicator |
|-------|----------------|
| `activationEvents` | `*` (all events) is suspicious |
| `contributes.commands` | Hidden commands |
| `extensionDependencies` | Unusual dependencies |
| `engines.vscode` | Very old version requirement |

### Permission Analysis

High-risk capabilities:
- File system access (especially `~/.ssh`, `~/.aws`, `~/.env`)
- Network access (especially to non-HTTPS URLs)
- Process execution
- Clipboard access
- Keychain/credential access

### Code Analysis

**Static patterns to detect:**
```
child_process
exec(
spawn(
eval(
Function(
new Function
fetch(
XMLHttpRequest
WebSocket
.ssh
.aws
.env
keychain
credential
password
token
secret
base64
atob
btoa
```

**Obfuscation indicators:**
- High entropy strings (encrypted/encoded data)
- Excessive string concatenation
- Minified code without source maps
- Unicode escapes for ASCII characters

---

## Product Features to Consider

### Core Scanner Features
- [ ] Download extension from marketplace by ID
- [ ] Extract and analyze VSIX contents
- [ ] Parse and analyze package.json manifest
- [ ] Scan JavaScript/TypeScript for dangerous patterns
- [ ] Check dependencies for known vulnerabilities
- [ ] Query marketplace API for metadata validation

### Detection Rules
- [ ] Age vs download count anomaly detection
- [ ] Publisher name typosquatting detection
- [ ] Fake download count detection (compare to similar extensions)
- [ ] Zero reviews with high downloads
- [ ] Dangerous permission combinations
- [ ] Known malicious code patterns (YARA-style rules)
- [ ] Obfuscation detection (entropy analysis)

### Enterprise Features
- [ ] Approval workflow integration
- [ ] Allowlist/blocklist management
- [ ] Scan history and audit trail
- [ ] Batch scanning of installed extensions
- [ ] Real-time monitoring for extension updates
- [ ] Integration with SIEM/security tools

### Agent-Native Features
- [ ] MCP server for agent integration
- [ ] Atomic commands (download, extract, analyze-*, report)
- [ ] JSON-first output for composability
- [ ] Context file for tracking scan history
- [ ] Approval decisions as queryable data

### Output Formats
- [ ] Text (human-readable)
- [ ] JSON (machine-readable)
- [ ] SARIF (CI/CD integration)
- [ ] CSV (spreadsheet analysis)
- [ ] HTML report

### Data Sources
- [ ] Microsoft VS Code Marketplace API
- [ ] Open VSX Registry API
- [ ] Local VSIX file analysis
- [ ] Known malware signatures database
- [ ] CVE database for dependency checking

---

## Known Malicious Extensions (Benchmarks)

Use these as test cases for scanner validation.

### 1. Solidity - ScreenConnect RAT (Cursor/Open VSX)

Reference: https://dex.koi.security/reports/cursor/8e0ec40b-ef95-4e11-9264-cf055c58050c/0.0.7

| Field | Value |
|-------|-------|
| Name | Solidity |
| Publisher | Ethereum (fake) |
| Platform | Cursor (Open VSX) |
| Published | 8/10/2025 |
| Installs | 380,000 (fake) |
| Rating | 1.0 (1 review) |
| Version | 0.0.7 |
| Risk | Critical |

**Findings from Koidex:**
1. **Malicious Activity Detected (Critical)** - Silently installs ScreenConnect client connecting to attacker-controlled server
2. **Associated with Malicious Campaign (Critical)** - Linked to known threat intelligence
3. **Installation Velocity Anomaly (Medium)** - 382,000 installs immediately after release = fake

### 2. Prettier-vscode-plus / OctoRAT (November 2025)

Reference: https://hunt.io/blog/malicious-vscode-extension-anivia-octorat-attack-chain

- Published to official VS Code Marketplace Nov 21, 2025
- Multi-stage attack: VBScript dropper -> PowerShell -> Anivia loader -> OctoRAT
- **Technical IOC:** Control panel title `<title>OctoRAT Center - Login</title>`
- Uses Base64-encoded AES encryption key and encrypted blob
- Creates COM objects for file operations and command execution

### 3. Fake Image Campaign (19 extensions, Feb-Dec 2025)

Reference: https://www.reversinglabs.com/blog/malicious-vs-code-fake-image

- **19 malicious extensions** hiding malware in dependency folders
- Active since February 2025, discovered December 2
- Abused `path-is-absolute` npm package (9B+ downloads)
- **Technique:** Malicious files posing as PNG images
- Hidden in `node_modules/path-is-absolute/` folder

### 4. GlassWorm Self-Propagating Malware (October 2025)

Reference: https://www.darkreading.com/application-security/self-propagating-glassworm-vs-code-supply-chain

- Uses printable Unicode characters that don't render in editors (invisible code)
- **C2:** Solana blockchain primary, Google Calendar backup
- **Capabilities:**
  - Harvests credentials from NPM, GitHub, Git
  - Targets cryptocurrency wallets
  - Deploys SOCKS proxy servers
  - Installs hidden VNC servers
  - Self-propagates using stolen credentials

### 5. DarkGPT Extension

Reference: https://safedep.io/dark-gpt-vscode-malicious-extension/

- GitHub: `cathedralkingz-afk/DarkGPT-Extension-For-VsCode`
- Payload dropper in `scripts/run.bat` (not in repo)
- **Code pattern:**
```javascript
powershell.exe -WindowStyle Hidden -Command "& { Start-Process -FilePath '${scriptPath}' -WindowStyle Hidden }"
```

### 6. susvsex Ransomware (November 2025)

Reference: https://www.businesstechweekly.com/technology-news/malicious-vs-code-extension-ransomware-capabilities-discovered-and-removed-from-marketplace/

- Publisher: suspublisher18
- Description: "Just testing"
- **Activation:** `*` (all events)
- **Function:** `zipUploadAndEncrypt`
  1. Creates ZIP archive of target directory
  2. Exfiltrates to remote server
  3. Encrypts original files

### 7. TigerJack Campaign (October 2025)

References:
- https://www.koi.ai/blog/tiger-jack-malicious-vscode-extensions-stealing-code
- https://www.bleepingcomputer.com/news/security/malicious-crypto-stealing-vscode-extensions-resurface-on-openvsx/
- https://cybersecuritynews.com/tigerjack-hacks-infiltrated-developer-marketplaces/

| Field | Value |
|-------|-------|
| Threat Actor | TigerJack |
| Publisher Aliases | ab-498, 498, 498-00 |
| Total Extensions | 11 |
| Victims | 17,000+ developers |
| Platforms | VS Code Marketplace, OpenVSX (Cursor, Windsurf) |

**Key Extensions:**

| Extension | Capability |
|-----------|------------|
| C++ Playground | Keylogger (500ms delay), steals .cpp files to ab498.pythonanywhere.com |
| HTTP Format | CoinIMP cryptocurrency miner |
| Python Format | Backdoor with 20-minute C2 check interval |

**Technical Details:**
- Keystroke capture triggered after 500ms delay
- Exfiltration endpoints: `ab498.pythonanywhere.com`, `api.codex.jaagrav.in`
- Embedded CoinIMP API credentials for mining
- Persistent backdoor downloads/executes arbitrary JavaScript every 20 minutes

**Timeline:**
- Extensions removed from Microsoft Marketplace
- Sept 17, 2025: Republication campaign - 5 extensions under "498-00" publisher
- **Still active on OpenVSX** (affects Cursor, Windsurf users)

### 8. Shiba Ransomware & Name Reuse Loophole (March-August 2025)

References:
- https://www.reversinglabs.com/blog/malware-vs-code-extension-names
- https://thehackernews.com/2025/03/vscode-marketplace-removes-two.html

| Field | Value |
|-------|-------|
| Extensions | ahban.shiba, ahban.cychelloworld, ahbanC.shiba |
| Discovery | March 2025 (initial), August 2025 (name reuse) |
| Payload | Early-stage ransomware |

**Attack Flow:**
1. Extension downloads second-stage PowerShell payload
2. Encrypts files in `testShiba` folder on Windows desktop
3. Displays ransom message: "Pay 1 ShibaCoin to ShibaWallet"

**Name Reuse Loophole (Critical Vulnerability):**
- VS Code documentation claims extension names must be unique
- Reality: Only **unpublished** extensions reserve names
- **Removed** extension names become available for anyone to claim
- Attacker republished "shiba" name after Microsoft removed original
- **Unfixed as of discovery** - affects all removed extensions

### 9. Bitcoin Black & Codo AI Infostealers (December 2025)

References:
- https://www.bleepingcomputer.com/news/security/malicious-vscode-extensions-on-microsofts-registry-drop-infostealers/
- https://www.koi.ai/blog/the-vs-code-malware-that-captures-your-screen

| Field | Value |
|-------|-------|
| Extensions | Bitcoin Black (theme), Codo AI (AI assistant) |
| Publisher | BigBlack |
| Removed | Dec 5 & Dec 8, 2025 |

**Disguises:**
- Bitcoin Black: "Premium dark theme inspired by Bitcoin with sleek black backgrounds"
- Codo AI: Working AI coding assistant with ChatGPT/DeepSeek integration (real functionality!)

**Red Flags for Themes:**
- Legitimate themes are JSON files defining colors only
- No activation events, no main entry point, no PowerShell
- Bitcoin Black had `"*"` activation event and executed PowerShell

**Malware Capabilities:**
- Data storage: `%APPDATA%\Local\Evelyn\`
- Screenshots via DLL-hijacked Lightshot executable
- Runs Chrome/Edge in headless mode to steal cookies
- Targets: Phantom, Metamask, Exodus wallets
- Collects: WiFi credentials, clipboard, running processes, installed programs

### 10. Material Icon Theme Impersonation (November 2025)

References:
- https://www.nextron-systems.com/2025/11/28/malicious-vs-code-extension-impersonating-material-icon-theme-found-in-marketplace/
- https://www.nextron-systems.com/2025/11/29/analysis-of-the-rust-implants-found-in-the-malicious-vs-code-extension/

| Field | Value |
|-------|-------|
| Fake Extension | Icon Theme: Material |
| Fake Publisher | IconKiefApp |
| Real Extension | Material Icon Theme by Philipp Kief (PKief) |
| Installs | 16,000+ |
| Malicious Version | 5.29.1 (Nov 28, 2025 at 11:34) |
| Clean Version | 5.29.0 |

**Payload:**
- Two Rust implants: Windows PE (os.node) + macOS Mach-O (darwin.node)
- Located in `dist/extension/desktop/` mimicking legitimate structure
- C2 via Solana wallet + Google Calendar fallback

**Connection to GlassWorm:**
- Hashes match previously observed GlassWorm behaviors
- Same C2 technique (Solana primary, Calendar backup)
- Suggests shared actor or toolkit

### Koidex "Catch of the Day" (All Critical, 0.0 stars)

| Extension | Publisher | Platform | Installs |
|-----------|-----------|----------|----------|
| FVP Free VPN | patrick.cruiado | Chrome | 90K |
| Solidity - Ethereum Language | Mark Wood | VS Code | 9.1K |
| vscode-pets- | wli273088 | VS Code | 7.5K |
| Discord RPC | David Ash | VS Code | 6.9K |
| ChatGPT - Co... | GPTOnce | VS Code | 2.2K |
| Sysl | Australia and New Zeala... | VS Code | 1.6K |

### 2025-2026 Statistics

| Metric | Value | Source |
|--------|-------|--------|
| VS Code malware (2024) | 27 detections | ReversingLabs |
| VS Code malware (2025, 10 months) | 105 detections | ReversingLabs |
| Increase | **4x year-over-year** | |
| Extensions removed (2025) | 110 of 136 reviewed | Various |
| TigerJack victims | 17,000+ developers | Koi Security |

### Key Detection Patterns Learned

Based on analyzed malware campaigns:

| Pattern | Example | Detection Rule |
|---------|---------|----------------|
| Theme with activation | Bitcoin Black | Themes should be JSON only, no `"*"` activation |
| Version bump with payload | Material Icon 5.29.0->5.29.1 | Compare file hashes between versions |
| .node files in extensions | os.node, darwin.node | Native binaries are rare, flag for review |
| dist/ folder structure abuse | GlassWorm | Check for executables in dist/ paths |
| Republished removed names | shiba | Cross-reference against removed extension list |
| OpenVSX persistence | TigerJack | Scan OpenVSX even after Marketplace removal |
| Working functionality | Codo AI | Malware can include real features as cover |
| Headless browser launch | Bitcoin Black | chrome --headless is suspicious |
| %APPDATA% data storage | Evelyn folder | Non-standard AppData folders |

---

## Downloadable Benchmark Samples

### GitHub Repositories with Sample Extensions

| Repository | Contents | License |
|------------|----------|---------|
| [KagemaNjoroge/malicious-vscode-extensions](https://github.com/KagemaNjoroge/malicious-vscode-extensions) | Community tracker with actual extension folders (e.g., `ShowSnowcrypto.SnowShoNo`). Accepts zipped extension contributions. | MIT |
| [b4ba/ECM3401-VSCode-Extensions](https://github.com/b4ba/ECM3401-VSCode-Extensions) | Educational attack suite with **pre-built .vsix files**. Includes: Extension-Attack-Suite, Malicious-API-Extension, API spoofing, Docker tampering, SSH key exfiltration. | GPL-3.0 |
| [0x-Apollyon/Malicious-VScode-Extension](https://github.com/0x-Apollyon/Malicious-VScode-Extension) | PoC demonstrating VS Code extension abuse with sample folders. | MIT |
| [securezeron/VsCodeExtLure](https://github.com/securezeron/vscodeextlure) | "Popping Shells With VS Code Extensions" - reverse shell PoC | - |
| [nf3xn/malext](https://github.com/nf3xn/malext) | Educational malicious extension example for security awareness | - |

### Specific File Hashes (VirusTotal Searchable)

**GlassWorm / Material Icon Theme Impersonation (Nov 2025)**

| File | SHA256 | Type |
|------|--------|------|
| os.node | `6ebeb188f3cc3b647c4460c0b8e41b75d057747c662f4cd7912d77deaccfd2f2` | Windows DLL (Rust) |
| darwin.node | `fb07743d139f72fca4616b01308f1f705f02fda72988027bc68e9316655eadda` | macOS Dylib (Rust) |
| extension.js (loader) | `9212a99a7730b9ee306e804af358955c3104e5afce23f7d5a207374482ab2f8f` | JavaScript |
| Decrypted C2 payload | `c32379e4567a926aa0d35d8123718e2ebeb15544a83a5b1da0269db5829d5ece` | JavaScript |

Reference: https://www.nextron-systems.com/2025/11/29/analysis-of-the-rust-implants-found-in-the-malicious-vs-code-extension/

### C2 Infrastructure IOCs

**IP Addresses:**
```
217.69.11.60    # GlassWorm primary C2
45.32.151.157   # GlassWorm Wave 4 (macOS)
45.32.150.251   # GlassWorm Wave 4 (macOS)
```

**Solana Wallet (Blockchain C2):**
```
BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC
```

**C2 URLs:**
```
hxxp://217[.]69.11.60/uVK7ZJefmiIoJkIP6lxWXw==
hxxp://217[.]69.11.60/get_arhive_npm/karMkkT87qcssRoaHL1zYQ==
hxxp://217[.]69.11.60/get_zombi_payload/uVK7ZJefmiIoJkIP6lxWXw%3D%3D
```

**Google Calendar Fallback C2:**
```
https://calendar.google.com/calendar/share?slt=1AXs0gW2ChIx550BJk0lEThoZf3_QvWIH_3UnB8o6GmkFhmRz2tKPa6Vqjn9sGOVi4_9apgcG27TRSQ
```

### Threat Actor Groups (Extension-focused)

| Group | Extensions | Victims | Techniques |
|-------|------------|---------|------------|
| **GlassWorm** | 12+ across OpenVSX/VSCode | 35,800+ downloads | Invisible Unicode, Solana C2, Rust implants, Google Calendar fallback |
| **WhiteCobra** | 24 extensions | $500K crypto theft, zak.eth victim | Multi-editor (VSCode, Cursor, Windsurf), evolved tactics |
| **TigerJack** | 11 extensions (ab-498, 498, 498-00) | 17,000+ developers | Keylogger, CoinIMP miner, 20-min backdoor polling |

### Extension Names for Blocklist Testing

**GlassWorm-associated (confirmed malicious):**
- CodeJoy (version 1.8.3 - auto-updated with malware)
- Material Icon Theme impersonator (IconKiefApp publisher, v5.29.1)

**WhiteCobra-associated:**
- Multiple Cursor/Windsurf extensions (24 total, see Koi Security reports)

**TigerJack-associated:**
- C++ Playground (498.cppplayground)
- HTTP Format (498.httpformat)
- Python Format (498.pythonformat)

**Other confirmed malicious:**
- susvsex (suspublisher18) - ransomware
- prettier-vscode-plus (publishingsofficial) - OctoRAT
- Bitcoin Black (BigBlack) - infostealer
- Codo AI (BigBlack) - infostealer with working AI features
- shiba (ahban.shiba, ahbanC.shiba) - ransomware, name reuse exploit

---

## GlassWorm YARA Detection Rules (Knostic/Kirin Scanner)

Reference: https://github.com/knostic/open-tools/tree/main/glassworm_yara

Open-source YARA rules for detecting GlassWorm malware in VS Code extensions. These can be integrated into vsix-audit or used as reference for detection logic.

### Rule Files Overview

| File | Rules | Purpose |
|------|-------|---------|
| `unicode_stealth.yar` | 2 | Invisible Unicode characters, zero-width obfuscation |
| `blockchain_c2.yar` | 3 | Solana RPC C2, memo field parsing, dynamic C2 resolution |
| `credential_harvesting.yar` | 5 | NPM/GitHub/OpenVSX/SSH credential theft |
| `google_calendar_c2.yar` | 4 | Calendar API abuse for C2 and exfiltration |
| `crypto_wallet_targeting.yar` | 4 | Wallet extension targeting, seed extraction, tx hijacking |
| `rat_capabilities.yar` | 5 | SOCKS proxy, VNC, remote execution, persistence |
| `self_propagation.yar` | 5 | Automated publishing, worm propagation, supply chain abuse |

### Key Detection Rules

**Unicode Stealth (Critical for AI coding assistants)**

| Rule | Score | Detection |
|------|-------|-----------|
| `GlassWorm_Unicode_Stealth` | - | Variation selectors (U+FE00-FE0F) + zero-width chars + eval/Function/atob |
| `GlassWorm_Suspicious_Code_Gaps` | - | Abnormal whitespace (10+ spaces), control chars + JS patterns |

**Credential Harvesting**

| Rule | Score | Detection |
|------|-------|-----------|
| `GlassWorm_NPM_Credential_Harvesting` | 85 | NPM token access + file read + network exfil |
| `GlassWorm_GitHub_Credential_Harvesting` | 85 | GitHub/Git creds + SSH keys + API patterns |
| `GlassWorm_OpenVSX_Credential_Harvesting` | 80 | OpenVSX auth tokens + extension publishing |
| `GlassWorm_SSH_Credential_Harvesting` | 90 | SSH private key access + key management |
| `GlassWorm_Credential_Exfiltration` | 85 | HTTP POST + encoded credential data |

**Crypto Wallet Targeting**

| Rule | Score | Detection |
|------|-------|-----------|
| `GlassWorm_Crypto_Wallet_Targeting` | 90 | 49+ wallet extension IDs + browser API access |
| `GlassWorm_Wallet_Seed_Extraction` | 95 | Seed phrase/mnemonic + storage read + decrypt |
| `GlassWorm_Wallet_Transaction_Interception` | 85 | Transaction hijack + sendTransaction/signTransaction hooks |
| `GlassWorm_Wallet_Extension_Enumeration` | 70 | Wallet recon + enumeration functions |

**Blockchain C2**

| Rule | Score | Detection |
|------|-------|-----------|
| `GlassWorm_Solana_C2` | - | Solana RPC + Web3.js + transaction parsing + HTTP |
| `GlassWorm_Blockchain_Memo_Parsing` | - | Memo field extraction + base64 decode + URL extract |
| `GlassWorm_Dynamic_C2_Resolution` | - | Blockchain polling + failover mechanisms |

**Google Calendar C2**

| Rule | Score | Detection |
|------|-------|-----------|
| `GlassWorm_Google_Calendar_C2` | 70-85 | Calendar API + auth tokens + event parsing |
| `GlassWorm_Calendar_Event_Commands` | - | Event parsing + command execution |
| `GlassWorm_Calendar_Backup_C2` | - | Backup C2 + rotation/resilience |
| `GlassWorm_Calendar_Event_Exfiltration` | - | Event creation + data encoding |

**RAT Capabilities**

| Rule | Score | Detection |
|------|-------|-----------|
| `GlassWorm_SOCKS_Proxy_Deployment` | 85 | Proxy server creation + network binding |
| `GlassWorm_VNC_Installation` | 90 | VNC/HVNC setup + remote desktop infra |
| `GlassWorm_Remote_Command_Execution` | 95 | Process spawn + remote shell + network control |
| `GlassWorm_Persistent_Backdoor` | 90 | Registry + services + scheduled tasks + hidden files |
| `GlassWorm_Network_Reconnaissance` | 75 | Network enumeration + lateral movement |

**Self-Propagation (Supply Chain)**

| Rule | Score | Detection |
|------|-------|-----------|
| `GlassWorm_Automated_Package_Publishing` | 85 | Automated npm/yarn/marketplace publishing |
| `GlassWorm_Credential_Reuse` | 80 | Credential validation + multi-account access |
| `GlassWorm_Git_Automation` | 85 | Automated git ops + infected code spread |
| `GlassWorm_Worm_Propagation` | 95 | Self-replication + autonomous behavior |
| `GlassWorm_Supply_Chain_Abuse` | 90 | Dependency injection + ecosystem abuse |

### Integration Options for vsix-audit

1. **Direct YARA integration** - Use `yara-python` to scan extension files
2. **Pattern extraction** - Convert YARA strings to regex patterns for JS-based scanning
3. **Rule reference** - Use as specification for custom detection logic

### Key String Patterns to Extract

**Zero-width characters (hex):**
```
\xFE\x00 through \xFE\x0F  (variation selectors)
\xE2\x80\x8B  (zero-width space)
\xE2\x80\x8C  (zero-width non-joiner)
\xE2\x80\x8D  (zero-width joiner)
\xEF\xBB\xBF  (zero-width no-break space / BOM)
```

**Wallet extension IDs (partial list):**
```
nkbihfbeogaeaoehlefnkodbefgpgknn  (MetaMask)
bfnaelmomeimhlpmgjnjophhpkkoljpa  (Phantom)
hnfanknocfeofbddgcijnmhnfnkdnaad  (Coinbase)
```

**Solana RPC indicators:**
```
@solana/web3.js
Connection
getTransaction
getParsedTransaction
```

---

## IOC Resources

- **ESET malware-ioc:** https://github.com/eset/malware-ioc
- **FireEye IOCs:** https://github.com/fireeye/iocs
- **Unit 42 IOCs:** https://github.com/pan-unit42/iocs
- **Koi Security Research:** https://www.koi.ai/blog (GlassWorm, WhiteCobra, TigerJack tracking)
- **MITRE ATT&CK G1052:** https://attack.mitre.org/groups/G1052/ (Contagious Interview TTPs)
- **Nextron THOR rules:** VS Code extension YARA signatures
- **Trend Micro Evelyn Stealer:** https://www.trendmicro.com/en_us/research/26/a/analysis-of-the-evelyn-stealer-campaign.html
- **Knostic GlassWorm YARA Rules:** https://github.com/knostic/open-tools/tree/main/glassworm_yara
