# Malicious CSS Source Code Samples 🚀

> A curated repository of **malicious CSS source code samples** for security research, red-team testing, and detection tool validation.

## 📌 Overview
This folder contains **20 real-world malicious CSS files**, each demonstrating unique **tactics, techniques, and procedures (TTPs)** attackers use to exploit vulnerabilities, evade detection, or execute unauthorized actions.

> **⚠️ Warning:** These files are **deliberately** malicious. Use in **controlled environments only** for research and security testing. Never deploy them in production systems.

## 📂 File List (Distinct TTPs with Metadata)
Each CSS file in this folder represents a **unique TTP** mapped to MITRE ATT&CK®. Below is a detailed breakdown:

### 1. **Suspicious FTP Import**  
- **Severity**: High  
- **MITRE ATT&CK**: `T1041`, `T1566`  
- **Description**: Imports malicious CSS from an FTP server, bypassing standard security controls.  
- **Why Malicious**: Attackers can serve dynamic malicious styles or exfiltrate user data via FTP.  

### 2. **Data URI Import**  
- **Severity**: High  
- **MITRE ATT&CK**: `T1027`, `T1190`  
- **Description**: Embeds base64-encoded malicious styles in a `data:` URI.  
- **Why Malicious**: Can bypass naive scanning and deliver hidden payloads.  

### 3. **WebSocket Import**  
- **Severity**: High  
- **MITRE ATT&CK**: `T1041`, `T1071`  
- **Description**: Fetches CSS content via `ws://`, which is abnormal for stylesheets.  
- **Why Malicious**: Could serve live attack code from an attacker-controlled WebSocket server.  

### 4. **Trojan Library Class Override**  
- **Severity**: Medium  
- **MITRE ATT&CK**: `T1564`, `T1041`  
- **Description**: Overrides common classes (like Bootstrap) to introduce malicious styles.  
- **Why Malicious**: Developers trust these classes, but Trojanized versions can track users or inject exploits.  

### 5. **Cryptominer Reference**  
- **Severity**: Medium  
- **MITRE ATT&CK**: `T1587.001`, `T1041`  
- **Description**: Uses `background-image` to load a cryptomining script.  
- **Why Malicious**: Leverages user browsers to mine cryptocurrency for an attacker.  

### 6. **Local File Import (file://)**  
- **Severity**: High  
- **MITRE ATT&CK**: `T1005`, `T1041`  
- **Description**: Tries to load local system files using the `file://` protocol.  
- **Why Malicious**: If successful, this could leak sensitive local data.  

### 7. **Obfuscated Base64 in Comments**  
- **Severity**: Medium  
- **MITRE ATT&CK**: `T1027`, `T1564`  
- **Description**: Hides malicious scripts or payloads inside base64-encoded comments.  
- **Why Malicious**: Attackers can encode and later extract hidden threats from comments.  

### 8. **IE `expression()` Hack**  
- **Severity**: High  
- **MITRE ATT&CK**: `T1059`, `T1190`  
- **Description**: Uses Internet Explorer’s proprietary `expression()` function to execute JavaScript.  
- **Why Malicious**: Allows execution of arbitrary JavaScript via CSS in older browsers.  

### 9. **Suspicious Domain References**  
- **Severity**: Medium  
- **MITRE ATT&CK**: `T1041`, `T1071`  
- **Description**: Loads assets from known malicious domains.  
- **Why Malicious**: Can be used for tracking, data theft, or injecting malicious content.  

### 10. **Large Nested Rules (DoS)**  
- **Severity**: Medium  
- **MITRE ATT&CK**: `T1499`  
- **Description**: Uses deeply nested rules to cause performance degradation.  
- **Why Malicious**: Can lead to excessive memory use or crash build pipelines.  

### 11. **Hidden Keylogger Trick (Attribute Selectors)**  
- **Severity**: High  
- **MITRE ATT&CK**: `T1056`, `T1041`  
- **Description**: Uses attribute selectors to capture typed characters and send them remotely.  
- **Why Malicious**: Can exfiltrate keystrokes via hidden tracking requests.  

### 12. **Malicious @font-face Domain**  
- **Severity**: Medium  
- **MITRE ATT&CK**: `T1190`, `T1071`  
- **Description**: Loads a font from an attacker-controlled domain.  
- **Why Malicious**: Corrupt or malicious fonts can exploit certain rasterizers.  

### 13. **Suspicious Query Param in @import**  
- **Severity**: Medium  
- **MITRE ATT&CK**: `T1041`, `T1566`  
- **Description**: Uses query parameters to pass suspicious execution instructions.  
- **Why Malicious**: Can dynamically serve malicious styles based on server commands.  

### 14. **IE Filter Obfuscation**  
- **Severity**: Medium  
- **MITRE ATT&CK**: `T1036`, `T1027`  
- **Description**: Uses Internet Explorer’s `filter:` property to obfuscate malicious URLs.  
- **Why Malicious**: Can be used to evade detection in legacy browsers.  

### 15. **Zero-Width Unicode for Stealth**  
- **Severity**: Medium  
- **MITRE ATT&CK**: `T1036`, `T1027`  
- **Description**: Inserts zero-width or RTL unicode characters to hide malicious content.  
- **Why Malicious**: Can fool scanners and human reviewers by making threats invisible.  

### 16. **Content Exfil Trick (`:after`)**  
- **Severity**: Medium  
- **MITRE ATT&CK**: `T1041`  
- **Description**: Uses `content:` in pseudo-elements to send data remotely.  
- **Why Malicious**: Allows hidden requests to attacker-controlled servers.  

### 17. **Recursive Import Loop (DoS)**  
- **Severity**: Low  
- **MITRE ATT&CK**: `T1499`  
- **Description**: Two CSS files import each other infinitely.  
- **Why Malicious**: Can crash CSS compilers or cause memory exhaustion.  

### 18. **Trojan `@keyframes`**  
- **Severity**: Medium  
- **MITRE ATT&CK**: `T1071`, `T1041`  
- **Description**: Uses animations to repeatedly load external attack scripts.  
- **Why Malicious**: Can be used for tracking, command execution, or exfiltration.  

### 19. **`calc()` Overload / DoS**  
- **Severity**: Medium  
- **MITRE ATT&CK**: `T1499`, `T1190`  
- **Description**: Uses excessive `calc()` calls to consume system resources.  
- **Why Malicious**: Can crash CSS parsers or browser render engines.  

### 20. **CSS Houdini / Custom Props Obfuscation**  
- **Severity**: Medium  
- **MITRE ATT&CK**: `T1027`, `T1059`  
- **Description**: Uses CSS variables and Houdini APIs to hide malicious payloads.  
- **Why Malicious**: Obfuscates threats inside dynamic CSS properties.  

## 📜 License  
[MIT License](../LICENSE) – Use responsibly.  

---  

**👾 NextSecurity – Stay Ahead of the Threats!** 🚀  
