# Malicious Source Code Samples 🚀

> A curated repository of **malicious source code samples** for security research, red-team testing, and detection tool validation.

## 📌 Overview
This repository contains **real-world malicious source code samples** across multiple file types (**CSS, Less, SVG, TTF, etc.**). Each sample demonstrates **tactics, techniques, and procedures (TTPs)** used by attackers to exploit vulnerabilities, evade detection, or execute unauthorized actions.

> **⚠️ Warning:** These files are **deliberately** malicious. Use in **controlled environments only** for research and security testing. Never deploy them in production systems.

## 📂 Repository Structure
```
malicious-source-code-samples/
├── README.md
├── dataset/
│   ├── css/
│   │   ├── malicious01.css
│   │   ├── malicious01.metadata.json
│   │   ├── malicious02.css
│   │   ├── malicious02.metadata.json
│   │   ├── ...
│   ├── less/        // (Future expansion)
│   ├── svg/         // (Future expansion)
│   ├── py/          // (Future expansion)
│   ├── js/          // (Future expansion)
│   └── ...
└── package.zip      // Optional all-in-one archive
```

### 🔍 What's Inside?
Each malicious file has a corresponding **metadata file** (`*.metadata.json`) detailing:
- **Severity**: High, Medium, Low
- **MITRE ATT&CK® TTPs**: e.g., `T1041`, `T1190`
- **Technical Description**: Why the file is malicious and how it could be exploited

## 🎯 How to Use
✅ **Security Research**: Study how attackers craft malicious payloads.  
✅ **Detection Testing**: Validate detection rules using **YARA, Semgrep (for some cases), Anti-Malware, and CDR solutions**.  
✅ **Red-Team Simulations**: Inject these files into test environments to assess security controls.  
✅ **Developer Awareness**: Train teams on real-world threats using actual source code.

## 🚀 Sample: `malicious01.css`
```css
/* Suspicious FTP Import */
@import url("ftp://malicious.example.com/evil.css");

body {
  background-color: #f0f0f0;
}
```

**Metadata (`malicious01.metadata.json`)**:
```json
{
  "fileName": "malicious01.css",
  "severity": "High",
  "mitreAttackRefs": ["T1041", "T1566"],
  "description": "Fetches malicious CSS from ftp://, enabling remote injection or tracking.",
  "whyMalicious": "Allows attacker-controlled content from an untrusted domain, bypassing standard HTTP/HTTPS security controls."
}
```

## ⚠️ Disclaimers & Warnings
- **🚨 These files are designed to be malicious**. Use only in sandboxed environments.  
- **🚫 Do NOT deploy in production systems.**  
- **💀 You are responsible for how you use this dataset.**  
- **📜 Legal & Ethical Use Only**: For **research, security training, and tool validation**.

## 🤝 Contributing
Want to add new malicious samples?
1. **Fork** this repo.  
2. **Create a new sample** in `dataset/<filetype>/maliciousXX.<ext>`.  
3. **Add metadata** in `maliciousXX.metadata.json`.  
4. **Submit a PR** explaining the **unique TTPs** in your sample.

## 📜 License
[MIT License](LICENSE) – Use responsibly.

---

**👾 NextSecurity – Stay Ahead of the Threats!** 🚀
