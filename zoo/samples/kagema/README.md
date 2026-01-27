# Malicious VS Code Extensions Tracker

A community-driven repository to identify, analyze, and document **malicious Visual Studio Code extensions** found on the Marketplace.

## Why this repo?
VS Code has become the most popular developer editor, but the Marketplace has weak controls. Malicious actors have been publishing extensions that:
- Run hidden PowerShell/NodeJS payloads
- Exfiltrate sensitive data
- Install backdoors (e.g. ScreenConnect, RATs)
- Hijack developer environments

This repo exists to **document and track these extensions** so the community can stay safe.

---


##  Contribution Guidelines

1. Create a folder with the **extension ID** (e.g. `ShowSnowcrypto.SnowShoNo`).
2. Add a `README.md` with:
   - Extension name, ID, publisher
   - Marketplace link (if still live)
   - Technical analysis (payloads, commands, IoCs)
   - Screenshots/logs if possible
3. Optionally include a **zipped copy of the extension** for research.
4. Open a pull request.

---


## 🌍 Community

Join me in making the VS Code ecosystem safer. Contributions are welcome — even just reporting suspicious extensions.


