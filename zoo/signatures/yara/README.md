# YARA Rules for VS Code Extension Malware

Detection signatures for scanning extensions.

## External Rules

We recommend using the Knostic GlassWorm YARA rules:

```bash
git clone https://github.com/knostic/open-tools.git
cp open-tools/glassworm_yara/*.yar zoo/signatures/yara/
```

### Knostic Rule Files

| File                          | Rules | Purpose                                              |
| ----------------------------- | ----- | ---------------------------------------------------- |
| `unicode_stealth.yar`         | 2     | Invisible Unicode characters, zero-width obfuscation |
| `blockchain_c2.yar`           | 3     | Solana RPC C2, memo field parsing                    |
| `credential_harvesting.yar`   | 5     | NPM/GitHub/OpenVSX/SSH credential theft              |
| `google_calendar_c2.yar`      | 4     | Calendar API abuse for C2                            |
| `crypto_wallet_targeting.yar` | 4     | Wallet extension targeting, seed extraction          |
| `rat_capabilities.yar`        | 5     | SOCKS proxy, VNC, remote execution                   |
| `self_propagation.yar`        | 5     | Automated publishing, worm propagation               |

Source: https://github.com/knostic/open-tools/tree/main/glassworm_yara

## Custom Rules

Add custom YARA rules to this directory. Follow naming convention:

```
{campaign}_{detection_type}.yar
```

Example: `tigerjack_keylogger.yar`

## Usage

```bash
# Scan with YARA-X
yr scan -r zoo/signatures/yara/unicode_stealth.yar path/to/extension/

# Or scan all rules in directory
for f in zoo/signatures/yara/*.yar; do yr scan -r "$f" path/to/extension/; done

# With vsix-audit (automatic)
vsix-audit scan extension.vsix  # YARA rules loaded automatically
```

## Rule metadata

Rules declare `severity` (`low`, `medium`, `high`, or `critical`) and a description.
Optional `capabilities` lists `network`, `execution`, `fileAccess`, `credentials`, or
`obfuscation`, separated by commas. The scanner reads these fields from YARA-X output.

The eval/Base64, eval/character-construction, obfuscation/eval, download/write/execute,
credential-file exfiltration, and remote-execution rules report medium-severity advisory
references. Their matches do not establish a data-flow relationship between the strings.
Verified clean bundles contain these combinations too; generated or dependency paths
receive the same checks.
The clean-corpus guard rejects every critical finding, including findings from new rules.
