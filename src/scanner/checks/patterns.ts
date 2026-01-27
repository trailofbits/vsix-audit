import { isScannable, SCANNABLE_EXTENSIONS_PATTERN } from "../constants.js";
import type { Finding, Severity, VsixContents } from "../types.js";
import { findLineNumberByIndex } from "../utils.js";

interface PatternRule {
  id: string;
  title: string;
  description: string;
  pattern: RegExp;
  severity: Severity;
  legitimateUses?: string[];
  redFlags?: string[];
}

const PATTERNS: PatternRule[] = [
  {
    id: "POWERSHELL_HIDDEN",
    title: "Hidden PowerShell execution",
    description:
      "Code executes PowerShell with hidden window. This is a common malware technique to run commands invisibly.",
    pattern: /powershell[^;]*-WindowStyle\s+Hidden/gi,
    severity: "critical",
  },
  {
    id: "POWERSHELL_DOWNLOAD_EXEC",
    title: "PowerShell download and execute",
    description:
      "Code uses PowerShell to download and execute remote content (IEX/Invoke-Expression with IRM/Invoke-RestMethod or IWR/Invoke-WebRequest).",
    pattern: /(?:irm|iwr|invoke-(?:webrequest|restmethod))[^|]*\|\s*(?:iex|invoke-expression)/gi,
    severity: "critical",
  },
  {
    id: "DISCORD_WEBHOOK",
    title: "Discord webhook exfiltration",
    description:
      "Code contains Discord webhook URL. This is commonly used to exfiltrate stolen data to attacker-controlled Discord channels.",
    pattern: /discord\.com\/api\/webhooks\/\d+\/[a-zA-Z0-9_-]+/g,
    severity: "high",
  },
  {
    id: "DISCORD_WEBHOOK_PARTIAL",
    title: "Discord webhook URL pattern",
    description:
      "Code references Discord webhook API. This is commonly used for data exfiltration.",
    pattern: /discord\.com\/api\/webhooks/g,
    severity: "high",
  },
  {
    id: "SSH_KEY_ACCESS",
    title: "SSH private key access",
    description:
      "Code accesses SSH private key files. This could indicate credential theft, but is expected in SSH client extensions and remote development tools.",
    pattern: /\.ssh\/id_(?:rsa|ed25519|ecdsa|dsa)/g,
    severity: "high",
    legitimateUses: ["SSH client extensions", "Remote development tools", "Git SSH authentication"],
    redFlags: ["Combined with network exfiltration", "Obfuscated file access", "Unexpected in theme/formatter"],
  },
  {
    id: "SSH_KEY_GENERIC",
    title: "SSH key file reference",
    description:
      "Code references .ssh directory. Could indicate SSH credential access, but is common in SSH extensions, remote development tools, and documentation.",
    pattern: /\.ssh\//g,
    severity: "medium",
    legitimateUses: ["Remote SSH extensions", "SSH config editors", "Git SSH operations", "Documentation"],
    redFlags: ["Combined with exfiltration patterns", "Obfuscated access"],
  },
  {
    id: "EVAL_ATOB",
    title: "Eval with base64 decode",
    description:
      "Code uses eval with atob (base64 decode). This is a common obfuscation technique to hide malicious code.",
    pattern: /(?:atob\s*\([^)]+\)[^;]*eval|eval\s*\([^)]*atob)/gi,
    severity: "high",
  },
  {
    id: "ATOB_SUSPICIOUS",
    title: "Base64 decoding in suspicious context",
    description:
      "Code uses atob() to decode base64. While not always malicious, this is commonly used to obfuscate payloads.",
    pattern: /atob\s*\(\s*["'`][A-Za-z0-9+/=]{50,}["'`]\s*\)/g,
    severity: "medium",
  },
  {
    id: "CHILD_PROCESS_EXEC",
    title: "Command execution via child_process",
    description:
      "Code uses child_process.exec or execSync. Common in extensions that run CLI tools (git, compilers, linters, debuggers). Review the commands being executed.",
    pattern: /(?:child_process|cp)['"]?\s*\)?\s*\.?\s*(?:exec|execSync|spawn|spawnSync)\s*\(/g,
    severity: "medium",
    legitimateUses: ["Git operations", "Build tools", "Linters", "Debuggers", "Language servers"],
    redFlags: ["PowerShell with hidden window", "Downloading remote scripts", "Obfuscated commands"],
  },
  {
    id: "REQUIRE_CHILD_PROCESS",
    title: "child_process module import",
    description:
      "Code imports child_process module which enables command execution. This is common in extensions that integrate with CLI tools.",
    pattern: /require\s*\(\s*["'`]child_process["'`]\s*\)/g,
    severity: "low",
    legitimateUses: ["Git integration", "Build systems", "Formatters", "Debuggers", "Terminal tools"],
    redFlags: ["No obvious CLI tool integration", "Combined with obfuscation"],
  },
  {
    id: "NATIVE_NODE_FILE",
    title: "Native .node binary",
    description:
      "Extension contains native .node binary reference. Native addons can execute code outside the Node.js sandbox. Common in debuggers, language servers, and performance-critical tools.",
    pattern: /\.node['"`]/g,
    severity: "medium",
    legitimateUses: ["Debugger extensions", "Language servers (LSP)", "Performance tools", "Native code integration"],
    redFlags: ["Unknown/obfuscated binary", "No clear native functionality needed", "Binary from untrusted source"],
  },
  {
    id: "BROWSER_STORAGE",
    title: "Browser data access",
    description:
      "Code accesses browser storage paths (Chrome, Firefox, etc.). This could indicate credential or cookie theft.",
    pattern:
      /(?:AppData|Application Support).*(?:Google\\Chrome|Mozilla\\Firefox|BraveSoftware)|Local Storage|leveldb|Cookies/gi,
    severity: "high",
  },
  {
    id: "CRYPTO_WALLET",
    title: "Cryptocurrency wallet access",
    description:
      "Code references cryptocurrency wallet paths or extensions. Could indicate crypto theft, but is expected in blockchain/Solidity development tools and security audit extensions.",
    pattern:
      /(?:metamask|phantom|solflare|exodus|atomic|trust.*wallet|\.wallet|wallet\.dat)/gi,
    severity: "high",
    legitimateUses: ["Solidity development tools", "Blockchain debuggers", "Security audit extensions", "Web3 development"],
    redFlags: ["File read operations on wallet paths", "Network exfiltration of wallet data", "Unexpected in non-blockchain extension"],
  },
  {
    id: "KEYLOGGER_PATTERN",
    title: "Potential keylogger behavior",
    description:
      "Code captures keyboard input which could indicate keylogging.",
    pattern: /onDidChangeTextDocument|keyboard|keydown|keyup|keypress/gi,
    severity: "low",
  },
  {
    id: "NETWORK_EXFIL",
    title: "Network data transmission",
    description:
      "Code makes HTTP requests with file or document content. Could indicate data exfiltration.",
    pattern: /(?:axios|fetch|http|request)\s*\.\s*(?:post|put)\s*\([^)]*(?:getText|readFile|content)/gi,
    severity: "medium",
  },
  {
    id: "OBFUSCATED_CODE",
    title: "Potentially obfuscated code",
    description:
      "Code contains patterns typical of obfuscation (long hex strings, unusual variable names).",
    pattern: /(?:_0x[a-f0-9]{4,}|\\x[a-f0-9]{2}){5,}/gi,
    severity: "medium",
  },
  {
    id: "VERCEL_APP",
    title: "Vercel app domain",
    description:
      "Code references a Vercel app domain. While Vercel is legitimate, it's commonly abused for C2 infrastructure by malware.",
    pattern: /[a-z0-9-]+\.vercel\.app/gi,
    severity: "medium",
  },
  {
    id: "PYTHONANYWHERE",
    title: "PythonAnywhere domain",
    description:
      "Code references a PythonAnywhere domain. This free hosting service is commonly abused for data exfiltration.",
    pattern: /[a-z0-9-]+\.pythonanywhere\.com/gi,
    severity: "medium",
  },
];

export function checkPatterns(contents: VsixContents): Finding[] {
  const findings: Finding[] = [];
  const seenFindings = new Set<string>();

  for (const [filename, buffer] of contents.files) {
    if (!isScannable(filename, SCANNABLE_EXTENSIONS_PATTERN)) continue;

    const content = buffer.toString("utf8");

    for (const rule of PATTERNS) {
      const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const key = `${rule.id}:${filename}:${match[0]}`;
        if (seenFindings.has(key)) continue;
        seenFindings.add(key);

        findings.push({
          id: rule.id,
          title: rule.title,
          description: rule.description,
          severity: rule.severity,
          category: "pattern",
          location: {
            file: filename,
            line: findLineNumberByIndex(content, match.index),
          },
          metadata: {
            matched: match[0].slice(0, 100),
            ...(rule.legitimateUses && { legitimateUses: rule.legitimateUses }),
            ...(rule.redFlags && { redFlags: rule.redFlags }),
          },
        });
      }
    }
  }

  return findings;
}

export function checkNativeFiles(contents: VsixContents): Finding[] {
  const findings: Finding[] = [];
  const nativeExtensions = [".node", ".dll", ".dylib", ".so", ".exe"];

  for (const filename of contents.files.keys()) {
    const ext = filename.slice(filename.lastIndexOf(".")).toLowerCase();
    if (nativeExtensions.includes(ext)) {
      findings.push({
        id: "NATIVE_BINARY",
        title: "Native binary file in extension",
        description: `Extension contains native binary "${filename}". Native code can execute outside the Node.js sandbox. Common in debuggers, language servers, and performance-critical tools.`,
        severity: "high",
        category: "pattern",
        location: {
          file: filename,
        },
        metadata: {
          extension: ext,
          legitimateUses: ["Debugger extensions (LLDB, GDB)", "Language servers", "Performance tools", "Syntax highlighting with tree-sitter"],
          redFlags: ["Unknown/obfuscated binary", "No clear native functionality needed", "Binary fetched from network"],
        },
      });
    }
  }

  return findings;
}

export function checkAllPatterns(contents: VsixContents): Finding[] {
  return [...checkPatterns(contents), ...checkNativeFiles(contents)];
}
