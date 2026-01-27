import type { Finding, Severity, VsixContents } from "../types.js";

interface PatternRule {
  id: string;
  title: string;
  description: string;
  pattern: RegExp;
  severity: Severity;
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
      "Code accesses SSH private key files. This could indicate credential theft.",
    pattern: /\.ssh\/id_(?:rsa|ed25519|ecdsa|dsa)/g,
    severity: "high",
  },
  {
    id: "SSH_KEY_GENERIC",
    title: "SSH key file reference",
    description:
      "Code references .ssh directory. Could indicate SSH credential access.",
    pattern: /\.ssh\//g,
    severity: "medium",
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
      "Code uses child_process.exec or execSync. While legitimate for some extensions, this can be used to run arbitrary system commands.",
    pattern: /(?:child_process|cp)['"]?\s*\)?\s*\.?\s*(?:exec|execSync|spawn|spawnSync)\s*\(/g,
    severity: "medium",
  },
  {
    id: "REQUIRE_CHILD_PROCESS",
    title: "child_process module import",
    description:
      "Code imports child_process module which enables command execution.",
    pattern: /require\s*\(\s*["'`]child_process["'`]\s*\)/g,
    severity: "low",
  },
  {
    id: "NATIVE_NODE_FILE",
    title: "Native .node binary",
    description:
      "Extension contains native .node binary. These are compiled native addons that can execute arbitrary code outside the Node.js sandbox.",
    pattern: /\.node['"`]/g,
    severity: "medium",
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
      "Code references cryptocurrency wallet paths or extensions. This could indicate crypto theft.",
    pattern:
      /(?:metamask|phantom|solflare|exodus|atomic|trust.*wallet|\.wallet|wallet\.dat)/gi,
    severity: "high",
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

const SCANNABLE_EXTENSIONS = new Set([
  ".js",
  ".ts",
  ".mjs",
  ".cjs",
  ".jsx",
  ".tsx",
  ".ps1",
  ".sh",
  ".bat",
  ".cmd",
  ".py",
]);

function isScannable(filename: string): boolean {
  const ext = filename.slice(filename.lastIndexOf(".")).toLowerCase();
  return SCANNABLE_EXTENSIONS.has(ext);
}

function findLineNumber(content: string, match: RegExpExecArray): number {
  const beforeMatch = content.slice(0, match.index);
  return beforeMatch.split("\n").length;
}

export function checkPatterns(contents: VsixContents): Finding[] {
  const findings: Finding[] = [];
  const seenFindings = new Set<string>();

  for (const [filename, buffer] of contents.files) {
    if (!isScannable(filename)) continue;

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
            line: findLineNumber(content, match),
          },
          metadata: {
            matched: match[0].slice(0, 100),
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
        description: `Extension contains native binary "${filename}". Native code can execute outside the Node.js sandbox and perform arbitrary system operations.`,
        severity: "high",
        category: "pattern",
        location: {
          file: filename,
        },
        metadata: {
          extension: ext,
        },
      });
    }
  }

  return findings;
}

export function checkAllPatterns(contents: VsixContents): Finding[] {
  return [...checkPatterns(contents), ...checkNativeFiles(contents)];
}
