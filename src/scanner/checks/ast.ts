import { parseSync, Visitor } from "oxc-parser";
import type {
  Argument,
  CallExpression,
  ImportExpression,
  MemberExpression,
  NewExpression,
  Node,
  Span,
} from "oxc-parser";
import { detectBundler, hasGenuineObfuscation } from "../bundler.js";
import { isScannable, SCANNABLE_EXTENSIONS_PATTERN } from "../constants.js";
import type { Finding, Severity, VsixContents } from "../types.js";

interface ASTPattern {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  detect: (node: Node, context: ASTContext) => ASTMatch | null;
  legitimateUses?: string[];
  redFlags?: string[];
}

interface ASTMatch {
  start: number;
  end: number;
  codeSnippet: string;
  additionalInfo: string | null;
}

interface ASTContext {
  filename: string;
  content: string;
  hasObfuscationIndicators: boolean;
  isBundled: boolean;
  lineStarts: number[];
}

/**
 * Pre-compute line start positions for fast line/column lookup from byte offsets.
 */
function computeLineStarts(content: string): number[] {
  const lineStarts = [0];
  for (let i = 0; i < content.length; i++) {
    if (content[i] === "\n") {
      lineStarts.push(i + 1);
    }
  }
  return lineStarts;
}

/**
 * Convert byte offset to line number (1-indexed).
 */
function offsetToLine(offset: number, lineStarts: number[]): number {
  let low = 0;
  let high = lineStarts.length - 1;
  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    const midStart = lineStarts[mid];
    if (midStart !== undefined && midStart <= offset) {
      low = mid;
    } else {
      high = mid - 1;
    }
  }
  return low + 1;
}

/**
 * Convert byte offset to column number (0-indexed).
 */
function offsetToColumn(offset: number, lineStarts: number[]): number {
  const line = offsetToLine(offset, lineStarts);
  const lineStart = lineStarts[line - 1] ?? 0;
  return offset - lineStart;
}

/**
 * Get code snippet around a node's location.
 */
function getCodeSnippet(
  content: string,
  start: number,
  end: number,
  lineStarts: number[],
  maxLen = 100,
): string {
  const lineNum = offsetToLine(start, lineStarts);
  const lines = content.split("\n");
  const line = lines[lineNum - 1];
  if (!line) return "(no line)";

  const lineStart = lineStarts[lineNum - 1] ?? 0;
  const colStart = start - lineStart;
  const colEnd = end - lineStart;

  const snippetStart = Math.max(0, colStart - 10);
  const snippetEnd = Math.min(line.length, colEnd + 30);
  let snippet = line.slice(snippetStart, snippetEnd);

  if (snippetStart > 0) snippet = "..." + snippet;
  if (snippetEnd < line.length) snippet = snippet + "...";

  return snippet.slice(0, maxLen);
}

/**
 * Check if a node is an Identifier with a specific name.
 */
function isIdentifier(node: Node | undefined, name?: string): boolean {
  if (!node || node.type !== "Identifier") return false;
  if (name !== undefined) {
    return (node as { name: string }).name === name;
  }
  return true;
}

/**
 * Get the name of an identifier node.
 */
function getIdentifierName(node: Node): string | null {
  if (node.type === "Identifier") {
    return (node as { name: string }).name;
  }
  return null;
}

/**
 * Check if a node is a call to a specific function name.
 */
function isCallTo(node: Node, name: string | string[]): node is CallExpression {
  if (node.type !== "CallExpression") return false;

  const names = Array.isArray(name) ? name : [name];
  const callee = (node as CallExpression).callee;

  // Direct call: eval()
  if (isIdentifier(callee)) {
    const calleeName = getIdentifierName(callee);
    if (calleeName && names.includes(calleeName)) {
      return true;
    }
  }

  // Member call: require("child_process").exec()
  if (callee.type === "MemberExpression") {
    const memberExpr = callee as MemberExpression;
    if (isIdentifier(memberExpr.property)) {
      const propName = getIdentifierName(memberExpr.property);
      if (propName && names.includes(propName)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Check if node is a new expression with specific constructor.
 */
function isNewExpression(node: Node, name: string): node is NewExpression {
  if (node.type !== "NewExpression") return false;
  const newExpr = node as NewExpression;
  return isIdentifier(newExpr.callee, name);
}

/**
 * Check if argument is a literal (string, number, boolean, template).
 * OXC uses "Literal" type for all primitive literals (ESTree spec).
 */
function isLiteral(node: Argument | Node | undefined): boolean {
  if (!node) return false;
  const type = node.type;
  // OXC uses "Literal" for string/number/boolean/null/regex/bigint
  // TemplateLiteral keeps its own type
  return type === "Literal" || type === "TemplateLiteral";
}

/**
 * Check if content has obfuscation indicators.
 */
function hasObfuscationIndicators(content: string): boolean {
  const indicators = [
    /_0x[a-f0-9]{4,}/i, // Hex variable names
    /\\x[a-f0-9]{2}(?:\\x[a-f0-9]{2}){5,}/i, // Many hex escapes
    /atob\s*\([^)]+\)/i, // Base64 decode
    /String\.fromCharCode\s*\([^)]*,/i, // Char code construction
  ];

  return indicators.some((pattern) => pattern.test(content));
}

const AST_PATTERNS: ASTPattern[] = [
  {
    id: "AST_EVAL_DYNAMIC",
    title: "eval() with dynamic argument",
    description:
      "eval() is called with a non-literal argument (variable or expression). This executes arbitrary code at runtime, making static analysis impossible.",
    severity: "high",
    detect: (node, context) => {
      // Skip in bundled code - bundlers use eval for CSS-in-JS, source maps,
      // hot module replacement, WASM initialization, etc.
      if (context.isBundled && !context.hasObfuscationIndicators) return null;

      if (!isCallTo(node, "eval")) return null;

      const arg = (node as CallExpression).arguments[0];
      if (!arg || isLiteral(arg)) return null;

      const span = node as Span;
      return {
        start: span.start,
        end: span.end,
        codeSnippet: getCodeSnippet(context.content, span.start, span.end, context.lineStarts),
        additionalInfo: context.hasObfuscationIndicators
          ? "Combined with obfuscation indicators"
          : null,
      };
    },
    legitimateUses: ["REPL implementations", "Dynamic expression evaluators"],
    redFlags: ["Argument is decoded/decrypted value", "Combined with obfuscation"],
  },
  {
    id: "AST_FUNCTION_CONSTRUCTOR",
    title: "Function() constructor creates code from string",
    description:
      "new Function() creates executable code from strings, similar to eval(). This can execute arbitrary code and bypass static analysis.",
    severity: "high",
    detect: (node, context) => {
      if (!isNewExpression(node, "Function")) return null;

      // Skip in bundled code - webpack/rollup use Function() for module loading
      if (context.isBundled && !context.hasObfuscationIndicators) return null;

      // Check if any argument is non-literal
      const hasDynamicArg = (node as NewExpression).arguments.some((arg) => !isLiteral(arg));

      const span = node as Span;
      return {
        start: span.start,
        end: span.end,
        codeSnippet: getCodeSnippet(context.content, span.start, span.end, context.lineStarts),
        additionalInfo: hasDynamicArg ? "Uses dynamic (non-literal) argument" : null,
      };
    },
    legitimateUses: ["Template compilation", "Code generators", "Bundlers"],
    redFlags: ["Dynamic arguments", "Combined with decode functions"],
  },
  {
    id: "AST_DYNAMIC_REQUIRE",
    title: "require() with dynamic argument",
    description:
      "require() is called with a variable or expression instead of a string literal. This can load arbitrary modules at runtime.",
    severity: "medium",
    detect: (node, context) => {
      // Skip in bundled code - __webpack_require__ uses dynamic requires
      if (context.isBundled) return null;

      if (node.type !== "CallExpression") return null;
      const callExpr = node as CallExpression;
      if (!isIdentifier(callExpr.callee, "require")) {
        return null;
      }

      const arg = callExpr.arguments[0];
      if (!arg || isLiteral(arg)) return null;

      const span = node as Span;
      return {
        start: span.start,
        end: span.end,
        codeSnippet: getCodeSnippet(context.content, span.start, span.end, context.lineStarts),
        additionalInfo: null,
      };
    },
    legitimateUses: ["Plugin systems", "Dynamic module loading", "Bundlers"],
    redFlags: ["Module name from network", "Combined with obfuscation"],
  },
  {
    id: "AST_DYNAMIC_IMPORT",
    title: "Dynamic import() with non-literal source",
    description:
      "import() is called with a variable or expression. This can load arbitrary modules at runtime.",
    severity: "medium",
    detect: (node, context) => {
      // OXC uses ImportExpression for dynamic imports
      if (node.type !== "ImportExpression") return null;

      const importExpr = node as ImportExpression;
      const source = importExpr.source;
      if (isLiteral(source as Argument)) return null;

      const span = node as Span;
      return {
        start: span.start,
        end: span.end,
        codeSnippet: getCodeSnippet(context.content, span.start, span.end, context.lineStarts),
        additionalInfo: null,
      };
    },
    legitimateUses: ["Lazy loading", "Code splitting"],
    redFlags: ["Module URL from network", "User-controlled path"],
  },
  {
    id: "AST_INDIRECT_CALL",
    title: "Indirect function call via computed property",
    description:
      "Function is called using computed property access like obj[var](). This can hide which function is being called.",
    severity: "low",
    detect: (node, context) => {
      // Skip in bundled code - this is extremely common in bundled code
      if (context.isBundled) return null;

      if (node.type !== "CallExpression") return null;
      const callExpr = node as CallExpression;
      if (callExpr.callee.type !== "MemberExpression") return null;

      const memberExpr = callExpr.callee as MemberExpression;
      if (!memberExpr.computed) return null;

      // Skip if property is a literal
      if (isLiteral(memberExpr.property as Argument)) return null;

      // Only flag in obfuscated contexts
      if (!context.hasObfuscationIndicators) return null;

      const span = node as Span;
      return {
        start: span.start,
        end: span.end,
        codeSnippet: getCodeSnippet(context.content, span.start, span.end, context.lineStarts),
        additionalInfo: "Appears in obfuscated code context",
      };
    },
    redFlags: ["Property name is computed/decoded"],
  },
  {
    id: "AST_PROCESS_BINDING",
    title: "Access to process internal bindings",
    description:
      "Code accesses process.binding() or process._linkedBinding() which provide access to Node.js internals and can bypass security restrictions.",
    severity: "high",
    detect: (node, context) => {
      if (!isCallTo(node, ["binding", "_linkedBinding"])) return null;

      // Check if it's on process object
      const callExpr = node as CallExpression;
      if (callExpr.callee.type !== "MemberExpression") return null;

      const memberExpr = callExpr.callee as MemberExpression;
      if (!isIdentifier(memberExpr.object, "process")) return null;

      const span = node as Span;
      return {
        start: span.start,
        end: span.end,
        codeSnippet: getCodeSnippet(context.content, span.start, span.end, context.lineStarts),
        additionalInfo: null,
      };
    },
    redFlags: ["Access to internal modules", "Bypass security checks"],
  },
  {
    id: "AST_GLOBAL_THIS_EVAL",
    title: "eval accessed via globalThis/window/global",
    description:
      "Code accesses eval through global object property access, which can evade simple eval detection.",
    severity: "high",
    detect: (node, context) => {
      if (node.type !== "MemberExpression") return null;

      const memberExpr = node as MemberExpression;
      const obj = memberExpr.object;
      if (!isIdentifier(obj)) return null;

      const objName = getIdentifierName(obj);
      if (!objName || !["globalThis", "window", "global", "self"].includes(objName)) {
        return null;
      }

      const prop = memberExpr.property;
      if (isIdentifier(prop, "eval")) {
        const span = node as Span;
        return {
          start: span.start,
          end: span.end,
          codeSnippet: getCodeSnippet(context.content, span.start, span.end, context.lineStarts),
          additionalInfo: null,
        };
      }

      // Check string literal property: globalThis["eval"]
      // OXC uses "Literal" type for string literals (ESTree spec)
      if (prop.type === "Literal") {
        const strLiteral = prop as { value: unknown };
        if (strLiteral.value === "eval") {
          const span = node as Span;
          return {
            start: span.start,
            end: span.end,
            codeSnippet: getCodeSnippet(context.content, span.start, span.end, context.lineStarts),
            additionalInfo: null,
          };
        }
      }

      return null;
    },
    redFlags: ["Evasion of eval detection"],
  },
];

/**
 * Parse and analyze a JavaScript/TypeScript file for suspicious patterns.
 */
function analyzeFile(filename: string, content: string): Finding[] {
  const findings: Finding[] = [];

  // Determine lang from extension
  const ext = filename.slice(filename.lastIndexOf(".")).toLowerCase();
  const langMap: Record<string, "js" | "jsx" | "ts" | "tsx"> = {
    ".js": "js",
    ".mjs": "js",
    ".cjs": "js",
    ".jsx": "jsx",
    ".ts": "ts",
    ".tsx": "tsx",
  };
  const lang = langMap[ext] || "tsx"; // Default to tsx for maximum compatibility

  // Try to parse the file
  let result;
  try {
    result = parseSync(filename, content, {
      lang,
      sourceType: "unambiguous",
    });
  } catch {
    // If parsing fails, skip this file
    return findings;
  }

  // If there are errors, skip this file (error recovery mode)
  if (result.errors.length > 0) {
    return findings;
  }

  const bundlerInfo = detectBundler(content, filename);
  const lineStarts = computeLineStarts(content);

  const context: ASTContext = {
    filename,
    content,
    hasObfuscationIndicators: hasObfuscationIndicators(content) || hasGenuineObfuscation(content),
    isBundled: bundlerInfo.isBundled,
    lineStarts,
  };

  const seenFindings = new Set<string>();

  const addFinding = (pattern: ASTPattern, match: ASTMatch) => {
    const line = offsetToLine(match.start, lineStarts);
    const key = `${pattern.id}:${filename}:${line}`;
    if (seenFindings.has(key)) return;
    seenFindings.add(key);

    const finding: Finding = {
      id: pattern.id,
      title: pattern.title,
      description: pattern.description,
      severity: pattern.severity,
      category: "ast",
      location: {
        file: filename,
        line,
        column: offsetToColumn(match.start, lineStarts),
      },
      metadata: {
        codeSnippet: match.codeSnippet,
        ...(pattern.legitimateUses && {
          legitimateUses: pattern.legitimateUses,
        }),
        ...(pattern.redFlags && { redFlags: pattern.redFlags }),
      },
    };

    if (match.additionalInfo) {
      finding.metadata!["additionalInfo"] = match.additionalInfo;
    }

    findings.push(finding);
  };

  // Process patterns for each node type using typed visitors
  const processNode = (node: Node) => {
    for (const pattern of AST_PATTERNS) {
      const match = pattern.detect(node, context);
      if (match) addFinding(pattern, match);
    }
  };

  const visitor = new Visitor({
    CallExpression(node) {
      processNode(node);
    },
    NewExpression(node) {
      processNode(node);
    },
    MemberExpression(node) {
      processNode(node);
    },
    ImportExpression(node) {
      processNode(node);
    },
  });

  visitor.visit(result.program);

  return findings;
}

export function checkAST(contents: VsixContents): Finding[] {
  const findings: Finding[] = [];

  for (const [filename, buffer] of contents.files) {
    // Skip vendor/third-party code - extension authors don't control this code
    // and popular packages like protobufjs, @babel/*, pino legitimately use eval/Function
    if (filename.includes("node_modules/") || filename.includes("vendor/")) {
      continue;
    }

    // Only analyze JS/TS files
    if (!isScannable(filename, SCANNABLE_EXTENSIONS_PATTERN)) continue;

    // Skip non-JS/TS files that might be in the scannable set (like .sh, .ps1)
    const ext = filename.slice(filename.lastIndexOf(".")).toLowerCase();
    if (![".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"].includes(ext)) continue;

    const content = buffer.toString("utf8");

    findings.push(...analyzeFile(filename, content));
  }

  return findings;
}
