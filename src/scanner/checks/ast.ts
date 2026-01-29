import { parse, type ParserOptions } from "@babel/parser";
import traverseModule from "@babel/traverse";
import type { CallExpression, NewExpression, Node, SourceLocation } from "@babel/types";
import { detectBundler, hasGenuineObfuscation } from "../bundler.js";
import { isScannable, SCANNABLE_EXTENSIONS_PATTERN } from "../constants.js";
import type { Finding, Severity, VsixContents } from "../types.js";

// Handle ESM/CJS interop for @babel/traverse
// The module exports { default: { default: traverseFn } } in ESM
type TraverseFn = (
  ast: ReturnType<typeof parse>,
  opts: { enter: (path: { node: Node }) => void },
) => void;

const traverse: TraverseFn = (
  typeof traverseModule === "function"
    ? traverseModule
    : (traverseModule as { default: TraverseFn }).default
) as TraverseFn;

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
  loc: SourceLocation | null | undefined;
  codeSnippet: string;
  additionalInfo: string | null;
}

interface ASTContext {
  filename: string;
  content: string;
  hasObfuscationIndicators: boolean;
  isBundled: boolean;
}

const PARSER_OPTIONS: ParserOptions = {
  sourceType: "unambiguous",
  plugins: [
    "typescript",
    "jsx",
    "decorators",
    "classProperties",
    "classPrivateProperties",
    "classPrivateMethods",
    "dynamicImport",
    "optionalChaining",
    "nullishCoalescingOperator",
  ],
  errorRecovery: true,
  allowReturnOutsideFunction: true,
  allowAwaitOutsideFunction: true,
  allowSuperOutsideMethod: true,
  allowUndeclaredExports: true,
};

/**
 * Get code snippet around a node's location
 */
function getCodeSnippet(
  content: string,
  loc: SourceLocation | null | undefined,
  maxLen = 100,
): string {
  if (!loc) return "(no location)";

  const lines = content.split("\n");
  const line = lines[loc.start.line - 1];
  if (!line) return "(no line)";

  const start = Math.max(0, loc.start.column - 10);
  const end = Math.min(line.length, loc.end.column + 30);
  let snippet = line.slice(start, end);

  if (start > 0) snippet = "..." + snippet;
  if (end < line.length) snippet = snippet + "...";

  return snippet.slice(0, maxLen);
}

/**
 * Check if a node is a call to a specific function name
 */
function isCallTo(node: Node, name: string | string[]): node is CallExpression {
  if (node.type !== "CallExpression") return false;

  const names = Array.isArray(name) ? name : [name];
  const callee = node.callee;

  // Direct call: eval()
  if (callee.type === "Identifier" && names.includes(callee.name)) {
    return true;
  }

  // Member call: require("child_process").exec()
  if (callee.type === "MemberExpression" && callee.property.type === "Identifier") {
    return names.includes(callee.property.name);
  }

  return false;
}

/**
 * Check if node is a new expression with specific constructor
 */
function isNewExpression(node: Node, name: string): node is NewExpression {
  if (node.type !== "NewExpression") return false;
  return node.callee.type === "Identifier" && node.callee.name === name;
}

/**
 * Check if argument is a literal (string, number, boolean)
 */
function isLiteral(node: Node | undefined): boolean {
  if (!node) return false;
  return (
    node.type === "StringLiteral" ||
    node.type === "NumericLiteral" ||
    node.type === "BooleanLiteral" ||
    node.type === "NullLiteral" ||
    node.type === "TemplateLiteral"
  );
}

/**
 * Check if content has obfuscation indicators
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
      if (!isCallTo(node, "eval")) return null;

      const arg = node.arguments[0];
      if (!arg || isLiteral(arg)) return null;

      return {
        loc: node.loc,
        codeSnippet: getCodeSnippet(context.content, node.loc),
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
      const hasDynamicArg = node.arguments.some((arg) => !isLiteral(arg));

      return {
        loc: node.loc,
        codeSnippet: getCodeSnippet(context.content, node.loc),
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
      if (node.callee.type !== "Identifier" || node.callee.name !== "require") {
        return null;
      }

      const arg = node.arguments[0];
      if (!arg || isLiteral(arg)) return null;

      return {
        loc: node.loc,
        codeSnippet: getCodeSnippet(context.content, node.loc),
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
      if (node.type !== "CallExpression") return null;
      if (node.callee.type !== "Import") return null;

      const arg = node.arguments[0];
      if (!arg || isLiteral(arg)) return null;

      return {
        loc: node.loc,
        codeSnippet: getCodeSnippet(context.content, node.loc),
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
      if (node.callee.type !== "MemberExpression") return null;
      if (!node.callee.computed) return null;

      // Skip if property is a literal
      if (isLiteral(node.callee.property)) return null;

      // Only flag in obfuscated contexts
      if (!context.hasObfuscationIndicators) return null;

      return {
        loc: node.loc,
        codeSnippet: getCodeSnippet(context.content, node.loc),
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
      if (node.callee.type !== "MemberExpression") return null;
      const obj = node.callee.object;
      if (obj.type !== "Identifier" || obj.name !== "process") return null;

      return {
        loc: node.loc,
        codeSnippet: getCodeSnippet(context.content, node.loc),
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

      const obj = node.object;
      if (obj.type !== "Identifier") return null;
      if (!["globalThis", "window", "global", "self"].includes(obj.name)) {
        return null;
      }

      const prop = node.property;
      if (prop.type === "Identifier" && prop.name === "eval") {
        return {
          loc: node.loc,
          codeSnippet: getCodeSnippet(context.content, node.loc),
          additionalInfo: null,
        };
      }
      if (prop.type === "StringLiteral" && prop.value === "eval") {
        return {
          loc: node.loc,
          codeSnippet: getCodeSnippet(context.content, node.loc),
          additionalInfo: null,
        };
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

  // Try to parse the file
  let ast;
  try {
    ast = parse(content, PARSER_OPTIONS);
  } catch {
    // If parsing fails, skip this file
    return findings;
  }

  const bundlerInfo = detectBundler(content, filename);

  const context: ASTContext = {
    filename,
    content,
    hasObfuscationIndicators: hasObfuscationIndicators(content) || hasGenuineObfuscation(content),
    isBundled: bundlerInfo.isBundled,
  };

  const seenFindings = new Set<string>();

  // Traverse the AST
  traverse(ast, {
    enter(path) {
      const node = path.node;
      for (const pattern of AST_PATTERNS) {
        const match = pattern.detect(node, context);
        if (!match) continue;

        const line = match.loc?.start.line ?? 0;
        const key = `${pattern.id}:${filename}:${line}`;
        if (seenFindings.has(key)) continue;
        seenFindings.add(key);

        const finding: Finding = {
          id: pattern.id,
          title: pattern.title,
          description: pattern.description,
          severity: pattern.severity,
          category: "ast",
          location: {
            file: filename,
          },
          metadata: {
            codeSnippet: match.codeSnippet,
            ...(pattern.legitimateUses && {
              legitimateUses: pattern.legitimateUses,
            }),
            ...(pattern.redFlags && { redFlags: pattern.redFlags }),
          },
        };

        // Add optional location fields
        if (match.loc?.start.line !== undefined) {
          finding.location!.line = match.loc.start.line;
        }
        if (match.loc?.start.column !== undefined) {
          finding.location!.column = match.loc.start.column;
        }
        if (match.additionalInfo) {
          finding.metadata!["additionalInfo"] = match.additionalInfo;
        }

        findings.push(finding);
      }
    },
  });

  return findings;
}

export function checkAST(contents: VsixContents): Finding[] {
  const findings: Finding[] = [];

  for (const [filename, buffer] of contents.files) {
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
