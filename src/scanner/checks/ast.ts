import { parseSync, Visitor } from "oxc-parser";
import type { Argument, CallExpression, NewExpression, Node, OxcError, Span } from "oxc-parser";
import { SourceBindings } from "#internal/scanner/source-bindings.js";
import { ObservationCollector } from "#internal/scanner/observations.js";
import { hasGenuineObfuscation } from "#internal/scanner/bundler.js";
import { isScannable, JS_EXTENSIONS } from "#internal/scanner/constants.js";
import type {
  CheckResult,
  Finding,
  Observation,
  Severity,
  VsixContents,
} from "#internal/scanner/types.js";
import {
  computeLineStarts,
  getStringContent,
  offsetToColumn,
  offsetToLine,
} from "#internal/scanner/utils.js";

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
  lineStarts: number[];
  bindings: SourceBindings;
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
  const lineStart = lineStarts[lineNum - 1] ?? 0;
  const nextLine = content.indexOf("\n", lineStart);
  const line = content.slice(lineStart, nextLine === -1 ? undefined : nextLine);
  const colStart = start - lineStart;
  const colEnd = end - lineStart;

  const snippetStart = Math.max(0, colStart - 10);
  const snippetEnd = Math.min(line.length, colEnd + 30);
  let snippet = line.slice(snippetStart, snippetEnd);

  if (snippetStart > 0) snippet = "..." + snippet;
  if (snippetEnd < line.length) snippet = snippet + "...";

  return snippet.slice(0, maxLen);
}

function isCallTo(node: Node, apis: string[], context: ASTContext): node is CallExpression {
  if (node.type !== "CallExpression") return false;
  const api = context.bindings.resolve(node.callee);
  return api !== null && apis.includes(api);
}

/**
 * Check if node is a new expression with specific constructor.
 */
function isNewExpression(node: Node, name: string, context: ASTContext): node is NewExpression {
  if (node.type !== "NewExpression") return false;
  const newExpr = node;
  return context.bindings.resolve(newExpr.callee) === `global.${name}`;
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
  return type === "Literal" || (node.type === "TemplateLiteral" && node.expressions.length === 0);
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
      "eval() is called with a non-literal argument. " +
      "Review where the argument comes from and what code it can execute.",
    severity: "high",
    detect: (node, context) => {
      if (!isCallTo(node, ["global.eval"], context)) return null;

      const arg = node.arguments[0];
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
      if (!isNewExpression(node, "Function", context)) return null;

      // An empty literal body is commonly used as a code-generation feature probe.
      if (node.arguments.length === 1 && node.arguments[0]?.type === "Literal") {
        if (node.arguments[0].value === "") return null;
      }

      // Check if any argument is non-literal
      const hasDynamicArg = node.arguments.some((arg) => !isLiteral(arg));

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
      if (!isCallTo(node, ["global.require"], context)) return null;
      const callExpr = node;

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

      const importExpr = node;
      const source = importExpr.source;
      if (isLiteral(source)) return null;

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
      if (node.type !== "CallExpression") return null;
      const callExpr = node;
      if (callExpr.callee.type !== "MemberExpression") return null;

      const memberExpr = callExpr.callee;
      if (!memberExpr.computed) return null;

      // Skip if property is a literal
      if (isLiteral(memberExpr.property)) return null;

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
      if (!isCallTo(node, ["process.binding", "process._linkedBinding"], context)) return null;

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

      if (context.bindings.resolve(node) !== "global.eval") return null;
      return {
        start: node.start,
        end: node.end,
        codeSnippet: getCodeSnippet(context.content, node.start, node.end, context.lineStarts),
        additionalInfo: null,
      };
    },
    redFlags: ["Evasion of eval detection"],
  },
];

function recordParseRecovery(
  filename: string,
  errors: readonly OxcError[],
  findings: Finding[],
): void {
  if (errors.length === 0) return;
  findings.push({
    id: "PARSE_FAILURE_AST",
    title: "AST parse recovery encountered errors",
    description:
      "File parsed with recoverable AST errors. " +
      "AST-based checks may be incomplete for this file, " +
      "which can hide suspicious control flow.",
    severity: "low",
    category: "pattern",
    location: { file: filename },
    metadata: {
      analysisIncomplete: true,
      errorCount: errors.length,
      error: errors[0]?.message ?? "Unknown parser error",
    },
  });
}

/**
 * Parse and analyze a JavaScript/TypeScript file for suspicious patterns.
 */
function analyzeFile(
  filename: string,
  content: string,
  findings: Finding[],
  observations: Observation[],
): boolean {
  const result = parseSync(filename.toLowerCase(), content, {
    sourceType: "unambiguous",
  });

  recordParseRecovery(filename, result.errors, findings);

  const lineStarts = computeLineStarts(content);

  const context: ASTContext = {
    filename,
    content,
    hasObfuscationIndicators: hasObfuscationIndicators(content) || hasGenuineObfuscation(content),
    lineStarts,
    bindings: new SourceBindings(result.program),
  };

  const seenFindings = new Set<string>();

  const addFinding = (pattern: ASTPattern, match: ASTMatch): void => {
    const line = offsetToLine(match.start, lineStarts);
    const key = `${pattern.id}:${filename}:${match.start}`;
    if (seenFindings.has(key)) return;
    seenFindings.add(key);

    const finding: Finding = {
      id: pattern.id,
      title: pattern.title,
      description: pattern.description,
      severity: pattern.severity,
      category: "ast",
      capabilities: ["execution"],
      location: {
        file: filename,
        line,
        column: offsetToColumn(match.start, lineStarts) + 1,
      },
      metadata: {
        codeSnippet: match.codeSnippet,
        ...(match.additionalInfo !== null && match.additionalInfo !== ""
          ? { additionalInfo: match.additionalInfo }
          : {}),
        ...(pattern.legitimateUses && {
          legitimateUses: pattern.legitimateUses,
        }),
        ...(pattern.redFlags && { redFlags: pattern.redFlags }),
      },
    };

    findings.push(finding);
  };

  const collector = new ObservationCollector(filename, content);
  const processNode = (node: Node): void => {
    collector.visit(node, context.bindings);
    for (const pattern of AST_PATTERNS) {
      const match = pattern.detect(node, context);
      if (match) addFinding(pattern, match);
    }
  };

  const visitor = new Visitor({
    ImportDeclaration(node): void {
      collector.visit(node, context.bindings);
    },
    CallExpression(node): void {
      processNode(node);
    },
    NewExpression(node): void {
      processNode(node);
    },
    MemberExpression(node): void {
      processNode(node);
    },
    ImportExpression(node): void {
      processNode(node);
    },
  });

  try {
    visitor.visit(result.program);
  } finally {
    for (const observation of collector.observations) observations.push(observation);
  }
  if (context.bindings.failure !== undefined) throw context.bindings.failure;
  return result.errors.length === 0;
}

function recordASTFailure(findings: Finding[], filename: string, error: unknown): void {
  const previousIndex = findings.findIndex(
    (finding) => finding.id === "PARSE_FAILURE_AST" && finding.location?.file === filename,
  );
  const previous = findings[previousIndex];
  const metadata: Record<string, unknown> = {
    ...previous?.metadata,
    analysisIncomplete: true,
    error: error instanceof Error ? error.message : String(error),
  };
  if (previous !== undefined) metadata["recoveryError"] = previous.metadata?.["error"];
  const failure: Finding = {
    id: "PARSE_FAILURE_AST",
    title: "AST analysis failure",
    description:
      "AST analysis could not complete for this file. Inspect it manually; " +
      "structural checks may have missed executable code.",
    severity: "low",
    category: "pattern",
    location: { file: filename },
    metadata,
  };
  if (previousIndex === -1) {
    findings.push(failure);
    return;
  }
  findings[previousIndex] = failure;
}

/** Analyze script files, reporting parser or traversal failures for each affected file. */
export function checkAST(contents: VsixContents): CheckResult {
  const findings: Finding[] = [];
  const warnings: string[] = [];
  const observations: Observation[] = [];

  for (const [filename, buffer] of contents.files) {
    // Only analyze JS/TS files
    if (!isScannable(filename, JS_EXTENSIONS)) continue;

    // Skip non-JS/TS files that might be in the scannable set (like .sh, .ps1)
    const content = getStringContent(contents, filename, buffer);

    try {
      if (!analyzeFile(filename, content, findings, observations)) {
        warnings.push(
          `AST analysis incomplete for ${JSON.stringify(filename)}; inspect it manually.`,
        );
      }
    } catch (error) {
      recordASTFailure(findings, filename, error);
      warnings.push(
        `AST analysis incomplete for ${JSON.stringify(filename)}; inspect it manually.`,
      );
    }
  }

  return { findings, warnings, observations };
}
