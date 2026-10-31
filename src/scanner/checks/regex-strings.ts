import { Visitor } from "oxc-parser";
import type {
  BindingPattern,
  CallExpression,
  Expression,
  Function as FunctionNode,
  ArrowFunctionExpression,
  NewExpression,
  ParamPattern,
  Program,
  StringLiteral,
  VisitorObject,
} from "oxc-parser";

interface Scope {
  parent: Scope | undefined;
  functionScope: boolean;
  bindings: Map<string, Binding | null>;
}

interface Binding {
  expression: Expression;
  scope: Scope;
}

interface ResolvedString {
  value: string;
  origins: Map<number, number>;
}

interface Construction {
  node: CallExpression | NewExpression;
  scope: Scope;
}

/** A statically resolved RegExp construction with source positions for literal embeddings. */
export interface RegexString {
  pattern: string;
  flags: string;
  origins: Map<number, number>;
}

const MAX_PATTERN_LENGTH = 65_536;
const MAX_RESOLUTION_DEPTH = 64;

function lookup(scope: Scope, name: string): Binding | null | undefined {
  let current: Scope | undefined = scope;
  while (current !== undefined) {
    if (current.bindings.has(name)) return current.bindings.get(name);
    current = current.parent;
  }
  return undefined;
}

function declarePattern(scope: Scope, pattern: BindingPattern | ParamPattern): void {
  switch (pattern.type) {
    case "Identifier":
      scope.bindings.set(pattern.name, null);
      break;
    case "AssignmentPattern":
      declarePattern(scope, pattern.left);
      break;
    case "RestElement":
      declarePattern(scope, pattern.argument);
      break;
    case "TSParameterProperty":
      declarePattern(scope, pattern.parameter);
      break;
    case "ObjectPattern":
      for (const property of pattern.properties) {
        declarePattern(scope, property.type === "RestElement" ? property.argument : property.value);
      }
      break;
    case "ArrayPattern":
      for (const element of pattern.elements) {
        if (element !== null) declarePattern(scope, element);
      }
      break;
  }
}

class Constructions {
  scope: Scope = { parent: undefined, functionScope: true, bindings: new Map() };
  calls: Construction[] = [];
  modifiedBuiltin = false;

  enter(functionScope = false): void {
    this.scope = { parent: this.scope, functionScope, bindings: new Map() };
  }

  exit(): void {
    if (this.scope.parent !== undefined) this.scope = this.scope.parent;
  }

  enterFunction(node: FunctionNode | ArrowFunctionExpression, declaration = false): void {
    if (declaration && node.id !== null) {
      let scope = this.scope;
      scope.bindings.set(node.id.name, null);
      while (!scope.functionScope && scope.parent !== undefined) scope = scope.parent;
      scope.bindings.set(node.id.name, null);
    }
    this.enter(true);
    if (node.id !== null) this.scope.bindings.set(node.id.name, null);
    for (const parameter of node.params) declarePattern(this.scope, parameter);
  }

  declarations(): VisitorObject {
    return {
      VariableDeclaration: (node): void => {
        let scope = this.scope;
        while (node.kind === "var" && !scope.functionScope && scope.parent !== undefined) {
          scope = scope.parent;
        }
        for (const declaration of node.declarations) {
          if (node.kind === "const" && declaration.id.type === "Identifier") {
            const binding =
              declaration.init === null ? null : { expression: declaration.init, scope };
            scope.bindings.set(declaration.id.name, binding);
          } else declarePattern(scope, declaration.id);
        }
      },
      ImportDeclaration: (node): void => {
        for (const specifier of node.specifiers)
          this.scope.bindings.set(specifier.local.name, null);
      },
      CallExpression: (node): void => {
        this.calls.push({ node, scope: this.scope });
      },
      NewExpression: (node): void => {
        this.calls.push({ node, scope: this.scope });
      },
      AssignmentExpression: (node): void => {
        if (node.left.type === "Identifier" && node.left.name === "RegExp") {
          this.modifiedBuiltin = true;
        }
        if (
          node.left.type === "MemberExpression" &&
          !node.left.computed &&
          node.left.property.type === "Identifier" &&
          node.left.property.name === "RegExp"
        ) {
          this.modifiedBuiltin = true;
        }
      },
    };
  }

  visitor(): VisitorObject {
    return {
      ...this.declarations(),
      BlockStatement: (): void => {
        this.enter();
      },
      "BlockStatement:exit": (): void => {
        this.exit();
      },
      ForStatement: (): void => {
        this.enter();
      },
      "ForStatement:exit": (): void => {
        this.exit();
      },
      ForInStatement: (): void => {
        this.enter();
      },
      "ForInStatement:exit": (): void => {
        this.exit();
      },
      ForOfStatement: (): void => {
        this.enter();
      },
      "ForOfStatement:exit": (): void => {
        this.exit();
      },
      SwitchStatement: (): void => {
        this.enter();
      },
      "SwitchStatement:exit": (): void => {
        this.exit();
      },
      StaticBlock: (): void => {
        this.enter(true);
      },
      "StaticBlock:exit": (): void => {
        this.exit();
      },
      FunctionDeclaration: (node): void => {
        this.enterFunction(node, true);
      },
      "FunctionDeclaration:exit": (): void => {
        this.exit();
      },
      FunctionExpression: (node): void => {
        this.enterFunction(node);
      },
      "FunctionExpression:exit": (): void => {
        this.exit();
      },
      ArrowFunctionExpression: (node): void => {
        this.enterFunction(node);
      },
      "ArrowFunctionExpression:exit": (): void => {
        this.exit();
      },
      CatchClause: (node): void => {
        this.enter();
        if (node.param !== null) declarePattern(this.scope, node.param);
      },
      "CatchClause:exit": (): void => {
        this.exit();
      },
      ClassDeclaration: (node): void => {
        if (node.id !== null) this.scope.bindings.set(node.id.name, null);
        this.enter();
      },
      "ClassDeclaration:exit": (): void => {
        this.exit();
      },
      ClassExpression: (node): void => {
        this.enter();
        if (node.id !== null) this.scope.bindings.set(node.id.name, null);
      },
      "ClassExpression:exit": (): void => {
        this.exit();
      },
    };
  }
}

function stringLiteral(node: StringLiteral, content: string): ResolvedString | undefined {
  if (node.value.length > MAX_PATTERN_LENGTH) return undefined;
  const source = Array.from(content.slice(node.start + 1, node.end - 1).matchAll(/\u202a/g));
  const decoded = Array.from(node.value.matchAll(/\u202a/g));
  const origins = new Map<number, number>();
  if (source.length === decoded.length) {
    for (const [index, match] of decoded.entries()) {
      const original = source[index];
      if (original !== undefined) origins.set(match.index, node.start + 1 + original.index);
    }
  }
  return { value: node.value, origins };
}

function concatenate(left: ResolvedString, right: ResolvedString): ResolvedString | undefined {
  if (left.value.length + right.value.length > MAX_PATTERN_LENGTH) return undefined;
  const origins = new Map(left.origins);
  for (const [index, source] of right.origins) origins.set(left.value.length + index, source);
  return { value: left.value + right.value, origins };
}

class StringResolver {
  private readonly cache = new Map<Binding, ResolvedString | undefined>();
  private readonly active = new Set<Binding>();

  constructor(private readonly content: string) {}

  resolve(node: Expression, scope: Scope, depth = 0): ResolvedString | undefined {
    if (depth > MAX_RESOLUTION_DEPTH) return undefined;
    if (node.type === "Literal" && typeof node.value === "string") {
      return stringLiteral(node, this.content);
    }
    if (node.type === "Identifier") return this.binding(lookup(scope, node.name), depth);
    if (node.type === "BinaryExpression" && node.operator === "+") {
      const left = this.resolve(node.left, scope, depth + 1);
      const right = this.resolve(node.right, scope, depth + 1);
      if (left !== undefined && right !== undefined) return concatenate(left, right);
    }
    return undefined;
  }

  private binding(binding: Binding | null | undefined, depth: number): ResolvedString | undefined {
    if (binding === undefined || binding === null || this.active.has(binding)) return undefined;
    if (this.cache.has(binding)) return this.cache.get(binding);
    this.active.add(binding);
    const result = this.resolve(binding.expression, binding.scope, depth + 1);
    this.active.delete(binding);
    this.cache.set(binding, result);
    return result;
  }
}

/** Resolve string literals and const concatenations passed to an unshadowed RegExp. */
export function regexStrings(program: Program, content: string): RegexString[] {
  const constructions = new Constructions();
  new Visitor(constructions.visitor()).visit(program);
  if (constructions.modifiedBuiltin) return [];
  const resolver = new StringResolver(content);
  const patterns: RegexString[] = [];
  for (const { node, scope } of constructions.calls) {
    if (node.callee.type !== "Identifier" || node.callee.name !== "RegExp") continue;
    if (lookup(scope, "RegExp") !== undefined) continue;
    const [pattern, flags] = node.arguments;
    if (pattern === undefined || pattern.type === "SpreadElement") continue;
    const resolved = resolver.resolve(pattern, scope);
    const mode =
      flags === undefined
        ? ""
        : flags.type === "SpreadElement"
          ? undefined
          : resolver.resolve(flags, scope)?.value;
    if (resolved !== undefined && mode !== undefined) {
      patterns.push({ pattern: resolved.value, flags: mode, origins: resolved.origins });
    }
  }
  return patterns;
}
