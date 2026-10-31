import { Visitor } from "oxc-parser";
import type {
  BindingPattern,
  CallExpression,
  Expression,
  Function as FunctionNode,
  ArrowFunctionExpression,
  NewExpression,
  Node,
  MemberExpression,
  ParamPattern,
  Program,
  StringLiteral,
  SpreadElement,
  VisitorObject,
} from "oxc-parser";

interface Scope {
  parent: Scope | undefined;
  functionScope: boolean;
  bindings: Map<string, Binding | null>;
}

interface BindingValue {
  expression: Expression;
  scope: Scope;
}

interface Binding {
  expression: Expression | undefined;
  scope: Scope;
  constant: boolean;
  values: BindingValue[];
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
  flags: string | undefined;
  origins: Map<number, number>;
  flagOrigins: Set<number>;
}

const MAX_PATTERN_LENGTH = 65_536;
const MAX_RESOLUTION_DEPTH = 64;
const GLOBAL_OBJECTS = new Set(["globalThis", "global", "window", "self"]);

function unwrapTypeExpression(node: Node): Node {
  while (
    node.type === "TSAsExpression" ||
    node.type === "TSSatisfiesExpression" ||
    node.type === "TSNonNullExpression" ||
    node.type === "TSTypeAssertion" ||
    node.type === "TSInstantiationExpression" ||
    node.type === "ParenthesizedExpression"
  ) {
    node = node.expression;
  }
  return node;
}

function regExpProperty(node: MemberExpression, scope: Scope, resolver: StringResolver): boolean {
  if (!node.computed) return node.property.type === "Identifier" && node.property.name === "RegExp";
  if (node.property.type === "Literal") return node.property.value === "RegExp";
  const resolved = resolver.resolve(node.property, scope);
  return resolved === undefined || resolved.value === "RegExp";
}

function globalReceiver(node: Expression, scope: Scope): boolean {
  const pending: BindingValue[] = [{ expression: node, scope }];
  const seen = new Set<Binding>();
  let candidate: BindingValue | undefined;
  while ((candidate = pending.pop()) !== undefined) {
    const expression = unwrapTypeExpression(candidate.expression);
    if (expression.type !== "Identifier") continue;
    const binding = lookup(candidate.scope, expression.name);
    if (binding === undefined) {
      if (GLOBAL_OBJECTS.has(expression.name)) return true;
      continue;
    }
    if (binding === null || seen.has(binding)) continue;
    seen.add(binding);
    for (const value of binding.values) pending.push(value);
  }
  return false;
}

function writesWrappedTarget(node: Node, scope: Scope, resolver: StringResolver): boolean {
  if (node.type === "AssignmentPattern") return writesRegExp(node.left, scope, resolver);
  if (node.type === "RestElement") return writesRegExp(node.argument, scope, resolver);
  return false;
}

function writesRegExp(node: Node, scope: Scope, resolver: StringResolver): boolean {
  node = unwrapTypeExpression(node);
  if (node.type === "Identifier") {
    return node.name === "RegExp" && lookup(scope, node.name) === undefined;
  }
  if (node.type === "ArrayPattern") {
    return node.elements.some(
      (element) => element !== null && writesRegExp(element, scope, resolver),
    );
  }
  if (node.type === "ObjectPattern") {
    return node.properties.some((property) =>
      writesRegExp(
        property.type === "RestElement" ? property.argument : property.value,
        scope,
        resolver,
      ),
    );
  }
  if (node.type !== "MemberExpression") return writesWrappedTarget(node, scope, resolver);
  return regExpProperty(node, scope, resolver) && globalReceiver(node.object, scope);
}

function bindingScope(scope: Scope, name: string): Scope {
  let current = scope;
  while (!current.bindings.has(name) && current.parent !== undefined) current = current.parent;
  return current;
}

function lookup(scope: Scope, name: string): Binding | null | undefined {
  return bindingScope(scope, name).bindings.get(name);
}

function makeBinding(expression: Expression | undefined, scope: Scope, constant = false): Binding {
  return {
    expression,
    scope,
    constant,
    values: expression === undefined ? [] : [{ expression, scope }],
  };
}

function declareName(scope: Scope, name: string): void {
  if (!scope.bindings.has(name)) scope.bindings.set(name, null);
}

function declarePattern(scope: Scope, pattern: BindingPattern | ParamPattern): void {
  switch (pattern.type) {
    case "Identifier":
      scope.bindings.set(pattern.name, null);
      break;
    case "AssignmentPattern":
      declarePattern(scope, pattern.left);
      if (pattern.left.type === "Identifier") {
        scope.bindings.set(pattern.left.name, makeBinding(pattern.right, scope));
      }
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
  writes: Array<{ node: Node; scope: Scope }> = [];
  assignments: Array<{ node: Node; value: Expression; scope: Scope }> = [];
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
      declareName(scope, node.id.name);
      while (!scope.functionScope && scope.parent !== undefined) scope = scope.parent;
      declareName(scope, node.id.name);
    }
    this.enter(true);
    if (node.id !== null) declareName(this.scope, node.id.name);
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
          if (declaration.id.type === "Identifier") {
            const binding = makeBinding(
              declaration.init ?? undefined,
              this.scope,
              node.kind === "const",
            );
            const previous = scope.bindings.get(declaration.id.name);
            if (node.kind === "var" && previous !== undefined && previous !== null) {
              previous.constant = false;
              for (const value of binding.values) previous.values.push(value);
            } else scope.bindings.set(declaration.id.name, binding);
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
        this.writes.push({ node: node.left, scope: this.scope });
        this.assignments.push({ node: node.left, value: node.right, scope: this.scope });
      },
      UpdateExpression: (node): void => {
        this.writes.push({ node: node.argument, scope: this.scope });
      },
      UnaryExpression: (node): void => {
        if (node.operator === "delete") {
          this.writes.push({ node: node.argument, scope: this.scope });
        }
      },
      WithStatement: (): void => {
        this.modifiedBuiltin = true;
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
      ForInStatement: (node): void => {
        this.enter();
        if (node.left.type !== "VariableDeclaration") {
          this.writes.push({ node: node.left, scope: this.scope });
        }
      },
      "ForInStatement:exit": (): void => {
        this.exit();
      },
      ForOfStatement: (node): void => {
        this.enter();
        if (node.left.type !== "VariableDeclaration") {
          this.writes.push({ node: node.left, scope: this.scope });
        }
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
        if (node.id !== null) declareName(this.scope, node.id.name);
        this.enter();
      },
      "ClassDeclaration:exit": (): void => {
        this.exit();
      },
      ClassExpression: (node): void => {
        this.enter();
        if (node.id !== null) declareName(this.scope, node.id.name);
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

  resolve(expression: Expression, scope: Scope, depth = 0): ResolvedString | undefined {
    const node = unwrapTypeExpression(expression);
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
    if (
      binding === undefined ||
      binding === null ||
      !binding.constant ||
      binding.expression === undefined ||
      this.active.has(binding)
    )
      return undefined;
    if (this.cache.has(binding)) return this.cache.get(binding);
    this.active.add(binding);
    const result = this.resolve(binding.expression, binding.scope, depth + 1);
    this.active.delete(binding);
    this.cache.set(binding, result);
    return result;
  }
}

function constructionFlags(
  flags: Expression | SpreadElement | undefined,
  resolver: StringResolver,
  scope: Scope,
): ResolvedString | undefined {
  if (flags === undefined) return { value: "", origins: new Map<number, number>() };
  if (flags.type === "SpreadElement") return undefined;
  return resolver.resolve(flags, scope);
}

function constructionPattern(
  { node, scope }: Construction,
  resolver: StringResolver,
): RegexString | undefined {
  const callee = unwrapTypeExpression(node.callee);
  if (callee.type !== "Identifier") return undefined;
  if (callee.name !== "RegExp" || lookup(scope, "RegExp") !== undefined) return undefined;
  const [pattern, flags] = node.arguments;
  if (pattern === undefined || pattern.type === "SpreadElement") return undefined;
  const resolved = resolver.resolve(pattern, scope);
  const mode = constructionFlags(flags, resolver, scope);
  if (resolved === undefined && mode === undefined) return undefined;
  return {
    pattern: resolved?.value ?? "",
    flags: mode?.value,
    origins: resolved?.origins ?? new Map<number, number>(),
    flagOrigins: new Set(mode?.origins.values()),
  };
}

function recordGlobalAliases(constructions: Constructions): void {
  for (const assignment of constructions.assignments) {
    const target = unwrapTypeExpression(assignment.node);
    if (target.type !== "Identifier") continue;
    const scope = bindingScope(assignment.scope, target.name);
    let binding = scope.bindings.get(target.name);
    if (binding === undefined && GLOBAL_OBJECTS.has(target.name)) continue;
    if (binding === undefined || binding === null) {
      binding = makeBinding(undefined, scope);
      scope.bindings.set(target.name, binding);
    }
    binding.constant = false;
    binding.values.push({ expression: assignment.value, scope: assignment.scope });
  }
}

/** Resolve string literals and const concatenations passed to an unshadowed RegExp. */
export function regexStrings(program: Program, content: string): RegexString[] {
  const constructions = new Constructions();
  new Visitor(constructions.visitor()).visit(program);
  if (constructions.modifiedBuiltin) return [];
  recordGlobalAliases(constructions);
  const resolver = new StringResolver(content);
  if (constructions.writes.some(({ node, scope }) => writesRegExp(node, scope, resolver)))
    return [];
  const patterns: RegexString[] = [];
  for (const construction of constructions.calls) {
    const pattern = constructionPattern(construction, resolver);
    if (pattern !== undefined) patterns.push(pattern);
  }
  return patterns;
}
