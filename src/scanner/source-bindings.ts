import { Visitor } from "oxc-parser";
import type {
  BindingPattern,
  Function as FunctionNode,
  ArrowFunctionExpression,
  Node,
  Program,
  ParamPattern,
  VariableDeclaration,
  VisitorObject,
} from "oxc-parser";

interface Binding {
  scope: Scope;
  source: string | Node | null;
  suffix: string;
  reassigned: boolean;
}

interface Scope {
  parent: Scope | null;
  functionScope: boolean;
  bindings: Map<string, Binding>;
}

const GLOBALS = new Set([
  "fetch",
  "eval",
  "Function",
  "require",
  "WebSocket",
  "EventSource",
  "XMLHttpRequest",
]);
const GLOBAL_OBJECTS = new Set(["globalThis", "window", "global", "self"]);

/** Return a statically named property, preserving computed names as unresolved. */
export function propertyName(node: Node, computed: boolean): string | null {
  if (!computed && node.type === "Identifier") return node.name;
  if (node.type === "Literal" && typeof node.value === "string") return node.value;
  return null;
}

/** Resolve lexical imports and aliases without assuming the identities of local methods. */
export class SourceBindings {
  /** The AST check reports a partial index as incomplete analysis, preserving earlier evidence. */
  failure: Error | undefined;
  private readonly scopes = new WeakMap<Node, Scope>();
  private readonly root: Scope = { parent: null, functionScope: true, bindings: new Map() };
  private current = this.root;
  private readonly overwritten = new Set<string>();

  constructor(program: Program) {
    const writes: Array<{ node: Node; scope: Scope }> = [];
    const visitor = new Visitor({ ...this.scopeVisitor(), ...this.bindingVisitor(writes) });
    try {
      visitor.visit(program);
    } catch (error) {
      this.failure = error instanceof Error ? error : new Error(String(error));
    }
    for (const { node, scope } of writes) this.invalidate(node, scope);
  }

  private scopeVisitor(): VisitorObject {
    const enter = (): void => {
      this.push(false);
    };
    const leave = (): void => {
      this.current = this.current.parent ?? this.root;
    };
    return {
      BlockStatement: enter,
      "BlockStatement:exit": leave,
      ForStatement: enter,
      "ForStatement:exit": leave,
      ForInStatement: enter,
      "ForInStatement:exit": leave,
      ForOfStatement: enter,
      "ForOfStatement:exit": leave,
      SwitchStatement: enter,
      "SwitchStatement:exit": leave,
      CatchClause: (node): void => {
        enter();
        if (node.param !== null) this.declarePattern(node.param, null, this.current);
      },
      "CatchClause:exit": leave,
      FunctionDeclaration: (node): void => {
        if (node.id !== null) this.declare(node.id.name, null, this.current);
        this.enterFunction(node);
      },
      "FunctionDeclaration:exit": leave,
      FunctionExpression: (node): void => {
        this.enterFunction(node);
      },
      "FunctionExpression:exit": leave,
      ArrowFunctionExpression: (node): void => {
        this.enterFunction(node);
      },
      "ArrowFunctionExpression:exit": leave,
      ClassDeclaration: (node): void => {
        if (node.id !== null) this.declare(node.id.name, null, this.current);
        enter();
      },
      "ClassDeclaration:exit": leave,
      ClassExpression: (node): void => {
        enter();
        if (node.id !== null) this.declare(node.id.name, null, this.current);
      },
      "ClassExpression:exit": leave,
    };
  }

  private bindingVisitor(writes: Array<{ node: Node; scope: Scope }>): VisitorObject {
    const remember = (node: Node): void => {
      this.scopes.set(node, this.current);
    };
    return {
      ImportDeclaration: (node): void => {
        for (const specifier of node.specifiers) {
          const suffix =
            specifier.type === "ImportSpecifier"
              ? `.${propertyName(specifier.imported, false) ?? "*"}`
              : "";
          const typeOnly =
            node.importKind === "type" ||
            (specifier.type === "ImportSpecifier" && specifier.importKind === "type");
          const source = typeOnly ? null : node.source.value.replace(/^node:/, "");
          this.declare(specifier.local.name, source, this.current, suffix);
        }
      },
      VariableDeclaration: (node): void => {
        this.declareVariables(node);
      },
      CallExpression: (node): void => {
        remember(node.callee);
      },
      NewExpression: (node): void => {
        remember(node.callee);
      },
      MemberExpression: remember,
      ImportExpression: remember,
      AssignmentExpression: (node): void => {
        writes.push({ node: node.left, scope: this.current });
      },
      UpdateExpression: (node): void => {
        writes.push({ node: node.argument, scope: this.current });
      },
    };
  }

  private push(functionScope: boolean): void {
    this.current = { parent: this.current, functionScope, bindings: new Map() };
  }

  private enterFunction(node: FunctionNode | ArrowFunctionExpression): void {
    this.push(true);
    if (node.id !== null) this.declare(node.id.name, null, this.current);
    for (const param of node.params) this.declareParameter(param);
  }

  private declareParameter(param: ParamPattern): void {
    if (param.type === "TSParameterProperty") {
      this.declarePattern(param.parameter, null, this.current);
    } else if (param.type === "RestElement") {
      this.declarePattern(param.argument, null, this.current);
    } else {
      this.declarePattern(param, null, this.current);
    }
  }

  private declareVariables(node: VariableDeclaration): void {
    let scope = this.current;
    if (node.kind === "var") {
      while (!scope.functionScope && scope.parent !== null) scope = scope.parent;
    }
    for (const declaration of node.declarations) {
      this.declarePattern(declaration.id, declaration.init, scope);
    }
  }

  private declare(name: string, source: string | Node | null, scope: Scope, suffix = ""): void {
    scope.bindings.set(name, { scope: this.current, source, suffix, reassigned: false });
  }

  private declarePattern(pattern: BindingPattern, source: Node | null, scope: Scope): void {
    if (pattern.type === "Identifier") {
      this.declare(pattern.name, source, scope);
    } else if (pattern.type === "AssignmentPattern") {
      this.declarePattern(pattern.left, null, scope);
    } else if (pattern.type === "ObjectPattern") {
      this.declareObject(pattern, source, scope);
    } else {
      for (const element of pattern.elements) {
        if (element === null) continue;
        this.declarePattern(
          element.type === "RestElement" ? element.argument : element,
          null,
          scope,
        );
      }
    }
  }

  private declareObject(
    pattern: Extract<BindingPattern, { type: "ObjectPattern" }>,
    source: Node | null,
    scope: Scope,
  ): void {
    for (const property of pattern.properties) {
      if (property.type === "RestElement") {
        this.declarePattern(property.argument, null, scope);
      } else if (property.value.type === "Identifier") {
        const name = propertyName(property.key, property.computed);
        this.declare(property.value.name, name === null ? null : source, scope, `.${name ?? "*"}`);
      } else {
        this.declarePattern(property.value, null, scope);
      }
    }
  }

  private lookup(name: string, scope: Scope): Binding | undefined {
    let current: Scope | null = scope;
    while (current !== null) {
      const binding = current.bindings.get(name);
      if (binding !== undefined) return binding;
      current = current.parent;
    }
    return undefined;
  }

  private invalidate(node: Node, scope: Scope): void {
    if (node.type === "Identifier") {
      const binding = this.lookup(node.name, scope);
      if (binding !== undefined) binding.reassigned = true;
      else if (GLOBALS.has(node.name)) this.overwritten.add(`global.${node.name}`);
    }
    if (node.type === "MemberExpression") {
      const api = this.resolveAt(node, scope, new Set());
      if (api !== null) this.overwritten.add(api);
    }
    this.invalidatePattern(node, scope);
  }

  private invalidatePattern(node: Node, scope: Scope): void {
    if (node.type === "ObjectPattern") {
      for (const property of node.properties) {
        this.invalidate(
          property.type === "RestElement" ? property.argument : property.value,
          scope,
        );
      }
    } else if (node.type === "ArrayPattern") {
      for (const item of node.elements.filter((element) => element !== null)) {
        this.invalidate(item, scope);
      }
    } else if (node.type === "AssignmentPattern") {
      this.invalidate(node.left, scope);
    } else if (node.type === "RestElement") {
      this.invalidate(node.argument, scope);
    }
  }

  /** Resolve an expression at its lexical scope; null means its identity is unknown. */
  resolve(node: Node): string | null {
    const api = this.resolveAt(node, this.scopes.get(node) ?? this.root, new Set());
    if (api === null) return null;
    for (const path of this.overwritten) {
      if (api === path || api.startsWith(`${path}.`)) return null;
    }
    return api;
  }

  private resolveAt(node: Node, scope: Scope, seen: Set<Binding>): string | null {
    if (node.type === "Identifier") return this.resolveIdentifier(node.name, scope, seen);
    if (node.type === "MemberExpression") return this.resolveMember(node, scope, seen);
    if (node.type === "CallExpression") return this.resolveRequire(node, scope, seen);
    if (node.type === "ChainExpression") return this.resolveAt(node.expression, scope, seen);
    if (node.type === "TSAsExpression" || node.type === "TSNonNullExpression") {
      return this.resolveAt(node.expression, scope, seen);
    }
    return null;
  }

  private resolveMember(
    node: Extract<Node, { type: "MemberExpression" }>,
    scope: Scope,
    seen: Set<Binding>,
  ): string | null {
    const base = this.resolveAt(node.object, scope, seen);
    const property = propertyName(node.property, node.computed) ?? "*";
    if (base === "global" && property === "process") return "process";
    return base === null ? null : `${base}.${property}`;
  }

  private resolveRequire(
    node: Extract<Node, { type: "CallExpression" }>,
    scope: Scope,
    seen: Set<Binding>,
  ): string | null {
    if (this.resolveAt(node.callee, scope, seen) !== "global.require") return null;
    const source = node.arguments[0];
    return source?.type === "Literal" && typeof source.value === "string"
      ? source.value.replace(/^node:/, "")
      : null;
  }

  private resolveIdentifier(name: string, scope: Scope, seen: Set<Binding>): string | null {
    const binding = this.lookup(name, scope);
    if (binding === undefined) return this.globalApi(name);
    if (binding.reassigned || seen.has(binding) || seen.size >= 32) return null;
    seen.add(binding);
    const source = binding.source;
    if (source === null) return null;
    if (typeof source === "string") return source + binding.suffix;
    const base = this.resolveAt(source, binding.scope, seen);
    return base === null ? null : base + binding.suffix;
  }

  private globalApi(name: string): string | null {
    if (GLOBAL_OBJECTS.has(name)) return "global";
    if (GLOBALS.has(name)) return `global.${name}`;
    return name === "process" ? "process" : null;
  }
}
