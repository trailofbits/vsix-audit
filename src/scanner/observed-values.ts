import type { Node } from "oxc-parser";
import { propertyName } from "#internal/scanner/source-bindings.js";
import type { ObservedValue } from "#internal/scanner/types.js";

/** Read bounded literal arguments, preserving unresolved expressions without evaluating them. */
export function observedValue(node: Node, source: string, depth = 0): ObservedValue {
  const unresolved: ObservedValue = {
    kind: "unresolved",
    expression: source.slice(node.start, node.end).slice(0, 200),
  };
  if (depth >= 8) return unresolved;
  const literal = literalValue(node);
  if (literal !== undefined) return literal;
  if (node.type === "ArrayExpression") return arrayValue(node, source, depth) ?? unresolved;
  if (node.type === "ObjectExpression") {
    return objectValue(node, source, depth) ?? unresolved;
  }
  return unresolved;
}

function primitiveValue(value: unknown): ObservedValue | undefined {
  if (typeof value === "string") {
    return value.length <= 4096 ? { kind: "literal", value } : undefined;
  }
  if (typeof value === "number") {
    return Number.isFinite(value) ? { kind: "literal", value } : undefined;
  }
  if (value === null || typeof value === "boolean") return { kind: "literal", value };
  return undefined;
}

function literalValue(node: Node): ObservedValue | undefined {
  if (node.type === "Literal") return "regex" in node ? undefined : primitiveValue(node.value);
  if (node.type !== "TemplateLiteral") return undefined;
  if (node.expressions.length > 0) return undefined;
  return primitiveValue(node.quasis[0]?.value.cooked);
}

function objectValue(
  node: Extract<Node, { type: "ObjectExpression" }>,
  source: string,
  depth: number,
): ObservedValue | null {
  if (node.properties.length > 64) return null;
  const properties: Record<string, ObservedValue> = Object.create(null) as Record<
    string,
    ObservedValue
  >;
  for (const property of node.properties) {
    if (property.type !== "Property" || property.kind !== "init" || property.method) return null;
    const key = propertyName(property.key, property.computed);
    if (key === null) return null;
    properties[key] = observedValue(property.value, source, depth + 1);
  }
  return { kind: "object", properties };
}

function arrayValue(
  node: Extract<Node, { type: "ArrayExpression" }>,
  source: string,
  depth: number,
): ObservedValue | null {
  if (node.elements.length > 64 || node.elements.some((item) => item === null)) return null;
  return {
    kind: "array",
    items: node.elements
      .filter((item) => item !== null)
      .map((item) => observedValue(item, source, depth + 1)),
  };
}
