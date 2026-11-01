import type { Node, Span } from "oxc-parser";
import { observedValue } from "#internal/scanner/observed-values.js";
import type { SourceBindings } from "#internal/scanner/source-bindings.js";
import type { Capability, Observation, ObservationKind } from "#internal/scanner/types.js";
import { computeLineStarts, offsetToColumn, offsetToLine } from "#internal/scanner/utils.js";

type Operation = { kind: ObservationKind; capability: Capability };
function apis(
  kind: ObservationKind,
  capability: Capability,
  bases: string[],
  methods: string[],
): Array<[string, Operation]> {
  return bases.flatMap((base) =>
    methods.map((method): [string, Operation] => [
      method === "" ? base : `${base}.${method}`,
      { kind, capability },
    ]),
  );
}

const FILE_MODULES = ["fs", "fs/promises", "fs.promises", "vscode.workspace.fs"];
const NETWORK_MODULES = ["http", "https", "net", "tls", "undici", "axios", "node-fetch"];
const OPERATIONS = new Map<string, Operation>([
  ...apis("network-request", "network", ["global"], ["fetch"]),
  ...apis("network-client", "network", ["global"], ["WebSocket", "EventSource", "XMLHttpRequest"]),
  ...apis("network-request", "network", NETWORK_MODULES, [
    "request",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "fetch",
    "connect",
    "createConnection",
  ]),
  ...apis("network-request", "network", ["axios", "node-fetch"], [""]),
  ...apis("file-read", "fileAccess", FILE_MODULES, [
    "readFile",
    "readFileSync",
    "createReadStream",
    "readdir",
    "readdirSync",
    "readDirectory",
  ]),
  ...apis("file-write", "fileAccess", FILE_MODULES, [
    "writeFile",
    "writeFileSync",
    "appendFile",
    "appendFileSync",
    "createWriteStream",
    "unlink",
    "unlinkSync",
    "rm",
    "rmSync",
    "rename",
    "renameSync",
    "copyFile",
    "copyFileSync",
    "delete",
    "copy",
  ]),
  ...apis(
    "process-execution",
    "execution",
    ["child_process"],
    ["exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"],
  ),
  ...apis("process-execution", "execution", ["vscode.window"], ["createTerminal"]),
  ...apis("process-execution", "execution", ["vscode.tasks"], ["executeTask"]),
  ...apis("code-execution", "execution", ["global"], ["eval", "Function"]),
  ...apis("code-execution", "execution", ["process"], ["binding", "_linkedBinding"]),
  ...apis("module-load", "execution", ["global"], ["require"]),
  ...apis(
    "credential-access",
    "credentials",
    ["keytar"],
    ["getPassword", "findPassword", "findCredentials", "setPassword", "deletePassword"],
  ),
  ...apis(
    "credential-access",
    "credentials",
    ["vscode.authentication"],
    ["getSession", "getAccounts"],
  ),
  ...apis("dynamic-call", "fileAccess", FILE_MODULES, ["*"]),
  ...apis("dynamic-call", "execution", ["child_process"], ["*"]),
  ...apis("dynamic-call", "network", NETWORK_MODULES, ["*"]),
]);

/** Collect source operations from the same parsed tree used by the AST security checks. */
export class ObservationCollector {
  readonly observations: Observation[] = [];
  private readonly lines: number[];

  constructor(
    private readonly filename: string,
    private readonly source: string,
  ) {
    this.lines = computeLineStarts(source);
  }

  /** Record calls and imports with their original source spans; never evaluate fixture code. */
  visit(node: Node, bindings: SourceBindings): void {
    if (node.type === "ImportDeclaration") {
      if (node.importKind !== "type") {
        this.add(node, "import", "import", { kind: "module-load", capability: "execution" }, [
          node.source,
        ]);
      }
      return;
    }
    if (node.type === "ImportExpression") {
      this.add(node, "import", "call", { kind: "module-load", capability: "execution" }, [
        node.source,
      ]);
      return;
    }
    if (node.type !== "CallExpression" && node.type !== "NewExpression") return;
    const api = bindings.resolve(node.callee);
    if (api === null) return;
    const operation = OPERATIONS.get(api);
    if (operation !== undefined) this.add(node, api, "call", operation, node.arguments);
  }

  private add(
    span: Span,
    api: string,
    evidence: Observation["evidence"],
    operation: Operation,
    args: Node[],
  ): void {
    this.observations.push({
      ...operation,
      api,
      evidence,
      arguments: args.map((arg) => observedValue(arg, this.source)),
      snippet: this.source.slice(span.start, span.end).slice(0, 200),
      location: {
        file: this.filename,
        line: offsetToLine(span.start, this.lines),
        column: offsetToColumn(span.start, this.lines) + 1,
        endLine: offsetToLine(span.end, this.lines),
        endColumn: offsetToColumn(span.end, this.lines) + 1,
        start: span.start,
        end: span.end,
      },
    });
  }
}
