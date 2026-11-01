import { spawn, type ChildProcess } from "node:child_process";
import type { Readable } from "node:stream";
import {
  createYaraOutputReader,
  type YaraOutputReader,
} from "#internal/scanner/checks/yara-output.js";

function completion(child: ChildProcess): Promise<void> {
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(`YARA-X exited with ${signal ?? `status ${String(code)}`}.`));
    });
  });
}

async function readOutput(stream: Readable, reader: YaraOutputReader): Promise<void> {
  try {
    for await (const chunk of stream as AsyncIterable<unknown>) {
      if (!Buffer.isBuffer(chunk)) throw new Error("YARA-X stdout must contain bytes.");
      reader.write(chunk);
    }
  } finally {
    reader.end();
  }
}

async function readDiagnostics(stream: Readable): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  let truncated = false;
  for await (const chunk of stream as AsyncIterable<unknown>) {
    if (!Buffer.isBuffer(chunk)) throw new Error("YARA-X stderr must contain bytes.");
    const remaining = 64 * 1024 - size;
    if (chunk.length > remaining) truncated = true;
    if (remaining > 0) {
      const retained = chunk.subarray(0, remaining);
      chunks.push(retained);
      size += retained.length;
    }
  }
  return (
    Buffer.concat(chunks).toString("utf8") + (truncated ? "\n[YARA diagnostics truncated]" : "")
  );
}

/**
 * Drain YARA output with bounded evidence and diagnostics, retaining records before process errors.
 */
export async function runYara(
  args: string[],
  onRecord: (value: unknown) => void,
  onInvalidOutput: (error: unknown) => void,
  timeout = 60_000,
): Promise<string> {
  const child = spawn("yr", args, {
    stdio: ["ignore", "pipe", "pipe"],
    timeout,
    killSignal: "SIGKILL",
  });
  const reader = createYaraOutputReader(onRecord, onInvalidOutput);
  const outcomes = await Promise.allSettled([
    completion(child),
    readOutput(child.stdout, reader),
    readDiagnostics(child.stderr),
  ] as const);
  const diagnostics = outcomes[2];
  const stderr = diagnostics.status === "fulfilled" ? diagnostics.value : "";
  const failure = outcomes.find((outcome) => outcome.status === "rejected");
  if (failure?.status === "rejected") {
    const reason: unknown = failure.reason;
    throw new Error(`${String(reason)} ${stderr}`);
  }
  return stderr;
}
