#!/usr/bin/env node
import { cli } from "./cli.js";

// On Windows, stdout/stderr are buffered when piped (not connected to a TTY).
// setBlocking(true) makes them synchronous so writes flush immediately,
// preventing output loss when process.exitCode is set and the process exits.
for (const stream of [process.stdout, process.stderr]) {
  const handle = (stream as unknown as { _handle?: { setBlocking?: (v: boolean) => void } })._handle;
  handle?.setBlocking?.(true);
}

cli.parse();
