import { readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { scanExtension, validateScanOptions } from "#internal/scanner/index.js";
import { createRepositoryCheck } from "#internal/scanner/checks/repository.js";
import type {
  BatchScanResult,
  ScanOptions,
  ScanResult,
  Severity,
} from "#internal/scanner/types.js";

export interface BatchScanCallbacks {
  onProgress?: (current: number, total: number, path: string) => void;
  onResult?: (path: string, result: ScanResult) => void;
  onError?: (path: string, error: string) => void;
}

export interface BatchScanOptions {
  concurrency?: number; // Default: 4
}

async function runWithConcurrency<T>(
  items: T[],
  concurrency: number,
  fn: (item: T, index: number) => Promise<void>,
): Promise<void> {
  const pending = items.entries();
  const running: Promise<void>[] = [];

  async function runNext(): Promise<void> {
    for (const [index, item] of pending) {
      await fn(item, index);
    }
  }

  // Start `concurrency` workers
  for (let i = 0; i < Math.min(concurrency, items.length); i++) {
    running.push(runNext());
  }

  await Promise.all(running);
}

type ScanOutcome = { result: ScanResult } | { error: string };

interface VsixFile {
  path: string;
  size: number;
}

export async function findVsixFiles(dir: string): Promise<string[]> {
  const files: VsixFile[] = [];

  async function walk(currentDir: string): Promise<void> {
    const entries = await readdir(currentDir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = join(currentDir, entry.name);

      if (entry.isDirectory()) {
        await walk(fullPath);
      } else if (entry.isFile() && entry.name.endsWith(".vsix")) {
        const fileStat = await stat(fullPath);
        files.push({ path: fullPath, size: fileStat.size });
      }
    }
  }

  await walk(dir);

  // Sort by size (smallest first) so smaller files complete sooner
  files.sort((a, b) => a.size - b.size);

  return files.map((f) => f.path);
}

/** Find VSIX archives recursively and scan them with bounded concurrency. */
export async function scanDirectory(
  dir: string,
  options: ScanOptions,
  callbacks?: BatchScanCallbacks,
  batchOptions?: BatchScanOptions,
): Promise<BatchScanResult> {
  const startTime = Date.now();
  const dirStat = await stat(dir).catch(() => null);
  if (!(dirStat?.isDirectory() === true)) {
    throw new Error(`Not a directory: ${dir}`);
  }

  const vsixFiles = await findVsixFiles(dir);
  const batch = await scanPaths(vsixFiles, options, callbacks, batchOptions);
  batch.summary.scanDuration = Date.now() - startTime;
  return batch;
}

/**
 * Scan explicit extension paths with bounded concurrency and deterministic result order.
 *
 * Records scan failures alongside successful results so callers can report partial batches.
 */
export async function scanPaths(
  paths: string[],
  options: ScanOptions,
  callbacks?: BatchScanCallbacks,
  batchOptions?: BatchScanOptions,
): Promise<BatchScanResult> {
  const startTime = Date.now();
  const concurrency = batchOptions?.concurrency ?? 4;
  const handlers = callbacks ?? {};
  if (!Number.isSafeInteger(concurrency) || concurrency < 1) {
    throw new Error(
      `Scan concurrency must be a positive safe integer, received ${String(concurrency)}.`,
    );
  }
  validateScanOptions(options);
  const repositoryCheck = createRepositoryCheck();

  let completed = 0;
  const resultsByIndex = new Map<number, ScanResult>();
  const errorsByIndex = new Map<number, { path: string; error: string }>();

  await runWithConcurrency(paths, concurrency, async (filePath, index) => {
    const outcome = await scanExtension(filePath, options, repositoryCheck).then<
      ScanOutcome,
      ScanOutcome
    >(
      (result) => ({ result }),
      (error: unknown) => ({ error: error instanceof Error ? error.message : String(error) }),
    );
    if ("result" in outcome) {
      resultsByIndex.set(index, outcome.result);
      handlers.onResult?.(filePath, outcome.result);
    } else {
      errorsByIndex.set(index, { path: filePath, error: outcome.error });
      handlers.onError?.(filePath, outcome.error);
    }
    handlers.onProgress?.(++completed, paths.length, filePath);
  });
  return collectBatch(paths, resultsByIndex, errorsByIndex, startTime);
}

function collectBatch(
  paths: string[],
  resultsByIndex: Map<number, ScanResult>,
  errorsByIndex: Map<number, { path: string; error: string }>,
  startTime: number,
): BatchScanResult {
  // Collect results in original file order for deterministic summary
  const results: ScanResult[] = [];
  const errors: Array<{ path: string; error: string }> = [];
  for (let i = 0; i < paths.length; i++) {
    const result = resultsByIndex.get(i);
    if (result) results.push(result);
    const error = errorsByIndex.get(i);
    if (error) errors.push(error);
  }

  return summarizeBatch(results, errors, paths.length, startTime);
}

/** Summarize completed targets and failures using the common batch output contract. */
export function summarizeBatch(
  results: ScanResult[],
  errors: BatchScanResult["errors"],
  totalFiles: number,
  startTime: number,
): BatchScanResult {
  const findingsBySeverity: Record<Severity, number> = {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };

  let totalFindings = 0;
  for (const result of results) {
    for (const finding of result.findings) {
      findingsBySeverity[finding.severity]++;
      totalFindings++;
    }
  }

  return {
    results,
    errors,
    summary: {
      totalFiles,
      scannedFiles: results.length,
      failedFiles: errors.length,
      totalFindings,
      findingsBySeverity,
      scanDuration: Date.now() - startTime,
    },
  };
}
