import { readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { scanExtension } from "./index.js";
import type { BatchScanResult, ScanOptions, ScanResult, Severity } from "./types.js";

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
  let nextIndex = 0;
  const running: Promise<void>[] = [];

  async function runNext(): Promise<void> {
    while (nextIndex < items.length) {
      const index = nextIndex++;
      const item = items[index]!;
      await fn(item, index);
    }
  }

  // Start `concurrency` workers
  for (let i = 0; i < Math.min(concurrency, items.length); i++) {
    running.push(runNext());
  }

  await Promise.all(running);
}

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

export async function scanDirectory(
  dir: string,
  options: ScanOptions,
  callbacks?: BatchScanCallbacks,
  batchOptions?: BatchScanOptions,
): Promise<BatchScanResult> {
  const startTime = Date.now();
  const concurrency = batchOptions?.concurrency ?? 4;

  const dirStat = await stat(dir).catch(() => null);
  if (!dirStat?.isDirectory()) {
    throw new Error(`Not a directory: ${dir}`);
  }

  const vsixFiles = await findVsixFiles(dir);

  let completed = 0;
  const resultsByIndex = new Map<number, ScanResult>();
  const errorsByIndex = new Map<number, { path: string; error: string }>();

  await runWithConcurrency(vsixFiles, concurrency, async (filePath, index) => {
    try {
      const result = await scanExtension(filePath, options);
      resultsByIndex.set(index, result);
      callbacks?.onResult?.(filePath, result);
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      errorsByIndex.set(index, { path: filePath, error: errorMsg });
      callbacks?.onError?.(filePath, errorMsg);
    } finally {
      // Call progress AFTER completion with accurate count
      callbacks?.onProgress?.(++completed, vsixFiles.length, filePath);
    }
  });

  // Collect results in original file order for deterministic summary
  const results: ScanResult[] = [];
  const errors: Array<{ path: string; error: string }> = [];
  for (let i = 0; i < vsixFiles.length; i++) {
    const result = resultsByIndex.get(i);
    if (result) results.push(result);
    const error = errorsByIndex.get(i);
    if (error) errors.push(error);
  }

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
      totalFiles: vsixFiles.length,
      scannedFiles: results.length,
      failedFiles: errors.length,
      totalFindings,
      findingsBySeverity,
      scanDuration: Date.now() - startTime,
    },
  };
}
