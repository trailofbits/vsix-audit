/**
 * Shared utility functions for scanner checks.
 */

/**
 * Pre-compute line start offsets for binary search.
 * Returns array where index i is the character offset
 * of line i+1 (0-indexed array, 1-indexed lines).
 */
export function computeLineStarts(content: string): number[] {
  const lineStarts = [0];
  for (let i = 0; i < content.length; i++) {
    if (content[i] === "\n") {
      lineStarts.push(i + 1);
    }
  }
  return lineStarts;
}

/**
 * Convert character offset to 1-indexed line number
 * using binary search on pre-computed line starts.
 */
export function offsetToLine(offset: number, lineStarts: number[]): number {
  let low = 0;
  let high = lineStarts.length - 1;
  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    const midStart = lineStarts[mid];
    if (midStart !== undefined && midStart <= offset) {
      low = mid;
    } else {
      high = mid - 1;
    }
  }
  return low + 1;
}

/**
 * Convert character offset to 0-indexed column number.
 */
export function offsetToColumn(offset: number, lineStarts: number[]): number {
  const line = offsetToLine(offset, lineStarts);
  const lineStart = lineStarts[line - 1] ?? 0;
  return offset - lineStart;
}

/**
 * Find line number for a string match in content.
 * Returns 1-indexed line number, or undefined if not found.
 *
 * When called multiple times on the same content, pass
 * pre-computed lineStarts for O(log n) per call instead
 * of O(n).
 */
export function findLineNumberByString(
  content: string,
  searchStr: string,
  lineStarts?: number[],
): number | undefined {
  const idx = content.indexOf(searchStr);
  if (idx === -1) return undefined;
  const starts = lineStarts ?? computeLineStarts(content);
  return offsetToLine(idx, starts);
}

/**
 * Find line number for a regex match by its character
 * offset. Returns 1-indexed line number.
 *
 * When called multiple times on the same content, pass
 * pre-computed lineStarts for O(log n) per call.
 */
export function findLineNumberByIndex(
  content: string,
  index: number,
  lineStarts?: number[],
): number {
  const starts = lineStarts ?? computeLineStarts(content);
  return offsetToLine(index, starts);
}
