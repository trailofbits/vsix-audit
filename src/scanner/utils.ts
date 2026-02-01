/**
 * Shared utility functions for scanner checks.
 */

/**
 * Find line number for a string match in content.
 * Returns 1-indexed line number, or undefined if not found.
 */
export function findLineNumberByString(content: string, searchStr: string): number | undefined {
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (lines[i]?.includes(searchStr)) {
      return i + 1;
    }
  }
  return undefined;
}

/**
 * Find line number for a regex match by its index.
 * Returns 1-indexed line number.
 */
export function findLineNumberByIndex(content: string, index: number): number {
  const beforeMatch = content.slice(0, index);
  return beforeMatch.split("\n").length;
}
