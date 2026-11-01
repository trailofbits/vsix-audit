const CONTROLS = /[\p{Cc}\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/gu;

function escapedControl(character: string): string {
  const code = character.charCodeAt(0);
  return code <= 0xff
    ? `\\x${code.toString(16).padStart(2, "0")}`
    : `\\u${code.toString(16).padStart(4, "0")}`;
}

/** Escape untrusted text before adding the CLI's colors or line breaks. */
export function terminalText(value: unknown): string {
  return String(value).replace(CONTROLS, escapedControl);
}

/** Serialize JSON reports while escaping controls that JSON leaves literal. */
export function reportJson(value: object): string {
  return JSON.stringify(value, null, 2).replace(
    /[\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/g,
    (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

/** Print errors without allowing paths, metadata, or subprocess output to control the terminal. */
export function printError(error: unknown): void {
  console.error("Error:", terminalText(error instanceof Error ? error.message : error));
}
