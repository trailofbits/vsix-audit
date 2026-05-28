import { describe, expect, it } from "vitest";
import { detectCyrillicHomoglyphs, scanCyrillicHomoglyphRuns } from "./homoglyph.js";

describe("homoglyph scanner", () => {
  it("classifies mixed Latin/Cyrillic tokens", () => {
    const cyrillicO = String.fromCodePoint(0x043e);
    const matches = scanCyrillicHomoglyphRuns(
      `const url = "https://g${cyrillicO}${cyrillicO}gle.com";`,
    );

    expect(matches).toHaveLength(1);
    expect(matches[0]?.kind).toBe("mixed-script");
    expect(matches[0]?.firstHomoglyph.decoded).toBe(cyrillicO);
  });

  it("breaks tokens on decoded escaped whitespace", () => {
    const escapedSpace = "\\" + "u0020";
    const matches = scanCyrillicHomoglyphRuns(`const label = "Русский${escapedSpace}English";`);

    expect(matches).toHaveLength(0);
  });

  it("classifies all-lookalike Cyrillic domain labels", () => {
    const spoofedPaypal = String.fromCodePoint(0x0440, 0x0430, 0x0443, 0x0440, 0x0430, 0x04cf);
    const matches = scanCyrillicHomoglyphRuns(`const url = "https://${spoofedPaypal}.com/login";`);

    expect(matches).toHaveLength(1);
    expect(matches[0]?.kind).toBe("all-lookalike-domain");
  });

  it("does not classify all-lookalike Cyrillic text outside domain contexts", () => {
    const lookAlikeWord = String.fromCodePoint(0x0440, 0x0430, 0x0443, 0x0440, 0x0430, 0x04cf);
    const matches = scanCyrillicHomoglyphRuns(`const label = "${lookAlikeWord}";`);

    expect(matches).toHaveLength(0);
  });

  it("reports decoded code points for escaped homoglyphs", () => {
    const escapedO = "\\" + "u043E";
    const matches = detectCyrillicHomoglyphs(
      `const url = "https://g${escapedO}${escapedO}gle.com";`,
    );

    expect(matches).toHaveLength(1);
    expect(matches[0]?.matched.codePointAt(0)).toBe(0x043e);
  });
});
