The Brotli fixture preserves `dist/node/main.js` from Markdown All in One 3.6.3.
Tests decompress and inspect the source without executing it. The accompanying
`markdown-all-in-one-LICENSE.txt` preserves the extension's distributed MIT license.

- Publisher and extension: `yzhang.markdown-all-in-one`, version `3.6.3`.
- Source: VS Code Marketplace, downloaded through the pinned clean-corpus manifest.
- Original VSIX SHA-256: `c4985b150497d430c3a7c884fd1f1ea7ed6de4846eb0192f8c770d9af8eb6e83`.
- Uncompressed source SHA-256: `9e351182a9d98bf1b3ba0b4bf5a08658e15147d4bd55596e8bf30b549145151b`.
- Uncompressed length: 1,533,214 bytes.
- The single U+202A is at UTF-16 offset 383,378, inside the KaTeX lexer class
  `[!-\\[\\]-‧<U+202A>-퟿豈-￿]`.

The exception covers only that character in that exact source. Renaming a file cannot
create an exception. Editing, prefixing, or appending source invalidates the hash.
New bundle versions require a fresh review and an independently verified source hash.

To reproduce the compressed fixture from the verified source, use Node's
`brotliCompressSync` with `BROTLI_PARAM_QUALITY` set to `11`. Decompression must restore
both the source length and SHA-256 listed above.
